// Package dns implements a minimal authoritative DNS server.
//
// It decodes RFC 1035 wire-format queries, resolves IP addresses encoded in
// subdomain labels (e.g. "192-168-1-1.dyn.example.com" → 192.168.1.1), and
// encodes responses. EDNS0 payload-size negotiation and TC-bit truncation for
// oversized UDP responses are supported.
//
// IP encoding rules:
//   - IPv4: dashes replace dots — "192-168-1-1"
//   - IPv6: dashes replace colons, double-dash replaces "::" — "2001-db8--1"
//   - An optional "ip6-" prefix forces IPv6 parsing on otherwise ambiguous labels
package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/Vr00mm/dynip-dns/internal/pkg/config"
)

// exit is the process-exit function. Overridden in tests to capture fatal errors.
var exit = os.Exit

const (
	typeA    = 1
	typeNS   = 2
	typeSOA  = 6
	typeTXT  = 16
	typeAAAA = 28
	typeANY  = 255
	classIN  = 1
	rcodeOK  = 0
	rcodeName = 3
)

type dnsHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type question struct {
	Name   string
	QType  uint16
	QClass uint16
}

type rr struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// HandleQuery parses a DNS request and returns the encoded response.
// maxUDP is the maximum UDP payload size advertised by the client (0 = TCP, no limit).
func HandleQuery(cfg config.Config, req []byte, maxUDP uint16) ([]byte, error) {
	hdr, q, _, err := parseQuery(req)
	if err != nil {
		return nil, err
	}

	rh := dnsHeader{ID: hdr.ID, Flags: 0x8000, QDCount: 1}
	if (hdr.Flags & 0x0100) != 0 {
		rh.Flags |= 0x0100
	}
	rh.Flags |= 0x0400 // AA

	answers := []rr{}
	auth := []rr{}
	extra := []rr{}

	qName := fqdn(strings.ToLower(q.Name))
	if !strings.HasSuffix(qName, cfg.Zone) {
		rh.Flags |= rcodeName
		return buildResponse(rh, q, answers, auth, extra)
	}

	host := strings.TrimSuffix(qName, cfg.Zone)
	host = strings.TrimSuffix(host, ".")

	switch q.QType {
	case typeSOA:
		if qName == cfg.Zone {
			answers = append(answers, soaRecord(cfg))
		} else {
			rh.Flags |= rcodeName
		}
	case typeNS:
		if qName == cfg.Zone {
			answers = append(answers, apexNS(cfg)...)
			if cfg.EnableGlue {
				extra = append(extra, glueRecords(cfg)...)
			}
		} else {
			rh.Flags |= rcodeName
		}
	case typeTXT:
		if qName == cfg.Zone {
			answers = append(answers,
				txtRecord(cfg.Zone, cfg.TTL, cfg.VersionTXT),
				txtRecord(cfg.Zone, cfg.TTL, "formats: ipv4=192-168-1-1 ipv6=2001-db8--1"),
			)
		} else {
			rh.Flags |= rcodeName
		}
	case typeA:
		switch {
		case qName == cfg.Zone:
			if cfg.EnableGlue {
				answers = append(answers, glueARecords(cfg)...)
			}
		case qName == cfg.Ns1Host || qName == cfg.Ns2Host:
			if cfg.EnableGlue {
				answers = append(answers, nameGlueARecords(cfg, qName)...)
			}
		default:
			if ip := findIPv4InLabels(host); ip != nil {
				answers = append(answers, aRecord(qName, cfg.TTL, ip))
			} else {
				rh.Flags |= rcodeName
			}
		}
	case typeAAAA:
		switch {
		case qName == cfg.Zone:
			if cfg.EnableGlue {
				answers = append(answers, glueAAAARecords(cfg)...)
			}
		case qName == cfg.Ns1Host || qName == cfg.Ns2Host:
			if cfg.EnableGlue {
				answers = append(answers, nameGlueAAAARecords(cfg, qName)...)
			}
		default:
			if ip := findIPv6InLabels(host); ip != nil {
				answers = append(answers, aaaaRecord(qName, cfg.TTL, ip))
			} else {
				rh.Flags |= rcodeName
			}
		}
	case typeANY:
		if qName == cfg.Zone {
			answers = append(answers, apexNS(cfg)...)
			answers = append(answers, soaRecord(cfg), txtRecord(cfg.Zone, cfg.TTL, cfg.VersionTXT))
			if cfg.EnableGlue {
				extra = append(extra, glueRecords(cfg)...)
			}
		} else {
			if ip4 := findIPv4InLabels(host); ip4 != nil {
				answers = append(answers, aRecord(qName, cfg.TTL, ip4))
			}
			if ip6 := findIPv6InLabels(host); ip6 != nil {
				answers = append(answers, aaaaRecord(qName, cfg.TTL, ip6))
			}
			if len(answers) == 0 {
				rh.Flags |= rcodeName
			}
		}
	default:
		if qName == cfg.Zone {
			auth = append(auth, soaRecord(cfg))
		}
	}

	if cfg.LogQueries {
		slog.Info("query",
			"qname", sanitizeName(qName),
			"qtype", q.QType,
			"rcode", rh.Flags&0x000f,
			"answers", len(answers),
			"authority", len(auth),
			"extra", len(extra),
		)
	}

	resp, err := buildResponse(rh, q, answers, auth, extra)
	if err != nil {
		return nil, err
	}
	if maxUDP > 0 && len(resp) > int(maxUDP) {
		rh.Flags |= 0x0200 // TC bit: tell client to retry over TCP
		resp, err = buildResponse(rh, q, nil, nil, nil)
	}
	return resp, err
}

// ParseEDNS0PayloadSize extracts the UDP payload size advertised by the client
// in an EDNS0 OPT record. Returns 512 if no OPT record is present.
func ParseEDNS0PayloadSize(msg []byte) uint16 {
	if len(msg) < 12 {
		return 512
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))
	if arCount == 0 {
		return 512
	}
	off := 12
	for range qdCount {
		_, newOff, err := decodeName(msg, off)
		if err != nil {
			return 512
		}
		off = newOff + 4 // skip qtype + qclass
	}
	for range arCount {
		if off >= len(msg) {
			break
		}
		_, newOff, err := decodeName(msg, off)
		if err != nil {
			break
		}
		off = newOff
		if off+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		udpSize := binary.BigEndian.Uint16(msg[off+2 : off+4]) // class field = payload size for OPT
		rdLen := binary.BigEndian.Uint16(msg[off+8 : off+10])
		off += 10 + int(rdLen)
		if rrType == 41 { // OPT record
			if udpSize < 512 {
				return 512
			}
			return udpSize
		}
	}
	return 512
}

func parseQuery(msg []byte) (dnsHeader, question, int, error) {
	if len(msg) < 12 {
		return dnsHeader{}, question{}, 0, errors.New("message too short")
	}
	h := dnsHeader{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}
	if h.QDCount < 1 {
		return h, question{}, 0, errors.New("no question")
	}
	off := 12
	name, off, err := decodeName(msg, off)
	if err != nil {
		return h, question{}, 0, err
	}
	if len(msg) < off+4 {
		return h, question{}, 0, errors.New("truncated question")
	}
	q := question{
		Name:   name,
		QType:  binary.BigEndian.Uint16(msg[off : off+2]),
		QClass: binary.BigEndian.Uint16(msg[off+2 : off+4]),
	}
	return h, q, off + 4, nil
}

func buildResponse(h dnsHeader, q question, ans, auth, extra []rr) ([]byte, error) {
	h.ANCount = uint16(len(ans))
	h.NSCount = uint16(len(auth))
	h.ARCount = uint16(len(extra))

	var out bytes.Buffer
	fields := []uint16{h.ID, h.Flags, h.QDCount, h.ANCount, h.NSCount, h.ARCount}
	for _, v := range fields {
		_ = binary.Write(&out, binary.BigEndian, v)
	}

	if err := encodeQuestion(&out, q); err != nil {
		return nil, err
	}
	for _, r := range ans {
		if err := encodeRR(&out, r); err != nil {
			return nil, err
		}
	}
	for _, r := range auth {
		if err := encodeRR(&out, r); err != nil {
			return nil, err
		}
	}
	for _, r := range extra {
		if err := encodeRR(&out, r); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func encodeQuestion(out *bytes.Buffer, q question) error {
	if err := encodeName(out, q.Name); err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, q.QType)
	_ = binary.Write(out, binary.BigEndian, q.QClass)
	return nil
}

func encodeRR(out *bytes.Buffer, r rr) error {
	if err := encodeName(out, r.Name); err != nil {
		return err
	}
	if len(r.Data) > 0xFFFF {
		return fmt.Errorf("rdata too large: %d bytes", len(r.Data))
	}
	_ = binary.Write(out, binary.BigEndian, r.Type)
	_ = binary.Write(out, binary.BigEndian, r.Class)
	_ = binary.Write(out, binary.BigEndian, r.TTL)
	_ = binary.Write(out, binary.BigEndian, uint16(len(r.Data)))
	_, _ = out.Write(r.Data)
	return nil
}

func encodeName(out *bytes.Buffer, name string) error {
	name = fqdn(name)
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) == 1 && labels[0] == "" {
		return out.WriteByte(0)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid label: %q", label)
		}
		out.WriteByte(byte(len(label)))
		out.WriteString(label)
	}
	return out.WriteByte(0)
}

func decodeName(msg []byte, off int) (string, int, error) {
	var labels []string
	start := off
	jumped := false
	seen := 0
	for {
		if off >= len(msg) {
			return "", 0, errors.New("name out of range")
		}
		ln := int(msg[off])
		if ln&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, errors.New("bad compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if ptr >= len(msg) {
				return "", 0, errors.New("compression pointer out of range")
			}
			if !jumped {
				start = off + 2
				jumped = true
			}
			off = ptr
			seen++
			if seen > 20 {
				return "", 0, errors.New("too many compression jumps")
			}
			continue
		}
		off++
		if ln == 0 {
			break
		}
		if off+ln > len(msg) {
			return "", 0, errors.New("label out of range")
		}
		labels = append(labels, string(msg[off:off+ln]))
		off += ln
	}
	if !jumped {
		start = off
	}
	return fqdn(strings.Join(labels, ".")), start, nil
}

// sanitizeName replaces ASCII control characters in a DNS name with '?' to
// prevent log injection via crafted labels containing newlines or other
// control bytes.
func sanitizeName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func fqdn(name string) string {
	if name == "" {
		return "."
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func aRecord(name string, ttl uint32, ip net.IP) rr {
	return rr{Name: fqdn(name), Type: typeA, Class: classIN, TTL: ttl, Data: ip.To4()}
}

func aaaaRecord(name string, ttl uint32, ip net.IP) rr {
	return rr{Name: fqdn(name), Type: typeAAAA, Class: classIN, TTL: ttl, Data: ip.To16()}
}

func txtRecord(name string, ttl uint32, text string) rr {
	b := []byte(text)
	if len(b) > 255 {
		b = b[:255]
	}
	return rr{Name: fqdn(name), Type: typeTXT, Class: classIN, TTL: ttl, Data: append([]byte{byte(len(b))}, b...)}
}

func nsRecord(zone, host string, ttl uint32) rr {
	var b bytes.Buffer
	if err := encodeName(&b, host); err != nil {
		slog.Error("encodeName failed for NS record", "host", host, "err", err)
		exit(1)
		return rr{}
	}
	return rr{Name: fqdn(zone), Type: typeNS, Class: classIN, TTL: ttl, Data: b.Bytes()}
}

func soaRecord(cfg config.Config) rr {
	var b bytes.Buffer
	for _, name := range []string{cfg.Ns1Host, cfg.Hostmaster} {
		if err := encodeName(&b, name); err != nil {
			slog.Error("encodeName failed for SOA record", "name", name, "err", err)
			exit(1)
			return rr{}
		}
	}
	fields := []uint32{cfg.Serial, 300, 60, 1200, cfg.TTL}
	for _, v := range fields {
		_ = binary.Write(&b, binary.BigEndian, v)
	}
	return rr{Name: cfg.Zone, Type: typeSOA, Class: classIN, TTL: cfg.TTL, Data: b.Bytes()}
}

func apexNS(cfg config.Config) []rr {
	return []rr{nsRecord(cfg.Zone, cfg.Ns1Host, cfg.TTL), nsRecord(cfg.Zone, cfg.Ns2Host, cfg.TTL)}
}

func glueRecords(cfg config.Config) []rr {
	out := glueARecords(cfg)
	out = append(out, glueAAAARecords(cfg)...)
	return out
}

func glueARecords(cfg config.Config) []rr {
	var out []rr
	if ip := cfg.Ns1IPv4; ip != nil && ip.To4() != nil {
		out = append(out, aRecord(cfg.Ns1Host, cfg.TTL, ip))
	}
	if ip := cfg.Ns2IPv4; ip != nil && ip.To4() != nil {
		out = append(out, aRecord(cfg.Ns2Host, cfg.TTL, ip))
	}
	return out
}

func glueAAAARecords(cfg config.Config) []rr {
	var out []rr
	if ip := cfg.Ns1IPv6; ip != nil && ip.To4() == nil {
		out = append(out, aaaaRecord(cfg.Ns1Host, cfg.TTL, ip))
	}
	if ip := cfg.Ns2IPv6; ip != nil && ip.To4() == nil {
		out = append(out, aaaaRecord(cfg.Ns2Host, cfg.TTL, ip))
	}
	return out
}

func nameGlueARecords(cfg config.Config, qName string) []rr {
	switch qName {
	case cfg.Ns1Host:
		if cfg.Ns1IPv4 != nil && cfg.Ns1IPv4.To4() != nil {
			return []rr{aRecord(cfg.Ns1Host, cfg.TTL, cfg.Ns1IPv4)}
		}
	case cfg.Ns2Host:
		if cfg.Ns2IPv4 != nil && cfg.Ns2IPv4.To4() != nil {
			return []rr{aRecord(cfg.Ns2Host, cfg.TTL, cfg.Ns2IPv4)}
		}
	}
	return nil
}

func nameGlueAAAARecords(cfg config.Config, qName string) []rr {
	switch qName {
	case cfg.Ns1Host:
		if cfg.Ns1IPv6 != nil && cfg.Ns1IPv6.To4() == nil {
			return []rr{aaaaRecord(cfg.Ns1Host, cfg.TTL, cfg.Ns1IPv6)}
		}
	case cfg.Ns2Host:
		if cfg.Ns2IPv6 != nil && cfg.Ns2IPv6.To4() == nil {
			return []rr{aaaaRecord(cfg.Ns2Host, cfg.TTL, cfg.Ns2IPv6)}
		}
	}
	return nil
}

func findIPv4InLabels(host string) net.IP {
	if host == "" {
		return nil
	}
	for label := range strings.SplitSeq(host, ".") {
		s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(label)), "ip-")
		s = strings.ReplaceAll(s, "-", ".")
		ip := net.ParseIP(s)
		if ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4
			}
		}
	}
	return nil
}

func findIPv6InLabels(host string) net.IP {
	if host == "" {
		return nil
	}
	for label := range strings.SplitSeq(host, ".") {
		s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(label)), "ip6-")
		// Use a Unicode private-use character as a placeholder for "--" → "::"
		// substitution. DNS labels are ASCII (IDN uses punycode), so this
		// character cannot appear in a legitimately decoded label and avoids
		// the null-byte collision that would occur with "\x00".
		const placeholder = "\ue000"
		s = strings.ReplaceAll(s, "--", placeholder)
		s = strings.ReplaceAll(s, "-", ":")
		s = strings.ReplaceAll(s, placeholder, "::")
		ip := net.ParseIP(s)
		if ip != nil && ip.To4() == nil {
			return ip
		}
	}
	return nil
}
