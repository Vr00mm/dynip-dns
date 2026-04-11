package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	typeA     = 1
	typeNS    = 2
	typeSOA   = 6
	typeTXT   = 16
	typeAAAA  = 28
	typeANY   = 255
	classIN   = 1
	rcodeOK   = 0
	rcodeName = 3
)

type Config struct {
	Zone       string
	TTL        uint32
	Bind       string
	Ns1Host    string
	Ns2Host    string
	Ns1IPv4    net.IP
	Ns2IPv4    net.IP
	Ns1IPv6    net.IP
	Ns2IPv6    net.IP
	Hostmaster string
	VersionTXT string
	EnableGlue bool
	LogQueries bool
	Serial     uint32
}

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

var configMap map[string]string

func loadConfigFile(path string) {
	configMap = make(map[string]string)
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Fatalf("cannot open config file %q: %v", path, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		configMap[key] = val
	}
}

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()
	loadConfigFile(*configPath)
	cfg := loadConfig()
	go serveUDP(cfg)
	serveTCP(cfg)
}

func loadConfig() Config {
	zone := fqdn(strings.ToLower(strings.TrimSpace(getEnv("ZONE", "yourdomain.com"))))
	cfg := Config{
		Zone:       zone,
		TTL:        parseUint32(getEnv("TTL", "60"), "TTL"),
		Bind:       strings.TrimSpace(getEnv("BIND", ":53")),
		Ns1Host:    fqdn(strings.ToLower(getEnv("NS1_HOST", "ns1."+zone))),
		Ns2Host:    fqdn(strings.ToLower(getEnv("NS2_HOST", "ns2."+zone))),
		Ns1IPv4:    parseIPOrNil(getEnv("NS1_IPV4", "")),
		Ns2IPv4:    parseIPOrNil(getEnv("NS2_IPV4", "")),
		Ns1IPv6:    parseIPOrNil(getEnv("NS1_IPV6", "")),
		Ns2IPv6:    parseIPOrNil(getEnv("NS2_IPV6", "")),
		Hostmaster: fqdn(strings.ToLower(getEnv("HOSTMASTER", "hostmaster."+zone))),
		VersionTXT: getEnv("VERSION_TXT", "dynip-dns"),
		EnableGlue: parseBool(getEnv("ENABLE_GLUE", "true")),
		LogQueries: parseBool(getEnv("LOG_QUERIES", "true")),
	}
	now := time.Now().UTC()
	cfg.Serial = uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)
	log.Printf("starting dynip-dns zone=%s bind=%s ttl=%d serial=%d", cfg.Zone, cfg.Bind, cfg.TTL, cfg.Serial)
	return cfg
}

func serveUDP(cfg Config) {
	pc, err := net.ListenPacket("udp", cfg.Bind)
	if err != nil {
		log.Fatalf("udp listen failed: %v", err)
	}
	defer pc.Close()
	log.Printf("listening on udp %s", cfg.Bind)

	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("udp read error: %v", err)
			continue
		}
		req := append([]byte(nil), buf[:n]...)
		maxUDP := parseEDNS0PayloadSize(req)
		resp, err := handleQuery(cfg, req, maxUDP)
		if err != nil {
			log.Printf("udp handle error: %v", err)
			continue
		}
		if _, err := pc.WriteTo(resp, addr); err != nil {
			log.Printf("udp write error: %v", err)
		}
	}
}

func serveTCP(cfg Config) {
	ln, err := net.Listen("tcp", cfg.Bind)
	if err != nil {
		log.Fatalf("tcp listen failed: %v", err)
	}
	defer ln.Close()
	log.Printf("listening on tcp %s", cfg.Bind)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("tcp accept error: %v", err)
			continue
		}
		go handleTCPConn(cfg, conn)
	}
}

func handleTCPConn(cfg Config, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	if size == 0 {
		return
	}
	req := make([]byte, size)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	resp, err := handleQuery(cfg, req, 0)
	if err != nil {
		log.Printf("tcp handle error: %v", err)
		return
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint16(len(resp)))
	out.Write(resp)
	_, _ = conn.Write(out.Bytes())
}

func handleQuery(cfg Config, req []byte, maxUDP uint16) ([]byte, error) {
	hdr, q, _, err := parseQuery(req)
	if err != nil {
		return nil, err
	}

	rh := DNSHeader{ID: hdr.ID, Flags: 0x8000, QDCount: 1}
	if (hdr.Flags & 0x0100) != 0 {
		rh.Flags |= 0x0100
	}
	rh.Flags |= 0x0400 // AA

	answers := []RR{}
	auth := []RR{}
	extra := []RR{}

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
		log.Printf("qname=%s qtype=%d rcode=%d answers=%d authority=%d extra=%d", qName, q.QType, rh.Flags&0x000f, len(answers), len(auth), len(extra))
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

// parseEDNS0PayloadSize extracts the UDP payload size advertised by the client
// in an EDNS0 OPT record. Returns 512 if no OPT record is present.
func parseEDNS0PayloadSize(msg []byte) uint16 {
	if len(msg) < 12 {
		return 512
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))
	if arCount == 0 {
		return 512
	}
	off := 12
	for i := 0; i < qdCount; i++ {
		_, newOff, err := decodeName(msg, off)
		if err != nil {
			return 512
		}
		off = newOff + 4 // skip qtype + qclass
	}
	for i := 0; i < arCount; i++ {
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

func parseQuery(msg []byte) (DNSHeader, Question, int, error) {
	if len(msg) < 12 {
		return DNSHeader{}, Question{}, 0, errors.New("message too short")
	}
	h := DNSHeader{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}
	if h.QDCount < 1 {
		return h, Question{}, 0, errors.New("no question")
	}
	off := 12
	name, off, err := decodeName(msg, off)
	if err != nil {
		return h, Question{}, 0, err
	}
	if len(msg) < off+4 {
		return h, Question{}, 0, errors.New("truncated question")
	}
	q := Question{
		Name:   name,
		QType:  binary.BigEndian.Uint16(msg[off : off+2]),
		QClass: binary.BigEndian.Uint16(msg[off+2 : off+4]),
	}
	return h, q, off + 4, nil
}

func buildResponse(h DNSHeader, q Question, ans, auth, extra []RR) ([]byte, error) {
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
	for _, rr := range ans {
		if err := encodeRR(&out, rr); err != nil {
			return nil, err
		}
	}
	for _, rr := range auth {
		if err := encodeRR(&out, rr); err != nil {
			return nil, err
		}
	}
	for _, rr := range extra {
		if err := encodeRR(&out, rr); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func encodeQuestion(out *bytes.Buffer, q Question) error {
	if err := encodeName(out, q.Name); err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, q.QType)
	_ = binary.Write(out, binary.BigEndian, q.QClass)
	return nil
}

func encodeRR(out *bytes.Buffer, rr RR) error {
	if err := encodeName(out, rr.Name); err != nil {
		return err
	}
	_ = binary.Write(out, binary.BigEndian, rr.Type)
	_ = binary.Write(out, binary.BigEndian, rr.Class)
	_ = binary.Write(out, binary.BigEndian, rr.TTL)
	_ = binary.Write(out, binary.BigEndian, uint16(len(rr.Data)))
	_, _ = out.Write(rr.Data)
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
	labels := []string{}
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

func fqdn(name string) string {
	if name == "" {
		return "."
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func aRecord(name string, ttl uint32, ip net.IP) RR {
	return RR{Name: fqdn(name), Type: typeA, Class: classIN, TTL: ttl, Data: ip.To4()}
}

func aaaaRecord(name string, ttl uint32, ip net.IP) RR {
	return RR{Name: fqdn(name), Type: typeAAAA, Class: classIN, TTL: ttl, Data: ip.To16()}
}

func txtRecord(name string, ttl uint32, text string) RR {
	b := []byte(text)
	if len(b) > 255 {
		b = b[:255]
	}
	return RR{Name: fqdn(name), Type: typeTXT, Class: classIN, TTL: ttl, Data: append([]byte{byte(len(b))}, b...)}
}

func nsRecord(zone, host string, ttl uint32) RR {
	var b bytes.Buffer
	_ = encodeName(&b, host)
	return RR{Name: fqdn(zone), Type: typeNS, Class: classIN, TTL: ttl, Data: b.Bytes()}
}

func soaRecord(cfg Config) RR {
	var b bytes.Buffer
	_ = encodeName(&b, cfg.Ns1Host)
	_ = encodeName(&b, cfg.Hostmaster)
	fields := []uint32{cfg.Serial, 300, 60, 1200, cfg.TTL}
	for _, v := range fields {
		_ = binary.Write(&b, binary.BigEndian, v)
	}
	return RR{Name: cfg.Zone, Type: typeSOA, Class: classIN, TTL: cfg.TTL, Data: b.Bytes()}
}

func apexNS(cfg Config) []RR {
	return []RR{nsRecord(cfg.Zone, cfg.Ns1Host, cfg.TTL), nsRecord(cfg.Zone, cfg.Ns2Host, cfg.TTL)}
}

func glueRecords(cfg Config) []RR {
	out := []RR{}
	out = append(out, glueARecords(cfg)...)
	out = append(out, glueAAAARecords(cfg)...)
	return out
}

func glueARecords(cfg Config) []RR {
	out := []RR{}
	if ip := cfg.Ns1IPv4; ip != nil && ip.To4() != nil {
		out = append(out, aRecord(cfg.Ns1Host, cfg.TTL, ip))
	}
	if ip := cfg.Ns2IPv4; ip != nil && ip.To4() != nil {
		out = append(out, aRecord(cfg.Ns2Host, cfg.TTL, ip))
	}
	return out
}

func glueAAAARecords(cfg Config) []RR {
	out := []RR{}
	if ip := cfg.Ns1IPv6; ip != nil && ip.To4() == nil {
		out = append(out, aaaaRecord(cfg.Ns1Host, cfg.TTL, ip))
	}
	if ip := cfg.Ns2IPv6; ip != nil && ip.To4() == nil {
		out = append(out, aaaaRecord(cfg.Ns2Host, cfg.TTL, ip))
	}
	return out
}

func nameGlueARecords(cfg Config, qName string) []RR {
	switch qName {
	case cfg.Ns1Host:
		if cfg.Ns1IPv4 != nil && cfg.Ns1IPv4.To4() != nil {
			return []RR{aRecord(cfg.Ns1Host, cfg.TTL, cfg.Ns1IPv4)}
		}
	case cfg.Ns2Host:
		if cfg.Ns2IPv4 != nil && cfg.Ns2IPv4.To4() != nil {
			return []RR{aRecord(cfg.Ns2Host, cfg.TTL, cfg.Ns2IPv4)}
		}
	}
	return nil
}

func nameGlueAAAARecords(cfg Config, qName string) []RR {
	switch qName {
	case cfg.Ns1Host:
		if cfg.Ns1IPv6 != nil && cfg.Ns1IPv6.To4() == nil {
			return []RR{aaaaRecord(cfg.Ns1Host, cfg.TTL, cfg.Ns1IPv6)}
		}
	case cfg.Ns2Host:
		if cfg.Ns2IPv6 != nil && cfg.Ns2IPv6.To4() == nil {
			return []RR{aaaaRecord(cfg.Ns2Host, cfg.TTL, cfg.Ns2IPv6)}
		}
	}
	return nil
}

func findIPv4InLabels(host string) net.IP {
	if host == "" {
		return nil
	}
	for _, label := range strings.Split(host, ".") {
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
	for _, label := range strings.Split(host, ".") {
		s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(label)), "ip6-")
		placeholder := "\x00"
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

func parseIPOrNil(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		log.Fatalf("invalid IP: %q", s)
	}
	return ip
}

func parseBool(s string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		log.Fatalf("invalid bool %q: %v", s, err)
	}
	return v
}

func parseUint32(s, field string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		log.Fatalf("invalid %s: %v", field, err)
	}
	return uint32(n)
}

func getEnv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	if configMap != nil {
		if v, ok := configMap[strings.ToUpper(k)]; ok && v != "" {
			return v
		}
	}
	return def
}
