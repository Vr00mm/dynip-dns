package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/Vr00mm/dynip-dns/internal/pkg/config"
)

// ---- test helpers -------------------------------------------------------

// buildQuery constructs a minimal RFC-1035 DNS query packet.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	var buf bytes.Buffer
	for _, v := range []uint16{id, 0x0100 /* RD */, 1, 0, 0, 0} {
		_ = binary.Write(&buf, binary.BigEndian, v)
	}
	_ = encodeName(&buf, name)
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(classIN))
	return buf.Bytes()
}

// buildQueryWithEDNS0 builds a DNS query that includes an EDNS0 OPT record
// advertising udpPayload as the maximum UDP response size.
func buildQueryWithEDNS0(id uint16, name string, qtype, udpPayload uint16) []byte {
	var buf bytes.Buffer
	// Header: ARCOUNT=1 for the OPT record.
	for _, v := range []uint16{id, 0x0100 /* RD */, 1, 0, 0, 1} {
		_ = binary.Write(&buf, binary.BigEndian, v)
	}
	_ = encodeName(&buf, name)
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(classIN))
	// OPT record: root name + type 41 + payload-size class + zero TTL + zero RDLENGTH.
	buf.WriteByte(0x00)                                  // root name
	_ = binary.Write(&buf, binary.BigEndian, uint16(41)) // type OPT
	_ = binary.Write(&buf, binary.BigEndian, udpPayload) // class = UDP payload size
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))  // TTL (extended RCODE + flags)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))  // RDLENGTH = 0
	return buf.Bytes()
}

// testCfg returns a Config with deterministic values for use in unit tests.
func testCfg() config.Config {
	return config.Config{
		Zone:       "example.com.",
		TTL:        60,
		Ns1Host:    "ns1.example.com.",
		Ns2Host:    "ns2.example.com.",
		Ns1IPv4:    net.ParseIP("192.0.2.1").To4(),
		Ns2IPv4:    net.ParseIP("192.0.2.2").To4(),
		Hostmaster: "hostmaster.example.com.",
		VersionTXT: "test",
		EnableGlue: true,
		LogQueries: false,
		Serial:     2024010100,
	}
}

func respRcode(resp []byte) int {
	if len(resp) < 4 {
		return -1
	}
	return int(binary.BigEndian.Uint16(resp[2:4]) & 0x000f)
}

func respAnCount(resp []byte) int {
	if len(resp) < 8 {
		return -1
	}
	return int(binary.BigEndian.Uint16(resp[6:8]))
}

func respNSCount(resp []byte) int {
	if len(resp) < 10 {
		return -1
	}
	return int(binary.BigEndian.Uint16(resp[8:10]))
}

func respFlags(resp []byte) uint16 {
	if len(resp) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(resp[2:4])
}

func respID(msg []byte) uint16 {
	if len(msg) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(msg[0:2])
}

// ---- ParseEDNS0PayloadSize ----------------------------------------------

func TestParseEDNS0PayloadSize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		msg      func() []byte
		expected uint16
	}{
		{
			"too short to parse",
			func() []byte { return []byte{0x00, 0x01} },
			512,
		},
		{
			"no OPT record (ARCOUNT=0)",
			func() []byte { return buildQuery(1, "example.com.", typeA) },
			512,
		},
		{
			"OPT with 4096 byte payload",
			func() []byte { return buildQueryWithEDNS0(1, "example.com.", typeA, 4096) },
			4096,
		},
		{
			"OPT with 1280 byte payload",
			func() []byte { return buildQueryWithEDNS0(1, "example.com.", typeA, 1280) },
			1280,
		},
		{
			"OPT with 256 (below minimum, clamp to 512)",
			func() []byte { return buildQueryWithEDNS0(1, "example.com.", typeA, 256) },
			512,
		},
		{
			"OPT with exactly 512",
			func() []byte { return buildQueryWithEDNS0(1, "example.com.", typeA, 512) },
			512,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseEDNS0PayloadSize(tt.msg())
			if got != tt.expected {
				t.Errorf("ParseEDNS0PayloadSize = %d, want %d", got, tt.expected)
			}
		})
	}
}

// ---- findIPv4InLabels ---------------------------------------------------

func TestFindIPv4InLabels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		host     string
		expected net.IP
	}{
		{"dash notation", "192-168-1-1", net.ParseIP("192.168.1.1").To4()},
		{"ip- prefix", "ip-10-0-0-1", net.ParseIP("10.0.0.1").To4()},
		{"in second label", "host.192-168-0-1.dyn", net.ParseIP("192.168.0.1").To4()},
		{"loopback", "127-0-0-1", net.ParseIP("127.0.0.1").To4()},
		{"empty host", "", nil},
		{"not an IP", "not-an-ip", nil},
		{"octet out of range", "256-0-0-1", nil},
		{"ipv6 not matched here", "2001-db8--1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := findIPv4InLabels(tt.host)
			if !got.Equal(tt.expected) {
				t.Errorf("findIPv4InLabels(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

// ---- findIPv6InLabels ---------------------------------------------------

func TestFindIPv6InLabels(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		host     string
		expected net.IP
	}{
		{"loopback double-dash", "--1", net.ParseIP("::1")},
		{"full address", "2001-db8-0-0-0-0-0-1", net.ParseIP("2001:db8::1")},
		{"ip6- prefix loopback", "ip6---1", net.ParseIP("::1")},
		{"compressed form", "2001-db8--1", net.ParseIP("2001:db8::1")},
		{"empty host", "", nil},
		{"invalid label", "xyz", nil},
		{"ipv4 not matched here", "192-168-1-1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := findIPv6InLabels(tt.host)
			if !got.Equal(tt.expected) {
				t.Errorf("findIPv6InLabels(%q) = %v, want %v", tt.host, got, tt.expected)
			}
		})
	}
}

// ---- sanitizeName -------------------------------------------------------

func TestSanitizeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean name", "example.com.", "example.com."},
		{"newline injection", "foo\nINFO: spoofed", "foo?INFO: spoofed"},
		{"carriage return", "foo\rbar", "foo?bar"},
		{"null byte", "foo\x00bar", "foo?bar"},
		{"tab is control", "foo\tbar", "foo?bar"},
		{"delete char", "foo\x7fbar", "foo?bar"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeName(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ---- encodeName / decodeName --------------------------------------------

func TestEncodeDecodeName_Roundtrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{"root", "."},
		{"single label", "com."},
		{"two labels", "example.com."},
		{"three labels", "foo.example.com."},
		{"max-length label (63 chars)", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxy.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := encodeName(&buf, tt.input); err != nil {
				t.Fatalf("encodeName(%q): %v", tt.input, err)
			}
			got, _, err := decodeName(buf.Bytes(), 0)
			if err != nil {
				t.Fatalf("decodeName: %v", err)
			}
			if got != fqdn(tt.input) {
				t.Errorf("roundtrip(%q) = %q, want %q", tt.input, got, fqdn(tt.input))
			}
		})
	}
}

func TestEncodeName_RejectsInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{"empty label in middle", "foo..bar."},
		{"label too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := encodeName(&buf, tt.input); err == nil {
				t.Errorf("encodeName(%q) expected error, got nil", tt.input)
			}
		})
	}
}

func TestDecodeName_RejectsInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{"empty input", []byte{}},
		{"truncated label body", []byte{0x05, 'h', 'i'}},
		{"truncated compression pointer", []byte{0xc0}},
		{"compression pointer out of range", []byte{0xc0, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := decodeName(tt.data, 0); err == nil {
				t.Errorf("decodeName(%x) expected error, got nil", tt.data)
			}
		})
	}
}

// ---- HandleQuery --------------------------------------------------------

func TestHandleQuery(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		wantRcode   int
		wantAnswers int
	}{
		// Apex records
		{"SOA apex", "example.com.", typeSOA, rcodeOK, 1},
		{"NS apex", "example.com.", typeNS, rcodeOK, 2},
		{"TXT apex", "example.com.", typeTXT, rcodeOK, 2},
		{"A apex glue", "example.com.", typeA, rcodeOK, 2},
		{"AAAA apex no ipv6 configured", "example.com.", typeAAAA, rcodeOK, 0},
		// Glue records for nameservers
		{"A ns1 glue", "ns1.example.com.", typeA, rcodeOK, 1},
		{"A ns2 glue", "ns2.example.com.", typeA, rcodeOK, 1},
		// Dynamic IP records
		{"A dynamic ipv4", "192-168-1-1.example.com.", typeA, rcodeOK, 1},
		{"A dynamic ipv4 ip- prefix", "ip-10-0-0-1.example.com.", typeA, rcodeOK, 1},
		{"AAAA dynamic ipv6", "2001-db8--1.example.com.", typeAAAA, rcodeOK, 1},
		{"AAAA loopback", "--1.example.com.", typeAAAA, rcodeOK, 1},
		// NXDOMAIN cases
		{"A unknown subdomain", "notfound.example.com.", typeA, rcodeName, 0},
		{"A outside zone", "other.domain.", typeA, rcodeName, 0},
		{"SOA subdomain nxdomain", "sub.example.com.", typeSOA, rcodeName, 0},
		{"NS subdomain nxdomain", "sub.example.com.", typeNS, rcodeName, 0},
		{"TXT subdomain nxdomain", "sub.example.com.", typeTXT, rcodeName, 0},
		// ANY queries
		{"ANY apex", "example.com.", typeANY, rcodeOK, 4},
		{"ANY dynamic ipv4 only", "192-168-1-1.example.com.", typeANY, rcodeOK, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := buildQuery(0x1234, tt.qname, tt.qtype)
			resp, err := HandleQuery(cfg, req, 0)
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if respFlags(resp)&0x8000 == 0 {
				t.Error("QR bit not set")
			}
			if respFlags(resp)&0x0400 == 0 {
				t.Error("AA bit not set")
			}
			if got := respRcode(resp); got != tt.wantRcode {
				t.Errorf("rcode = %d, want %d", got, tt.wantRcode)
			}
			if got := respAnCount(resp); got != tt.wantAnswers {
				t.Errorf("answer count = %d, want %d", got, tt.wantAnswers)
			}
		})
	}
}

func TestHandleQuery_IDMirrored(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	const wantID = uint16(0xABCD)
	req := buildQuery(wantID, "example.com.", typeSOA)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respID(resp); got != wantID {
		t.Errorf("response ID = 0x%04x, want 0x%04x", got, wantID)
	}
}

func TestHandleQuery_TCBitOnUDPTruncation(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	req := buildQuery(1, "example.com.", typeNS)
	// Force truncation by advertising a tiny UDP payload size.
	resp, err := HandleQuery(cfg, req, 50)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if respFlags(resp)&0x0200 == 0 {
		t.Errorf("TC bit not set; flags=0x%04x, len=%d", respFlags(resp), len(resp))
	}
}

func TestHandleQuery_RDPreserved(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	req := buildQuery(1, "example.com.", typeSOA) // buildQuery sets RD=1
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if respFlags(resp)&0x0100 == 0 {
		t.Error("RD bit should be mirrored from query")
	}
}

func TestHandleQuery_MalformedRequests(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	tests := []struct {
		name string
		data []byte
	}{
		{"too short", []byte{0x00, 0x01}},
		{"header only — zero questions", make([]byte, 12)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := HandleQuery(cfg, tt.data, 0)
			if err == nil {
				t.Error("expected error for malformed request, got nil")
			}
		})
	}
}

func TestHandleQuery_UnknownTypeAtApex(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	// Unknown type at the zone apex: response must be NOERROR with SOA in authority.
	req := buildQuery(1, "example.com.", 999)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respRcode(resp); got != rcodeOK {
		t.Errorf("rcode = %d, want NOERROR (%d)", got, rcodeOK)
	}
	if got := respAnCount(resp); got != 0 {
		t.Errorf("answer count = %d, want 0", got)
	}
	if got := respNSCount(resp); got != 1 {
		t.Errorf("authority count = %d, want 1 (SOA)", got)
	}
}

func TestHandleQuery_ANYBothIPVersions(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	// A subdomain label that encodes IPv4 in one part and IPv6 in another
	// gives both an A and an AAAA answer for ANY.
	// host = "192-168-1-1.2001-db8--1" → findIPv4InLabels finds 192.168.1.1,
	// findIPv6InLabels finds 2001:db8::1.
	req := buildQuery(1, "192-168-1-1.2001-db8--1.example.com.", typeANY)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respAnCount(resp); got != 2 {
		t.Errorf("answer count = %d, want 2 (A + AAAA)", got)
	}
}

func TestHandleQuery_AAAANsGlueWithIPv6(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		qname  string
		ns1ip6 net.IP
		ns2ip6 net.IP
	}{
		{
			name:   "ns1 AAAA glue",
			qname:  "ns1.example.com.",
			ns1ip6: net.ParseIP("2001:db8::1"),
		},
		{
			name:   "ns2 AAAA glue",
			qname:  "ns2.example.com.",
			ns2ip6: net.ParseIP("2001:db8::2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := testCfg()
			cfg.Ns1IPv6 = tt.ns1ip6
			cfg.Ns2IPv6 = tt.ns2ip6
			req := buildQuery(1, tt.qname, typeAAAA)
			resp, err := HandleQuery(cfg, req, 0)
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if got := respAnCount(resp); got != 1 {
				t.Errorf("answer count = %d, want 1 (AAAA glue)", got)
			}
		})
	}
}

func TestHandleQuery_DisabledGlue(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	cfg.EnableGlue = false
	tests := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"A apex no glue", "example.com.", typeA},
		{"AAAA apex no glue", "example.com.", typeAAAA},
		{"A ns1 no glue", "ns1.example.com.", typeA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := buildQuery(1, tt.qname, tt.qtype)
			resp, err := HandleQuery(cfg, req, 0)
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if got := respAnCount(resp); got != 0 {
				t.Errorf("answer count = %d, want 0 (glue disabled)", got)
			}
		})
	}
}

// ---- HandleQuery additional branches ------------------------------------

func TestHandleQuery_AAAANxdomain(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	// Non-apex subdomain with no IPv6 label → NXDOMAIN.
	req := buildQuery(1, "notfound.example.com.", typeAAAA)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respRcode(resp); got != rcodeName {
		t.Errorf("rcode = %d, want %d (NXDOMAIN)", got, rcodeName)
	}
}

func TestHandleQuery_ANYNxdomain(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	// Non-apex subdomain with no IP in any label → NXDOMAIN for ANY.
	req := buildQuery(1, "notfound.example.com.", typeANY)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respRcode(resp); got != rcodeName {
		t.Errorf("rcode = %d, want %d (NXDOMAIN)", got, rcodeName)
	}
}

func TestHandleQuery_GlueAAAAAtApex(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	cfg.Ns1IPv6 = net.ParseIP("2001:db8::1")
	cfg.Ns2IPv6 = net.ParseIP("2001:db8::2")
	// NS query at apex with IPv6 glue configured.
	req := buildQuery(1, "example.com.", typeNS)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respAnCount(resp); got != 2 {
		t.Errorf("answer count = %d, want 2", got)
	}
}

func TestHandleQuery_NameGlueARecords_NilReturn(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	cfg.Ns1IPv4 = nil
	cfg.Ns2IPv4 = nil
	// A query for ns1/ns2 with glue enabled but no IPv4 → 0 answers.
	req := buildQuery(1, "ns1.example.com.", typeA)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respAnCount(resp); got != 0 {
		t.Errorf("answer count = %d, want 0 (no IPv4 configured)", got)
	}
}

func TestHandleQuery_NameGlueAAAARecords_NilReturn(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	// AAAA query for ns1/ns2 with glue enabled but no IPv6 → 0 answers.
	req := buildQuery(1, "ns1.example.com.", typeAAAA)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respAnCount(resp); got != 0 {
		t.Errorf("answer count = %d, want 0 (no IPv6 configured)", got)
	}
}

func TestHandleQuery_UnknownTypeNotAtApex(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	// Unknown type at a non-apex name → NOERROR, no authority SOA.
	req := buildQuery(1, "sub.example.com.", 999)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if got := respRcode(resp); got != rcodeOK {
		t.Errorf("rcode = %d, want NOERROR", got)
	}
	if got := respNSCount(resp); got != 0 {
		t.Errorf("authority count = %d, want 0 (not at apex)", got)
	}
}

// ---- txtRecord truncation -----------------------------------------------

func TestTxtRecord_Truncation(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("a", 300) // > 255 chars
	rec := txtRecord("example.com.", 60, text)
	// Data = 1 (length byte) + 255 (capped text)
	if len(rec.Data) != 256 {
		t.Errorf("txtRecord data len = %d, want 256", len(rec.Data))
	}
	if rec.Data[0] != 255 {
		t.Errorf("txtRecord length byte = %d, want 255", rec.Data[0])
	}
}

// ---- nsRecord / soaRecord exit paths ------------------------------------

func TestNSRecord_ExitOnInvalidHost(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	// Label longer than 63 chars → encodeName returns error.
	longLabel := strings.Repeat("a", 64) + ".com."
	rec := nsRecord("example.com.", longLabel, 60)
	if !exited {
		t.Error("expected exit to be called for invalid NS host")
	}
	if rec.Type != 0 {
		t.Error("expected zero-value rr on error")
	}
}

func TestSOARecord_ExitOnInvalidName(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	cfg := testCfg()
	cfg.Ns1Host = strings.Repeat("a", 64) + ".com." // invalid label
	rec := soaRecord(cfg)
	if !exited {
		t.Error("expected exit to be called for invalid SOA name")
	}
	if rec.Type != 0 {
		t.Error("expected zero-value rr on error")
	}
}

// ---- decodeName compression pointer -------------------------------------

func TestDecodeName_CompressionPointer(t *testing.T) {
	t.Parallel()
	// Message layout:
	//   offset 0-4: "bar." encoded (0x03, 'b', 'a', 'r', 0x00)
	//   offset 5-6: compression pointer to offset 0 (0xc0, 0x00)
	// decodeName(msg, 5) should follow the pointer and return "bar."
	msg := []byte{0x03, 'b', 'a', 'r', 0x00, 0xc0, 0x00}
	name, _, err := decodeName(msg, 5)
	if err != nil {
		t.Fatalf("decodeName with valid compression pointer: %v", err)
	}
	if name != "bar." {
		t.Errorf("decodeName = %q, want %q", name, "bar.")
	}
}

func TestDecodeName_TooManyCompressionJumps(t *testing.T) {
	t.Parallel()
	// Two pointers forming a cycle: offset 0 → offset 2 → offset 0 → ...
	// 0xc0,0x02 = pointer to offset 2; 0xc0,0x00 = pointer to offset 0.
	msg := []byte{0xc0, 0x02, 0xc0, 0x00}
	_, _, err := decodeName(msg, 0)
	if err == nil {
		t.Error("expected error for cyclic compression pointers")
	}
}

// ---- parseQuery error paths ---------------------------------------------

func TestParseQuery_InvalidName(t *testing.T) {
	t.Parallel()
	// Valid 12-byte header with QDCOUNT=1, then a label claiming 16 bytes
	// but only 1 byte present → decodeName returns error.
	msg := make([]byte, 14)
	binary.BigEndian.PutUint16(msg[0:2], 1)      // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // flags RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT=1
	msg[12] = 0x10                                // label length 16
	msg[13] = 'x'                                 // only 1 byte of label body
	_, _, _, err := parseQuery(msg)
	if err == nil {
		t.Error("expected error for truncated name label")
	}
}

func TestParseQuery_TruncatedQuestion(t *testing.T) {
	t.Parallel()
	// Valid name "a." but only 3 bytes after it (qtype+qclass needs 4).
	var msg bytes.Buffer
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 0} {
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	msg.WriteByte(1)   // label length 1
	msg.WriteByte('a') // label "a"
	msg.WriteByte(0)   // end of name
	msg.WriteByte(0)   // 1st byte of qtype (need 4 total)
	msg.WriteByte(0)   // 2nd byte
	msg.WriteByte(0)   // 3rd byte — one short
	_, _, _, err := parseQuery(msg.Bytes())
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("expected truncated question error, got %v", err)
	}
}

// ---- buildResponse / encodeRR error paths -------------------------------

func TestBuildResponse_EncodeQuestionError(t *testing.T) {
	t.Parallel()
	h := dnsHeader{ID: 1, Flags: 0x8000, QDCount: 1}
	// Name with a label > 63 chars → encodeName fails.
	q := question{
		Name:   strings.Repeat("x", 64) + ".com.",
		QType:  typeA,
		QClass: classIN,
	}
	_, err := buildResponse(h, q, nil, nil, nil)
	if err == nil {
		t.Error("expected error for invalid question name")
	}
}

func TestEncodeRR_NameError(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := rr{
		Name:  strings.Repeat("x", 64) + ".com.", // label > 63 chars
		Type:  typeA,
		Class: classIN,
		TTL:   60,
		Data:  []byte{1, 2, 3, 4},
	}
	if err := encodeRR(&out, r); err == nil {
		t.Error("expected error for invalid RR name")
	}
}

func TestEncodeRR_RDataTooLarge(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	r := rr{
		Name:  "example.com.",
		Type:  typeA,
		Class: classIN,
		TTL:   60,
		Data:  make([]byte, 0x10000), // 65536 bytes > max uint16
	}
	if err := encodeRR(&out, r); err == nil {
		t.Error("expected error for oversized rdata")
	}
}

// ---- ParseEDNS0PayloadSize edge cases -----------------------------------

func TestParseEDNS0PayloadSize_NonOPTAdditional(t *testing.T) {
	t.Parallel()
	// Build a query with ARCOUNT=1 but the AR record is a regular A record (type 1),
	// not OPT (type 41). ParseEDNS0PayloadSize must return the default 512.
	var msg bytes.Buffer
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 1} { // ARCOUNT=1
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	// Question: "a." type A class IN
	msg.WriteByte(1)
	msg.WriteByte('a')
	msg.WriteByte(0)
	_ = binary.Write(&msg, binary.BigEndian, uint16(typeA))
	_ = binary.Write(&msg, binary.BigEndian, uint16(classIN))
	// AR: root name + type A (1) + class IN + TTL 0 + rdlength 4 + 4-byte IP
	msg.WriteByte(0)                                    // root name
	_ = binary.Write(&msg, binary.BigEndian, uint16(1)) // type A
	_ = binary.Write(&msg, binary.BigEndian, uint16(1)) // class IN
	_ = binary.Write(&msg, binary.BigEndian, uint32(0)) // TTL
	_ = binary.Write(&msg, binary.BigEndian, uint16(4)) // RDLENGTH
	msg.Write([]byte{1, 2, 3, 4})                       // RDATA
	got := ParseEDNS0PayloadSize(msg.Bytes())
	if got != 512 {
		t.Errorf("ParseEDNS0PayloadSize = %d, want 512 for non-OPT AR", got)
	}
}

func TestParseEDNS0PayloadSize_TruncatedAfterQuestion(t *testing.T) {
	t.Parallel()
	// Header with QDCOUNT=1 ARCOUNT=1, but message is truncated mid-question.
	// decodeName in the qdCount loop should fail → return 512.
	var msg bytes.Buffer
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 1} {
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	// Truncated name: label claims 10 bytes but only 2 bytes follow.
	msg.WriteByte(10)
	msg.WriteByte('x')
	msg.WriteByte('y')
	got := ParseEDNS0PayloadSize(msg.Bytes())
	if got != 512 {
		t.Errorf("ParseEDNS0PayloadSize = %d, want 512 for truncated question", got)
	}
}

func TestParseEDNS0PayloadSize_TruncatedAR(t *testing.T) {
	t.Parallel()
	// Valid question but AR section has a truncated name.
	var msg bytes.Buffer
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 1} {
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	// Question: "a." type A class IN
	msg.WriteByte(1)
	msg.WriteByte('a')
	msg.WriteByte(0)
	_ = binary.Write(&msg, binary.BigEndian, uint16(typeA))
	_ = binary.Write(&msg, binary.BigEndian, uint16(classIN))
	// AR: malformed name (length byte > remaining bytes)
	msg.WriteByte(20) // claim 20 bytes but EOF
	got := ParseEDNS0PayloadSize(msg.Bytes())
	if got != 512 {
		t.Errorf("ParseEDNS0PayloadSize = %d, want 512 for truncated AR", got)
	}
}

// ---- additional coverage tests ------------------------------------------

func TestHandleQuery_LogQueries(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	cfg.LogQueries = true
	req := buildQuery(42, "example.com.", typeSOA)
	resp, err := HandleQuery(cfg, req, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if respAnCount(resp) != 1 {
		t.Errorf("expected 1 answer, got %d", respAnCount(resp))
	}
}

// TestHandleQuery_BuildResponseError triggers the buildResponse error path inside
// HandleQuery by supplying a glue-enabled config whose Ns1Host has a label > 63
// chars. nsRecord calls exit(1) for the invalid host (hence the exit mock), then
// the glue A record with the same invalid name causes encodeRR to fail, so
// buildResponse returns an error and HandleQuery propagates it.
func TestHandleQuery_BuildResponseError(t *testing.T) {
	// Cannot be parallel: modifies the package-level exit variable.
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	cfg := testCfg()
	cfg.EnableGlue = true
	cfg.Ns1Host = strings.Repeat("x", 64) + ".example.com." // label > 63 chars → invalid
	cfg.Ns1IPv4 = net.ParseIP("192.0.2.1").To4()
	req := buildQuery(7, "example.com.", typeNS)
	_, err := HandleQuery(cfg, req, 0)
	if err == nil {
		t.Error("expected error from buildResponse, got nil")
	}
	if !exited {
		t.Error("expected exit to be called for invalid NS host encoding")
	}
}

func TestBuildResponse_AnsLoopError(t *testing.T) {
	t.Parallel()
	h := dnsHeader{ID: 1, Flags: 0x8000, QDCount: 1}
	q := question{Name: "example.com.", QType: typeA, QClass: classIN}
	badRR := rr{
		Name:  strings.Repeat("x", 64) + ".com.", // label > 63 chars
		Type:  typeA,
		Class: classIN,
		TTL:   60,
		Data:  []byte{1, 2, 3, 4},
	}
	_, err := buildResponse(h, q, []rr{badRR}, nil, nil)
	if err == nil {
		t.Error("expected error for invalid answer RR name")
	}
}

func TestBuildResponse_AuthLoopError(t *testing.T) {
	t.Parallel()
	h := dnsHeader{ID: 1, Flags: 0x8000, QDCount: 1}
	q := question{Name: "example.com.", QType: typeA, QClass: classIN}
	badRR := rr{
		Name:  strings.Repeat("x", 64) + ".com.", // label > 63 chars
		Type:  typeA,
		Class: classIN,
		TTL:   60,
		Data:  []byte{1, 2, 3, 4},
	}
	_, err := buildResponse(h, q, nil, []rr{badRR}, nil)
	if err == nil {
		t.Error("expected error for invalid authority RR name")
	}
}

// TestParseEDNS0PayloadSize_ARCountExceedsData exercises the
// "off >= len(msg)" break in the AR loop. ARCOUNT=2 but the message only
// contains one complete (non-OPT) additional record; on the second iteration
// off is already at the end of the slice.
func TestParseEDNS0PayloadSize_ARCountExceedsData(t *testing.T) {
	t.Parallel()
	var msg bytes.Buffer
	// Header: ARCOUNT=2, QDCOUNT=1
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 2} {
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	// Question: "a." type A class IN
	msg.WriteByte(1)
	msg.WriteByte('a')
	msg.WriteByte(0)
	_ = binary.Write(&msg, binary.BigEndian, uint16(typeA))
	_ = binary.Write(&msg, binary.BigEndian, uint16(classIN))
	// AR1: root name + type A + class IN + TTL 0 + rdlen 4 + rdata (complete)
	msg.WriteByte(0)                                    // root name
	_ = binary.Write(&msg, binary.BigEndian, uint16(1)) // type A
	_ = binary.Write(&msg, binary.BigEndian, uint16(1)) // class IN
	_ = binary.Write(&msg, binary.BigEndian, uint32(0)) // TTL
	_ = binary.Write(&msg, binary.BigEndian, uint16(4)) // RDLENGTH
	msg.Write([]byte{1, 2, 3, 4})                       // RDATA
	// AR2: no data — off will equal len(msg) at the start of the second iteration.
	got := ParseEDNS0PayloadSize(msg.Bytes())
	if got != 512 {
		t.Errorf("ParseEDNS0PayloadSize = %d, want 512", got)
	}
}

// TestParseEDNS0PayloadSize_TruncatedARHeader exercises the
// "off+10 > len(msg)" break. The AR has a valid root-label name but fewer
// than 10 bytes remain for the fixed RR header fields.
func TestParseEDNS0PayloadSize_TruncatedARHeader(t *testing.T) {
	t.Parallel()
	var msg bytes.Buffer
	// Header: ARCOUNT=1, QDCOUNT=1
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 1} {
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	// Question: "a." type A class IN
	msg.WriteByte(1)
	msg.WriteByte('a')
	msg.WriteByte(0)
	_ = binary.Write(&msg, binary.BigEndian, uint16(typeA))
	_ = binary.Write(&msg, binary.BigEndian, uint16(classIN))
	// AR: valid root name (\x00) + only 9 bytes (need 10 for type+class+ttl+rdlen)
	msg.WriteByte(0)                      // root name
	msg.Write([]byte{0, 1, 0, 1, 0, 0, 0, 0, 0}) // 9 bytes — one short
	got := ParseEDNS0PayloadSize(msg.Bytes())
	if got != 512 {
		t.Errorf("ParseEDNS0PayloadSize = %d, want 512", got)
	}
}

// ---- fuzz ---------------------------------------------------------------

// FuzzDecodeName ensures that decodeName never panics regardless of input.
func FuzzDecodeName(f *testing.F) {
	// Seed with valid DNS name encodings.
	f.Add([]byte{0x00}) // root
	f.Add([]byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00})
	// Compression pointer back to offset 0.
	f.Add([]byte{0x03, 'f', 'o', 'o', 0x00, 0xc0, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input.
		decodeName(data, 0) //nolint:errcheck
	})
}
