//go:build integration

package server

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Vr00mm/dynip-dns/internal/pkg/config"
)

// integrationCfg returns a config bound to a random loopback port.
// The caller must fill in Bind after reserving a free port.
func integrationCfg(bind string) config.Config {
	return config.Config{
		Zone:       "example.com.",
		TTL:        60,
		Bind:       bind,
		Ns1Host:    "ns1.example.com.",
		Ns2Host:    "ns2.example.com.",
		Ns1IPv4:    net.ParseIP("192.0.2.1").To4(),
		Hostmaster: "hostmaster.example.com.",
		VersionTXT: "test",
		EnableGlue: true,
		LogQueries: false,
		Serial:     2024010100,
	}
}

// freePort returns an OS-assigned free localhost port.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// rawSOAQuery is a minimal DNS/UDP query for SOA of example.com.
var rawSOAQuery = makeTCPQuery()[2:] // strip TCP length prefix

func TestServeUDP_Integration(t *testing.T) {
	bind := freePort(t)
	cfg := integrationCfg(bind)
	s := New(cfg)
	go s.serveUDP()
	time.Sleep(20 * time.Millisecond) // let the listener start

	conn, err := net.Dial("udp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(rawSOAQuery); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading UDP response: %v", err)
	}
	if n < 4 {
		t.Fatalf("response too short: %d bytes", n)
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	if flags&0x8000 == 0 {
		t.Error("QR bit not set in UDP response")
	}
	if flags&0x000f != 0 {
		t.Errorf("RCODE = %d, want NOERROR (0)", flags&0x000f)
	}
}

func TestServeTCP_Integration(t *testing.T) {
	bind := freePort(t)
	cfg := integrationCfg(bind)
	s := New(cfg)
	go s.serveTCP()
	time.Sleep(20 * time.Millisecond) // let the listener start

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	query := makeTCPQuery()
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("reading response length: %v", err)
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	resp := make([]byte, size)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Error("QR bit not set in TCP response")
	}
	if flags&0x000f != 0 {
		t.Errorf("RCODE = %d, want NOERROR (0)", flags&0x000f)
	}
}
