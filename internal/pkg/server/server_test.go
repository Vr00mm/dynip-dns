package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Vr00mm/dynip-dns/internal/pkg/config"
)

// testCfg returns a minimal Config for server unit tests.
func testCfg() config.Config {
	return config.Config{
		Zone:       "example.com.",
		TTL:        60,
		Ns1Host:    "ns1.example.com.",
		Ns2Host:    "ns2.example.com.",
		Hostmaster: "hostmaster.example.com.",
		VersionTXT: "test",
		EnableGlue: false,
		LogQueries: false,
		Serial:     2024010100,
	}
}

// makeTCPQuery builds a raw DNS/TCP query (2-byte length prefix + message)
// for the SOA record of example.com.
func makeTCPQuery() []byte {
	var msg bytes.Buffer
	// Header: ID=1, RD, QDCOUNT=1, all other counts=0.
	for _, v := range []uint16{1, 0x0100, 1, 0, 0, 0} {
		_ = binary.Write(&msg, binary.BigEndian, v)
	}
	// Question: example.com. / SOA / IN
	for _, label := range []string{"example", "com"} {
		msg.WriteByte(byte(len(label)))
		msg.WriteString(label)
	}
	msg.WriteByte(0)                                    // root label
	_ = binary.Write(&msg, binary.BigEndian, uint16(6)) // SOA
	_ = binary.Write(&msg, binary.BigEndian, uint16(1)) // IN

	raw := msg.Bytes()
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint16(len(raw)))
	out.Write(raw)
	return out.Bytes()
}

// ---- New ----------------------------------------------------------------

func TestNew(t *testing.T) {
	t.Parallel()
	s := New(testCfg())
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.limiter == nil {
		t.Error("limiter not initialized")
	}
	if s.tcpSem == nil {
		t.Error("tcpSem not initialized")
	}
	if cap(s.tcpSem) != maxTCPConns {
		t.Errorf("tcpSem capacity = %d, want %d", cap(s.tcpSem), maxTCPConns)
	}
}

// ---- handleTCPConn ------------------------------------------------------

func TestServer_HandleTCPConn(t *testing.T) {
	t.Parallel()
	s := New(testCfg())

	// net.Pipe gives a synchronous in-memory connection pair — no ports needed.
	client, serverSide := net.Pipe()
	defer client.Close()

	go s.handleTCPConn(serverSide)

	// Send the query.
	query := makeTCPQuery()
	if _, err := client.Write(query); err != nil {
		t.Fatalf("writing query: %v", err)
	}

	// Read the 2-byte length prefix from the response.
	var lenBuf [2]byte
	if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
		t.Fatalf("reading response length: %v", err)
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	if size == 0 {
		t.Fatal("expected non-empty DNS response")
	}
	resp := make([]byte, size)
	if _, err := io.ReadFull(client, resp); err != nil {
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

func TestServer_HandleTCPConn_ZeroLengthPrefix(t *testing.T) {
	t.Parallel()
	s := New(testCfg())
	client, serverSide := net.Pipe()

	go s.handleTCPConn(serverSide)

	// A zero-length prefix must cause handleTCPConn to return without writing.
	_ = binary.Write(client, binary.BigEndian, uint16(0))
	client.Close()
	// handleTCPConn must exit cleanly (goroutine leak detector would catch a hang).
}

func TestServer_HandleTCPConn_Malformed(t *testing.T) {
	t.Parallel()
	s := New(testCfg())
	client, serverSide := net.Pipe()
	defer client.Close()

	go s.handleTCPConn(serverSide)

	// Claim 10 bytes but send only 5 → ReadFull will fail.
	_ = binary.Write(client, binary.BigEndian, uint16(10))
	client.Write([]byte{1, 2, 3, 4, 5})
	client.Close()
	// Must not panic.
}

func TestServer_HandleTCPConn_ReadLenError(t *testing.T) {
	t.Parallel()
	s := New(testCfg())
	client, serverSide := net.Pipe()
	// Close the client immediately — io.ReadFull for the 2-byte length prefix will
	// fail with io.EOF, exercising the early-return path in handleTCPConn.
	client.Close()

	done := make(chan struct{})
	go func() {
		s.handleTCPConn(serverSide)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleTCPConn did not exit after client close")
	}
}

// ---- ipRateLimiter ------------------------------------------------------

func TestIPRateLimiter_AllowsUpToLimit(t *testing.T) {
	t.Parallel()
	r := newRateLimiter()
	const ip = "10.0.0.1"

	for i := range udpRateLimit {
		if !r.allow(ip) {
			t.Fatalf("request %d/%d should be allowed", i+1, udpRateLimit)
		}
	}
	if r.allow(ip) {
		t.Errorf("request %d should be denied (bucket empty)", udpRateLimit+1)
	}
}

func TestIPRateLimiter_IndependentBuckets(t *testing.T) {
	t.Parallel()
	r := newRateLimiter()

	// Exhaust one IP's bucket.
	for range udpRateLimit {
		r.allow("192.0.2.1")
	}
	// A different IP should still be allowed.
	if !r.allow("192.0.2.2") {
		t.Error("distinct IP should have its own full bucket")
	}
}

func TestIPRateLimiter_TokenRefill(t *testing.T) {
	t.Parallel()
	r := newRateLimiter()
	const ip = "10.0.0.1"

	// Exhaust the bucket completely.
	for range udpRateLimit {
		r.allow(ip)
	}
	if r.allow(ip) {
		t.Fatal("bucket should be empty after exhaustion")
	}

	// Simulate 1 second passing by back-dating the bucket's lastSeen timestamp.
	// server_test is package server, so rateBucket fields are accessible.
	r.mu.Lock()
	r.buckets[ip].lastSeen = time.Now().Add(-time.Second)
	r.mu.Unlock()

	// Token refill: 1 second × udpRateLimit tokens/sec → bucket should have tokens again.
	if !r.allow(ip) {
		t.Error("bucket should have refilled after simulated 1 second")
	}
}

func TestIPRateLimiter_BucketCapPreventsOOM(t *testing.T) {
	t.Parallel()
	r := newRateLimiter()

	// Fill the limiter to its cap using distinct IPs.
	for i := range maxRateBuckets {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xff, i&0xff)
		r.allow(ip)
	}
	// A brand-new IP must be dropped to protect memory.
	if r.allow("99.99.99.99") {
		t.Error("new IP should be rejected when bucket map is at capacity")
	}
}

// ---- Test for removeIdleBuckets (idle cleanup) ----
func TestIPRateLimiter_RemoveIdleBuckets(t *testing.T) {
	t.Parallel()
	r := newRateLimiter()
	const ip = "10.0.0.1"
	r.buckets[ip] = &rateBucket{tokens: 1, lastSeen: time.Now().Add(-2 * time.Minute)}
	if len(r.buckets) != 1 {
		t.Fatal("bucket not added")
	}
	r.removeIdleBuckets(time.Now(), time.Minute)
	if len(r.buckets) != 0 {
		t.Error("idle bucket was not removed")
	}
}

func freePort() string {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestServer_Run_UDP_TCP(t *testing.T) {
	t.Parallel()
	cfg := testCfg()
	cfg.Bind = freePort()
	s := New(cfg)

	// ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	// defer cancel()
	done := make(chan struct{})
	go func() {
		s.Run()
		close(done)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// --- UDP test ---
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	query := makeTCPQuery()[2:] // strip length prefix for UDP
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	resp := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _, err := conn.ReadFrom(resp)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if n < 4 {
		t.Fatalf("udp response too short: %d bytes", n)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Error("UDP QR bit not set")
	}

	// --- TCP test ---
	tcpConn, err := net.Dial("tcp", cfg.Bind)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer tcpConn.Close()
	if _, err := tcpConn.Write(makeTCPQuery()); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(tcpConn, lenBuf[:]); err != nil {
		t.Fatalf("tcp read len: %v", err)
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	if size == 0 {
		t.Fatal("tcp: expected non-empty DNS response")
	}
	respTCP := make([]byte, size)
	if _, err := io.ReadFull(tcpConn, respTCP); err != nil {
		t.Fatalf("tcp read body: %v", err)
	}
	if len(respTCP) < 4 {
		t.Fatalf("tcp response too short: %d bytes", len(respTCP))
	}
	flags = binary.BigEndian.Uint16(respTCP[2:4])
	if flags&0x8000 == 0 {
		t.Error("TCP QR bit not set")
	}

	// Stop the server (by killing the process, since Run blocks)
	// In real code, refactor for graceful shutdown.
}

// ---- Error path tests for serveUDP/serveTCP ----

type errPacketConn struct {
	stop <-chan struct{}
}

func (e *errPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-e.stop:
		return 0, nil, io.EOF
	case <-time.After(5 * time.Millisecond):
		return 0, nil, io.EOF
	}
}

func (e *errPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return 0, io.ErrClosedPipe
}
func (e *errPacketConn) Close() error                       { return nil }
func (e *errPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (e *errPacketConn) SetDeadline(t time.Time) error      { return nil }
func (e *errPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (e *errPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type errListener struct{}

func (e *errListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (e *errListener) Close() error              { return nil }
func (e *errListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServeUDP_ListenPacketError(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	s := New(testCfg())
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return nil, io.ErrClosedPipe
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("serveUDP did not exit in time after listen error")
	}
	if !exited {
		t.Error("expected exit(1) to be called on listen failure")
	}
}

func TestServeUDP_ReadWriteError(t *testing.T) {
	s := New(testCfg())
	stop := make(chan struct{})
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return &errPacketConn{stop: stop}, nil
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP(stop)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("serveUDP did not exit in time")
	}
}

func TestServeTCP_ListenError(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	s := New(testCfg())
	s.listen = func(network, address string) (net.Listener, error) {
		return nil, io.ErrClosedPipe
	}
	done := make(chan struct{})
	go func() {
		s.serveTCP()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("serveTCP did not exit in time after listen error")
	}
	if !exited {
		t.Error("expected exit(1) to be called on listen failure")
	}
}

func TestServeTCP_AcceptError(t *testing.T) {
	s := New(testCfg())
	s.listen = func(network, address string) (net.Listener, error) {
		return &errListener{}, nil
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		s.serveTCP(stop)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("serveTCP did not exit in time")
	}
}

// ---- handleTCPConn additional paths -------------------------------------

// mockConn is a net.Conn that returns an error on SetDeadline.
type mockConn struct {
	net.Conn
	setDeadlineErr error
}

func (m *mockConn) SetDeadline(t time.Time) error { return m.setDeadlineErr }

func TestServer_HandleTCPConn_DeadlineError(t *testing.T) {
	t.Parallel()
	s := New(testCfg())
	// Use net.Pipe so we have a real bidirectional connection.
	client, serverSide := net.Pipe()
	defer client.Close()

	// Wrap the server side with a conn that errors on SetDeadline.
	wrapped := &mockConn{Conn: serverSide, setDeadlineErr: io.ErrClosedPipe}

	go s.handleTCPConn(wrapped)

	// Send a valid query — handleTCPConn should still proceed despite the deadline error.
	query := makeTCPQuery()
	if _, err := client.Write(query); err != nil {
		t.Fatalf("writing query: %v", err)
	}
	// Read the response to confirm handleTCPConn continued.
	var lenBuf [2]byte
	if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
		t.Fatalf("reading response length: %v", err)
	}
	size := binary.BigEndian.Uint16(lenBuf[:])
	if size == 0 {
		t.Fatal("expected non-empty DNS response even with deadline error")
	}
}

func TestServer_HandleTCPConn_HandleQueryError(t *testing.T) {
	t.Parallel()
	s := New(testCfg())
	client, serverSide := net.Pipe()
	defer client.Close()

	go s.handleTCPConn(serverSide)

	// Send a correctly-framed message whose content is too short for HandleQuery
	// (5 bytes < 12 minimum) — HandleQuery will return an error.
	const bodyLen = 5
	var frame [2 + bodyLen]byte
	binary.BigEndian.PutUint16(frame[:2], bodyLen)
	// body is all zeros: valid length prefix but invalid DNS message
	if _, err := client.Write(frame[:]); err != nil {
		t.Fatalf("writing frame: %v", err)
	}
	// handleTCPConn should close the conn without writing a response.
	// Reads should return EOF.
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := client.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection to be closed after HandleQuery error")
	}
}

// ---- serveTCP connection limit ------------------------------------------

// oneConnListener returns one connection then EOF on subsequent Accept calls.
type oneConnListener struct {
	conn    net.Conn
	mu      sync.Mutex
	served  bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.served {
		l.served = true
		return l.conn, nil
	}
	return nil, io.EOF
}
func (l *oneConnListener) Close() error  { return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestServeTCP_ConnectionLimit(t *testing.T) {
	s := New(testCfg())

	// Pre-fill the semaphore to simulate maxTCPConns active connections.
	for range maxTCPConns {
		s.tcpSem <- struct{}{}
	}

	client, serverSide := net.Pipe()
	defer client.Close()

	s.listen = func(network, address string) (net.Listener, error) {
		return &oneConnListener{conn: serverSide}, nil
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		s.serveTCP(stop)
		close(done)
	}()

	// The server should close serverSide because the semaphore is full.
	client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := client.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected connection to be rejected (limit reached)")
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Error("serveTCP did not exit in time")
	}
}

// ---- serveUDP additional paths ------------------------------------------

// badAddrConn returns a source address whose String() has no port separator,
// causing net.SplitHostPort to fail.
type badAddrConn struct {
	stop <-chan struct{}
}

type badAddr struct{}

func (a badAddr) Network() string { return "udp" }
func (a badAddr) String() string  { return "not-a-valid-host-port" }

func (c *badAddrConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.stop:
		return 0, nil, io.EOF
	case <-time.After(5 * time.Millisecond):
		// Return a non-empty packet with an unparseable source address.
		b[0] = 0
		return 1, badAddr{}, nil
	}
}
func (c *badAddrConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }
func (c *badAddrConn) Close() error                                  { return nil }
func (c *badAddrConn) LocalAddr() net.Addr                           { return &net.UDPAddr{} }
func (c *badAddrConn) SetDeadline(t time.Time) error                 { return nil }
func (c *badAddrConn) SetReadDeadline(t time.Time) error             { return nil }
func (c *badAddrConn) SetWriteDeadline(t time.Time) error            { return nil }

func TestServeUDP_BadSourceAddress(t *testing.T) {
	s := New(testCfg())
	stop := make(chan struct{})
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return &badAddrConn{stop: stop}, nil
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP(stop)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("serveUDP did not exit in time")
	}
}

// rateLimitConn serves a valid DNS query repeatedly from the same IP so that
// the rate limiter eventually blocks the source.
type rateLimitConn struct {
	query []byte
	addr  net.Addr
	count int
	stop  <-chan struct{}
	mu    sync.Mutex
}

func (c *rateLimitConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	n := c.count
	c.count++
	c.mu.Unlock()

	if n < udpRateLimit+5 {
		copy(b, c.query)
		return len(c.query), c.addr, nil
	}
	<-c.stop
	return 0, nil, io.EOF
}
func (c *rateLimitConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }
func (c *rateLimitConn) Close() error                                  { return nil }
func (c *rateLimitConn) LocalAddr() net.Addr                           { return &net.UDPAddr{} }
func (c *rateLimitConn) SetDeadline(t time.Time) error                 { return nil }
func (c *rateLimitConn) SetReadDeadline(t time.Time) error             { return nil }
func (c *rateLimitConn) SetWriteDeadline(t time.Time) error            { return nil }

func TestServeUDP_RateLimit(t *testing.T) {
	s := New(testCfg())
	stop := make(chan struct{})

	query := makeTCPQuery()[2:] // strip length prefix for UDP
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return &rateLimitConn{
			query: query,
			addr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234},
			stop:  stop,
		}, nil
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP(stop)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Error("serveUDP did not exit in time")
	}
}

// handleErrConn returns a malformed DNS packet (too short) from a valid source
// address so that HandleQuery returns an error.
type handleErrConn struct {
	stop <-chan struct{}
}

func (c *handleErrConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.stop:
		return 0, nil, io.EOF
	case <-time.After(5 * time.Millisecond):
		// Return 3 bytes — too short for HandleQuery (needs ≥ 12).
		b[0], b[1], b[2] = 0, 0, 0
		return 3, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5353}, nil
	}
}
func (c *handleErrConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }
func (c *handleErrConn) Close() error                                  { return nil }
func (c *handleErrConn) LocalAddr() net.Addr                           { return &net.UDPAddr{} }
func (c *handleErrConn) SetDeadline(t time.Time) error                 { return nil }
func (c *handleErrConn) SetReadDeadline(t time.Time) error             { return nil }
func (c *handleErrConn) SetWriteDeadline(t time.Time) error            { return nil }

func TestServeUDP_HandleError(t *testing.T) {
	s := New(testCfg())
	stop := make(chan struct{})
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return &handleErrConn{stop: stop}, nil
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP(stop)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("serveUDP did not exit in time")
	}
}

// writeErrConn returns a valid DNS query on ReadFrom but errors on WriteTo.
type writeErrConn struct {
	query []byte
	addr  net.Addr
	stop  <-chan struct{}
	sent  bool
	mu    sync.Mutex
}

func (c *writeErrConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	done := c.sent
	c.mu.Unlock()
	if !done {
		c.mu.Lock()
		c.sent = true
		c.mu.Unlock()
		copy(b, c.query)
		return len(c.query), c.addr, nil
	}
	<-c.stop
	return 0, nil, io.EOF
}
func (c *writeErrConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return 0, io.ErrClosedPipe // always fail
}
func (c *writeErrConn) Close() error                    { return nil }
func (c *writeErrConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (c *writeErrConn) SetDeadline(t time.Time) error   { return nil }
func (c *writeErrConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *writeErrConn) SetWriteDeadline(t time.Time) error { return nil }

func TestServeUDP_WriteError(t *testing.T) {
	s := New(testCfg())
	stop := make(chan struct{})

	query := makeTCPQuery()[2:] // strip length prefix for UDP
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return &writeErrConn{
			query: query,
			addr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 1234},
			stop:  stop,
		}, nil
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP(stop)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Error("serveUDP did not exit in time")
	}
}

// ---- serveUDP top-of-loop stop check ------------------------------------

// stopOnWriteConn triggers stop closure on the first successful WriteTo,
// so the next loop iteration's stop check returns cleanly.
type stopOnWriteConn struct {
	query []byte
	addr  net.Addr
	stop  chan struct{}
	mu    sync.Mutex
	fired bool
}

func (c *stopOnWriteConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.stop:
		return 0, nil, io.EOF
	default:
	}
	copy(b, c.query)
	return len(c.query), c.addr, nil
}
func (c *stopOnWriteConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fired {
		c.fired = true
		close(c.stop) // triggers top-of-loop stop check on next iteration
	}
	return len(b), nil
}
func (c *stopOnWriteConn) Close() error                    { return nil }
func (c *stopOnWriteConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (c *stopOnWriteConn) SetDeadline(t time.Time) error   { return nil }
func (c *stopOnWriteConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stopOnWriteConn) SetWriteDeadline(t time.Time) error { return nil }

func TestServeUDP_StopAtTopOfLoop(t *testing.T) {
	s := New(testCfg())
	stop := make(chan struct{})

	query := makeTCPQuery()[2:] // strip length prefix for UDP
	s.listenPacket = func(network, address string) (net.PacketConn, error) {
		return &stopOnWriteConn{
			query: query,
			addr:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 4), Port: 1234},
			stop:  stop,
		}, nil
	}
	done := make(chan struct{})
	go func() {
		s.serveUDP(stop)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("serveUDP did not exit via top-of-loop stop check")
	}
}
