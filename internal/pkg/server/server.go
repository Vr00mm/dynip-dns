// Package server runs the DNS listeners for dynip-dns.
//
// It provides a [Server] that listens on both UDP and TCP, applies per-source-IP
// token-bucket rate limiting on UDP, and enforces a concurrent-connection cap on
// TCP. Each incoming message is parsed and answered by [dns.HandleQuery].
package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Vr00mm/dynip-dns/internal/pkg/config"
	"github.com/Vr00mm/dynip-dns/internal/pkg/dns"
)

// exit is the process-exit function. Overridden in tests to capture fatal errors.
var exit = os.Exit

const (
	udpRateLimit   = 20           // sustained queries/second per source IP (token bucket rate)
	bucketCapacity = udpRateLimit // max burst equals the per-second limit
	maxRateBuckets = 100_000      // cap map size; new IPs dropped when full (~8 MB at ~80 B/entry)
	maxTCPConns    = 1_000        // max concurrent TCP handlers
)

// rateBucket is a token-bucket entry for a single source IP.
// Tokens refill at udpRateLimit per second up to bucketCapacity.
type rateBucket struct {
	tokens   float64
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
}

func newRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{buckets: make(map[string]*rateBucket)}
}

func (r *ipRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	b, ok := r.buckets[ip]
	if !ok {
		// Drop new IPs when the map is full to prevent memory exhaustion
		// from spoofed-source UDP floods.
		if len(r.buckets) >= maxRateBuckets {
			return false
		}
		// New IP: full bucket minus the current request.
		r.buckets[ip] = &rateBucket{tokens: bucketCapacity - 1, lastSeen: now}
		return true
	}
	// Refill tokens proportional to elapsed time, then consume one for this request.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(float64(bucketCapacity), b.tokens+elapsed*float64(udpRateLimit))
	b.lastSeen = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (r *ipRateLimiter) cleanup() {
	for {
		time.Sleep(time.Minute)
		r.removeIdleBuckets(time.Now(), time.Minute)
	}
}

// removeIdleBuckets removes buckets idle longer than idleThreshold.
// Exposed for testing.
func (r *ipRateLimiter) removeIdleBuckets(now time.Time, idleThreshold time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, b := range r.buckets {
		if now.Sub(b.lastSeen) > idleThreshold {
			delete(r.buckets, ip)
		}
	}

}

// Server is a DNS server that listens on UDP and TCP.
// Create one with [New] and start it with [Run].
// The zero value is not usable; always use New.
type Server struct {
	cfg     config.Config
	limiter *ipRateLimiter
	tcpSem  chan struct{}

	listenPacket func(network, address string) (net.PacketConn, error)
	listen       func(network, address string) (net.Listener, error)
}

// New creates a Server from the given configuration.
// Call [Server.Run] to start listening.
func New(cfg config.Config) *Server {
	return &Server{
		cfg:          cfg,
		limiter:      newRateLimiter(),
		tcpSem:       make(chan struct{}, maxTCPConns),
		listenPacket: net.ListenPacket,
		listen:       net.Listen,
	}
}

// Run starts the UDP and TCP listeners and blocks until the TCP listener exits.
// The UDP listener runs in a separate goroutine.
// Use [Server.serveUDP] and [Server.serveTCP] directly (with a stop channel) for
// controlled shutdown in tests.
func (s *Server) Run() {
	go s.limiter.cleanup()
	go s.serveUDP()
	s.serveTCP()
}

func (s *Server) serveUDP(stopCh ...<-chan struct{}) {
	pc, err := s.listenPacket("udp", s.cfg.Bind)
	if err != nil {
		slog.Error("udp listen failed", "err", err)
		exit(1)
		return
	}
	defer pc.Close()
	slog.Info("listening", "proto", "udp", "addr", s.cfg.Bind)

	buf := make([]byte, 1500)
	for {
		select {
		case <-firstCh(stopCh):
			return
		default:
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			slog.Error("udp read error", "err", err)
			select {
			case <-firstCh(stopCh):
				return
			default:
			}
			continue
		}
		srcIP, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			slog.Warn("udp: bad source address", "addr", addr, "err", err)
			continue
		}
		if !s.limiter.allow(srcIP) {
			slog.Warn("udp rate limit exceeded", "src", srcIP)
			continue
		}
		req := append([]byte(nil), buf[:n]...)
		maxUDP := dns.ParseEDNS0PayloadSize(req)
		resp, err := dns.HandleQuery(s.cfg, req, maxUDP)
		if err != nil {
			slog.Error("udp handle error", "err", err)
			continue
		}
		if _, err := pc.WriteTo(resp, addr); err != nil {
			slog.Error("udp write error", "err", err)
		}
	}
}

func (s *Server) serveTCP(stopCh ...<-chan struct{}) {
	ln, err := s.listen("tcp", s.cfg.Bind)
	if err != nil {
		slog.Error("tcp listen failed", "err", err)
		exit(1)
		return
	}
	defer ln.Close()
	slog.Info("listening", "proto", "tcp", "addr", s.cfg.Bind)

	for {
		select {
		case <-firstCh(stopCh):
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("tcp accept error", "err", err)
			continue
		}
		select {
		case s.tcpSem <- struct{}{}:
			go func() {
				defer func() { <-s.tcpSem }()
				s.handleTCPConn(conn)
			}()
		default:
			slog.Warn("tcp connection limit reached", "remote", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// firstCh returns the first channel in stopCh, or a nil channel if none.
func firstCh(stopCh []<-chan struct{}) <-chan struct{} {
	if len(stopCh) > 0 {
		return stopCh[0]
	}
	return nil
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		slog.Warn("failed to set TCP deadline", "remote", conn.RemoteAddr(), "err", err)
	}

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
	resp, err := dns.HandleQuery(s.cfg, req, 0)
	if err != nil {
		slog.Error("tcp handle error", "err", err)
		return
	}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, uint16(len(resp)))
	out.Write(resp)
	_, _ = conn.Write(out.Bytes())
}
