// Package config loads and validates the runtime configuration for dynip-dns.
// Values are resolved in priority order: environment variable → config file → built-in default.
// Invalid values (bad IP, unparseable bool/int) are logged and cause the process to exit.
package config

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// exit is the process-exit function. Overridden in tests to capture fatal errors.
var exit = os.Exit

// Config holds the runtime configuration for the DNS server.
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

// LoadConfigFile parses a key=value config file and returns the resulting map.
// Environment variables always take priority over file values.
func LoadConfigFile(path string) map[string]string {
	cm := make(map[string]string)
	if path == "" {
		return cm
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cm
		}
		slog.Error("cannot open config file", "path", path, "err", err)
		exit(1)
		return cm
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
		cm[key] = val
	}
	return cm
}

// LoadConfig builds a Config from a key=value map (typically from LoadConfigFile)
// with environment variables taking priority.
func LoadConfig(cm map[string]string) Config {
	get := func(k, def string) string { return getEnv(cm, k, def) }
	zone := fqdn(strings.ToLower(strings.TrimSpace(get("ZONE", "yourdomain.com"))))
	cfg := Config{
		Zone:       zone,
		TTL:        parseUint32(get("TTL", "60"), "TTL"),
		Bind:       strings.TrimSpace(get("BIND", ":53")),
		Ns1Host:    fqdn(strings.ToLower(get("NS1_HOST", "ns1."+zone))),
		Ns2Host:    fqdn(strings.ToLower(get("NS2_HOST", "ns2."+zone))),
		Ns1IPv4:    parseIPOrNil(get("NS1_IPV4", "")),
		Ns2IPv4:    parseIPOrNil(get("NS2_IPV4", "")),
		Ns1IPv6:    parseIPOrNil(get("NS1_IPV6", "")),
		Ns2IPv6:    parseIPOrNil(get("NS2_IPV6", "")),
		Hostmaster: fqdn(strings.ToLower(get("HOSTMASTER", "hostmaster."+zone))),
		VersionTXT: get("VERSION_TXT", "dynip-dns"),
		EnableGlue: parseBool(get("ENABLE_GLUE", "true")),
		LogQueries: parseBool(get("LOG_QUERIES", "true")),
	}
	now := time.Now().UTC()
	cfg.Serial = uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)
	slog.Info("starting dynip-dns", "zone", cfg.Zone, "bind", cfg.Bind, "ttl", cfg.TTL, "serial", cfg.Serial)
	return cfg
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

// getEnv returns the value for key k, checking the environment first, then
// the config file map cm, then falling back to def.
func getEnv(cm map[string]string, k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	if v, ok := cm[strings.ToUpper(k)]; ok && v != "" {
		return v
	}
	return def
}

func parseIPOrNil(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		slog.Error("invalid IP in config", "value", s)
		exit(1)
		return nil
	}
	return ip
}

func parseBool(s string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		slog.Error("invalid bool in config", "value", s, "err", err)
		exit(1)
		return false
	}
	return v
}

func parseUint32(s, field string) uint32 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		slog.Error("invalid value in config", "field", field, "err", err)
		exit(1)
		return 0
	}
	return uint32(n)
}
