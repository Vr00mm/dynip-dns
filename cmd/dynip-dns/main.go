// Command dynip-dns is a lightweight authoritative DNS server that resolves
// hostnames to IP addresses encoded directly in the subdomain label.
// No database or dynamic updates are required — encode the IP in the name and query it.
//
// Usage:
//
//	dynip-dns [-config /path/to/dynip-dns.conf]
//
// Configuration is loaded from the file given by -config (optional), with
// environment variables taking precedence over file values.
// See the README for the full list of configuration keys.
package main

import (
	"flag"

	"github.com/Vr00mm/dynip-dns/internal/pkg/config"
	"github.com/Vr00mm/dynip-dns/internal/pkg/server"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()
	cm := config.LoadConfigFile(*configPath)
	cfg := config.LoadConfig(cm)
	server.New(cfg).Run()
}
