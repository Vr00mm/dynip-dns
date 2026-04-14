package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// ---- LoadConfigFile -----------------------------------------------------
// ---- parseIPOrNil / parseBool / parseUint32 ----

func Test_parseIPOrNil(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	tests := []struct {
		name     string
		in       string
		want     net.IP
		wantExit bool
	}{
		{"empty", "", nil, false},
		{"valid", "1.2.3.4", net.ParseIP("1.2.3.4"), false},
		{"invalid", "not-an-ip", nil, true},
	}
	for _, tt := range tests {
		exited = false
		got := parseIPOrNil(tt.in)
		if tt.wantExit != exited {
			t.Errorf("%s: wantExit=%v exited=%v", tt.name, tt.wantExit, exited)
		}
		if !tt.wantExit && ((got == nil) != (tt.want == nil) || (got != nil && !got.Equal(tt.want))) {
			t.Errorf("%s: got=%v want=%v", tt.name, got, tt.want)
		}
	}
}

func Test_parseBool(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	tests := []struct {
		in       string
		want     bool
		wantExit bool
	}{
		{"true", true, false},
		{"false", false, false},
		{"1", true, false},
		{"0", false, false},
		{"notabool", false, true},
	}
	for _, tt := range tests {
		exited = false
		got := parseBool(tt.in)
		if tt.wantExit != exited {
			t.Errorf("in=%q wantExit=%v exited=%v", tt.in, tt.wantExit, exited)
		}
		if !tt.wantExit && got != tt.want {
			t.Errorf("in=%q got=%v want=%v", tt.in, got, tt.want)
		}
	}
}

func Test_parseUint32(t *testing.T) {
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	tests := []struct {
		in       string
		field    string
		want     uint32
		wantExit bool
	}{
		{"123", "TTL", 123, false},
		{"0", "TTL", 0, false},
		{"notanint", "TTL", 0, true},
	}
	for _, tt := range tests {
		exited = false
		got := parseUint32(tt.in, tt.field)
		if tt.wantExit != exited {
			t.Errorf("in=%q wantExit=%v exited=%v", tt.in, tt.wantExit, exited)
		}
		if !tt.wantExit && got != tt.want {
			t.Errorf("in=%q got=%v want=%v", tt.in, got, tt.want)
		}
	}
}

func Test_fqdn(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"", "."},
		{"foo.", "foo."},
		{"foo", "foo."},
	}
	for _, tt := range tests {
		if got := fqdn(tt.in); got != tt.want {
			t.Errorf("fqdn(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadConfigFile_EmptyPath(t *testing.T) {
	t.Parallel()
	cm := LoadConfigFile("")
	if len(cm) != 0 {
		t.Errorf("expected empty map for empty path, got %v", cm)
	}
}

func TestLoadConfigFile_NotFound(t *testing.T) {
	t.Parallel()
	cm := LoadConfigFile(filepath.Join(t.TempDir(), "nonexistent.env"))
	if len(cm) != 0 {
		t.Errorf("expected empty map for missing file, got %v", cm)
	}
}

func TestLoadConfigFile_ParsesFile(t *testing.T) {
	t.Parallel()
	content := "ZONE=test.example.\nTTL=120\n# a comment\n\nBIND=:5353\n"
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cm := LoadConfigFile(path)
	tests := []struct{ key, want string }{
		{"ZONE", "test.example."},
		{"TTL", "120"},
		{"BIND", ":5353"},
	}
	for _, tt := range tests {
		if got := cm[tt.key]; got != tt.want {
			t.Errorf("cm[%q] = %q, want %q", tt.key, got, tt.want)
		}
	}
	// Comments and blank lines must be ignored.
	if _, ok := cm[""]; ok {
		t.Error("empty key should not be present")
	}
}

func TestLoadConfigFile_NoEqualsLine(t *testing.T) {
	t.Parallel()
	content := "KEY=value\nNOEQUALS\nOTHER=val\n"
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cm := LoadConfigFile(path)
	if cm["KEY"] != "value" {
		t.Errorf("cm[KEY] = %q, want %q", cm["KEY"], "value")
	}
	if _, ok := cm["NOEQUALS"]; ok {
		t.Error("line without '=' should be skipped")
	}
}

func TestLoadConfigFile_OpenError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, cannot create unreadable file")
	}
	origExit := exit
	var exited bool
	exit = func(code int) { exited = true }
	t.Cleanup(func() { exit = origExit })

	path := filepath.Join(t.TempDir(), "unreadable.env")
	if err := os.WriteFile(path, []byte("KEY=VAL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	cm := LoadConfigFile(path)
	if !exited {
		t.Error("expected exit to be called on unreadable file")
	}
	if len(cm) != 0 {
		t.Error("expected empty map after open error")
	}
}

func TestLoadConfigFile_KeysUpperCased(t *testing.T) {
	t.Parallel()
	content := "zone=lower.example.\n"
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cm := LoadConfigFile(path)
	if _, ok := cm["zone"]; ok {
		t.Error("keys must be stored upper-cased, not lower-cased")
	}
	if cm["ZONE"] != "lower.example." {
		t.Errorf("cm[ZONE] = %q, want %q", cm["ZONE"], "lower.example.")
	}
}

// ---- LoadConfig ---------------------------------------------------------

func TestLoadConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := LoadConfig(map[string]string{})
	if cfg.Zone == "" {
		t.Error("Zone must have a default")
	}
	if cfg.TTL == 0 {
		t.Error("TTL must have a default")
	}
	if cfg.Serial == 0 {
		t.Error("Serial must be set at startup")
	}
	if cfg.Ns1Host == "" || cfg.Ns2Host == "" {
		t.Error("NS hosts must have defaults derived from zone")
	}
}

func TestLoadConfig_Override(t *testing.T) {
	t.Parallel()
	cm := map[string]string{
		"ZONE": "myzone.example.",
		"TTL":  "300",
	}
	cfg := LoadConfig(cm)
	if cfg.Zone != "myzone.example." {
		t.Errorf("Zone = %q, want %q", cfg.Zone, "myzone.example.")
	}
	if cfg.TTL != 300 {
		t.Errorf("TTL = %d, want 300", cfg.TTL)
	}
	// NS hosts must be derived from the overridden zone.
	if cfg.Ns1Host != "ns1.myzone.example." {
		t.Errorf("Ns1Host = %q, want %q", cfg.Ns1Host, "ns1.myzone.example.")
	}
}

func TestLoadConfig_EnvVarPriority(t *testing.T) {
	// t.Setenv cannot be used in parallel tests.
	t.Setenv("ZONE", "env.example.")
	cm := map[string]string{"ZONE": "file.example."}
	cfg := LoadConfig(cm)
	if cfg.Zone != "env.example." {
		t.Errorf("Zone = %q, want env.example. (env var should beat file value)", cfg.Zone)
	}
}

func TestLoadConfig_ZoneAlwaysFQDN(t *testing.T) {
	t.Parallel()
	// Zone without trailing dot must be normalised to FQDN.
	cfg := LoadConfig(map[string]string{"ZONE": "nodot.example"})
	if cfg.Zone != "nodot.example." {
		t.Errorf("Zone = %q, want trailing dot", cfg.Zone)
	}
}

func TestLoadConfig_SerialIsDateBased(t *testing.T) {
	t.Parallel()
	cfg := LoadConfig(map[string]string{})
	// Serial is YYYYMMDD00; must be >= 2024010100.
	if cfg.Serial < 2024010100 {
		t.Errorf("Serial = %d looks wrong (expected YYYYMMDD00 format)", cfg.Serial)
	}
}
