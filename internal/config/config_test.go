package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfiguration(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	token := strings.Repeat("x", 32)
	base := "[client]\nremote_addr='localhost:2333'\ndefault_token='" + token + "'\n[client.transport]\ntype='noise'\n[client.transport.noise]\nlocal_private_key='" + key + "'\nremote_public_key='" + key + "'\n[client.services.ssh]\nlocal_addr='localhost:22'\n"
	load := func(s string) (*Config, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.toml")
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		return Load(p)
	}
	cfg, e := load(base)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Client.Services["ssh"].Token != token || cfg.Client.Pool.Size != 4 {
		t.Fatal("defaults or token inheritance")
	}
	for name, s := range map[string]string{
		"unknown":                 base + "[client.pool]\nunknown=1\n",
		"both":                    base + "[server]\nbind_addr='localhost:2334'\n",
		"no service":              strings.Split(base, "[client.services.ssh]")[0],
		"short token":             strings.Replace(base, token, "tiny", 1),
		"empty token":             base + "token=''\n",
		"bad key":                 strings.Replace(base, key, "not-base64", 1),
		"noise with tls":          base + "[client.transport.tls]\nca_file='ca.pem'\n",
		"zero pool":               base + "[client.pool]\nsize=0\n",
		"long timeout":            strings.Replace(base, "remote_addr=", "dial_timeout='6s'\nremote_addr=", 1),
		"bad port":                strings.Replace(base, "localhost:2333", "localhost:0", 1),
		"signed port":             strings.Replace(base, "localhost:2333", "localhost:+2333", 1),
		"wrong role empty field":  base + "bind_addr=''\n",
		"invalid explicit tls CA": strings.Replace(strings.Replace(base, "[client.transport.noise]\nlocal_private_key='"+key+"'\nremote_public_key='"+key+"'\n", "", 1), "type='noise'", "type='wss'", 1) + "[client.transport.tls]\nca_file=''\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, e := load(s)
			if e == nil {
				t.Fatal("accepted invalid configuration")
			}
			if strings.Contains(e.Error(), token) || strings.Contains(e.Error(), key) {
				t.Fatal("secret in error", e)
			}
		})
	}
	if _, err := load(base + "[client.pool]\nunknown=1\n"); err == nil || !strings.Contains(err.Error(), "unknown") || !strings.Contains(err.Error(), "config.toml:") {
		t.Fatal("unknown field lacks safe position", err)
	}
	if _, err := load(strings.Replace(strings.Replace(base, "[client.transport.noise]\nlocal_private_key='"+key+"'\nremote_public_key='"+key+"'\n", "", 1), "type='noise'", "type='wss'", 1) + "[client.transport.tls]\nca_file=''\n"); err == nil || !strings.Contains(err.Error(), "ca_file: empty value") {
		t.Fatal("explicit empty CA unexpectedly defaulted", err)
	}
	cfg, e = load(base + "token='" + strings.Repeat("y", 32) + "'\n")
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Client.Services["ssh"].Token != strings.Repeat("y", 32) {
		t.Fatal("service token override")
	}
}
