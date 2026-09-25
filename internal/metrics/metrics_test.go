package metrics

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/pool"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var (
	testCfg = &config.Metrics{UsernameHash: sha256.Sum256([]byte("prom")), PasswordHash: sha256.Sum256([]byte("correct horse battery"))}
	testLog = slog.New(slog.NewJSONHandler(io.Discard, nil))
)

func scrape(t *testing.T, h http.Handler, method, path, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandlerAuthAndRouting(t *testing.T) {
	h := NewServer([]string{"svc"}, map[string]*pool.Pool{"svc": pool.New(1)}).Handler(testCfg, testLog)
	for _, c := range []struct {
		name, method, path, user, pass string
		code                           int
	}{
		{"no credentials", "GET", "/metrics", "", "", 401},
		{"wrong password", "GET", "/metrics", "prom", "wrong horse battery", 401},
		{"wrong user", "GET", "/metrics", "admin", "correct horse battery", 401},
		{"empty password", "GET", "/metrics", "prom", "", 401},
		{"unauthenticated other path", "GET", "/other", "", "", 401},
		{"other path", "GET", "/other", "prom", "correct horse battery", 404},
		{"post", "POST", "/metrics", "prom", "correct horse battery", 405},
		{"ok", "GET", "/metrics", "prom", "correct horse battery", 200},
	} {
		rec := scrape(t, h, c.method, c.path, c.user, c.pass)
		if rec.Code != c.code {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.code)
		}
		if c.code == 401 && !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Errorf("%s: missing WWW-Authenticate", c.name)
		}
		if c.code != 200 && strings.Contains(rec.Body.String(), "compress_proxy_") {
			t.Errorf("%s: metrics leaked", c.name)
		}
	}
}

func TestServerExposition(t *testing.T) {
	p := pool.New(4)
	w, _ := p.Register(1, pool.Options{}, func() {})
	w.Idle()
	x := NewServer([]string{"svc"}, map[string]*pool.Pool{"svc": p})
	s := x.Service("svc")
	s.Relay.ToTunnelRaw.Add(5)
	s.Relay.ToTunnelCompressed.Add(3)
	s.Opened.Add(1)
	s.Visitors.Add(2)
	s.LeaseDone(LeaseOK, 20*time.Millisecond)
	s.LeaseDone(LeaseDialFailed, time.Millisecond)
	s.Closed("expired")
	s.Closed("something new")
	s.DispatchFailed(pool.ErrFull)
	x.Rejected("authentication_failed")
	rec := scrape(t, x.Handler(testCfg, testLog), "GET", "/metrics", "prom", "correct horse battery")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`compress_proxy_build_info{go_version="`,
		`role="server"`,
		`compress_proxy_tunnel_connections{service="svc",state="idle"} 1`,
		`compress_proxy_tunnel_connections{service="svc",state="leased"} 0`,
		`compress_proxy_tunnel_connections_opened_total{service="svc"} 1`,
		`compress_proxy_relay_raw_bytes_total{direction="to_tunnel",service="svc"} 5`,
		`compress_proxy_relay_raw_bytes_total{direction="from_tunnel",service="svc"} 0`,
		`compress_proxy_relay_compressed_bytes_total{direction="to_tunnel",service="svc"} 3`,
		`compress_proxy_leases_total{outcome="ok",service="svc"} 1`,
		`compress_proxy_leases_total{outcome="dial_failed",service="svc"} 1`,
		`compress_proxy_leases_total{outcome="client_close",service="svc"} 0`,
		`compress_proxy_lease_duration_seconds_count{service="svc"} 2`,
		`compress_proxy_lease_duration_seconds_bucket{service="svc",le="0.025"} 2`,
		`compress_proxy_lease_duration_seconds_bucket{service="svc",le="0.01"} 1`,
		`compress_proxy_server_connections_closed_total{reason="expired",service="svc"} 1`,
		`compress_proxy_server_connections_closed_total{reason="error",service="svc"} 1`,
		`compress_proxy_server_visitors_total{service="svc"} 2`,
		`compress_proxy_server_pending_visitors{service="svc"} 0`,
		`compress_proxy_server_dispatch_failures_total{reason="full",service="svc"} 1`,
		`compress_proxy_server_dispatch_failures_total{reason="wait_timeout",service="svc"} 0`,
		`compress_proxy_server_registrations_rejected_total{code="authentication_failed"} 1`,
		"go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, unwanted := range []string{"compress_proxy_client_", `state="busy"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("server exposes %s", unwanted)
		}
	}
	if problems, e := testutil.GatherAndLint(x.reg); e != nil || len(problems) > 0 {
		t.Fatalf("lint: %v %v", e, problems)
	}
}

func TestClientExposition(t *testing.T) {
	x := NewClient([]string{"svc"}, func() map[string]Slots { return map[string]Slots{"svc": {Connecting: 1, Idle: 2, Busy: 3}} })
	s := x.Service("svc")
	s.Relay.FromTunnelRaw.Add(7)
	s.LocalDialFailures.Add(1)
	s.DialFailures.Add(4)
	s.Rejected("invalid_pool")
	s.Rejected("unheard_of")
	s.Retired("surplus")
	body := scrape(t, x.Handler(testCfg, testLog), "GET", "/metrics", "prom", "correct horse battery").Body.String()
	for _, want := range []string{
		`role="client"`,
		`compress_proxy_tunnel_connections{service="svc",state="connecting"} 1`,
		`compress_proxy_tunnel_connections{service="svc",state="idle"} 2`,
		`compress_proxy_tunnel_connections{service="svc",state="busy"} 3`,
		`compress_proxy_relay_raw_bytes_total{direction="from_tunnel",service="svc"} 7`,
		`compress_proxy_client_local_dial_failures_total{service="svc"} 1`,
		`compress_proxy_client_dial_failures_total{service="svc"} 4`,
		`compress_proxy_client_registrations_rejected_total{code="invalid_pool",service="svc"} 1`,
		`compress_proxy_client_registrations_rejected_total{code="other",service="svc"} 1`,
		`compress_proxy_client_connections_retired_total{reason="surplus",service="svc"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, unwanted := range []string{"compress_proxy_server_", `outcome="client_close"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("client exposes %s", unwanted)
		}
	}
	if problems, e := testutil.GatherAndLint(x.reg); e != nil || len(problems) > 0 {
		t.Fatalf("lint: %v %v", e, problems)
	}
}

// Exporters use private registries, so a process (or test binary) can hold
// several with the same service names without registration conflicts.
func TestExportersAreIndependent(t *testing.T) {
	a := NewServer([]string{"svc"}, map[string]*pool.Pool{"svc": pool.New(1)})
	b := NewServer([]string{"svc"}, map[string]*pool.Pool{"svc": pool.New(1)})
	a.Service("svc").Visitors.Add(1)
	if !strings.Contains(scrape(t, b.Handler(testCfg, testLog), "GET", "/metrics", "prom", "correct horse battery").Body.String(), `compress_proxy_server_visitors_total{service="svc"} 0`) {
		t.Fatal("exporters share state")
	}
	var nilExporter *Exporter
	nilExporter.Service("svc").LeaseDone(LeaseOK, time.Second)
	nilExporter.Rejected("authentication_failed")
}

func TestServeStopsOnCancel(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	x := NewClient([]string{"svc"}, func() map[string]Slots { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.Serve(ctx, ln, testCfg, testLog) }()
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/metrics", nil)
	req.SetBasicAuth("prom", "correct horse battery")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "compress_proxy_build_info") {
		t.Fatalf("scrape: %d", resp.StatusCode)
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if _, e = net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond); e == nil {
		t.Fatal("listener still open")
	}
}
