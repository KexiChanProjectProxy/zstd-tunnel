package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// sample is one parsed line of the Prometheus text format.
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

var labelPair = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)

func parseExposition(body []byte) ([]sample, error) {
	var out []sample
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cut := strings.LastIndexByte(line, ' ')
		if cut < 0 {
			return nil, fmt.Errorf("malformed line %q", line)
		}
		v, e := strconv.ParseFloat(line[cut+1:], 64)
		if e != nil {
			return nil, fmt.Errorf("malformed value in %q", line)
		}
		series := line[:cut]
		s := sample{name: series, labels: map[string]string{}, value: v}
		if i := strings.IndexByte(series, '{'); i >= 0 {
			s.name = series[:i]
			for _, m := range labelPair.FindAllStringSubmatch(series[i:], -1) {
				s.labels[m[1]] = m[2]
			}
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// value returns the sample with the given name whose labels include all of
// the given "key=value" pairs.
func value(samples []sample, name string, labels ...string) (float64, bool) {
next:
	for _, s := range samples {
		if s.name != name {
			continue
		}
		for _, kv := range labels {
			k, v, _ := strings.Cut(kv, "=")
			if s.labels[k] != v {
				continue next
			}
		}
		return s.value, true
	}
	return 0, false
}

func (s *scene) request(method, addr, path, user, pass string) (*http.Response, []byte, error) {
	req, e := http.NewRequestWithContext(s.ctx, method, "http://"+addr+path, nil)
	if e != nil {
		return nil, nil, e
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, e := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if e != nil {
		return nil, nil, e
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(resp.Body)
	return resp, body, e
}

func (s *scene) scrape(addr string) ([]sample, error) {
	resp, body, e := s.request("GET", addr, "/metrics", s.metricsUser, s.metricsPass)
	if e != nil {
		return nil, e
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scrape status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		return nil, fmt.Errorf("scrape content type %q", ct)
	}
	return parseExposition(body)
}

// expectation checks one series against a bound.
type expectation struct {
	name   string
	labels []string
	check  func(float64) bool
	want   string
}

func atLeast(n float64) (func(float64) bool, string) {
	return func(v float64) bool { return v >= n }, fmt.Sprintf(">= %g", n)
}

func expect(name string, bound float64, labels ...string) expectation {
	c, w := atLeast(bound)
	return expectation{name: name, labels: labels, check: c, want: w}
}

// awaitMetrics scrapes addr until every expectation holds. Counters are
// updated just after the events the scenario waits for, so a scrape may
// briefly lag behind.
func (s *scene) awaitMetrics(addr string, exps []expectation) ([]sample, error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		samples, e := s.scrape(addr)
		if e != nil {
			return nil, e
		}
		var failed []string
		for _, x := range exps {
			v, ok := value(samples, x.name, x.labels...)
			if !ok {
				failed = append(failed, fmt.Sprintf("%s%v missing", x.name, x.labels))
			} else if !x.check(v) {
				failed = append(failed, fmt.Sprintf("%s%v = %g, want %s", x.name, x.labels, v, x.want))
			}
		}
		if len(failed) == 0 {
			return samples, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New(strings.Join(failed, "; "))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// checkAuth verifies that the endpoint at addr refuses unauthenticated and
// malformed requests.
func (s *scene) checkAuth(addr string) error {
	for _, c := range []struct {
		name, method, path, user, pass string
		code                           int
	}{
		{"no credentials", "GET", "/metrics", "", "", 401},
		{"wrong password", "GET", "/metrics", s.metricsUser, s.metricsPass + "x", 401},
		{"wrong user", "GET", "/metrics", "admin", s.metricsPass, 401},
		{"other path", "GET", "/", s.metricsUser, s.metricsPass, 404},
		{"post", "POST", "/metrics", s.metricsUser, s.metricsPass, 405},
	} {
		resp, body, e := s.request(c.method, addr, c.path, c.user, c.pass)
		if e != nil {
			return fmt.Errorf("%s: %w", c.name, e)
		}
		if resp.StatusCode != c.code {
			return fmt.Errorf("%s: status %d, want %d", c.name, resp.StatusCode, c.code)
		}
		if c.code == 401 && !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic ") {
			return fmt.Errorf("%s: missing WWW-Authenticate", c.name)
		}
		if bytes.Contains(body, []byte("compress_proxy_")) {
			return fmt.Errorf("%s: metrics in refused response", c.name)
		}
	}
	return nil
}

// metricsScenario drives traffic through both processes and checks what
// their /metrics endpoints report.
func metricsScenario(ctx context.Context, binary, kind string) error {
	s, e := newScene(ctx, binary, kind, steady(1, 2), "2s", map[string]string{"echo": "echo", "digest": "digest", "flaky": "echo"})
	if e != nil {
		return e
	}
	defer s.close()
	if e = s.start(); e != nil {
		return e
	}
	for _, p := range []*process{s.server, s.client} {
		if _, e = p.waitEvent(ctx, 3*time.Second, func(ev event) bool { return ev["event"] == "metrics_listening" }); e != nil {
			return e
		}
	}
	for _, addr := range []string{s.serverMetrics, s.clientMetrics} {
		if e = s.checkAuth(addr); e != nil {
			return fmt.Errorf("%s: %w", addr, e)
		}
	}
	if e = echo(s, "echo", []byte("metrics")); e != nil {
		return e
	}
	data := bytes.Repeat([]byte("compressible metrics payload "), (1<<20)/29+1)[:1<<20]
	if e = digest(s, data); e != nil {
		return e
	}
	s.fixtures["flaky"].close()
	c, e := s.connect("flaky")
	if e != nil {
		return e
	}
	_, e = io.ReadAll(c)
	_ = c.Close()
	if e != nil {
		return e
	}
	for _, name := range []string{"echo", "digest", "flaky"} {
		if e = s.awaitFinished(name, 1); e != nil {
			return e
		}
	}
	srv, e := s.awaitMetrics(s.serverMetrics, []expectation{
		expect("compress_proxy_build_info", 1, "role=server"),
		expect("compress_proxy_tunnel_connections", 1, "service=echo", "state=idle"),
		expect("compress_proxy_tunnel_connections_opened_total", 1, "service=digest"),
		expect("compress_proxy_server_visitors_total", 1, "service=digest"),
		expect("compress_proxy_relay_raw_bytes_total", 1<<20, "service=digest", "direction=to_tunnel"),
		expect("compress_proxy_relay_compressed_bytes_total", 1, "service=digest", "direction=to_tunnel"),
		expect("compress_proxy_leases_total", 1, "service=digest", "outcome=ok"),
		expect("compress_proxy_leases_total", 1, "service=flaky", "outcome=dial_failed"),
		expect("compress_proxy_lease_duration_seconds_count", 1, "service=digest"),
		expect("compress_proxy_server_pending_visitors", 0, "service=echo"),
		expect("go_goroutines", 1),
		expect("process_cpu_seconds_total", 0),
	})
	if e != nil {
		return fmt.Errorf("server metrics: %w", e)
	}
	cli, e := s.awaitMetrics(s.clientMetrics, []expectation{
		expect("compress_proxy_build_info", 1, "role=client"),
		expect("compress_proxy_tunnel_connections", 1, "service=echo", "state=idle"),
		expect("compress_proxy_relay_raw_bytes_total", 1<<20, "service=digest", "direction=from_tunnel"),
		expect("compress_proxy_leases_total", 1, "service=digest", "outcome=ok"),
		expect("compress_proxy_leases_total", 1, "service=flaky", "outcome=dial_failed"),
		expect("compress_proxy_client_local_dial_failures_total", 1, "service=flaky"),
	})
	if e != nil {
		return fmt.Errorf("client metrics: %w", e)
	}
	raw, _ := value(srv, "compress_proxy_relay_raw_bytes_total", "service=digest", "direction=to_tunnel")
	sent, _ := value(srv, "compress_proxy_relay_compressed_bytes_total", "service=digest", "direction=to_tunnel")
	received, _ := value(cli, "compress_proxy_relay_compressed_bytes_total", "service=digest", "direction=from_tunnel")
	if sent >= raw/10 {
		return fmt.Errorf("compressed %g of %g raw bytes; repetitive payload should shrink tenfold", sent, raw)
	}
	if sent != received {
		return fmt.Errorf("server sent %g compressed bytes, client received %g", sent, received)
	}
	back, _ := value(cli, "compress_proxy_relay_compressed_bytes_total", "service=digest", "direction=to_tunnel")
	got, _ := value(srv, "compress_proxy_relay_compressed_bytes_total", "service=digest", "direction=from_tunnel")
	if back == 0 || back != got {
		return fmt.Errorf("client sent %g compressed bytes, server received %g", back, got)
	}
	fmt.Printf("evidence metrics digest raw=%.0f compressed=%.0f ratio=%.1f\n", raw, sent, raw/sent)
	return nil
}
