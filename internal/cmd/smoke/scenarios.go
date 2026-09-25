package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

func scenarios(ctx context.Context, binary, kind string) error {
	if e := basicScenarios(ctx, binary, kind); e != nil {
		return e
	}
	if e := poolGrowth(ctx, binary, kind); e != nil {
		return fmt.Errorf("pool-growth: %w", e)
	}
	pass(kind, "pool-growth")
	if e := idleExpiry(ctx, binary, kind); e != nil {
		return fmt.Errorf("idle-expiry: %w", e)
	}
	pass(kind, "idle-expiry")
	if e := maxLifetime(ctx, binary, kind); e != nil {
		return fmt.Errorf("max-lifetime: %w", e)
	}
	pass(kind, "max-lifetime")
	if e := authentication(ctx, binary, kind); e != nil {
		return fmt.Errorf("authentication: %w", e)
	}
	pass(kind, "authentication")
	if e := shutdownScenarios(ctx, binary, kind); e != nil {
		return fmt.Errorf("shutdown: %w", e)
	}
	pass(kind, "shutdown")
	return nil
}
func basicScenarios(ctx context.Context, binary, kind string) error {
	// A short heartbeat lets the server notice a stopped client quickly:
	// idle connections are only probed by heartbeats.
	pool := steady(1, 2)
	pool.heartbeat = "1s"
	s, e := newScene(ctx, binary, kind, pool, "400ms", map[string]string{"echo": "echo", "digest": "digest", "hold": "hold", "tagA": "tagA", "tagB": "tagB", "flaky": "echo"})
	if e != nil {
		return e
	}
	defer s.close()
	if e = s.start(); e != nil {
		return e
	}
	if e = echo(s, "echo", []byte("x")); e != nil {
		return fmt.Errorf("small-message: %w", e)
	}
	pass(kind, "small-message")
	data := bytes.Repeat([]byte("whole megabyte"), ((1<<20)/14)+1)
	data = data[:1<<20]
	if e = digest(s, data); e != nil {
		return fmt.Errorf("half-close: %w", e)
	}
	if e = digest(s, nil); e != nil {
		return fmt.Errorf("empty half-close: %w", e)
	}
	pass(kind, "half-close")
	for i := range 100 {
		if e = digest(s, []byte(fmt.Sprintf("serial lease %03d different content", i))); e != nil {
			return fmt.Errorf("serial-reuse #%d: %w", i, e)
		}
	}
	if e = s.assertReuse("digest", 102); e != nil {
		return e
	}
	pass(kind, "serial-reuse")
	// With no client connected, a visitor waits acquire_timeout and is closed.
	if e = s.stopClient(); e != nil {
		return e
	}
	waiting, e := s.connect("hold")
	if e != nil {
		return e
	}
	started := time.Now()
	_ = waiting.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	_, e = waiting.Read(one[:])
	_ = waiting.Close()
	if !errors.Is(e, io.EOF) {
		return fmt.Errorf("acquire-timeout expected EOF: %w", e)
	}
	if elapsed := time.Since(started); elapsed < 300*time.Millisecond {
		return fmt.Errorf("visitor closed after %v, before acquire_timeout", elapsed)
	}
	if e = s.restartClient(); e != nil {
		return e
	}
	if e = echo(s, "echo", []byte("after client restart")); e != nil {
		return e
	}
	pass(kind, "acquire-timeout")
	for _, name := range []string{"tagA", "tagB"} {
		c, err := s.connect(name)
		if err != nil {
			return err
		}
		_ = c.CloseWrite()
		b, err := io.ReadAll(c)
		_ = c.Close()
		if err != nil || string(b) != name {
			return fmt.Errorf("service isolation %s: %q %v", name, b, err)
		}
	}
	pass(kind, "service-isolation")
	old := s.fixtures["flaky"]
	addr := old.addr()
	old.close()
	c, e := s.connect("flaky")
	if e != nil {
		return e
	}
	_, e = io.ReadAll(c)
	_ = c.Close()
	if e != nil {
		return e
	}
	f, e := startFixture("echo", addr)
	if e != nil {
		return e
	}
	s.fixtures["flaky"] = f
	if e = echo(s, "flaky", []byte("restored")); e != nil {
		return e
	}
	if e = s.assertReuse("flaky", 2); e != nil {
		return e
	}
	pass(kind, "local-dial-failure")
	c, e = s.connect("hold")
	if e != nil {
		return e
	}
	defer c.Close()
	h, e := s.fixtures["hold"].next(ctx, 2*time.Second)
	if e != nil {
		return e
	}
	s.server.signal(os.Kill)
	_ = s.server.wait(2 * time.Second)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, e = c.Read(one[:])
	if e == nil {
		return errors.New("old lease survived server death")
	}
	close(h.release)
	if e = s.restartServer(); e != nil {
		return e
	}
	if e = echo(s, "echo", []byte("after restart")); e != nil {
		return e
	}
	pass(kind, "server-restart")
	if e = s.stopIdle(); e != nil {
		return e
	}
	pass(kind, "shutdown-idle")
	return nil
}
func echo(s *scene, name string, data []byte) error {
	c, e := s.connect(name)
	if e != nil {
		return e
	}
	defer c.Close()
	if _, e = c.Write(data); e != nil {
		return e
	}
	b := make([]byte, len(data))
	if _, e = io.ReadFull(c, b); e != nil {
		return e
	}
	if !bytes.Equal(b, data) {
		return errors.New("echo mismatch")
	}
	_ = c.CloseWrite()
	_, e = io.ReadAll(c)
	return e
}
func digest(s *scene, data []byte) error {
	c, e := s.connect("digest")
	if e != nil {
		return e
	}
	defer c.Close()
	if len(data) > 0 {
		if _, e = c.Write(data); e != nil {
			return e
		}
	}
	if e = c.CloseWrite(); e != nil {
		return e
	}
	b, e := io.ReadAll(c)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(data)
	expected := fmt.Sprintf("SHA256:%x\n", sum)
	if string(b) != expected {
		return fmt.Errorf("SHA mismatch %q != %q", b, expected)
	}
	return nil
}

// countEvents counts server events for a service matching event and,
// when reason is set, the close reason.
func countEvents(s *scene, service, name, reason string) int {
	n := 0
	for _, ev := range s.server.events() {
		if ev["service"] == service && ev["event"] == name && (reason == "" || ev["reason"] == reason) {
			n++
		}
	}
	return n
}

// poolGrowth: busy connections are replaced so the pool keeps min_idle idle
// connections, and connections beyond max_idle are closed on release.
func poolGrowth(ctx context.Context, binary, kind string) error {
	s, e := newScene(ctx, binary, kind, steady(1, 2), "3s", map[string]string{"hold": "hold"})
	if e != nil {
		return e
	}
	defer s.close()
	if e = s.start(); e != nil {
		return e
	}
	c := make([]*net.TCPConn, 3)
	h := make([]*held, 3)
	for i := range 3 {
		c[i], e = s.connect("hold")
		if e != nil {
			return e
		}
		defer c[i].Close()
		h[i], e = s.fixtures["hold"].next(ctx, 3*time.Second)
		if e != nil {
			return fmt.Errorf("visitor %d not served: %w", i+1, e)
		}
	}
	for i := range 3 {
		_ = c[i].CloseWrite()
		close(h[i].release)
		var b [1]byte
		if _, e = io.ReadFull(c[i], b[:]); e != nil {
			return e
		}
		if _, e = io.ReadAll(c[i]); e != nil {
			return e
		}
	}
	if e = s.awaitFinished("hold", 3); e != nil {
		return e
	}
	seen := make(map[any]bool)
	for _, ev := range s.server.events() {
		if ev["event"] == "lease_started" {
			seen[ev["connection_id"]] = true
		}
	}
	if len(seen) != 3 {
		return fmt.Errorf("3 concurrent leases used %d connections", len(seen))
	}
	if _, e = s.server.waitEvent(ctx, 3*time.Second, func(event) bool { return countEvents(s, "hold", "connection_closed", "client_close") >= 2 }); e != nil {
		return fmt.Errorf("surplus idle connections not closed: %w", e)
	}
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	if n := countEvents(s, "hold", "connection_closed", "client_close"); n != 2 {
		return fmt.Errorf("%d surplus closes, want 2", n)
	}
	return echoHold(s)
}

// echoHold proves the hold service still serves after pool changes.
func echoHold(s *scene) error {
	c, e := s.connect("hold")
	if e != nil {
		return e
	}
	defer c.Close()
	h, e := s.fixtures["hold"].next(s.ctx, 3*time.Second)
	if e != nil {
		return e
	}
	_ = c.CloseWrite()
	close(h.release)
	var b [1]byte
	if _, e = io.ReadFull(c, b[:]); e != nil {
		return e
	}
	_, e = io.ReadAll(c)
	return e
}

// idleExpiry: an unused connection is closed after idle_timeout plus jitter
// and replaced, without disturbing service.
func idleExpiry(ctx context.Context, binary, kind string) error {
	pool := steady(1, 1)
	pool.idle, pool.idleJitter = "1s", "300ms"
	s, e := newScene(ctx, binary, kind, pool, "2s", map[string]string{"echo": "echo"})
	if e != nil {
		return e
	}
	defer s.close()
	if e = s.start(); e != nil {
		return e
	}
	started := time.Now()
	if _, e = s.server.waitEvent(ctx, 3*time.Second, func(event) bool { return countEvents(s, "echo", "connection_closed", "expired") >= 1 }); e != nil {
		return fmt.Errorf("idle connection not expired: %w", e)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond {
		return fmt.Errorf("expired after %v, before idle_timeout", elapsed)
	}
	if _, e = s.server.waitEvent(ctx, 3*time.Second, func(event) bool { return s.readyCount("echo") >= 2 }); e != nil {
		return fmt.Errorf("expired connection not replaced: %w", e)
	}
	return echo(s, "echo", []byte("after idle expiry"))
}

// maxLifetime: a connection that is always busy still retires once it
// outlives max_lifetime, and traffic moves to a newer connection.
func maxLifetime(ctx context.Context, binary, kind string) error {
	pool := steady(1, 2)
	pool.lifetime = "2s"
	s, e := newScene(ctx, binary, kind, pool, "2s", map[string]string{"echo": "echo"})
	if e != nil {
		return e
	}
	defer s.close()
	if e = s.start(); e != nil {
		return e
	}
	for until := time.Now().Add(4 * time.Second); time.Now().Before(until); {
		if e = echo(s, "echo", []byte("lifetime")); e != nil {
			return fmt.Errorf("lease failed during rotation: %w", e)
		}
	}
	if countEvents(s, "echo", "connection_closed", "expired") == 0 {
		return errors.New("no connection retired by max_lifetime")
	}
	seen := map[any]bool{}
	for _, ev := range s.server.events() {
		if ev["event"] == "lease_started" {
			seen[ev["connection_id"]] = true
		}
	}
	if len(seen) < 2 {
		return fmt.Errorf("leases stayed on %d connection", len(seen))
	}
	return nil
}
func authentication(ctx context.Context, binary, kind string) error {
	variants := []string{"token", "unknown-service"}
	if kind == "noise" {
		variants = append(variants, "client-pin", "server-pin")
	} else {
		variants = append(variants, "ca", "hostname")
	}
	for _, variant := range variants {
		for attempt := range 3 {
			err := authenticationVariant(ctx, binary, kind, variant)
			if err == nil {
				break
			}
			if !strings.Contains(err.Error(), "address already in use") || attempt == 2 {
				return err
			}
		}
	}
	return nil
}
func authenticationVariant(ctx context.Context, binary, kind, variant string) error {
	s, e := newScene(ctx, binary, kind, steady(1, 2), "400ms", map[string]string{"echo": "echo"})
	if e != nil {
		return e
	}
	defer s.close()
	if variant == "ca" {
		if e = s.wrongCA(); e != nil {
			return e
		}
	}
	var token, pin, trust string
	switch variant {
	case "token":
		token = strings.Repeat("w", 48)
	case "server-pin":
		k, err := generateKey(ctx, binary)
		if err != nil {
			return err
		}
		pin = k.Public
	case "client-pin":
		trust = "pin"
	case "ca", "hostname":
		trust = variant
	}
	if e = s.writeConfigs(token, pin, trust); e != nil {
		return e
	}
	if variant == "unknown-service" {
		data, err := os.ReadFile(s.clientFile)
		if err != nil {
			return err
		}
		changed := strings.Replace(string(data), "[client.services.echo]", "[client.services.missing]", 1)
		if changed == string(data) {
			return errors.New("missing client service table")
		}
		if err = os.WriteFile(s.clientFile, []byte(changed), 0600); err != nil {
			return err
		}
		if err = check(ctx, binary, s.clientFile); err != nil {
			return err
		}
	}
	s.server, e = startProcess(ctx, binary, "server", "-c", s.serverFile)
	if e != nil {
		return e
	}
	if _, e = s.server.waitEvent(ctx, 4*time.Second, func(ev event) bool { return ev["event"] == "server_listening" && ev["service"] == "echo" }); e != nil {
		return e
	}
	s.client, e = startProcess(ctx, binary, "client", "-c", s.clientFile)
	if e != nil {
		return e
	}
	select {
	case <-time.After(600 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	if e = missingEvent(s, "pool_ready"); e != nil {
		return fmt.Errorf("%s: %w", variant, e)
	}
	if variant == "token" || variant == "unknown-service" {
		if _, err := s.server.waitEvent(ctx, 2*time.Second, func(ev event) bool {
			return ev["event"] == "registration_rejected" && ev["code"] == "authentication_failed"
		}); err != nil {
			return err
		}
	}
	c, e := s.connect("echo")
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, e = c.Read(b[:])
	if !errors.Is(e, io.EOF) {
		return fmt.Errorf("%s unexpectedly reached service: %v", variant, e)
	}
	return nil
}
func shutdownScenarios(ctx context.Context, binary, kind string) error {
	for _, hung := range []bool{false, true} {
		s, e := newScene(ctx, binary, kind, steady(1, 2), "1s", map[string]string{"hold": "hold"})
		if e != nil {
			return e
		}
		if e = s.start(); e != nil {
			s.close()
			return e
		}
		c, e := s.connect("hold")
		if e != nil {
			s.close()
			return e
		}
		h, e := s.fixtures["hold"].next(ctx, 2*time.Second)
		if e != nil {
			s.close()
			return e
		}
		started := time.Now()
		s.server.signal(syscall.SIGTERM)
		if !hung {
			_ = c.CloseWrite()
			close(h.release)
			var b [1]byte
			if _, e = io.ReadFull(c, b[:]); e != nil {
				s.close()
				return e
			}
			if _, e = io.ReadAll(c); e != nil {
				s.close()
				return e
			}
		}
		e = s.server.wait(33 * time.Second)
		if e != nil {
			s.close()
			return e
		}
		s.server = nil
		if hung {
			if elapsed := time.Since(started); elapsed < 29*time.Second || elapsed > 33*time.Second {
				s.close()
				return fmt.Errorf("drain duration %v", elapsed)
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, e = c.Read(b[:]); e == nil {
				s.close()
				return errors.New("hung lease not closed")
			}
			close(h.release)
		}
		_ = c.Close()
		s.close()
	}
	return nil
}
