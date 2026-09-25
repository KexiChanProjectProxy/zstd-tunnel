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
	if e := poolCapacity(ctx, binary, kind); e != nil {
		return fmt.Errorf("pool-capacity: %w", e)
	}
	pass(kind, "pool-capacity")
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
	s, e := newScene(ctx, binary, kind, 1, "400ms", map[string]string{"echo": "echo", "digest": "digest", "hold": "hold", "tagA": "tagA", "tagB": "tagB", "flaky": "echo"})
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
	if e = s.awaitFinished("digest", 102); e != nil {
		return e
	}
	if e = s.assertUnique("digest", 102); e != nil {
		return e
	}
	pass(kind, "serial-reuse")
	first, e := s.connect("hold")
	if e != nil {
		return e
	}
	defer first.Close()
	h, e := s.fixtures["hold"].next(ctx, 2*time.Second)
	if e != nil {
		return e
	}
	second, e := s.connect("hold")
	if e != nil {
		return e
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	_, e = second.Read(one[:])
	if !errors.Is(e, io.EOF) {
		return fmt.Errorf("acquire-timeout expected EOF: %w", e)
	}
	_ = first.CloseWrite()
	close(h.release)
	if _, e = io.ReadFull(first, one[:]); e != nil || one[0] != 'h' {
		return fmt.Errorf("active lease damaged: %v", e)
	}
	if _, e = io.ReadAll(first); e != nil {
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
	if e = s.awaitFinished("flaky", 2); e != nil {
		return e
	}
	if e = s.assertUnique("flaky", 2); e != nil {
		return e
	}
	pass(kind, "local-dial-failure")
	c, e = s.connect("hold")
	if e != nil {
		return e
	}
	defer c.Close()
	h, e = s.fixtures["hold"].next(ctx, 2*time.Second)
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
func poolCapacity(ctx context.Context, binary, kind string) error {
	s, e := newScene(ctx, binary, kind, 2, "3s", map[string]string{"hold": "hold"})
	if e != nil {
		return e
	}
	defer s.close()
	if e = s.start(); e != nil {
		return e
	}
	c := make([]*net.TCPConn, 3)
	h := make([]*held, 3)
	for i := range 2 {
		c[i], e = s.connect("hold")
		if e != nil {
			return e
		}
		defer c[i].Close()
		h[i], e = s.fixtures["hold"].next(ctx, 2*time.Second)
		if e != nil {
			return e
		}
	}
	c[2], e = s.connect("hold")
	if e != nil {
		return e
	}
	defer c[2].Close()
	select {
	case <-s.fixtures["hold"].arrival:
		return errors.New("third entered occupied pool")
	case <-time.After(200 * time.Millisecond):
	}
	_ = c[0].CloseWrite()
	close(h[0].release)
	var b [1]byte
	if _, e = io.ReadFull(c[0], b[:]); e != nil {
		return e
	}
	if _, e = io.ReadAll(c[0]); e != nil {
		return e
	}
	h[2], e = s.fixtures["hold"].next(ctx, 3*time.Second)
	if e != nil {
		return e
	}
	for i := 1; i <= 2; i++ {
		_ = c[i].CloseWrite()
		close(h[i].release)
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
	if len(seen) > 2 {
		return fmt.Errorf("pool created %d connections", len(seen))
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
	s, e := newScene(ctx, binary, kind, 1, "400ms", map[string]string{"echo": "echo"})
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
		s, e := newScene(ctx, binary, kind, 1, "1s", map[string]string{"hold": "hold"})
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
