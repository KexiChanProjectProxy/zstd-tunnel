package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type scene struct {
	ctx                                                      context.Context
	binary, kind, dir, tunnel, serverFile, clientFile, token string
	public                                                   map[string]string
	fixtures                                                 map[string]*fixture
	server, client                                           *process
	serverKey, clientKey                                     keyPair
	size                                                     int
	timeout                                                  string
}

func newScene(ctx context.Context, binary, kind string, size int, timeout string, modes map[string]string) (_ *scene, err error) {
	s := &scene{ctx: ctx, binary: binary, kind: kind, size: size, timeout: timeout, public: make(map[string]string), fixtures: make(map[string]*fixture)}
	dir, e := os.MkdirTemp("", "compress-proxy-smoke-")
	if e != nil {
		return nil, e
	}
	s.dir = dir
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	for name, mode := range modes {
		f, err := startFixture(mode, "")
		if err != nil {
			return nil, err
		}
		s.fixtures[name] = f
		addr, err := freeAddr()
		if err != nil {
			return nil, err
		}
		s.public[name] = addr
	}
	s.tunnel, e = freeAddr()
	if e != nil {
		return nil, e
	}
	s.serverKey, e = generateKey(ctx, binary)
	if e != nil {
		return nil, e
	}
	s.clientKey, e = generateKey(ctx, binary)
	if e != nil {
		return nil, e
	}
	token := make([]byte, 48)
	if _, e = rand.Read(token); e != nil {
		return nil, e
	}
	s.token = base64.StdEncoding.EncodeToString(token)
	if kind == "wss" {
		if e = createCertificate(dir); e != nil {
			return nil, e
		}
	}
	s.serverFile = filepath.Join(dir, "server.toml")
	s.clientFile = filepath.Join(dir, "client.toml")
	e = s.writeConfigs("", "", "")
	return s, e
}
func (s *scene) writeConfigs(tokenOverride, clientKeyOverride, trustOverride string) error {
	clientToken := s.token
	if tokenOverride != "" {
		clientToken = tokenOverride
	}
	clientPub := s.clientKey.Public
	if clientKeyOverride != "" {
		clientPub = clientKeyOverride
	}
	server := fmt.Sprintf("[server]\nbind_addr=%s\ndefault_token=%s\n[server.transport]\ntype=%s\n", quote(s.tunnel), quote(s.token), quote(s.kind))
	client := fmt.Sprintf("[client]\nremote_addr=%s\ndial_timeout=\"5s\"\ndefault_token=%s\n[client.transport]\ntype=%s\n", quote(s.tunnel), quote(clientToken), quote(s.kind))
	if s.kind == "noise" {
		clientPin := s.serverKey.Public
		if trustOverride == "pin" {
			wrong, e := generateKey(s.ctx, s.binary)
			if e != nil {
				return e
			}
			clientPin = wrong.Public
		}
		server += fmt.Sprintf("[server.transport.noise]\nlocal_private_key=%s\nremote_public_key=%s\n", quote(s.serverKey.Private), quote(clientPub))
		client += fmt.Sprintf("[client.transport.noise]\nlocal_private_key=%s\nremote_public_key=%s\n", quote(s.clientKey.Private), quote(clientPin))
	} else {
		server += "[server.transport.tls]\ncert_file=\"server.crt\"\nkey_file=\"server.key\"\n"
		ca := "ca.crt"
		hostname := "localhost"
		if trustOverride == "ca" {
			ca = "wrong/ca.crt"
		}
		if trustOverride == "hostname" {
			hostname = "wrong.local"
		}
		client += fmt.Sprintf("[client.transport.tls]\nca_file=%s\nserver_name=%s\n", quote(ca), quote(hostname))
	}
	server += fmt.Sprintf("[server.pool]\nmax_connections=%d\nmax_pending=64\nacquire_timeout=%s\n", s.size, quote(s.timeout))
	client += fmt.Sprintf("[client.pool]\nsize=%d\n", s.size)
	for name, fixture := range s.fixtures {
		server += fmt.Sprintf("[server.services.%s]\nbind_addr=%s\n", name, quote(s.public[name]))
		client += fmt.Sprintf("[client.services.%s]\nlocal_addr=%s\n", name, quote(fixture.addr()))
	}
	if e := os.WriteFile(s.serverFile, []byte(server), 0600); e != nil {
		return e
	}
	if e := os.WriteFile(s.clientFile, []byte(client), 0600); e != nil {
		return e
	}
	if e := check(s.ctx, s.binary, s.serverFile); e != nil {
		return e
	}
	return check(s.ctx, s.binary, s.clientFile)
}
func (s *scene) start() error {
	for attempt := range 3 {
		err := s.startOnce()
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "address already in use") || attempt == 2 {
			return err
		}
		if s.server != nil {
			_ = s.server.wait(time.Second)
			s.server = nil
		}
		for name, f := range s.fixtures {
			mode := f.mode
			f.close()
			next, e := startFixture(mode, "")
			if e != nil {
				return e
			}
			s.fixtures[name] = next
			addr, e := freeAddr()
			if e != nil {
				return e
			}
			s.public[name] = addr
		}
		var e error
		s.tunnel, e = freeAddr()
		if e != nil {
			return e
		}
		if e = s.writeConfigs("", "", ""); e != nil {
			return e
		}
	}
	return errors.New("port allocation failed")
}
func (s *scene) startOnce() error {
	var e error
	s.server, e = startProcess(s.ctx, s.binary, "server", "-c", s.serverFile)
	if e != nil {
		return e
	}
	for name := range s.fixtures {
		if _, e = s.server.waitEvent(s.ctx, 4*time.Second, func(ev event) bool { return ev["event"] == "server_listening" && ev["service"] == name }); e != nil {
			return e
		}
	}
	s.client, e = startProcess(s.ctx, s.binary, "client", "-c", s.clientFile)
	if e != nil {
		return e
	}
	for name := range s.fixtures {
		if _, e = s.server.waitEvent(s.ctx, 5*time.Second, func(ev event) bool { return ev["event"] == "pool_ready" && ev["service"] == name }); e != nil {
			return e
		}
	}
	return nil
}
func (s *scene) restartServer() error {
	var e error
	s.server, e = startProcess(s.ctx, s.binary, "server", "-c", s.serverFile)
	if e != nil {
		return e
	}
	_, e = s.server.waitEvent(s.ctx, 60*time.Second, func(ev event) bool { return ev["event"] == "pool_ready" })
	return e
}
func (s *scene) close() {
	if s.client != nil {
		s.client.signal(syscall.SIGTERM)
	}
	if s.server != nil {
		s.server.signal(syscall.SIGTERM)
	}
	for _, f := range s.fixtures {
		f.close()
	}
	if s.client != nil {
		if e := s.client.wait(32 * time.Second); e != nil {
			fmt.Fprintln(os.Stderr, "client cleanup:", e)
		}
		s.client = nil
	}
	if s.server != nil {
		if e := s.server.wait(32 * time.Second); e != nil {
			fmt.Fprintln(os.Stderr, "server cleanup:", e)
		}
		s.server = nil
	}
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
}
func (s *scene) connect(name string) (*net.TCPConn, error) {
	c, e := net.DialTimeout("tcp", s.public[name], 2*time.Second)
	if e != nil {
		return nil, e
	}
	tcp := c.(*net.TCPConn)
	_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
	return tcp, nil
}
func (s *scene) stopIdle() error {
	if s.client != nil {
		s.client.signal(syscall.SIGTERM)
		if e := s.client.wait(3 * time.Second); e != nil {
			return e
		}
		s.client = nil
	}
	if s.server != nil {
		s.server.signal(syscall.SIGTERM)
		if e := s.server.wait(3 * time.Second); e != nil {
			return e
		}
		s.server = nil
	}
	return nil
}
func (s *scene) assertUnique(name string, leases int) error {
	_, err := s.server.waitEvent(s.ctx, 5*time.Second, func(event) bool {
		count := 0
		for _, ev := range s.server.events() {
			if ev["event"] == "pool_ready" && ev["service"] == name {
				count++
			}
		}
		return count >= leases+1
	})
	if err != nil {
		return err
	}
	events := s.server.events()
	var id float64
	var prev float64
	count, finished, readyAfter := 0, 0, 0
	awaitingReady := false
	for _, ev := range events {
		if ev["service"] != name {
			continue
		}
		switch ev["event"] {
		case "pool_ready":
			if awaitingReady {
				readyAfter++
				awaitingReady = false
			}
		case "lease_started":
			if awaitingReady {
				return fmt.Errorf("lease %d started before prior release barrier", count+1)
			}
			current, _ := ev["connection_id"].(float64)
			lease, _ := ev["lease_id"].(float64)
			if count > 0 && (current != id || lease != prev+1) {
				return fmt.Errorf("lease changed physical connection/id: %v after %v/%v", ev, id, prev)
			}
			id = current
			prev = lease
			count++
		case "lease_finished":
			finished++
			awaitingReady = true
		}
	}
	if count != leases || finished != leases || readyAfter != leases || awaitingReady {
		return fmt.Errorf("lease log counts started=%d finished=%d ready-after-barrier=%d expected %d", count, finished, readyAfter, leases)
	}
	fmt.Printf("evidence %s connection_id=%.0f lease_id=1..%.0f\n", name, id, prev)
	return nil
}
func (s *scene) awaitFinished(name string, count int) error {
	_, e := s.server.waitEvent(s.ctx, 5*time.Second, func(event) bool {
		n := 0
		for _, ev := range s.server.events() {
			if ev["service"] == name && ev["event"] == "lease_finished" {
				n++
			}
		}
		return n >= count
	})
	return e
}
func missingEvent(s *scene, eventName string) error {
	for _, ev := range s.server.events() {
		if ev["event"] == eventName {
			return errors.New("unexpected " + eventName)
		}
	}
	return nil
}
func (s *scene) wrongCA() error {
	dir := filepath.Join(s.dir, "wrong")
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	return createCertificate(dir)
}
