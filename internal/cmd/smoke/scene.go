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
	pool                                                     poolSpec
	timeout                                                  string
	// Every scene enables the metrics endpoint on both processes.
	serverMetrics, clientMetrics, metricsUser, metricsPass string
}

// poolSpec is the [client.pool] table a scene writes.
type poolSpec struct {
	min, max                                              int
	heartbeat, idle, idleJitter, lifetime, lifetimeJitter string
}

// steady keeps connections alive for the whole scene so that connection
// reuse is observable.
func steady(min, max int) poolSpec {
	return poolSpec{min: min, max: max, heartbeat: "15s", idle: "10m", idleJitter: "0s", lifetime: "1h", lifetimeJitter: "0s"}
}

func newScene(ctx context.Context, binary, kind string, pool poolSpec, timeout string, modes map[string]string) (_ *scene, err error) {
	s := &scene{ctx: ctx, binary: binary, kind: kind, pool: pool, timeout: timeout, public: make(map[string]string), fixtures: make(map[string]*fixture)}
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
	if e = s.allocateAddrs(); e != nil {
		return nil, e
	}
	password := make([]byte, 24)
	if _, e = rand.Read(password); e != nil {
		return nil, e
	}
	s.metricsUser, s.metricsPass = "prom", base64.StdEncoding.EncodeToString(password)
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

// allocateAddrs picks the tunnel and metrics listen addresses.
func (s *scene) allocateAddrs() error {
	for _, dst := range []*string{&s.tunnel, &s.serverMetrics, &s.clientMetrics} {
		addr, e := freeAddr()
		if e != nil {
			return e
		}
		*dst = addr
	}
	return nil
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
	server += fmt.Sprintf("[server.pool]\nmax_pending=64\nacquire_timeout=%s\n", quote(s.timeout))
	pl := s.pool
	client += fmt.Sprintf("[client.pool]\nmin_idle=%d\nmax_idle=%d\nheartbeat=%s\nidle_timeout=%s\nidle_jitter=%s\nmax_lifetime=%s\nlifetime_jitter=%s\n", pl.min, pl.max, quote(pl.heartbeat), quote(pl.idle), quote(pl.idleJitter), quote(pl.lifetime), quote(pl.lifetimeJitter))
	server += fmt.Sprintf("[server.metrics]\nbind_addr=%s\nusername=%s\npassword=%s\n", quote(s.serverMetrics), quote(s.metricsUser), quote(s.metricsPass))
	client += fmt.Sprintf("[client.metrics]\nbind_addr=%s\nusername=%s\npassword=%s\n", quote(s.clientMetrics), quote(s.metricsUser), quote(s.metricsPass))
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
		if s.client != nil {
			_ = s.client.wait(time.Second)
			s.client = nil
		}
		if e := s.allocateAddrs(); e != nil {
			return e
		}
		if e := s.writeConfigs("", "", ""); e != nil {
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
			// Include the client's stderr so a client bind failure is
			// recognised and retried by start.
			return fmt.Errorf("%w; client stderr: %s", e, s.client.output())
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
func (s *scene) readyCount(name string) int {
	n := 0
	for _, ev := range s.server.events() {
		if ev["event"] == "pool_ready" && ev["service"] == name {
			n++
		}
	}
	return n
}

// stopClient terminates the client and waits until the server has closed
// every tunnel connection it had registered.
func (s *scene) stopClient() error {
	s.client.signal(syscall.SIGTERM)
	if e := s.client.wait(5 * time.Second); e != nil {
		return e
	}
	s.client = nil
	_, e := s.server.waitEvent(s.ctx, 5*time.Second, func(event) bool {
		open := map[any]bool{}
		for _, ev := range s.server.events() {
			switch ev["event"] {
			case "pool_ready":
				open[ev["connection_id"]] = true
			case "connection_closed":
				delete(open, ev["connection_id"])
			}
		}
		return len(open) == 0
	})
	return e
}
func (s *scene) restartClient() error {
	before := map[string]int{}
	for name := range s.fixtures {
		before[name] = s.readyCount(name)
	}
	var e error
	s.client, e = startProcess(s.ctx, s.binary, "client", "-c", s.clientFile)
	if e != nil {
		return e
	}
	for name := range s.fixtures {
		if _, e = s.server.waitEvent(s.ctx, 5*time.Second, func(event) bool { return s.readyCount(name) > before[name] }); e != nil {
			return e
		}
	}
	return nil
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

// assertReuse checks that serial leases were carried by a small number of
// long-lived tunnel connections, that lease IDs on each connection run
// 1,2,3..., and that no connection started a lease before its previous
// lease passed the release barrier.
func (s *scene) assertReuse(name string, leases int) error {
	if e := s.awaitFinished(name, leases); e != nil {
		return e
	}
	type conn struct {
		last          float64
		leases        int
		awaitingReady bool
	}
	conns := map[float64]*conn{}
	started, finished := 0, 0
	for _, ev := range s.server.events() {
		if ev["service"] != name {
			continue
		}
		id, _ := ev["connection_id"].(float64)
		c := conns[id]
		if c == nil {
			c = &conn{}
			conns[id] = c
		}
		switch ev["event"] {
		case "pool_ready":
			c.awaitingReady = false
		case "lease_started":
			lease, _ := ev["lease_id"].(float64)
			if c.awaitingReady {
				return fmt.Errorf("connection %.0f lease %.0f started before prior release barrier", id, lease)
			}
			if lease != c.last+1 {
				return fmt.Errorf("connection %.0f lease id %.0f after %.0f", id, lease, c.last)
			}
			c.last = lease
			c.leases++
			started++
		case "lease_finished":
			finished++
			c.awaitingReady = true
		}
	}
	used := 0
	for _, c := range conns {
		if c.leases > 0 {
			used++
		}
	}
	if started != leases || finished != leases {
		return fmt.Errorf("lease log counts started=%d finished=%d expected %d", started, finished, leases)
	}
	if used > 2 {
		return fmt.Errorf("%d serial leases used %d tunnel connections", leases, used)
	}
	fmt.Printf("evidence %s leases=%d connections=%d\n", name, leases, used)
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
