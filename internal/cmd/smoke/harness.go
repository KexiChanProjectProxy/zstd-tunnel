package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type event map[string]any
type process struct {
	cmd     *exec.Cmd
	mu      sync.Mutex
	logs    []event
	stderr  bytes.Buffer
	partial []byte
	notify  chan struct{}
	done    chan error
}

func startProcess(ctx context.Context, binary string, args ...string) (*process, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	p := &process{cmd: cmd, notify: make(chan struct{}, 1), done: make(chan error, 1)}
	cmd.Stderr = p
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	go func() { p.done <- cmd.Wait() }()
	return p, nil
}
func (p *process) Write(data []byte) (int, error) {
	p.mu.Lock()
	p.partial = append(p.partial, data...)
	notified := false
	for {
		idx := bytes.IndexByte(p.partial, '\n')
		if idx < 0 {
			break
		}
		line := p.partial[:idx]
		p.stderr.Write(line)
		p.stderr.WriteByte('\n')
		var item event
		if json.Unmarshal(line, &item) == nil {
			p.logs = append(p.logs, item)
		}
		p.partial = p.partial[idx+1:]
		notified = true
	}
	p.mu.Unlock()
	if notified {
		select {
		case p.notify <- struct{}{}:
		default:
		}
	}
	return len(data), nil
}
func (p *process) events() []event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]event(nil), p.logs...)
}
func (p *process) waitEvent(ctx context.Context, timeout time.Duration, pred func(event) bool) (event, error) {
	limit := time.NewTimer(timeout)
	defer limit.Stop()
	for {
		for _, ev := range p.events() {
			if pred(ev) {
				return ev, nil
			}
		}
		select {
		case <-p.notify:
		case <-limit.C:
			return nil, fmt.Errorf("event timeout; stderr: %s", p.output())
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
func (p *process) output() string { p.mu.Lock(); defer p.mu.Unlock(); return p.stderr.String() }
func (p *process) signal(sig os.Signal) {
	if p != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(sig)
	}
}
func (p *process) wait(timeout time.Duration) error {
	select {
	case e := <-p.done:
		return e
	case <-time.After(timeout):
		p.signal(os.Kill)
		select {
		case <-p.done:
		default:
		}
		return errors.New("process exit timeout: " + p.output())
	}
}
func freeAddr() (string, error) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return "", e
	}
	addr := l.Addr().String()
	return addr, l.Close()
}

type held struct{ release chan struct{} }
type fixture struct {
	ln       net.Listener
	mode     string
	arrival  chan *held
	stopped  chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
	active   map[net.Conn]struct{}
}

func startFixture(mode, address string) (*fixture, error) {
	if address == "" {
		var e error
		address, e = freeAddr()
		if e != nil {
			return nil, e
		}
	}
	ln, e := net.Listen("tcp", address)
	if e != nil {
		return nil, e
	}
	f := &fixture{ln: ln, mode: mode, arrival: make(chan *held, 16), stopped: make(chan struct{}), active: make(map[net.Conn]struct{})}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			f.mu.Lock()
			f.active[c] = struct{}{}
			f.mu.Unlock()
			go f.handle(c)
		}
	}()
	return f, nil
}
func (f *fixture) handle(c net.Conn) {
	defer func() { _ = c.Close(); f.mu.Lock(); delete(f.active, c); f.mu.Unlock() }()
	switch f.mode {
	case "echo":
		_, _ = io.Copy(c, c)
	case "digest":
		h := sha256.New()
		_, _ = io.Copy(h, c)
		_, _ = fmt.Fprintf(c, "SHA256:%x\n", h.Sum(nil))
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	case "hold":
		control := &held{release: make(chan struct{})}
		f.arrival <- control
		select {
		case <-control.release:
		case <-f.stopped:
			return
		}
		_, _ = c.Write([]byte("h"))
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	case "tagA", "tagB":
		_, _ = c.Write([]byte(f.mode))
		_, _ = io.Copy(io.Discard, c)
	}
}
func (f *fixture) addr() string { return f.ln.Addr().String() }
func (f *fixture) close() {
	f.stopOnce.Do(func() { close(f.stopped); _ = f.ln.Close() })
	f.mu.Lock()
	conns := make([]net.Conn, 0, len(f.active))
	for c := range f.active {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}
func (f *fixture) next(ctx context.Context, limit time.Duration) (*held, error) {
	select {
	case h := <-f.arrival:
		return h, nil
	case <-time.After(limit):
		return nil, errors.New("fixture arrival timeout")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type keyPair struct {
	Private string `json:"private_key"`
	Public  string `json:"public_key"`
}

func generateKey(ctx context.Context, binary string) (keyPair, error) {
	b, e := exec.CommandContext(ctx, binary, "keygen").Output()
	var k keyPair
	if e == nil {
		e = json.Unmarshal(b, &k)
	}
	if e == nil {
		a, x := base64.StdEncoding.DecodeString(k.Private)
		b, y := base64.StdEncoding.DecodeString(k.Public)
		if x != nil || y != nil || len(a) != 32 || len(b) != 32 {
			e = errors.New("invalid keygen result")
		}
	}
	return k, e
}
func createCertificate(dir string) error {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smoke CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		return e
	}
	der, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		return e
	}
	for name, data := range map[string][]byte{"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), "server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), "server.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})} {
		if e = os.WriteFile(filepath.Join(dir, name), data, 0600); e != nil {
			return e
		}
	}
	_, e = tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	return e
}
func quote(s string) string { b, _ := json.Marshal(s); return string(b) }
func check(ctx context.Context, binary, path string) error {
	out, e := exec.CommandContext(ctx, binary, "check", "-c", path).CombinedOutput()
	if e != nil {
		return fmt.Errorf("check %s: %w: %s", filepath.Base(path), e, out)
	}
	if strings.TrimSpace(string(out)) != "configuration valid" {
		return fmt.Errorf("unexpected check output: %q", out)
	}
	return nil
}
