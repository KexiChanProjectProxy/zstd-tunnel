package client

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/metrics"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/relay"
)

type failingWriteConn struct{ net.Conn }

func (c failingWriteConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestFailedOpenOKClosesLocalTCP(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	local := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			local <- c.(*net.TCPConn)
		}
	}()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	r := &runtime{cfg: &config.Client{DialTimeout: time.Second}}
	s := &slot{}
	done := make(chan error, 1)
	go func() {
		done <- r.lease(protocol.NewConn(failingWriteConn{left}), s, config.Service{Addr: ln.Addr().String()}, &relay.Relay{}, 1, &metrics.Service{})
	}()
	var conn *net.TCPConn
	select {
	case conn = <-local:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("local dial did not succeed")
	}
	select {
	case e = <-done:
		if !errors.Is(e, io.ErrClosedPipe) {
			t.Fatalf("unexpected OPEN_OK error: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("OPEN_OK did not fail")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = conn.Read(b[:]); e != io.EOF {
		t.Fatalf("local TCP leaked after OPEN_OK failure: %v", e)
	}
}

func closedAddr(t *testing.T) string {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// barrier drives one failed-dial lease through RELEASE and returns the
// frame the client answered with.
func barrier(t *testing.T, idle, maxIdle int) (protocol.Frame, error, *slot) {
	t.Helper()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	svc := &service{name: "svc", idle: idle}
	r := &runtime{cfg: &config.Client{DialTimeout: time.Second, Pool: config.ClientPool{MinIdle: 1, MaxIdle: maxIdle}}}
	s := &slot{state: busySlot, svc: svc}
	done := make(chan error, 1)
	go func() {
		done <- r.lease(protocol.NewConn(left), s, config.Service{Addr: closedAddr(t)}, &relay.Relay{}, 1, &metrics.Service{})
	}()
	server := protocol.NewConn(right)
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	if f, e := server.ReadFrame(); e != nil || f.Type != protocol.OPEN_ERR {
		t.Fatalf("OPEN_ERR: %v", e)
	}
	if e := server.WriteFrame(protocol.Frame{Type: protocol.RELEASE, LeaseID: 1}); e != nil {
		t.Fatal(e)
	}
	f, e := server.ReadFrame()
	if e != nil {
		t.Fatal(e)
	}
	f.Payload = nil
	select {
	case e = <-done:
	case <-time.After(time.Second):
		t.Fatal("lease blocked")
	}
	return f, e, s
}

func TestSurplusIdleClosesAtBarrier(t *testing.T) {
	f, e, s := barrier(t, 1, 1)
	if f.Type != protocol.CLOSE || f.LeaseID != 0 || !errors.Is(e, errSurplus) {
		t.Fatalf("frame %d error %v", f.Type, e)
	}
	if s.state != busySlot || s.svc.idle != 1 {
		t.Fatal("surplus connection counted as idle")
	}
}

func TestReturnsToIdleBelowMax(t *testing.T) {
	f, e, s := barrier(t, 1, 2)
	if f.Type != protocol.READY || f.LeaseID != 1 || e != nil {
		t.Fatalf("frame %d error %v", f.Type, e)
	}
	if s.state != idleSlot || s.svc.idle != 2 {
		t.Fatal("returned connection not counted as idle")
	}
}
