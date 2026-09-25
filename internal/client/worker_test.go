package client

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
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
		done <- r.lease(protocol.NewConn(failingWriteConn{left}), s, config.Service{Addr: ln.Addr().String()}, &relay.Relay{}, 1)
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
