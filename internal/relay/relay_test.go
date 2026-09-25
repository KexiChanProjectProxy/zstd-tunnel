package relay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	got := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.Accept(); got <- c.(*net.TCPConn) }()
	a, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	return a.(*net.TCPConn), <-got
}
func TestRelayInteractiveAndReuse(t *testing.T) {
	var server, client Relay
	defer server.Close()
	defer client.Close()
	for id := uint64(1); id <= 2; id++ {
		visitor, front := tcpPair(t)
		target, backend := tcpPair(t)
		left, right := net.Pipe()
		s := protocol.NewConn(left)
		c := protocol.NewConn(right)
		done := make(chan error, 2)
		go func() { done <- server.Run(context.Background(), s, front, id) }()
		go func() { done <- client.Run(context.Background(), c, backend, id) }()
		msg := []byte("hello")
		if id == 2 {
			msg = []byte("second lease")
		}
		_ = visitor.SetDeadline(time.Now().Add(2 * time.Second))
		_ = target.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e := visitor.Write(msg); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, len(msg))
		if _, e := io.ReadFull(target, buf); e != nil || string(buf) != string(msg) {
			t.Fatalf("flush: %q %v", buf, e)
		}
		if _, e := target.Write(buf); e != nil {
			t.Fatal(e)
		}
		if _, e := io.ReadFull(visitor, buf); e != nil || string(buf) != string(msg) {
			t.Fatalf("reverse: %q %v", buf, e)
		}
		_ = visitor.CloseWrite()
		_ = target.CloseWrite()
		for range 2 {
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("relay stuck")
			}
		}
		_ = visitor.Close()
		_ = target.Close()
		_ = s.Close()
		_ = c.Close()
	}
}
