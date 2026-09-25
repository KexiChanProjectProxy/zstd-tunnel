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
	server.Counters, client.Counters = &Counters{}, &Counters{}
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
	// Counters accumulate across both leases on the reused relays.
	const payload = uint64(len("hello") + len("second lease"))
	sc, cc := server.Counters, client.Counters
	for name, got := range map[string]uint64{"server to_tunnel raw": sc.ToTunnelRaw.Load(), "server from_tunnel raw": sc.FromTunnelRaw.Load(), "client to_tunnel raw": cc.ToTunnelRaw.Load(), "client from_tunnel raw": cc.FromTunnelRaw.Load()} {
		if got != payload {
			t.Errorf("%s = %d, want %d", name, got, payload)
		}
	}
	if a, b := sc.ToTunnelCompressed.Load(), cc.FromTunnelCompressed.Load(); a == 0 || a != b {
		t.Errorf("server sent %d compressed bytes, client received %d", a, b)
	}
	if a, b := cc.ToTunnelCompressed.Load(), sc.FromTunnelCompressed.Load(); a == 0 || a != b {
		t.Errorf("client sent %d compressed bytes, server received %d", a, b)
	}
}

// A local peer that half-closes and then resets its socket leaves the relay
// with a dead socket when the tunnel FIN arrives. Shutting down the write
// side then fails with ENOTCONN, which must not fail the lease: the peer is
// gone and the incoming stream ended cleanly.
func TestRelayToleratesResetPeerAtCloseWrite(t *testing.T) {
	var server, client Relay
	defer server.Close()
	defer client.Close()
	visitor, front := tcpPair(t)
	defer visitor.Close()
	target, backend := tcpPair(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	go func() { serverDone <- server.Run(context.Background(), protocol.NewConn(left), front, 1) }()
	go func() { clientDone <- client.Run(context.Background(), protocol.NewConn(right), backend, 1) }()
	// The backend closes first: its FIN crosses the tunnel and reaches the visitor.
	_ = target.CloseWrite()
	_ = visitor.SetDeadline(time.Now().Add(2 * time.Second))
	if b, e := io.ReadAll(visitor); e != nil || len(b) != 0 {
		t.Fatalf("backend FIN not relayed: %q %v", b, e)
	}
	// Then it resets the connection before the visitor has finished.
	if e := target.SetLinger(0); e != nil {
		t.Fatal(e)
	}
	_ = target.Close()
	time.Sleep(100 * time.Millisecond)
	_ = visitor.CloseWrite()
	// Collect both results before failing so the deferred Close calls never
	// race with a relay that is still running.
	var results [2]error
	for i, done := range []chan error{clientDone, serverDone} {
		select {
		case results[i] = <-done:
		case <-time.After(2 * time.Second):
			_ = left.Close()
			_ = backend.Close()
			_ = front.Close()
			results[i] = <-done
			t.Errorf("relay %d stuck", i)
		}
	}
	if results[0] != nil || results[1] != nil {
		t.Fatalf("relay failed after peer reset: client %v, server %v", results[0], results[1])
	}
}
