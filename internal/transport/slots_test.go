package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestHandshakeSlotsRejectExcess(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l := newListener(context.Background(), ln)
	defer l.stop()
	var clients []net.Conn
	var accepted []net.Conn
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
		for _, c := range accepted {
			_ = c.Close()
		}
	}()
	for range 64 {
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, conn)
	}
	if len(l.slots) != 64 {
		t.Fatalf("expected 64 guards, got %d", len(l.slots))
	}
	extra, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer extra.Close()
	out := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); out <- c }()
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = extra.Read(b[:]); e != io.EOF {
		t.Fatalf("65th unauthenticated socket not closed: %v", e)
	}
	if e = accepted[0].(*guardedConn).g.complete(); e != nil {
		t.Fatal(e)
	}
	next, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	select {
	case c := <-out:
		if c == nil {
			t.Fatal("listener stopped")
		}
		accepted = append(accepted, c)
	case <-time.After(time.Second):
		t.Fatal("released slot not usable")
	}
	_ = accepted[0].Close()
}
