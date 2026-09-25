package server

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/pool"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/relay"
	"github.com/klauspost/compress/zstd"
)

func TestOpenErrorClosesPublicBeforeReleaseBarrier(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.Accept(); accepted <- c.(*net.TCPConn) }()
	visitor, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer visitor.Close()
	public := <-accepted
	defer public.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := protocol.NewConn(left)
	client := protocol.NewConn(right)
	p := pool.New(1, 1)
	w, _ := p.Register(1, func() {})
	defer w.Closed()
	done := make(chan error, 1)
	go func() { done <- (&runtime{}).lease(server, public, w, &relay.Relay{}, 1) }()
	f, e := client.ReadFrame()
	if e != nil || f.Type != protocol.OPEN {
		t.Fatalf("OPEN: %v", e)
	}
	if e = client.WriteFrame(protocol.Frame{Type: protocol.OPEN_ERR, LeaseID: 1, Payload: protocol.JSON(protocol.Code{Code: "dial_failed"})}); e != nil {
		t.Fatal(e)
	}
	f, e = client.ReadFrame()
	if e != nil || f.Type != protocol.RELEASE {
		t.Fatalf("RELEASE: %v", e)
	}
	_ = visitor.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = visitor.Read(b[:]); e != io.EOF {
		t.Fatalf("public TCP not closed before READY: %v", e)
	}
	if e = client.WriteFrame(protocol.Frame{Type: protocol.READY, LeaseID: 1}); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("release barrier blocked")
	}
}

func TestDataAfterFINRejectsRelease(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c.(*net.TCPConn)
		}
	}()
	visitorConn, e := net.Dial("tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	visitor := visitorConn.(*net.TCPConn)
	defer visitor.Close()
	public := <-accepted
	defer public.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	server := protocol.NewConn(left)
	client := protocol.NewConn(right)
	p := pool.New(1, 1)
	w, _ := p.Register(1, func() {})
	defer w.Closed()
	var codec relay.Relay
	defer codec.Close()
	done := make(chan error, 1)
	go func() { done <- (&runtime{}).lease(server, public, w, &codec, 1) }()
	f, e := client.ReadFrame()
	if e != nil || f.Type != protocol.OPEN {
		t.Fatal("missing OPEN", e)
	}
	if e = client.WriteFrame(protocol.Frame{Type: protocol.OPEN_OK, LeaseID: 1}); e != nil {
		t.Fatal(e)
	}
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = encoder.Write([]byte("valid payload"))
	if err = encoder.Close(); err != nil {
		t.Fatal(err)
	}
	forged := make(chan error, 1)
	go func() {
		for _, frame := range []protocol.Frame{{Type: protocol.DATA, LeaseID: 1, Payload: compressed.Bytes()}, {Type: protocol.FIN, LeaseID: 1}, {Type: protocol.DATA, LeaseID: 1, Payload: []byte("after FIN")}} {
			if err := client.WriteFrame(frame); err != nil {
				forged <- err
				return
			}
		}
		forged <- nil
	}()
	_ = visitor.CloseWrite()
	_ = visitor.SetReadDeadline(time.Now().Add(2 * time.Second))
	received, err := io.ReadAll(visitor)
	if err != nil || string(received) != "valid payload" {
		t.Fatalf("valid payload lost: %q %v", received, err)
	}
	for {
		frame, err := client.ReadFrame()
		if err != nil {
			t.Fatal("missing RELEASE", err)
		}
		if frame.Type == protocol.RELEASE {
			break
		}
		if frame.Type != protocol.DATA && frame.Type != protocol.FIN {
			t.Fatal("unexpected server frame")
		}
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("DATA after FIN accepted as READY")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("release did not reject DATA")
	}
	select {
	case <-forged:
	case <-time.After(time.Second):
		t.Fatal("forged writer blocked")
	}
}
