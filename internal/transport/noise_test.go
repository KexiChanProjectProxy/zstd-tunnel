package transport

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
)

func TestNoiseRecords(t *testing.T) {
	a, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	b, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	result := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		c, e := handshakeNoise(right, b.Private, a.Public, false)
		if e != nil {
			errs <- e
			return
		}
		result <- c
	}()
	client, e := handshakeNoise(left, a.Private, b.Public, true)
	if e != nil {
		t.Fatal(e)
	}
	server := <-result
	defer client.Close()
	defer server.Close()
	payload := bytes.Repeat([]byte("abcdefg"), 15000)
	go func() { _, e := client.Write(payload); errs <- e }()
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(server, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("client to server: %v", e)
	}
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
	go func() { _, e := server.Write(payload); errs <- e }()
	if _, e := io.ReadFull(client, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("server to client: %v", e)
	}
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
	if n, e := client.Read(nil); n != 0 || e != nil {
		t.Fatalf("empty read: %v", e)
	}
}
func TestNoiseWrongPin(t *testing.T) {
	a, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	b, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	wrong, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(time.Second))
	_ = right.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, e := handshakeNoise(right, b.Private, a.Public, false); done <- e }()
	_, e := handshakeNoise(left, a.Private, wrong.Public, true)
	if e == nil {
		t.Fatal("wrong pin accepted")
	}
	_ = left.Close()
	if e = <-done; e == nil {
		t.Fatal("server accepted wrong pin")
	}
}
