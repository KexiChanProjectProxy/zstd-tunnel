package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
)

type recordWire struct {
	net.Conn
	mode    string
	enabled bool
	saved   []byte
}

func (w *recordWire) Write(p []byte) (int, error) {
	if !w.enabled || len(p) < 3 {
		return w.Conn.Write(p)
	}
	data := bytes.Clone(p)
	switch w.mode {
	case "flip":
		data[len(data)-1] ^= 1
	case "length":
		data[0] = 0
		data[1] = 0
	case "truncate":
		n, e := w.Conn.Write(data[:len(data)/2])
		_ = w.Conn.Close()
		if e == nil {
			e = io.ErrUnexpectedEOF
		}
		return n, e
	case "replay":
		w.saved = bytes.Clone(data)
	}
	return w.Conn.Write(data)
}
func TestNoiseRejectsCorruptedRecords(t *testing.T) {
	for _, mode := range []string{"flip", "length", "truncate", "replay"} {
		t.Run(mode, func(t *testing.T) {
			a, _ := noise.DH25519.GenerateKeypair(rand.Reader)
			b, _ := noise.DH25519.GenerateKeypair(rand.Reader)
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			wire := &recordWire{Conn: left, mode: mode}
			done := make(chan net.Conn, 1)
			go func() {
				conn, e := handshakeNoise(right, b.Private, a.Public, false)
				if e == nil {
					done <- conn
				}
			}()
			client, e := handshakeNoise(wire, a.Private, b.Public, true)
			if e != nil {
				t.Fatal(e)
			}
			server := <-done
			defer server.Close()
			wire.enabled = true
			errCh := make(chan error, 1)
			go func() { _, e := client.Write([]byte("secret")); errCh <- e }()
			buf := make([]byte, 6)
			_ = server.SetReadDeadline(time.Now().Add(time.Second))
			_, e = io.ReadFull(server, buf)
			if mode == "replay" {
				if e != nil || string(buf) != "secret" {
					t.Fatal(e)
				}
				go func() { _, _ = wire.Conn.Write(wire.saved) }()
				_, e = server.Read(buf)
			}
			if e == nil {
				t.Fatalf("forged record accepted: %q", buf)
			}
			_ = client.Close()
			select {
			case <-errCh:
			case <-time.After(time.Second):
				t.Fatal("writer blocked")
			}
			if mode == "replay" && errors.Is(e, io.EOF) {
				t.Fatal("replay yielded EOF rather than auth failure")
			}
		})
	}
}

type tinyConn struct{ net.Conn }

func (c tinyConn) Read(p []byte) (int, error)  { return c.Conn.Read(p[:min(len(p), 1)]) }
func (c tinyConn) Write(p []byte) (int, error) { return c.Conn.Write(p[:min(len(p), 3)]) }
func TestNoiseHandlesShortReadsAndWrites(t *testing.T) {
	a, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	b, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	result := make(chan net.Conn, 1)
	go func() {
		c, e := handshakeNoise(tinyConn{right}, b.Private, a.Public, false)
		if e == nil {
			result <- c
		}
	}()
	client, e := handshakeNoise(tinyConn{left}, a.Private, b.Public, true)
	if e != nil {
		t.Fatal(e)
	}
	server := <-result
	defer client.Close()
	defer server.Close()
	payload := bytes.Repeat([]byte("test"), 10000)
	sent := make(chan error, 1)
	go func() { _, e := client.Write(payload); sent <- e }()
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(server, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("short IO: %v", e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
}
