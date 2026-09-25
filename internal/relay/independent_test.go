package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/klauspost/compress/zstd"
)

type captureConn struct {
	net.Conn
	remaining int
	data      bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) {
	if len(p) == 13 && p[0] == protocol.DATA {
		c.remaining = int(binary.BigEndian.Uint32(p[9:]))
	} else if c.remaining > 0 {
		n := min(c.remaining, len(p))
		_, _ = c.data.Write(p[:n])
		c.remaining -= n
	}
	return c.Conn.Write(p)
}
func TestEachLeaseDecodesIndependently(t *testing.T) {
	prefix := make([]byte, 32768)
	if _, e := rand.Read(prefix); e != nil {
		t.Fatal(e)
	}
	var a, b Relay
	defer a.Close()
	defer b.Close()
	for lease := uint64(1); lease <= 2; lease++ {
		visitor, front := tcpPair(t)
		target, backend := tcpPair(t)
		left, right := net.Pipe()
		capture := &captureConn{Conn: left}
		done := make(chan error, 2)
		go func() { done <- a.Run(context.Background(), protocol.NewConn(capture), front, lease) }()
		go func() { done <- b.Run(context.Background(), protocol.NewConn(right), backend, lease) }()
		sent := make(chan error, 1)
		go func() {
			_, e := visitor.Write(prefix)
			if e == nil {
				e = visitor.CloseWrite()
			}
			sent <- e
		}()
		_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
		body, e := io.ReadAll(target)
		if e != nil || !bytes.Equal(body, prefix) {
			t.Fatalf("lease %d decode: %v", lease, e)
		}
		_ = target.CloseWrite()
		if e = <-sent; e != nil {
			t.Fatal(e)
		}
		for range 2 {
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		}
		if lease == 2 {
			decoder, e := zstd.NewReader(bytes.NewReader(capture.data.Bytes()))
			if e != nil {
				t.Fatal(e)
			}
			independent, e := io.ReadAll(decoder)
			decoder.Close()
			if e != nil || !bytes.Equal(independent, prefix) {
				t.Fatalf("second lease needs previous dictionary: %v", e)
			}
		}
		_ = visitor.Close()
		_ = target.Close()
		_ = left.Close()
		_ = right.Close()
	}
}
