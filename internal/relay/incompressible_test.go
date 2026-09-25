package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
)

func TestRelayIncompressibleHash(t *testing.T) {
	visitor, front := tcpPair(t)
	defer visitor.Close()
	target, backend := tcpPair(t)
	defer target.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var server, client Relay
	defer server.Close()
	defer client.Close()
	finished := make(chan error, 2)
	go func() { finished <- server.Run(context.Background(), protocol.NewConn(left), front, 1) }()
	go func() { finished <- client.Run(context.Background(), protocol.NewConn(right), backend, 1) }()
	input := make([]byte, 1<<20)
	if _, e := rand.Read(input); e != nil {
		t.Fatal(e)
	}
	sent := make(chan error, 1)
	go func() {
		_, e := visitor.Write(input)
		if e == nil {
			e = visitor.CloseWrite()
		}
		sent <- e
	}()
	_ = target.SetReadDeadline(time.Now().Add(5 * time.Second))
	hash := sha256.New()
	n, e := io.Copy(hash, target)
	expected := sha256.Sum256(input)
	if e != nil || n != int64(len(input)) || !bytes.Equal(hash.Sum(nil), expected[:]) {
		t.Fatalf("incompressible hash mismatch %d: %v", n, e)
	}
	_ = target.CloseWrite()
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if e = <-finished; e != nil {
			t.Fatal(e)
		}
	}
}
