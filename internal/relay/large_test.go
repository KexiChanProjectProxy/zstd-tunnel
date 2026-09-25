package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
)

type countingConn struct {
	net.Conn
	pending    int
	compressed int
}

func (c *countingConn) Write(p []byte) (int, error) {
	if len(p) == 13 && p[0] == protocol.DATA {
		c.pending = int(binary.BigEndian.Uint32(p[9:]))
	} else if c.pending > 0 {
		c.compressed += min(c.pending, len(p))
		c.pending -= min(c.pending, len(p))
	}
	return c.Conn.Write(p)
}
func TestRelayLargeCompressed(t *testing.T) {
	visitor, front := tcpPair(t)
	defer visitor.Close()
	target, backend := tcpPair(t)
	defer target.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	meter := &countingConn{Conn: left}
	var a, b Relay
	a.Counters, b.Counters = &Counters{}, &Counters{}
	defer a.Close()
	defer b.Close()
	done := make(chan error, 2)
	go func() { done <- a.Run(context.Background(), protocol.NewConn(meter), front, 1) }()
	go func() { done <- b.Run(context.Background(), protocol.NewConn(right), backend, 1) }()
	data := bytes.Repeat([]byte("a"), 4<<20)
	expected := sha256.Sum256(data)
	sent := make(chan error, 1)
	go func() {
		_, e := visitor.Write(data)
		if e == nil {
			e = visitor.CloseWrite()
		}
		sent <- e
	}()
	_ = target.SetReadDeadline(time.Now().Add(8 * time.Second))
	sum := sha256.New()
	n, e := io.Copy(sum, target)
	if e != nil || n != int64(len(data)) || !bytes.Equal(sum.Sum(nil), expected[:]) {
		t.Fatalf("large transfer: %d %v", n, e)
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
	if meter.compressed >= len(data)/10 {
		t.Fatalf("compressed DATA %d bytes exceeds 10%% of input", meter.compressed)
	}
	if got := a.Counters.ToTunnelRaw.Load(); got != uint64(len(data)) {
		t.Fatalf("to_tunnel raw counter %d, sent %d", got, len(data))
	}
	if got := a.Counters.ToTunnelCompressed.Load(); got != uint64(meter.compressed) {
		t.Fatalf("to_tunnel compressed counter %d, wire meter %d", got, meter.compressed)
	}
	if got := b.Counters.FromTunnelCompressed.Load(); got != uint64(meter.compressed) {
		t.Fatalf("from_tunnel compressed counter %d, wire meter %d", got, meter.compressed)
	}
	if got := b.Counters.FromTunnelRaw.Load(); got != uint64(len(data)) {
		t.Fatalf("from_tunnel raw counter %d, sent %d", got, len(data))
	}
}
