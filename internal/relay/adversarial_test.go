package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/klauspost/compress/zstd"
)

func encoded(t *testing.T, payload []byte, window int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, e := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(window))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(payload); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}
func TestRelayRejectsMalformedInbound(t *testing.T) {
	good := encoded(t, []byte("complete compressed content"), 1<<20)
	large := make([]byte, (2<<20)+1)
	if _, e := rand.Read(large); e != nil {
		t.Fatal(e)
	}
	oversized := encoded(t, large, 2<<20)
	for _, tc := range []struct {
		name    string
		id      uint64
		encoded []byte
		fin     bool
	}{{"truncated ZSTD", 1, good[:len(good)/2], true}, {"oversize window", 1, oversized, true}, {"wrong lease id", 2, good, false}} {
		t.Run(tc.name, func(t *testing.T) {
			visitor, front := tcpPair(t)
			defer visitor.Close()
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			tunnel := protocol.NewConn(left)
			peer := protocol.NewConn(right)
			_ = visitor.CloseWrite()
			var codec Relay
			defer codec.Close()
			done := make(chan error, 1)
			go func() { done <- codec.Run(context.Background(), tunnel, front, 1) }()
			go func() {
				for {
					f, e := peer.ReadFrame()
					if e != nil || f.Type == protocol.FIN {
						return
					}
				}
			}()
			go func() {
				for len(tc.encoded) > 0 {
					n := min(32768, len(tc.encoded))
					if peer.WriteFrame(protocol.Frame{Type: protocol.DATA, LeaseID: tc.id, Payload: tc.encoded[:n]}) != nil {
						return
					}
					tc.encoded = tc.encoded[n:]
				}
				if tc.fin {
					_ = peer.WriteFrame(protocol.Frame{Type: protocol.FIN, LeaseID: tc.id})
				}
			}()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("malformed relay accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("malformed relay hung")
			}
		})
	}
}
func TestRelayLeavesFollowingControlFrameUnread(t *testing.T) {
	visitor, front := tcpPair(t)
	defer visitor.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = visitor.CloseWrite()
	tunnel := protocol.NewConn(left)
	peer := protocol.NewConn(right)
	var codec Relay
	defer codec.Close()
	done := make(chan error, 1)
	go func() { done <- codec.Run(context.Background(), tunnel, front, 7) }()
	go func() {
		for {
			f, e := peer.ReadFrame()
			if e != nil || f.Type == protocol.FIN {
				return
			}
		}
	}()
	compressed := encoded(t, []byte("payload"), 1<<20)
	sent := make(chan error, 1)
	go func() {
		for _, f := range []protocol.Frame{{Type: protocol.DATA, LeaseID: 7, Payload: compressed}, {Type: protocol.FIN, LeaseID: 7}, {Type: protocol.RELEASE, LeaseID: 7}} {
			if e := peer.WriteFrame(f); e != nil {
				sent <- e
				return
			}
		}
		sent <- nil
	}()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay stuck before RELEASE")
	}
	f, e := tunnel.ReadFrame()
	if e != nil || f.Type != protocol.RELEASE || f.LeaseID != 7 {
		t.Fatalf("RELEASE lost: %v %v", f.Type, e)
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
}
func TestRelayCancellationUnblocksBothPumps(t *testing.T) {
	visitor, front := tcpPair(t)
	defer visitor.Close()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var codec Relay
	defer codec.Close()
	done := make(chan error, 1)
	go func() { done <- codec.Run(ctx, protocol.NewConn(left), front, 1) }()
	cancel()
	select {
	case e := <-done:
		if e == nil || errors.Is(e, io.EOF) {
			t.Fatal("cancellation reported normal EOF")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation leaked blocked pump")
	}
}
