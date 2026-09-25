package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type tinyReader struct{ io.Reader }

func (t tinyReader) Read(p []byte) (int, error) { return t.Reader.Read(p[:min(len(p), 1)]) }
func TestFrames(t *testing.T) {
	var b bytes.Buffer
	out := NewConn(&rw{Reader: &b, Writer: &b})
	for _, f := range []Frame{{Type: READY}, {Type: DATA, LeaseID: 1, Payload: []byte("hello")}, {Type: FIN, LeaseID: 1}, {Type: CLOSE}} {
		if e := out.WriteFrame(f); e != nil {
			t.Fatal(e)
		}
	}
	in := NewConn(&rw{Reader: tinyReader{&b}, Writer: io.Discard})
	for _, typ := range []uint8{READY, DATA, FIN, CLOSE} {
		f, e := in.ReadFrame()
		if e != nil || f.Type != typ {
			t.Fatalf("frame %d: %v", typ, e)
		}
	}
	for _, tc := range []struct {
		typ uint8
		n   uint32
	}{{DATA, 0}, {DATA, 32769}, {HELLO, 4097}, {READY, 1}, {CLOSE, 1}, {99, 0}} {
		var h [13]byte
		h[0] = tc.typ
		binary.BigEndian.PutUint32(h[9:], tc.n)
		c := NewConn(&rw{Reader: bytes.NewReader(h[:]), Writer: io.Discard})
		if _, e := c.ReadFrame(); e == nil {
			t.Fatalf("accepted type %d length %d", tc.typ, tc.n)
		}
	}
}

type rw struct {
	io.Reader
	io.Writer
}

func (r *rw) Close() error                     { return nil }
func (r *rw) LocalAddr() net.Addr              { return nil }
func (r *rw) RemoteAddr() net.Addr             { return nil }
func (r *rw) SetDeadline(time.Time) error      { return nil }
func (r *rw) SetReadDeadline(time.Time) error  { return nil }
func (r *rw) SetWriteDeadline(time.Time) error { return nil }
func TestJSON(t *testing.T) {
	for _, s := range []string{`{"version":1,"unknown":2}`, `{"version":1} {"version":2}`} {
		var h Hello
		if DecodeJSON([]byte(s), &h) == nil {
			t.Fatal("accepted", s)
		}
	}
}
