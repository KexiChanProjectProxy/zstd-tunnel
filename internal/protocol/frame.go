package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
)

const (
	HELLO     uint8 = 1
	HELLO_OK  uint8 = 2
	HELLO_ERR uint8 = 3
	READY     uint8 = 4
	OPEN      uint8 = 5
	OPEN_OK   uint8 = 6
	OPEN_ERR  uint8 = 7
	DATA      uint8 = 8
	FIN       uint8 = 9
	RELEASE   uint8 = 10
	PING      uint8 = 11
	PONG      uint8 = 12
	// CLOSE announces that the sender is gracefully closing an idle
	// connection. It carries no payload and lease ID 0.
	CLOSE uint8 = 13
)

type Frame struct {
	Type    uint8
	LeaseID uint64
	Payload []byte
}
type Conn struct {
	net.Conn
	readBuf     [32768]byte
	writeHeader [13]byte
}

func NewConn(raw net.Conn) *Conn { return &Conn{Conn: raw} }
func valid(typ uint8, n int) error {
	switch typ {
	case DATA:
		if n < 1 || n > 32768 {
			return errors.New("invalid DATA length")
		}
	case HELLO, HELLO_ERR, OPEN_ERR:
		if n < 1 || n > 4096 {
			return errors.New("invalid JSON length")
		}
	case PING, PONG:
		if n != 8 {
			return errors.New("invalid nonce length")
		}
	case HELLO_OK, READY, OPEN, OPEN_OK, FIN, RELEASE, CLOSE:
		if n != 0 {
			return errors.New("unexpected payload")
		}
	default:
		return errors.New("unknown frame type")
	}
	return nil
}
func (c *Conn) ReadFrame() (Frame, error) {
	var h [13]byte
	if _, e := io.ReadFull(c.Conn, h[:]); e != nil {
		return Frame{}, e
	}
	typ := h[0]
	n := int(binary.BigEndian.Uint32(h[9:]))
	if e := valid(typ, n); e != nil {
		return Frame{}, e
	}
	f := Frame{Type: typ, LeaseID: binary.BigEndian.Uint64(h[1:]), Payload: c.readBuf[:n]}
	if _, e := io.ReadFull(c.Conn, f.Payload); e != nil {
		return Frame{}, e
	}
	return f, nil
}
func (c *Conn) WriteFrame(f Frame) error {
	if e := valid(f.Type, len(f.Payload)); e != nil {
		return e
	}
	c.writeHeader[0] = f.Type
	binary.BigEndian.PutUint64(c.writeHeader[1:], f.LeaseID)
	binary.BigEndian.PutUint32(c.writeHeader[9:], uint32(len(f.Payload)))
	if e := writeFull(c.Conn, c.writeHeader[:]); e != nil {
		return e
	}
	return writeFull(c.Conn, f.Payload)
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type Hello struct {
	Version     int        `json:"version"`
	Service     string     `json:"service"`
	Token       string     `json:"token"`
	Compression string     `json:"compression"`
	Pool        PoolParams `json:"pool"`
}

// PoolParams are the client's per-connection pool timings, in milliseconds.
type PoolParams struct {
	HeartbeatMS      int64 `json:"heartbeat_ms"`
	IdleTimeoutMS    int64 `json:"idle_timeout_ms"`
	IdleJitterMS     int64 `json:"idle_jitter_ms"`
	MaxLifetimeMS    int64 `json:"max_lifetime_ms"`
	LifetimeJitterMS int64 `json:"lifetime_jitter_ms"`
}
type Code struct {
	Code string `json:"code"`
}

func DecodeJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var x any
	if e := d.Decode(&x); e != io.EOF {
		if e == nil {
			return errors.New("trailing JSON value")
		}
		return e
	}
	return nil
}
func JSON(v any) []byte { b, _ := json.Marshal(v); return b }
