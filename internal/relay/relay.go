package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/klauspost/compress/zstd"
)

// Counters accumulates relayed payload bytes across every lease a Relay
// runs. Directions are seen from this process: to_tunnel bytes are read raw
// from the local TCP socket and written compressed into DATA frames;
// from_tunnel bytes are read compressed from DATA frames and written raw to
// the local socket. Frame headers and control frames are not counted.
type Counters struct {
	ToTunnelRaw, ToTunnelCompressed, FromTunnelCompressed, FromTunnelRaw atomic.Uint64
}

func add(c *atomic.Uint64, n int) {
	if c != nil && n > 0 {
		c.Add(uint64(n))
	}
}

type Relay struct {
	// Counters, when set, receives the byte counts of every lease. It is
	// meant to be shared by all relays of one service and is never reset.
	Counters *Counters
	encoder  *zstd.Encoder
	decoder  *zstd.Decoder
	writer   frameWriter
	reader   frameReader
	readBuf  [32768]byte
	copyBuf  [32768]byte
}
type frameWriter struct {
	conn  *protocol.Conn
	id    uint64
	bytes *atomic.Uint64
}

func (w *frameWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), 32768)
		_ = w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		e := w.conn.WriteFrame(protocol.Frame{Type: protocol.DATA, LeaseID: w.id, Payload: p[:n]})
		if e != nil {
			return total, e
		}
		add(w.bytes, n)
		p = p[n:]
		total += n
	}
	return total, nil
}

type frameReader struct {
	conn    *protocol.Conn
	id      uint64
	pending []byte
	fin     bool
	bytes   *atomic.Uint64
}

func (r *frameReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.fin {
		return 0, io.EOF
	}
	f, e := r.conn.ReadFrame()
	if e != nil {
		return 0, fmt.Errorf("missing FIN: %w", e)
	}
	if f.LeaseID != r.id {
		return 0, errors.New("wrong lease id")
	}
	switch f.Type {
	case protocol.DATA:
		// Count on receipt: later calls serve the same bytes from pending.
		add(r.bytes, len(f.Payload))
		r.pending = f.Payload
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	case protocol.FIN:
		r.fin = true
		return 0, io.EOF
	default:
		return 0, errors.New("unexpected relay frame")
	}
}
func (r *frameReader) finish() error {
	if len(r.pending) != 0 {
		return errors.New("unread compressed data")
	}
	if r.fin {
		return nil
	}
	f, e := r.conn.ReadFrame()
	if e != nil {
		return e
	}
	if f.Type != protocol.FIN || f.LeaseID != r.id {
		return errors.New("expected FIN after compressed frame")
	}
	r.fin = true
	return nil
}
func (r *Relay) init() error {
	if r.encoder != nil {
		return nil
	}
	var e error
	r.encoder, e = zstd.NewWriter(&r.writer, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithEncoderCRC(true), zstd.WithZeroFrames(true))
	if e != nil {
		return e
	}
	r.decoder, e = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(1<<20), zstd.WithDecoderMaxMemory(1<<20))
	return e
}

type deadlineWriter struct {
	conn  *net.TCPConn
	bytes *atomic.Uint64
}

func (w deadlineWriter) Write(p []byte) (int, error) {
	if e := w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); e != nil {
		return 0, e
	}
	n, e := w.conn.Write(p)
	add(w.bytes, n)
	return n, e
}
func (r *Relay) Run(ctx context.Context, tunnel *protocol.Conn, tcp *net.TCPConn, id uint64) error {
	if e := r.init(); e != nil {
		return e
	}
	var toRaw, toCompressed, fromCompressed, fromRaw *atomic.Uint64
	if c := r.Counters; c != nil {
		toRaw, toCompressed, fromCompressed, fromRaw = &c.ToTunnelRaw, &c.ToTunnelCompressed, &c.FromTunnelCompressed, &c.FromTunnelRaw
	}
	r.writer.conn = tunnel
	r.writer.id = id
	r.writer.bytes = toCompressed
	r.reader = frameReader{conn: tunnel, id: id, bytes: fromCompressed}
	r.encoder.Reset(&r.writer)
	if e := r.decoder.Reset(&r.reader); e != nil {
		return e
	}
	abort := func() { _ = tcp.Close(); _ = tunnel.Close() }
	stop := context.AfterFunc(ctx, abort)
	defer stop()
	errorsCh := make(chan error, 2)
	go func() {
		for {
			_ = tcp.SetReadDeadline(time.Time{})
			n, e := tcp.Read(r.readBuf[:])
			add(toRaw, n)
			if n > 0 {
				if _, err := r.encoder.Write(r.readBuf[:n]); err != nil {
					errorsCh <- err
					return
				}
				if err := r.encoder.Flush(); err != nil {
					errorsCh <- err
					return
				}
			}
			if e != nil {
				if e != io.EOF {
					errorsCh <- e
					return
				}
				if err := r.encoder.Close(); err != nil {
					errorsCh <- err
					return
				}
				_ = tunnel.SetWriteDeadline(time.Now().Add(30 * time.Second))
				errorsCh <- tunnel.WriteFrame(protocol.Frame{Type: protocol.FIN, LeaseID: id})
				return
			}
		}
	}()
	go func() {
		_, e := io.CopyBuffer(deadlineWriter{conn: tcp, bytes: fromRaw}, r.decoder, r.copyBuf[:])
		if e == nil {
			e = r.reader.finish()
		}
		if e == nil {
			// ENOTCONN means the local peer already reset the socket.
			// The incoming stream ended with FIN, so nothing is lost.
			if e = tcp.CloseWrite(); errors.Is(e, syscall.ENOTCONN) {
				e = nil
			}
		}
		errorsCh <- e
	}()
	first := <-errorsCh
	if first != nil {
		abort()
	}
	second := <-errorsCh
	if second != nil {
		abort()
	}
	if first == nil && second == nil {
		if e := r.decoder.Reset(nil); e != nil {
			return e
		}
		_ = tunnel.SetWriteDeadline(time.Time{})
		return nil
	}
	r.Close()
	if first != nil {
		return first
	}
	return second
}
func (r *Relay) Close() {
	if r.decoder != nil {
		r.decoder.Close()
		r.decoder = nil
	}
	r.encoder = nil
	r.writer.conn = nil
	r.reader = frameReader{}
}
