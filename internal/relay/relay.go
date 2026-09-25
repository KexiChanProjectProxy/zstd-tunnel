package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/protocol"
	"github.com/klauspost/compress/zstd"
)

type Relay struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
	writer  frameWriter
	reader  frameReader
	readBuf [32768]byte
	copyBuf [32768]byte
}
type frameWriter struct {
	conn *protocol.Conn
	id   uint64
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

type deadlineWriter struct{ conn *net.TCPConn }

func (w deadlineWriter) Write(p []byte) (int, error) {
	if e := w.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); e != nil {
		return 0, e
	}
	return w.conn.Write(p)
}
func (r *Relay) Run(ctx context.Context, tunnel *protocol.Conn, tcp *net.TCPConn, id uint64) error {
	if e := r.init(); e != nil {
		return e
	}
	r.writer.conn = tunnel
	r.writer.id = id
	r.reader = frameReader{conn: tunnel, id: id}
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
		_, e := io.CopyBuffer(deadlineWriter{conn: tcp}, r.decoder, r.copyBuf[:])
		if e == nil {
			e = r.reader.finish()
		}
		if e == nil {
			e = tcp.CloseWrite()
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
