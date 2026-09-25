package transport

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
)

const chunk = 32768

func fullWrite(w io.Writer, b []byte) error {
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
func dialNoise(ctx context.Context, c config.ClientTransport) (net.Conn, error) {
	d := net.Dialer{Timeout: c.DialTimeout, KeepAlive: -1}
	raw, e := d.DialContext(ctx, "tcp", c.RemoteAddr)
	if e != nil {
		return nil, e
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
	}
	conn, e := handshakeNoise(raw, c.PrivateKey, c.PeerKey, true)
	if e != nil {
		_ = raw.Close()
		return nil, e
	}
	return conn, nil
}
func handshakeNoise(raw net.Conn, private, peer []byte, initiator bool) (net.Conn, error) {
	priv, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		return nil, e
	}
	hs, e := noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s), Pattern: noise.HandshakeKK, Initiator: initiator, Prologue: []byte("compress-proxy/1"), StaticKeypair: noise.DHKey{Private: private, Public: priv.PublicKey().Bytes()}, PeerStatic: peer})
	if e != nil {
		return nil, e
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	defer raw.SetDeadline(time.Time{})
	var c1, c2 *noise.CipherState
	send := func() error {
		msg, a, b, e := hs.WriteMessage(nil, nil)
		if e != nil {
			return e
		}
		if len(msg) != 48 {
			return errors.New("invalid KK message")
		}
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(len(msg)))
		if e = fullWrite(raw, h[:]); e != nil {
			return e
		}
		if e = fullWrite(raw, msg); e != nil {
			return e
		}
		if a != nil {
			c1, c2 = a, b
		}
		return nil
	}
	recv := func() error {
		var h [2]byte
		if e := readFull(raw, h[:]); e != nil {
			return e
		}
		if binary.BigEndian.Uint16(h[:]) != 48 {
			return errors.New("invalid KK message length")
		}
		var msg [48]byte
		if e := readFull(raw, msg[:]); e != nil {
			return e
		}
		payload, a, b, e := hs.ReadMessage(nil, msg[:])
		if e != nil {
			return e
		}
		if len(payload) != 0 {
			return errors.New("unexpected handshake payload")
		}
		if a != nil {
			c1, c2 = a, b
		}
		return nil
	}
	if initiator {
		e = send()
		if e == nil {
			e = recv()
		}
	} else {
		e = recv()
		if e == nil {
			e = send()
		}
	}
	if e != nil {
		return nil, e
	}
	if c1 == nil || c2 == nil {
		return nil, errors.New("incomplete handshake")
	}
	if initiator {
		return &noiseConn{Conn: raw, send: c1, recv: c2}, nil
	}
	return &noiseConn{Conn: raw, send: c2, recv: c1}, nil
}
func readFull(r io.Reader, b []byte) error { _, e := io.ReadFull(r, b); return e }

type noiseConn struct {
	net.Conn
	send, recv *noise.CipherState
	writeMu    sync.Mutex
	plain      [chunk]byte
	cipher     [chunk + 16]byte
	pending    []byte
	outbound   [chunk + 18]byte
	closeOnce  sync.Once
}

func (c *noiseConn) Close() error {
	var e error
	c.closeOnce.Do(func() { e = c.Conn.Close() })
	return e
}
func (c *noiseConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var h [2]byte
		if e := readFull(c.Conn, h[:]); e != nil {
			_ = c.Close()
			return 0, e
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n < 17 || n > chunk+16 {
			_ = c.Close()
			return 0, errors.New("invalid ciphertext length")
		}
		if e := readFull(c.Conn, c.cipher[:n]); e != nil {
			_ = c.Close()
			return 0, e
		}
		decoded, e := c.recv.Decrypt(c.plain[:0], h[:], c.cipher[:n])
		if e != nil {
			_ = c.Close()
			return 0, e
		}
		c.pending = decoded
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *noiseConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), chunk)
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], uint16(n+16))
		copy(c.outbound[:2], h[:])
		cipher, e := c.send.Encrypt(c.outbound[2:2], h[:], p[:n])
		if e != nil {
			_ = c.Close()
			return total, e
		}
		if e = fullWrite(c.Conn, c.outbound[:2+len(cipher)]); e != nil {
			_ = c.Close()
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
