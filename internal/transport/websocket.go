package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
)

const subprotocol = "compress-proxy.v1"

type wsConn struct {
	net.Conn
	ws     *websocket.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func newWSConn(ws *websocket.Conn) net.Conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(64 << 10)
	return &wsConn{Conn: c, ws: ws, cancel: cancel}
}
func (c *wsConn) Close() error { c.once.Do(func() { c.cancel(); _ = c.ws.CloseNow() }); return nil }
func dialWS(ctx context.Context, c config.ClientTransport) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(c.RemoteAddr)
	if c.ServerName != "" {
		host = c.ServerName
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.RootCAs, ServerName: host}
	tr := &http.Transport{TLSClientConfig: conf, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, DialContext: (&net.Dialer{Timeout: c.DialTimeout, KeepAlive: 30 * time.Second}).DialContext}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
	handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, _, e := websocket.Dial(handshake, "wss://"+c.RemoteAddr+c.Path, &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return nil, e
	}
	if ws.Subprotocol() != subprotocol {
		_ = ws.CloseNow()
		return nil, errors.New("subprotocol mismatch")
	}
	return newWSConn(ws), nil
}
func serveWS(ctx context.Context, l *guardedListener, c config.ServerTransport, accept func(*Incoming)) error {
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{c.Certificate}, NextProtos: []string{"http/1.1"}}, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		if tc, ok := conn.(*tls.Conn); ok {
			if gc, ok := tc.NetConn().(*guardedConn); ok {
				return context.WithValue(ctx, guardKey{}, gc.g)
			}
		}
		return ctx
	}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.beginHandler() {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		defer l.wg.Done()
		w.Header().Set("Connection", "close")
		if r.ProtoMajor != 1 || r.Method != "GET" || r.URL.Path != c.Path || r.URL.RawQuery != "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		g, ok := r.Context().Value(guardKey{}).(*guard)
		if !ok {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{subprotocol}, CompressionMode: websocket.CompressionDisabled})
		if e != nil {
			g.fail()
			return
		}
		if ws.Subprotocol() != subprotocol {
			_ = ws.CloseNow()
			g.fail()
			return
		}
		if !g.next() {
			_ = ws.CloseNow()
			return
		}
		conn := newWSConn(ws)
		in := &Incoming{Conn: conn, guard: g}
		accept(in)
		g.mu.Lock()
		done := g.done
		g.mu.Unlock()
		if !done {
			_ = in.Close()
			g.fail()
		}
	})}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	e := srv.Serve(tls.NewListener(l, srv.TLSConfig))
	if ctx.Err() != nil || errors.Is(e, http.ErrServerClosed) || strings.Contains(e.Error(), "closed network connection") {
		return nil
	}
	return e
}

type guardKey struct{}
