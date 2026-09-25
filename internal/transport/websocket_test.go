package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
)

func TestWSSStream(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	root, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	priv, _ := x509.MarshalECPrivateKey(key)
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, config.ServerTransport{Type: "wss", Certificate: cert, Path: "/tunnel"}, func(in *Incoming) {
			if e := in.CompleteAuth(); e == nil {
				go func() { defer in.Close(); _, _ = io.Copy(in, in) }()
			}
		})
	}()
	clientCfg := config.ClientTransport{Type: "wss", RootCAs: roots, ServerName: "localhost", RemoteAddr: ln.Addr().String(), Path: "/tunnel", DialTimeout: time.Second}
	dialCtx, stop := context.WithCancel(context.Background())
	conn, e := Dial(dialCtx, clientCfg)
	if e != nil {
		t.Fatal(e)
	}
	stop()
	defer conn.Close()
	if _, e = conn.Write([]byte("hello")); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e = io.ReadFull(conn, buf); e != nil || string(buf) != "hello" {
		t.Fatalf("lifetime context: %q %v", buf, e)
	}
	bad := clientCfg
	bad.ServerName = "wrong.local"
	if c, e := Dial(context.Background(), bad); e == nil {
		c.Close()
		t.Fatal("wrong hostname accepted")
	}
	bad = clientCfg
	bad.RootCAs = x509.NewCertPool()
	if c, e := Dial(context.Background(), bad); e == nil {
		c.Close()
		t.Fatal("wrong CA accepted")
	}
	bad = clientCfg
	bad.Path = "/else"
	if c, e := Dial(context.Background(), bad); e == nil {
		_ = c.Close()
		t.Fatal("wrong path accepted")
	}
	if ws, _, e := websocket.Dial(context.Background(), "ws://"+clientCfg.RemoteAddr+"/tunnel", nil); e == nil {
		_ = ws.CloseNow()
		t.Fatal("plaintext websocket accepted")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}}}
	url := "wss://" + clientCfg.RemoteAddr + "/tunnel"
	wrong, _, e := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPClient: httpClient, Subprotocols: []string{"wrong"}})
	if e == nil {
		defer wrong.CloseNow()
		if wrong.Subprotocol() == "wrong" {
			t.Fatal("unexpected subprotocol accepted")
		}
		readCtx, stopRead := context.WithTimeout(context.Background(), time.Second)
		defer stopRead()
		if _, _, e = wrong.Read(readCtx); e == nil {
			t.Fatal("wrong subprotocol remained usable")
		}
	}
	for _, test := range []struct {
		name string
		typ  websocket.MessageType
		body []byte
	}{{"text", websocket.MessageText, []byte("forbidden")}, {"oversize", websocket.MessageBinary, bytes.Repeat([]byte("x"), 70<<10)}} {
		t.Run(test.name, func(t *testing.T) {
			ws, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{HTTPClient: httpClient, Subprotocols: []string{subprotocol}})
			if err != nil {
				t.Fatal(err)
			}
			defer ws.CloseNow()
			readCtx, stopRead := context.WithTimeout(context.Background(), 2*time.Second)
			defer stopRead()
			_ = ws.Write(readCtx, test.typ, test.body)
			total := 0
			for {
				_, content, readErr := ws.Read(readCtx)
				if readErr != nil {
					if readCtx.Err() != nil || total >= len(test.body) {
						t.Fatalf("message not rejected after %d bytes: %v", total, readErr)
					}
					break
				}
				total += len(content)
			}
			if test.typ == websocket.MessageText && total != 0 {
				t.Fatal("text delivered as binary")
			}
		})
	}
	cancel()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server didn't stop")
	}
}
