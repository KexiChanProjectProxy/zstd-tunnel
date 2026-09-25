package config

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

var serviceName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Config struct {
	Server *Server
	Client *Client
}
type Service struct {
	Addr      string
	Token     string
	TokenHash [32]byte
}
type Server struct {
	BindAddr  string
	Services  map[string]Service
	Transport ServerTransport
	Pool      ServerPool
	Metrics   *Metrics
}
type Client struct {
	RemoteAddr  string
	DialTimeout time.Duration
	Services    map[string]Service
	Transport   ClientTransport
	Pool        ClientPool
	Metrics     *Metrics
}

// Metrics configures the Prometheus endpoint. A nil *Metrics disables it.
// Only credential hashes are kept; the endpoint compares hashes.
type Metrics struct {
	BindAddr                   string
	UsernameHash, PasswordHash [32]byte
}
type ServerPool struct {
	MaxPending     int
	AcquireTimeout time.Duration
}
type ClientPool struct {
	MinIdle, MaxIdle                                                int
	Heartbeat, IdleTimeout, IdleJitter, MaxLifetime, LifetimeJitter time.Duration
}
type ServerTransport struct {
	Type                string
	PrivateKey, PeerKey []byte
	Certificate         tls.Certificate
	Path                string
}
type ClientTransport struct {
	Type                         string
	PrivateKey, PeerKey          []byte
	RootCAs                      *x509.CertPool
	ServerName, Path, RemoteAddr string
	DialTimeout                  time.Duration
}

type rawConfig struct {
	Server *rawServer `toml:"server"`
	Client *rawClient `toml:"client"`
}
type rawService struct {
	BindAddr  *string `toml:"bind_addr"`
	LocalAddr *string `toml:"local_addr"`
	Token     *string `toml:"token"`
}
type rawServer struct {
	BindAddr     string                `toml:"bind_addr"`
	DefaultToken *string               `toml:"default_token"`
	Services     map[string]rawService `toml:"services"`
	Transport    rawTransport          `toml:"transport"`
	Pool         rawServerPool         `toml:"pool"`
	Metrics      *rawMetrics           `toml:"metrics"`
}
type rawClient struct {
	RemoteAddr   string                `toml:"remote_addr"`
	DialTimeout  *string               `toml:"dial_timeout"`
	DefaultToken *string               `toml:"default_token"`
	Services     map[string]rawService `toml:"services"`
	Transport    rawTransport          `toml:"transport"`
	Pool         rawClientPool         `toml:"pool"`
	Metrics      *rawMetrics           `toml:"metrics"`
}
type rawMetrics struct {
	BindAddr *string `toml:"bind_addr"`
	Username *string `toml:"username"`
	Password *string `toml:"password"`
}
type rawTransport struct {
	Type      string    `toml:"type"`
	Noise     *rawNoise `toml:"noise"`
	TLS       *rawTLS   `toml:"tls"`
	WebSocket *rawWS    `toml:"websocket"`
}
type rawNoise struct {
	LocalPrivateKey string `toml:"local_private_key"`
	RemotePublicKey string `toml:"remote_public_key"`
}
type rawTLS struct {
	CertFile   *string `toml:"cert_file"`
	KeyFile    *string `toml:"key_file"`
	CAFile     *string `toml:"ca_file"`
	ServerName *string `toml:"server_name"`
}
type rawWS struct {
	Path *string `toml:"path"`
}
type rawServerPool struct {
	MaxPending     *int    `toml:"max_pending"`
	AcquireTimeout *string `toml:"acquire_timeout"`
}
type rawClientPool struct {
	MinIdle        *int    `toml:"min_idle"`
	MaxIdle        *int    `toml:"max_idle"`
	Heartbeat      *string `toml:"heartbeat"`
	IdleTimeout    *string `toml:"idle_timeout"`
	IdleJitter     *string `toml:"idle_jitter"`
	MaxLifetime    *string `toml:"max_lifetime"`
	LifetimeJitter *string `toml:"lifetime_jitter"`
}

func Load(path string) (cfg *Config, err error) {
	defer func() {
		if err != nil && !strings.HasPrefix(err.Error(), "configuration "+filepath.Base(path)+":") {
			err = fmt.Errorf("configuration %s: %w", filepath.Base(path), err)
		}
	}()
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("configuration file: %w", err)
	}
	defer f.Close()
	var raw rawConfig
	if err = toml.NewDecoder(f).DisallowUnknownFields().Decode(&raw); err != nil {
		category := "invalid TOML syntax or value"
		var unknown *toml.StrictMissingError
		if errors.As(err, &unknown) {
			category = "unknown field"
		}
		var decoded *toml.DecodeError
		if errors.As(err, &decoded) {
			row, column := decoded.Position()
			field := "field"
			key := decoded.Key()
			if len(key) > 0 && len(key[len(key)-1]) < 32 && serviceName.MatchString(key[len(key)-1]) {
				field = key[len(key)-1]
			}
			return nil, fmt.Errorf("configuration %s:%d:%d: %s: %s", filepath.Base(path), row, column, field, category)
		}
		return nil, fmt.Errorf("configuration %s: %s", filepath.Base(path), category)
	}
	if (raw.Server == nil) == (raw.Client == nil) {
		return nil, errors.New("configuration: exactly one of server or client required")
	}
	dir := filepath.Dir(path)
	if raw.Server != nil {
		r := raw.Server
		if err = address(r.BindAddr, false); err != nil {
			return nil, fmt.Errorf("server.bind_addr: %w", err)
		}
		services, err := parseServices(r.Services, r.DefaultToken, true)
		if err != nil {
			return nil, err
		}
		tr, err := serverTransport(r.Transport, dir)
		if err != nil {
			return nil, err
		}
		p := ServerPool{MaxPending: 64, AcquireTimeout: 5 * time.Second}
		if r.Pool.MaxPending != nil {
			p.MaxPending = *r.Pool.MaxPending
		}
		if r.Pool.AcquireTimeout != nil {
			p.AcquireTimeout, err = time.ParseDuration(*r.Pool.AcquireTimeout)
			if err != nil {
				return nil, errors.New("server.pool.acquire_timeout: invalid duration")
			}
		}
		if p.MaxPending < 1 || p.MaxPending > 4096 || p.AcquireTimeout <= 0 || p.AcquireTimeout > time.Minute {
			return nil, errors.New("server.pool: invalid limits")
		}
		m, err := metricsConfig(r.Metrics, "server.metrics")
		if err != nil {
			return nil, err
		}
		return &Config{Server: &Server{BindAddr: r.BindAddr, Services: services, Transport: tr, Pool: p, Metrics: m}}, nil
	}
	r := raw.Client
	if err = address(r.RemoteAddr, true); err != nil {
		return nil, fmt.Errorf("client.remote_addr: %w", err)
	}
	services, err := parseServices(r.Services, r.DefaultToken, false)
	if err != nil {
		return nil, err
	}
	tr, err := clientTransport(r.Transport, dir)
	if err != nil {
		return nil, err
	}
	timeout := 5 * time.Second
	if r.DialTimeout != nil {
		timeout, err = time.ParseDuration(*r.DialTimeout)
		if err != nil {
			return nil, errors.New("client.dial_timeout: invalid duration")
		}
	}
	if timeout <= 0 || timeout > 5*time.Second {
		return nil, errors.New("client.dial_timeout: out of range")
	}
	pool, err := clientPool(r.Pool)
	if err != nil {
		return nil, err
	}
	m, err := metricsConfig(r.Metrics, "client.metrics")
	if err != nil {
		return nil, err
	}
	tr.RemoteAddr = r.RemoteAddr
	tr.DialTimeout = timeout
	return &Config{Client: &Client{RemoteAddr: r.RemoteAddr, DialTimeout: timeout, Services: services, Transport: tr, Pool: pool, Metrics: m}}, nil
}

// metricsConfig validates a [server.metrics] or [client.metrics] table.
// Basic auth is mandatory when the endpoint is enabled. Error messages never
// include the configured values.
func metricsConfig(r *rawMetrics, prefix string) (*Metrics, error) {
	if r == nil {
		return nil, nil
	}
	if r.BindAddr == nil {
		return nil, fmt.Errorf("%s.bind_addr: required", prefix)
	}
	if err := address(*r.BindAddr, false); err != nil {
		return nil, fmt.Errorf("%s.bind_addr: %w", prefix, err)
	}
	if r.Username == nil {
		return nil, fmt.Errorf("%s.username: required", prefix)
	}
	if len(*r.Username) < 1 || len(*r.Username) > 64 || strings.ContainsAny(*r.Username, ":\x00\r\n") {
		return nil, fmt.Errorf("%s.username: must be 1..64 bytes without ':' or control characters", prefix)
	}
	if r.Password == nil {
		return nil, fmt.Errorf("%s.password: required", prefix)
	}
	if len(*r.Password) < 16 || len(*r.Password) > 256 {
		return nil, fmt.Errorf("%s.password: length must be 16..256 bytes", prefix)
	}
	return &Metrics{BindAddr: *r.BindAddr, UsernameHash: sha256.Sum256([]byte(*r.Username)), PasswordHash: sha256.Sum256([]byte(*r.Password))}, nil
}

func clientPool(r rawClientPool) (ClientPool, error) {
	p := ClientPool{MinIdle: 2, MaxIdle: 8, Heartbeat: 15 * time.Second, IdleTimeout: 5 * time.Minute, MaxLifetime: time.Hour}
	if r.MinIdle != nil {
		p.MinIdle = *r.MinIdle
	}
	if r.MaxIdle != nil {
		p.MaxIdle = *r.MaxIdle
	}
	for _, d := range []struct {
		name string
		raw  *string
		dst  *time.Duration
	}{{"heartbeat", r.Heartbeat, &p.Heartbeat}, {"idle_timeout", r.IdleTimeout, &p.IdleTimeout}, {"max_lifetime", r.MaxLifetime, &p.MaxLifetime}, {"idle_jitter", r.IdleJitter, &p.IdleJitter}, {"lifetime_jitter", r.LifetimeJitter, &p.LifetimeJitter}} {
		if d.raw == nil {
			continue
		}
		v, e := time.ParseDuration(*d.raw)
		if e != nil {
			return p, fmt.Errorf("client.pool.%s: invalid duration", d.name)
		}
		*d.dst = v
	}
	if r.IdleJitter == nil {
		p.IdleJitter = p.IdleTimeout / 10
	}
	if r.LifetimeJitter == nil {
		p.LifetimeJitter = p.MaxLifetime / 10
	}
	if e := ValidatePool(p); e != nil {
		return p, fmt.Errorf("client.pool.%w", e)
	}
	return p, nil
}

// ValidatePool checks the pool limits shared by client configuration and
// the parameters a client announces to the server in HELLO.
func ValidatePool(p ClientPool) error {
	switch {
	case p.MinIdle < 1 || p.MinIdle > 1024:
		return errors.New("min_idle: out of range")
	case p.MaxIdle < p.MinIdle || p.MaxIdle > 1024:
		return errors.New("max_idle: must be min_idle..1024")
	case p.Heartbeat < time.Second || p.Heartbeat > 10*time.Minute:
		return errors.New("heartbeat: out of range")
	case p.IdleTimeout < time.Second || p.IdleTimeout > 24*time.Hour:
		return errors.New("idle_timeout: out of range")
	case p.IdleJitter < 0 || p.IdleJitter > p.IdleTimeout:
		return errors.New("idle_jitter: must be 0..idle_timeout")
	case p.MaxLifetime < time.Second || p.MaxLifetime > 7*24*time.Hour:
		return errors.New("max_lifetime: out of range")
	case p.LifetimeJitter < 0 || p.LifetimeJitter > p.MaxLifetime:
		return errors.New("lifetime_jitter: must be 0..max_lifetime")
	}
	return nil
}

func address(s string, requireHost bool) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil || s == "" {
		return errors.New("invalid host:port")
	}
	if requireHost && host == "" {
		return errors.New("empty host")
	}
	if port == "" {
		return errors.New("invalid port")
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return errors.New("invalid port")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid port")
	}
	return nil
}
func parseServices(raw map[string]rawService, def *string, server bool) (map[string]Service, error) {
	if len(raw) == 0 {
		return nil, errors.New("services: at least one service required")
	}
	out := make(map[string]Service, len(raw))
	for name, s := range raw {
		if !serviceName.MatchString(name) {
			return nil, errors.New("services: invalid name")
		}
		field := "local_addr"
		var selected *string
		if server {
			selected = s.BindAddr
			field = "bind_addr"
			if s.LocalAddr != nil {
				return nil, fmt.Errorf("services.%s.local_addr: not allowed", name)
			}
		} else {
			selected = s.LocalAddr
			if s.BindAddr != nil {
				return nil, fmt.Errorf("services.%s.bind_addr: not allowed", name)
			}
		}
		addr := ""
		if selected != nil {
			addr = *selected
		}
		if err := address(addr, !server); err != nil {
			return nil, fmt.Errorf("services.%s.%s: %w", name, field, err)
		}
		tok := s.Token
		if tok == nil {
			tok = def
		}
		if tok == nil || len(*tok) < 32 || len(*tok) > 256 {
			return nil, fmt.Errorf("services.%s.token: length must be 32..256 bytes", name)
		}
		out[name] = Service{Addr: addr, Token: *tok, TokenHash: sha256.Sum256([]byte(*tok))}
	}
	return out, nil
}
func key(s string) ([]byte, error) {
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) != 32 {
		return nil, errors.New("invalid base64 X25519 key")
	}
	return b, nil
}
func noiseKeys(r *rawNoise) ([]byte, []byte, error) {
	if r == nil {
		return nil, nil, errors.New("transport.noise: required")
	}
	a, e := key(r.LocalPrivateKey)
	if e != nil {
		return nil, nil, fmt.Errorf("transport.noise.local_private_key: %w", e)
	}
	b, e := key(r.RemotePublicKey)
	if e != nil {
		return nil, nil, fmt.Errorf("transport.noise.remote_public_key: %w", e)
	}
	return a, b, nil
}
func wsPath(r *rawWS) (string, error) {
	p := "/tunnel"
	if r != nil && r.Path != nil {
		p = *r.Path
	}
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
		return "", errors.New("transport.websocket.path: invalid path")
	}
	return p, nil
}
func serverTransport(r rawTransport, dir string) (ServerTransport, error) {
	t := ServerTransport{Type: r.Type}
	switch r.Type {
	case "noise":
		if r.TLS != nil || r.WebSocket != nil {
			return t, errors.New("transport: unexpected subtable")
		}
		a, b, e := noiseKeys(r.Noise)
		t.PrivateKey, t.PeerKey = a, b
		return t, e
	case "wss":
		if r.Noise != nil || r.TLS == nil {
			return t, errors.New("transport: tls required; noise forbidden")
		}
		if r.TLS.CAFile != nil || r.TLS.ServerName != nil {
			return t, errors.New("server.transport.tls: client-only field")
		}
		if r.TLS.CertFile == nil || r.TLS.KeyFile == nil || *r.TLS.CertFile == "" || *r.TLS.KeyFile == "" {
			return t, errors.New("server.transport.tls: certificate and key required")
		}
		var e error
		t.Certificate, e = tls.LoadX509KeyPair(filepath.Join(dir, *r.TLS.CertFile), filepath.Join(dir, *r.TLS.KeyFile))
		if e != nil {
			return t, errors.New("server.transport.tls: invalid certificate or key")
		}
		t.Path, e = wsPath(r.WebSocket)
		return t, e
	default:
		return t, errors.New("transport.type: expected noise or wss")
	}
}
func clientTransport(r rawTransport, dir string) (ClientTransport, error) {
	t := ClientTransport{Type: r.Type}
	switch r.Type {
	case "noise":
		if r.TLS != nil || r.WebSocket != nil {
			return t, errors.New("transport: unexpected subtable")
		}
		a, b, e := noiseKeys(r.Noise)
		t.PrivateKey, t.PeerKey = a, b
		return t, e
	case "wss":
		if r.Noise != nil {
			return t, errors.New("transport: unexpected noise subtable")
		}
		if r.TLS != nil {
			if r.TLS.CertFile != nil || r.TLS.KeyFile != nil {
				return t, errors.New("client.transport.tls: server-only field")
			}
			if r.TLS.ServerName != nil {
				if *r.TLS.ServerName == "" {
					return t, errors.New("client.transport.tls.server_name: empty value")
				}
				t.ServerName = *r.TLS.ServerName
			}
			if r.TLS.CAFile != nil {
				if *r.TLS.CAFile == "" {
					return t, errors.New("client.transport.tls.ca_file: empty value")
				}
				pem, e := os.ReadFile(filepath.Join(dir, *r.TLS.CAFile))
				if e != nil {
					return t, errors.New("client.transport.tls.ca_file: cannot read")
				}
				roots := x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return t, errors.New("client.transport.tls.ca_file: invalid PEM")
				}
				t.RootCAs = roots
			}
		}
		var e error
		t.Path, e = wsPath(r.WebSocket)
		return t, e
	default:
		return t, errors.New("transport.type: expected noise or wss")
	}
}
