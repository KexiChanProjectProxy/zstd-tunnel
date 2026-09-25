// Package metrics exports tunnel statistics in the Prometheus format.
//
// The server and client record events on plain atomic counters held by
// Service; a custom collector reads them, together with point-in-time pool
// and connection snapshots, whenever /metrics is scraped. This is the only
// package that imports the Prometheus client library.
package metrics

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/pool"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/relay"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "compress_proxy"

// LeaseOutcome classifies how a lease ended.
type LeaseOutcome uint8

const (
	LeaseOK LeaseOutcome = iota
	// LeaseDialFailed: the client could not reach the local service.
	LeaseDialFailed
	// LeaseClientClose: the client closed the connection at the release
	// barrier instead of returning it to the pool (server only).
	LeaseClientClose
	// LeaseError: the tunnel connection failed during the lease.
	LeaseError
)

var leaseOutcomes = [...]string{"ok", "dial_failed", "client_close", "error"}

// Label values for the fixed-cardinality counters. The last entry of each
// list is the fallback for unknown input.
var (
	rejectCodes    = [...]string{"incompatible_protocol", "authentication_failed", "invalid_pool", "shutting_down", "other"}
	closeReasons   = [...]string{"expired", "shutdown", "client_close", "error"}
	retireReasons  = [...]string{"server_close", "surplus", "error"}
	dispatchErrors = [...]string{"stopped", "full", "expired", "canceled"}
)

func index(names []string, v string) int {
	for i, n := range names {
		if n == v {
			return i
		}
	}
	return len(names) - 1
}

// Service holds the counters of one configured service. The zero value is
// usable, which keeps unit tests that build bare runtimes simple.
type Service struct {
	// Relay is shared by every relay of the service.
	Relay relay.Counters
	// Opened counts tunnel connections that completed registration.
	Opened atomic.Uint64
	// Visitors counts public TCP connections accepted by the server.
	Visitors atomic.Uint64
	// DialFailures counts client tunnel dials that failed.
	DialFailures atomic.Uint64
	// LocalDialFailures counts client dials to the local service that failed.
	LocalDialFailures atomic.Uint64

	leases   [len(leaseOutcomes)]atomic.Uint64
	closed   [len(closeReasons)]atomic.Uint64
	retired  [len(retireReasons)]atomic.Uint64
	dispatch [len(dispatchErrors)]atomic.Uint64
	rejected [len(rejectCodes)]atomic.Uint64
	duration prometheus.Observer
}

// LeaseDone records a finished lease and its duration.
func (s *Service) LeaseDone(o LeaseOutcome, d time.Duration) {
	s.leases[o].Add(1)
	if s.duration != nil {
		s.duration.Observe(d.Seconds())
	}
}

// Closed records why the server closed a registered tunnel connection:
// expired, shutdown, client_close or error.
func (s *Service) Closed(reason string) { s.closed[index(closeReasons[:], reason)].Add(1) }

// Retired records why the client closed a registered tunnel connection:
// server_close, surplus or error.
func (s *Service) Retired(reason string) { s.retired[index(retireReasons[:], reason)].Add(1) }

// Rejected records a HELLO_ERR code received by the client.
func (s *Service) Rejected(code string) { s.rejected[index(rejectCodes[:], code)].Add(1) }

// DispatchFailed records a visitor the server could not queue.
func (s *Service) DispatchFailed(e error) {
	i := 3
	switch {
	case errors.Is(e, pool.ErrStopped):
		i = 0
	case errors.Is(e, pool.ErrFull):
		i = 1
	case errors.Is(e, pool.ErrExpired):
		i = 2
	}
	s.dispatch[i].Add(1)
}

// Slots is the client's view of one service's tunnel connections.
type Slots struct{ Connecting, Idle, Busy int }

// Exporter owns a private registry, so several can coexist in one process.
type Exporter struct {
	role     string
	reg      *prometheus.Registry
	services map[string]*Service
	rejected [len(rejectCodes)]atomic.Uint64
	pools    map[string]*pool.Pool
	slots    func() map[string]Slots
}

// NewServer builds the exporter of a server; pools supplies connection and
// visitor gauges.
func NewServer(services []string, pools map[string]*pool.Pool) *Exporter {
	return newExporter("server", services, pools, nil)
}

// NewClient builds the exporter of a client; slots is called on every
// scrape for connection gauges.
func NewClient(services []string, slots func() map[string]Slots) *Exporter {
	return newExporter("client", services, nil, slots)
}

func newExporter(role string, services []string, pools map[string]*pool.Pool, slots func() map[string]Slots) *Exporter {
	x := &Exporter{role: role, reg: prometheus.NewRegistry(), services: make(map[string]*Service, len(services)), pools: pools, slots: slots}
	durations := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace,
		Name:      "lease_duration_seconds",
		Help:      "Time from OPEN to the release barrier of each lease.",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300, 900, 3600},
	}, []string{"service"})
	for _, name := range services {
		x.services[name] = &Service{duration: durations.WithLabelValues(name)}
	}
	x.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		durations,
		&collector{x: x, d: newDescs()},
	)
	return x
}

// Service returns the counters of a configured service. On a nil Exporter
// it returns a detached Service, so code under test needs no exporter.
func (x *Exporter) Service(name string) *Service {
	if x == nil {
		return &Service{}
	}
	if s := x.services[name]; s != nil {
		return s
	}
	return &Service{}
}

// Rejected records a registration the server refused. It has no service
// label: the service name in a rejected HELLO is unauthenticated input.
func (x *Exporter) Rejected(code string) {
	if x != nil {
		x.rejected[index(rejectCodes[:], code)].Add(1)
	}
}

type descs struct {
	build, conns, opened, raw, compressed, leases                  *prometheus.Desc
	srvRejected, srvClosed, srvVisitors, srvPending, srvDispatch   *prometheus.Desc
	cliDialFailures, cliRejected, cliRetired, cliLocalDialFailures *prometheus.Desc
}

func newDescs() descs {
	d := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(namespace, "", name), help, labels, nil)
	}
	return descs{
		build:                d("build_info", "Build information; always 1.", "role", "version", "go_version"),
		conns:                d("tunnel_connections", "Tunnel connections by state. Server states: registering, idle, leased, releasing, checking, expiring. Client states: connecting, idle, busy.", "service", "state"),
		opened:               d("tunnel_connections_opened_total", "Tunnel connections that completed registration.", "service"),
		raw:                  d("relay_raw_bytes_total", "Uncompressed payload bytes on the local TCP side. to_tunnel: read from the local socket; from_tunnel: written to it.", "service", "direction"),
		compressed:           d("relay_compressed_bytes_total", "Compressed DATA payload bytes on the tunnel side, excluding frame headers.", "service", "direction"),
		leases:               d("leases_total", "Finished leases by outcome.", "service", "outcome"),
		srvRejected:          d("server_registrations_rejected_total", "Tunnel registrations refused, by HELLO_ERR code.", "code"),
		srvClosed:            d("server_connections_closed_total", "Registered tunnel connections closed by the server, by reason.", "service", "reason"),
		srvVisitors:          d("server_visitors_total", "Public TCP connections accepted.", "service"),
		srvPending:           d("server_pending_visitors", "Visitors queued for an idle tunnel connection.", "service"),
		srvDispatch:          d("server_dispatch_failures_total", "Visitors closed without being served. stopped/full/expired/canceled: refused on arrival; wait_timeout/wait_canceled: dropped from the queue.", "service", "reason"),
		cliDialFailures:      d("client_dial_failures_total", "Tunnel connection attempts that failed before registration.", "service"),
		cliRejected:          d("client_registrations_rejected_total", "HELLO_ERR replies received, by code.", "service", "code"),
		cliRetired:           d("client_connections_retired_total", "Registered tunnel connections closed by the client, by reason.", "service", "reason"),
		cliLocalDialFailures: d("client_local_dial_failures_total", "Leases whose dial to the local service failed.", "service"),
	}
}

type collector struct {
	x *Exporter
	d descs
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	d := c.d
	for _, v := range []*prometheus.Desc{d.build, d.conns, d.opened, d.raw, d.compressed, d.leases} {
		ch <- v
	}
	if c.x.role == "server" {
		for _, v := range []*prometheus.Desc{d.srvRejected, d.srvClosed, d.srvVisitors, d.srvPending, d.srvDispatch} {
			ch <- v
		}
	} else {
		for _, v := range []*prometheus.Desc{d.cliDialFailures, d.cliRejected, d.cliRetired, d.cliLocalDialFailures} {
			ch <- v
		}
	}
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown"
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	x, d := c.x, c.d
	counter := func(desc *prometheus.Desc, v uint64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, float64(v), labels...)
	}
	gauge := func(desc *prometheus.Desc, v int, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(v), labels...)
	}
	gauge(d.build, 1, x.role, version(), runtime.Version())
	var slots map[string]Slots
	if x.slots != nil {
		slots = x.slots()
	}
	for name, s := range x.services {
		counter(d.opened, s.Opened.Load(), name)
		counter(d.raw, s.Relay.ToTunnelRaw.Load(), name, "to_tunnel")
		counter(d.raw, s.Relay.FromTunnelRaw.Load(), name, "from_tunnel")
		counter(d.compressed, s.Relay.ToTunnelCompressed.Load(), name, "to_tunnel")
		counter(d.compressed, s.Relay.FromTunnelCompressed.Load(), name, "from_tunnel")
		for i, o := range leaseOutcomes {
			if x.role == "client" && LeaseOutcome(i) == LeaseClientClose {
				continue
			}
			counter(d.leases, s.leases[i].Load(), name, o)
		}
		if x.role == "server" {
			st := x.pools[name].Stats()
			for state, n := range map[string]int{"registering": st.Registering, "idle": st.Idle, "leased": st.Leased, "releasing": st.Releasing, "checking": st.Checking, "expiring": st.Expiring} {
				gauge(d.conns, n, name, state)
			}
			gauge(d.srvPending, st.Pending, name)
			counter(d.srvVisitors, s.Visitors.Load(), name)
			for i, r := range closeReasons {
				counter(d.srvClosed, s.closed[i].Load(), name, r)
			}
			for i, r := range dispatchErrors {
				counter(d.srvDispatch, s.dispatch[i].Load(), name, r)
			}
			counter(d.srvDispatch, st.WaitTimeouts, name, "wait_timeout")
			counter(d.srvDispatch, st.WaitCanceled, name, "wait_canceled")
			continue
		}
		sl := slots[name]
		gauge(d.conns, sl.Connecting, name, "connecting")
		gauge(d.conns, sl.Idle, name, "idle")
		gauge(d.conns, sl.Busy, name, "busy")
		counter(d.cliDialFailures, s.DialFailures.Load(), name)
		counter(d.cliLocalDialFailures, s.LocalDialFailures.Load(), name)
		for i, code := range rejectCodes {
			counter(d.cliRejected, s.rejected[i].Load(), name, code)
		}
		for i, r := range retireReasons {
			counter(d.cliRetired, s.retired[i].Load(), name, r)
		}
	}
	if x.role == "server" {
		for i, code := range rejectCodes {
			counter(d.srvRejected, x.rejected[i].Load(), code)
		}
	}
}

// Handler serves GET /metrics to clients presenting the configured basic
// auth credentials. Authentication is checked before routing so an
// unauthenticated client learns nothing about the endpoint.
func (x *Exporter) Handler(cfg *config.Metrics, log *slog.Logger) http.Handler {
	metrics := promhttp.HandlerFor(x.reg, promhttp.HandlerOpts{
		ErrorLog:            slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ErrorHandling:       promhttp.ContinueOnError,
		Timeout:             10 * time.Second,
		MaxRequestsInFlight: 4,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		u, p := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(pass))
		// Both comparisons always run; & does not short-circuit.
		if subtle.ConstantTimeCompare(u[:], cfg.UsernameHash[:])&subtle.ConstantTimeCompare(p[:], cfg.PasswordHash[:]) != 1 || !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="compress-proxy", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		metrics.ServeHTTP(w, r)
	})
}

// Serve runs the metrics HTTP server on ln until ctx is cancelled, then
// closes it without waiting for in-flight scrapes. It returns nil after a
// cancellation and the listener error otherwise.
func (x *Exporter) Serve(ctx context.Context, ln net.Listener, cfg *config.Metrics, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           x.Handler(cfg, log),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	e := srv.Serve(ln)
	if ctx.Err() != nil || errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
