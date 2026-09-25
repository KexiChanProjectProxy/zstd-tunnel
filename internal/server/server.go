package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/metrics"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/pool"
	"github.com/kexichanprojectproxy/zstd-tunnel/internal/transport"
)

func Run(ctx context.Context, cfg *config.Server) error {
	if cfg == nil || len(cfg.Services) == 0 {
		return errors.New("invalid server configuration")
	}
	tunnel, e := net.Listen("tcp", cfg.BindAddr)
	if e != nil {
		return e
	}
	listeners := make(map[string]net.Listener, len(cfg.Services))
	for name, service := range cfg.Services {
		ln, err := net.Listen("tcp", service.Addr)
		if err != nil {
			_ = tunnel.Close()
			for _, open := range listeners {
				_ = open.Close()
			}
			return err
		}
		listeners[name] = ln
	}
	var metricsLn net.Listener
	if cfg.Metrics != nil {
		if metricsLn, e = net.Listen("tcp", cfg.Metrics.BindAddr); e != nil {
			_ = tunnel.Close()
			for _, open := range listeners {
				_ = open.Close()
			}
			return e
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	r := &runtime{cfg: cfg, pools: make(map[string]*pool.Pool, len(listeners)), log: log}
	names := make([]string, 0, len(listeners))
	for name := range listeners {
		r.pools[name] = pool.New(cfg.Pool.MaxPending)
		names = append(names, name)
	}
	r.metrics = metrics.NewServer(names, r.pools)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var accepts sync.WaitGroup
	// One slot per goroutine that may report a failure: the service
	// listeners, the tunnel listener and the metrics server.
	errs := make(chan error, len(listeners)+2)
	for name, ln := range listeners {
		log.Info("service listening", "event", "server_listening", "service", name, "address", ln.Addr().String())
		accepts.Add(1)
		go func(name string, ln net.Listener) {
			defer accepts.Done()
			stats := r.metrics.Service(name)
			for {
				conn, err := ln.Accept()
				if err != nil {
					if runCtx.Err() == nil {
						errs <- err
					}
					return
				}
				tcp := conn.(*net.TCPConn)
				_ = tcp.SetKeepAlive(true)
				stats.Visitors.Add(1)
				if err := r.pools[name].Dispatch(runCtx, tcp, time.Now().Add(cfg.Pool.AcquireTimeout)); err != nil {
					stats.DispatchFailed(err)
				}
			}
		}(name, ln)
	}
	log.Info("tunnel listening", "event", "server_listening", "address", tunnel.Addr().String())
	accepts.Add(1)
	go func() {
		defer accepts.Done()
		if err := transport.Serve(runCtx, tunnel, cfg.Transport, r.register); err != nil && runCtx.Err() == nil {
			errs <- err
		}
	}()
	// The metrics server outlives the drain below so scrapes can watch
	// leases finish; it has its own context and stops just before Run returns.
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	defer stopMetrics()
	var metricsDone sync.WaitGroup
	if metricsLn != nil {
		log.Info("metrics listening", "event", "metrics_listening", "address", metricsLn.Addr().String())
		metricsDone.Add(1)
		go func() {
			defer metricsDone.Done()
			if err := r.metrics.Serve(metricsCtx, metricsLn, cfg.Metrics, log); err != nil && metricsCtx.Err() == nil {
				errs <- err
			}
		}()
	}
	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errs:
	}
	drainDeadline := time.Now().Add(30 * time.Second)
	cancel()
	for _, p := range r.pools {
		p.Stop()
	}
	_ = tunnel.Close()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	accepts.Wait()
	done := make(chan struct{})
	go func() { r.workers.Wait(); close(done) }()
	timer := time.NewTimer(time.Until(drainDeadline))
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		for _, p := range r.pools {
			p.Force()
		}
		<-done
	}
	stopMetrics()
	metricsDone.Wait()
	return failure
}
