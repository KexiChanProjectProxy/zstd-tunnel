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
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	r := &runtime{cfg: cfg, pools: make(map[string]*pool.Pool, len(listeners)), log: log}
	for name := range listeners {
		r.pools[name] = pool.New(cfg.Pool.MaxPending)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var accepts sync.WaitGroup
	errs := make(chan error, len(listeners)+1)
	for name, ln := range listeners {
		log.Info("service listening", "event", "server_listening", "service", name, "address", ln.Addr().String())
		accepts.Add(1)
		go func(name string, ln net.Listener) {
			defer accepts.Done()
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
				_ = r.pools[name].Dispatch(runCtx, tcp, time.Now().Add(cfg.Pool.AcquireTimeout))
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
	return failure
}
