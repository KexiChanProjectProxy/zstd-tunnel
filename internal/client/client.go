package client

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
)

func Run(ctx context.Context, cfg *config.Client) error {
	if cfg == nil || len(cfg.Services) == 0 || config.ValidatePool(cfg.Pool) != nil {
		return errors.New("invalid client configuration")
	}
	var metricsLn net.Listener
	if cfg.Metrics != nil {
		var e error
		if metricsLn, e = net.Listen("tcp", cfg.Metrics.BindAddr); e != nil {
			return e
		}
	}
	r := &runtime{cfg: cfg, log: slog.New(slog.NewJSONHandler(os.Stderr, nil)), slots: make(map[*slot]struct{}), services: make(map[string]*service, len(cfg.Services))}
	names := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		names = append(names, name)
	}
	r.metrics = metrics.NewClient(names, r.snapshot)
	for name, cfg := range cfg.Services {
		r.services[name] = &service{name: name, cfg: cfg, wake: make(chan struct{}, 1), backoff: baseBackoff, stats: r.metrics.Service(name)}
	}
	// runCtx also stops the connections when the metrics server fails.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, svc := range r.services {
		r.wg.Add(1)
		go r.control(runCtx, svc)
	}
	// The metrics server outlives the drain below so scrapes can watch
	// leases finish; it stops just before Run returns.
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	defer stopMetrics()
	var metricsDone sync.WaitGroup
	errs := make(chan error, 1)
	if metricsLn != nil {
		r.log.Info("metrics listening", "event", "metrics_listening", "address", metricsLn.Addr().String())
		metricsDone.Add(1)
		go func() {
			defer metricsDone.Done()
			if err := r.metrics.Serve(metricsCtx, metricsLn, cfg.Metrics, r.log); err != nil && metricsCtx.Err() == nil {
				errs <- err
			}
		}()
	}
	var failure error
	select {
	case <-ctx.Done():
	case failure = <-errs:
	}
	cancel()
	drainDeadline := time.Now().Add(30 * time.Second)
	r.stop()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	timer := time.NewTimer(time.Until(drainDeadline))
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		r.force()
		<-done
	}
	stopMetrics()
	metricsDone.Wait()
	return failure
}
