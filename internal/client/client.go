package client

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/kexichanprojectproxy/zstd-tunnel/internal/config"
)

func Run(ctx context.Context, cfg *config.Client) error {
	if cfg == nil || len(cfg.Services) == 0 || config.ValidatePool(cfg.Pool) != nil {
		return errors.New("invalid client configuration")
	}
	r := &runtime{cfg: cfg, log: slog.New(slog.NewJSONHandler(os.Stderr, nil)), slots: make(map[*slot]struct{})}
	for name, cfg := range cfg.Services {
		svc := &service{name: name, cfg: cfg, wake: make(chan struct{}, 1), backoff: baseBackoff}
		r.wg.Add(1)
		go r.control(ctx, svc)
	}
	<-ctx.Done()
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
	return nil
}
