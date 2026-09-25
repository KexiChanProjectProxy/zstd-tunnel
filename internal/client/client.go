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
	if cfg == nil || len(cfg.Services) == 0 || cfg.Pool.Size < 1 {
		return errors.New("invalid client configuration")
	}
	r := &runtime{cfg: cfg, log: slog.New(slog.NewJSONHandler(os.Stderr, nil)), slots: make(map[*slot]struct{})}
	for name, service := range cfg.Services {
		for range cfg.Pool.Size {
			r.wg.Add(1)
			go r.runSlot(ctx, name, service)
		}
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
