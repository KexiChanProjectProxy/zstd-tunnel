package pool

import (
	"container/list"
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

var ErrStopped = errors.New("pool stopping")
var ErrFull = errors.New("pool capacity exceeded")
var ErrExpired = errors.New("acquire deadline expired")

type state uint8

const (
	registering state = iota
	idle
	leased
	releasing
	checking
	closed
)

type waiter struct {
	tcp      *net.TCPConn
	ctx      context.Context
	deadline time.Time
	node     *list.Element
	stop     func() bool
	timer    *time.Timer
	waiting  bool
}
type Worker struct {
	p         *Pool
	state     state
	mailbox   *net.TCPConn
	business  *net.TCPConn
	wake      chan struct{}
	closeConn func()
	ID        uint64
}
type Pool struct {
	mu              sync.Mutex
	max, pendingMax int
	stopping        bool
	workers         map[*Worker]struct{}
	idle            list.List
	waiting         list.List
	pending         int
}

func New(maxConnections, maxPending int) *Pool {
	return &Pool{max: maxConnections, pendingMax: maxPending, workers: make(map[*Worker]struct{})}
}
func (p *Pool) Register(id uint64, closeConn func()) (*Worker, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopping {
		return nil, ErrStopped
	}
	if len(p.workers) >= p.max {
		return nil, ErrFull
	}
	w := &Worker{p: p, state: registering, wake: make(chan struct{}, 1), closeConn: closeConn, ID: id}
	p.workers[w] = struct{}{}
	return w, nil
}
func (w *Worker) Closed() {
	p := w.p
	p.mu.Lock()
	if w.state == closed {
		p.mu.Unlock()
		return
	}
	w.state = closed
	delete(p.workers, w)
	for e := p.idle.Front(); e != nil; e = e.Next() {
		if e.Value == w {
			p.idle.Remove(e)
			break
		}
	}
	tcp := w.mailbox
	w.mailbox = nil
	business := w.business
	w.business = nil
	w.notify()
	p.mu.Unlock()
	if tcp != nil {
		_ = tcp.Close()
	}
	if business != nil {
		_ = business.Close()
	}
	w.closeConn()
}
func (w *Worker) notify() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}
func (p *Pool) matchLocked(w *Worker) []*net.TCPConn {
	var expired []*net.TCPConn
	for e := p.waiting.Front(); e != nil; {
		next := e.Next()
		v := e.Value.(*waiter)
		if v.ctx.Err() != nil || !time.Now().Before(v.deadline) {
			p.removeLocked(v)
			expired = append(expired, v.tcp)
			e = next
			continue
		}
		p.removeLocked(v)
		w.state = leased
		w.mailbox = v.tcp
		w.business = v.tcp
		w.notify()
		return expired
	}
	p.idle.PushBack(w)
	w.state = idle
	return expired
}
func (p *Pool) removeLocked(v *waiter) {
	if !v.waiting {
		return
	}
	v.waiting = false
	p.waiting.Remove(v.node)
	p.pending--
	if v.stop != nil {
		v.stop()
	}
	if v.timer != nil {
		v.timer.Stop()
	}
}
func (w *Worker) Idle() bool {
	p := w.p
	p.mu.Lock()
	if p.stopping || w.state == closed {
		p.mu.Unlock()
		w.Closed()
		return false
	}
	w.business = nil
	expired := p.matchLocked(w)
	p.mu.Unlock()
	for _, tcp := range expired {
		_ = tcp.Close()
	}
	return true
}
func (w *Worker) Releasing() {
	p := w.p
	p.mu.Lock()
	if w.state == leased {
		w.state = releasing
	}
	p.mu.Unlock()
}
func (p *Pool) Dispatch(ctx context.Context, tcp *net.TCPConn, deadline time.Time) error {
	p.mu.Lock()
	var err error
	switch {
	case p.stopping:
		err = ErrStopped
	case ctx.Err() != nil:
		err = ctx.Err()
	case !time.Now().Before(deadline):
		err = ErrExpired
	}
	if err != nil {
		p.mu.Unlock()
		_ = tcp.Close()
		return err
	}
	if p.waiting.Len() == 0 && p.idle.Len() > 0 {
		e := p.idle.Front()
		w := e.Value.(*Worker)
		p.idle.Remove(e)
		w.state = leased
		w.mailbox = tcp
		w.business = tcp
		w.notify()
		p.mu.Unlock()
		return nil
	}
	if p.pending >= p.pendingMax {
		p.mu.Unlock()
		_ = tcp.Close()
		return ErrFull
	}
	v := &waiter{tcp: tcp, ctx: ctx, deadline: deadline, waiting: true}
	v.node = p.waiting.PushBack(v)
	p.pending++
	cancel := func() {
		p.mu.Lock()
		if !v.waiting {
			p.mu.Unlock()
			return
		}
		p.removeLocked(v)
		p.mu.Unlock()
		_ = tcp.Close()
	}
	v.stop = context.AfterFunc(ctx, cancel)
	v.timer = time.AfterFunc(time.Until(deadline), cancel)
	p.mu.Unlock()
	return nil
}
func (w *Worker) Next(ctx context.Context) (*net.TCPConn, bool) {
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		p := w.p
		p.mu.Lock()
		if w.state == closed || p.stopping && w.state == idle {
			p.mu.Unlock()
			return nil, false
		}
		if w.mailbox != nil {
			tcp := w.mailbox
			w.mailbox = nil
			p.mu.Unlock()
			return tcp, false
		}
		p.mu.Unlock()
		select {
		case <-w.wake:
			continue
		case <-timer.C:
			p.mu.Lock()
			if w.state == idle && !p.stopping {
				for e := p.idle.Front(); e != nil; e = e.Next() {
					if e.Value == w {
						p.idle.Remove(e)
						break
					}
				}
				w.state = checking
				p.mu.Unlock()
				return nil, true
			}
			p.mu.Unlock()
			timer.Reset(15 * time.Second)
		case <-ctx.Done():
			return nil, false
		}
	}
}
func (p *Pool) Stop() {
	p.mu.Lock()
	if p.stopping {
		p.mu.Unlock()
		return
	}
	p.stopping = true
	var tcp []*net.TCPConn
	var toClose []*Worker
	for e := p.waiting.Front(); e != nil; {
		next := e.Next()
		v := e.Value.(*waiter)
		p.removeLocked(v)
		tcp = append(tcp, v.tcp)
		e = next
	}
	for w := range p.workers {
		if w.state == idle || w.state == checking || w.state == registering {
			toClose = append(toClose, w)
		}
	}
	p.mu.Unlock()
	for _, c := range tcp {
		_ = c.Close()
	}
	for _, w := range toClose {
		w.Closed()
	}
}
func (p *Pool) Force() {
	p.mu.Lock()
	workers := make([]*Worker, 0, len(p.workers))
	for w := range p.workers {
		workers = append(workers, w)
	}
	p.mu.Unlock()
	for _, w := range workers {
		w.Closed()
	}
}
func (p *Pool) Count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.workers) }
