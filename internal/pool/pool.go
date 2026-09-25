package pool

import (
	"container/list"
	"context"
	"errors"
	"math/rand/v2"
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
	expiring
	closed
)

// Outcome tells a worker goroutine what to do next.
type Outcome uint8

const (
	// Ready: the worker is in the idle list and can wait in Next.
	Ready Outcome = iota
	// Leased: Next returned a public TCP connection to serve.
	Leased
	// Check: the worker was taken out of the idle list for a heartbeat.
	Check
	// Expired: the worker hit its idle or lifetime deadline and must close.
	Expired
	// Stopped: the pool is stopping or the worker was closed.
	Stopped
)

// Options are the per-connection timings. A zero Heartbeat, IdleTimeout or
// MaxLifetime disables that timer.
type Options struct {
	Heartbeat, IdleTimeout, IdleJitter, MaxLifetime, LifetimeJitter time.Duration
}

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
	opts      Options
	dies      time.Time
	expires   time.Time
	elem      *list.Element
	ID        uint64
}
type Pool struct {
	mu         sync.Mutex
	pendingMax int
	stopping   bool
	workers    map[*Worker]struct{}
	idle       list.List // ordered by ascending Worker.ID; Back is the newest
	waiting    list.List
	pending    int
}

func New(maxPending int) *Pool {
	return &Pool{pendingMax: maxPending, workers: make(map[*Worker]struct{})}
}

// never is far enough in the future to stand for a disabled deadline.
var never = time.Unix(1<<62, 0)

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}
func after(now time.Time, base, spread time.Duration) time.Time {
	if base <= 0 {
		return never
	}
	return now.Add(base + jitter(spread))
}
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (p *Pool) Register(id uint64, opts Options, closeConn func()) (*Worker, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopping {
		return nil, ErrStopped
	}
	w := &Worker{p: p, state: registering, wake: make(chan struct{}, 1), closeConn: closeConn, opts: opts, ID: id}
	w.dies = after(time.Now(), opts.MaxLifetime, opts.LifetimeJitter)
	p.workers[w] = struct{}{}
	return w, nil
}
func (p *Pool) unlinkLocked(w *Worker) {
	if w.elem != nil {
		p.idle.Remove(w.elem)
		w.elem = nil
	}
}

// pushIdleLocked keeps the idle list ordered by connection ID so that
// Dispatch can always pick the most recently established connection.
func (p *Pool) pushIdleLocked(w *Worker) {
	e := p.idle.Back()
	for e != nil && e.Value.(*Worker).ID > w.ID {
		e = e.Prev()
	}
	if e == nil {
		w.elem = p.idle.PushFront(w)
	} else {
		w.elem = p.idle.InsertAfter(w, e)
	}
	w.state = idle
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
	p.unlinkLocked(w)
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
	p.pushIdleLocked(w)
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

// Idle returns the worker to service after registration, a lease or a
// heartbeat check. It reports Expired when the connection has outlived
// MaxLifetime; the caller must then close it. The idle deadline restarts
// only when the worker comes back from registration or a lease, never after
// a heartbeat, so heartbeats do not keep an unused connection alive.
func (w *Worker) Idle() Outcome {
	p := w.p
	p.mu.Lock()
	if p.stopping || w.state == closed {
		p.mu.Unlock()
		w.Closed()
		return Stopped
	}
	w.business = nil
	now := time.Now()
	if !now.Before(w.dies) {
		w.state = expiring
		p.mu.Unlock()
		return Expired
	}
	if w.state != checking {
		w.expires = after(now, w.opts.IdleTimeout, w.opts.IdleJitter)
	}
	expired := p.matchLocked(w)
	p.mu.Unlock()
	for _, tcp := range expired {
		_ = tcp.Close()
	}
	return Ready
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
		w := p.idle.Back().Value.(*Worker)
		p.unlinkLocked(w)
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

// timer returns a timer channel firing after d, or nil (never fires) when
// the deadline is disabled.
func timer(d time.Duration, disabled bool) (*time.Timer, <-chan time.Time) {
	if disabled {
		return nil, nil
	}
	t := time.NewTimer(d)
	return t, t.C
}

// takeIdleLocked moves an idle worker into state s, reporting whether it was
// idle. Only idle workers can be taken, so this never races with Dispatch.
func (p *Pool) takeIdleLocked(w *Worker, s state) bool {
	if w.state != idle || p.stopping {
		return false
	}
	p.unlinkLocked(w)
	w.state = s
	return true
}

// Next waits for a lease, a heartbeat check or the idle/lifetime deadline.
func (w *Worker) Next(ctx context.Context) (*net.TCPConn, Outcome) {
	p := w.p
	p.mu.Lock()
	deadline := earlier(w.expires, w.dies)
	p.mu.Unlock()
	if deadline.IsZero() {
		deadline = never
	}
	hb, hbC := timer(w.opts.Heartbeat, w.opts.Heartbeat <= 0)
	if hb != nil {
		defer hb.Stop()
	}
	ex, exC := timer(time.Until(deadline), deadline.Equal(never))
	if ex != nil {
		defer ex.Stop()
	}
	for {
		p.mu.Lock()
		if w.state == closed || p.stopping && w.state == idle {
			p.mu.Unlock()
			return nil, Stopped
		}
		if w.mailbox != nil {
			tcp := w.mailbox
			w.mailbox = nil
			p.mu.Unlock()
			return tcp, Leased
		}
		p.mu.Unlock()
		select {
		case <-w.wake:
		case <-hbC:
			p.mu.Lock()
			ok := p.takeIdleLocked(w, checking)
			p.mu.Unlock()
			if ok {
				return nil, Check
			}
			hb.Reset(w.opts.Heartbeat)
		case <-exC:
			// If the worker is no longer idle it was leased (the mailbox
			// is set and wake is pending) or closed; the loop handles both.
			p.mu.Lock()
			ok := p.takeIdleLocked(w, expiring)
			p.mu.Unlock()
			if ok {
				return nil, Expired
			}
		case <-ctx.Done():
			return nil, Stopped
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
		switch w.state {
		case idle, checking, registering, expiring:
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
