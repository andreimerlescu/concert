package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Listeners that can change while concert runs.
//
// An endpoint is one listening address served by an http.Server. Moving it
// to another address binds the new address first, starts serving there, and
// then shuts the old server down gracefully: connections that are already
// open finish on the old server (up to the endpoint's grace period) while
// new connections go to the new one. Nothing is refused in between.
//
// TLS is switched per connection rather than per server. The listener wraps
// each accepted connection in TLS when a certificate configuration is
// installed, so turning Let's Encrypt on or off, or changing its hostnames,
// needs no new socket. The http.Server is started without a TLSConfig, which
// makes Serve configure HTTP/2, and TLS connections that negotiate h2
// through ALPN are served over HTTP/2 as before.

// endpoint is one address served by concert: the main listener or the admin
// portal.
type endpoint struct {
	name    string
	handler http.Handler
	newSrv  func(http.Handler) *http.Server
	grace   time.Duration
	tls     atomic.Pointer[tls.Config] // nil: plain HTTP
	fatal   chan error                 // a server that stopped on its own

	mu      sync.Mutex
	cur     *serving // nil when not serving
	retired sync.WaitGroup
}

// serving is one http.Server on one listener.
type serving struct {
	addr string       // as configured, such as ":8080"
	ln   net.Listener // the bound socket
	srv  *http.Server
}

func newEndpoint(name string, h http.Handler, grace time.Duration, newSrv func(http.Handler) *http.Server) *endpoint {
	return &endpoint{name: name, handler: h, newSrv: newSrv, grace: grace, fatal: make(chan error, 1)}
}

// setTLS installs the certificate configuration new connections use. nil
// serves plain HTTP. Connections already open keep what they negotiated.
func (e *endpoint) setTLS(tc *tls.Config) {
	e.tls.Store(tc)
}

// addr is the configured address being served, or "" when not serving.
func (e *endpoint) addr() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur == nil {
		return ""
	}
	return e.cur.addr
}

// describe is the endpoint's state for operators.
func (e *endpoint) describe() string {
	if e == nil {
		return "not running"
	}
	e.mu.Lock()
	cur := e.cur
	e.mu.Unlock()
	if cur == nil {
		return "off"
	}
	mode := "plain HTTP"
	if e.tls.Load() != nil {
		mode = "TLS (Let's Encrypt)"
	}
	return fmt.Sprintf("%s · %s", cur.ln.Addr(), mode)
}

// serveOn starts serving on ln, which is bound to addr. When the endpoint
// was already serving elsewhere, the old server drains in the background.
func (e *endpoint) serveOn(ln net.Listener, addr string) {
	s := &serving{addr: addr, ln: ln, srv: e.newSrv(e.handler)}
	go func() {
		err := s.srv.Serve(&switchListener{Listener: ln, tls: &e.tls})
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case e.fatal <- fmt.Errorf("%s %s: %w", e.name, addr, err):
			default:
			}
		}
	}()

	e.mu.Lock()
	old := e.cur
	e.cur = s
	e.mu.Unlock()
	if old != nil {
		log.Printf("%s: now listening on %s (was %s); open connections finish on the old listener",
			e.name, ln.Addr(), old.ln.Addr())
		e.retire(old)
	}
}

// stopServing stops accepting connections; open ones drain in the background.
func (e *endpoint) stopServing() {
	e.mu.Lock()
	old := e.cur
	e.cur = nil
	e.mu.Unlock()
	if old != nil {
		log.Printf("%s: stopped listening on %s", e.name, old.ln.Addr())
		e.retire(old)
	}
}

func (e *endpoint) retire(s *serving) {
	e.retired.Add(1)
	go func() {
		defer e.retired.Done()
		_ = e.drain(s)
	}()
}

// drain shuts s down, giving open connections up to the grace period and
// then closing whatever is left, such as long-lived streams.
func (e *endpoint) drain(s *serving) error {
	ctx, cancel := context.WithTimeout(context.Background(), e.grace)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		_ = s.srv.Close()
		return err
	}
	return nil
}

// shutdown stops serving and waits for every server this endpoint ever ran,
// including ones retired by earlier moves.
func (e *endpoint) shutdown() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	cur := e.cur
	e.cur = nil
	e.mu.Unlock()

	var err error
	if cur != nil {
		if derr := e.drain(cur); derr != nil {
			err = fmt.Errorf("shutdown %s: %w", e.name, derr)
		}
	}
	e.retired.Wait()
	return err
}

// switchListener wraps accepted connections in TLS while a configuration is
// installed on the endpoint.
type switchListener struct {
	net.Listener
	tls *atomic.Pointer[tls.Config]
}

func (l *switchListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc := l.tls.Load(); tc != nil {
		return tls.Server(c, tc), nil
	}
	return c, nil
}

// listen binds a TCP address.
func listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// bindMove binds addr for endpoint e to move to. Binding a different host on
// the port e already holds fails while e holds it, so that case gets advice
// instead of a bare "address already in use".
func bindMove(e *endpoint, addr string) (net.Listener, error) {
	ln, err := listen(addr)
	if err == nil {
		return ln, nil
	}
	if cur := e.addr(); errors.Is(err, syscall.EADDRINUSE) && samePort(cur, addr) {
		return nil, fmt.Errorf("cannot listen on %s while %s holds the same port on %s: move to a different port first, then to %s",
			addr, e.name, cur, addr)
	}
	return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
}

func samePort(a, b string) bool {
	_, pa, errA := net.SplitHostPort(a)
	_, pb, errB := net.SplitHostPort(b)
	return errA == nil && errB == nil && pa == pb
}

// newServer is the main listener's http.Server.
func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: it would cut off streamed and upgraded responses.
	}
}

// serve runs h on ln over plain HTTP until ctx is cancelled, then drains for
// up to grace. It returns nil on a clean shutdown.
func serve(ctx context.Context, ln net.Listener, h http.Handler, grace time.Duration) error {
	return serveWith(ctx, ln, h, grace, nil)
}

// serveWith is serve with optional TLS: when tc is non-nil, connections on
// ln are served over TLS using the certificates tc provides.
func serveWith(ctx context.Context, ln net.Listener, h http.Handler, grace time.Duration, tc *tls.Config) error {
	e := newEndpoint("listener", h, grace, newServer)
	e.setTLS(tc)
	e.serveOn(ln, ln.Addr().String())
	return awaitShutdown(ctx, e)
}

// awaitShutdown serves until ctx is cancelled or main stops on its own, then
// drains main and every other endpoint. A clean shutdown returns nil.
func awaitShutdown(ctx context.Context, main *endpoint, others ...*endpoint) error {
	var failure error
	select {
	case err := <-main.fatal:
		failure = fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		log.Println("draining...")
	}

	var errs []error
	for _, e := range append([]*endpoint{main}, others...) {
		if err := e.shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	if failure != nil {
		return failure
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	log.Println("stopped")
	return nil
}
