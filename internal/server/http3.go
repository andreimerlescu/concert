package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Opt-in HTTP/3 (QUIC) listener using github.com/quic-go/quic-go/http3.
// Shares Concert's TLS configuration (hot-reloaded PEM certificates, ACME
// autocert, and multi-vhost SNI) and HTTP handler chain, and advertises
// HTTP/3 via Alt-Svc on HTTP/1.1 and HTTP/2 HTTPS responses.

func altSvcMiddleware(listenAddr string, next http.Handler) http.Handler {
	_, port, _ := net.SplitHostPort(listenAddr)
	if port == "" {
		port = "443"
	}
	val := `h3=":` + port + `"; ma=2592000`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.ProtoMajor < 3 {
			w.Header().Add("Alt-Svc", val)
		}
		next.ServeHTTP(w, r)
	})
}

// startHTTP3Server binds UDP on listenAddr and serves HTTP/3 using tlsCfg and
// handler. Returns a graceful shutdown closure.
func startHTTP3Server(listenAddr string, tlsCfg *tls.Config, handler http.Handler) (func() error, error) {
	if tlsCfg == nil {
		return nil, errors.New("http3 requires TLS")
	}
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("http3 UDP listen %s: %w", listenAddr, err)
	}
	closeFn, err := startHTTP3OnPacketConn(pc, tlsCfg, handler)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return closeFn, nil
}

// h3AbortMarkerServer satisfies httputil.ReverseProxy.shouldPanicOnCopyError,
// which checks req.Context().Value(http.ServerContextKey) != nil before
// panicking with http.ErrAbortHandler on mid-body copy errors. quic-go/http3
// populates http3.ServerContextKey rather than http.ServerContextKey, so
// without this wrapper ReverseProxy would suppress the panic and close the
// QUIC stream cleanly with a silently truncated 200 OK.
var h3AbortMarkerServer = &http.Server{}

func withHTTP3AbortContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(http.ServerContextKey) == nil {
			r = r.WithContext(context.WithValue(r.Context(), http.ServerContextKey, h3AbortMarkerServer))
		}
		next.ServeHTTP(w, r)
	})
}

func startHTTP3OnPacketConn(pc net.PacketConn, tlsCfg *tls.Config, handler http.Handler) (func() error, error) {
	h3TLS := tlsCfg.Clone()
	h3TLS.MinVersion = tls.VersionTLS13
	h3TLS.NextProtos = []string{http3.NextProtoH3}

	srv := &http3.Server{
		Addr:        pc.LocalAddr().String(),
		TLSConfig:   h3TLS,
		Handler:     withHTTP3AbortContext(handler),
		IdleTimeout: 60 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(pc); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Printf("http3: serve %s: %v", pc.LocalAddr(), err)
		}
	}()

	var once sync.Once
	return func() error {
		var retErr error
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
			defer cancel()
			retErr = srv.Shutdown(ctx)
			_ = pc.Close()
			<-done
		})
		return retErr
	}, nil
}
