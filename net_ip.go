package main

import (
	"net/http"
	"net/netip"
	"strings"
)

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// clientIP returns the connection address, or, when the connection comes
// from a trusted proxy, the right-most X-Forwarded-For entry that is not
// itself a trusted proxy. Entries left of that point are client-controlled
// and ignored. Scans right to left without allocating.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	remote, ok := remoteAddr(r)
	if !ok {
		return netip.Addr{}
	}
	if !containsAddr(trusted, remote) {
		return remote
	}

	hop := remote
	vals := r.Header.Values("X-Forwarded-For")
	for i := len(vals) - 1; i >= 0; i-- {
		s := vals[i]
		for s != "" {
			var part string
			if j := strings.LastIndexByte(s, ','); j >= 0 {
				part, s = s[j+1:], s[:j]
			} else {
				part, s = s, ""
			}
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			a, err := netip.ParseAddr(part)
			if err != nil {
				return remote // malformed chain: trust nothing in it
			}
			a = a.Unmap()
			if !containsAddr(trusted, a) {
				return a
			}
			hop = a
		}
	}
	return hop // every hop was trusted: internal traffic
}
