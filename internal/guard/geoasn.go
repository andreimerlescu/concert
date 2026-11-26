package guard

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	// ErrInvalidCountryCode is returned when a Geo/ASN policy receives a
	// country code that is not a valid 2-letter ASCII ISO-3166-1 alpha-2 code.
	ErrInvalidCountryCode = errors.New("guard: invalid ISO-3166-1 alpha-2 country code")

	// ErrInvalidASN is returned when a Geo/ASN policy receives ASN 0.
	ErrInvalidASN = errors.New("guard: invalid ASN (must be > 0)")
)

// IPLookup resolves an IP address to its ISO-3166-1 alpha-2 country code and
// autonomous system number (ASN).
//
// Implementations must be safe for concurrent use when shared by a
// [GeoASNPolicy]. ok is false when the backing database has no record for ip
// or is temporarily unavailable. This narrow interface aligns with Concert's
// internal ipinfo lookup (CountryCode, Number, Found).
type IPLookup interface {
	Lookup(ip netip.Addr) (country string, asn uint32, ok bool)
}

// IPLookupFunc is a function adapter implementing [IPLookup].
type IPLookupFunc func(ip netip.Addr) (country string, asn uint32, ok bool)

// Lookup invokes f(ip) to satisfy [IPLookup].
//
// # Parameters
//
//   - ip: Normalized client IP address.
//
// # Returns
//
// Country code, ASN, and found flag returned by f; returns ("", 0, false) if f is nil.
//
// # Example
//
//	lookup := guard.IPLookupFunc(func(ip netip.Addr) (string, uint32, bool) {
//	    return "US", 13335, true
//	})
//	cc, asn, ok := lookup.Lookup(netip.MustParseAddr("1.1.1.1"))
//	_, _, _ = cc, asn, ok
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (f IPLookupFunc) Lookup(ip netip.Addr) (country string, asn uint32, ok bool) {
	if f == nil {
		return "", 0, false
	}
	return f(ip)
}

// GeoASNConfig defines allow and deny rules for [GeoASNPolicy].
type GeoASNConfig struct {
	// AllowCountries restricts access to the listed ISO-3166-1 alpha-2 country
	// codes (case-insensitive) when non-empty. Combined via OR with AllowASNs.
	AllowCountries []string

	// DenyCountries blocks traffic from the listed ISO-3166-1 alpha-2 country
	// codes. Deny rules always take precedence over allow rules.
	DenyCountries []string

	// AllowASNs restricts access to the listed autonomous system numbers when
	// non-empty. Combined via OR with AllowCountries.
	AllowASNs []uint32

	// DenyASNs blocks traffic from the listed autonomous system numbers.
	// Deny rules always take precedence over allow rules.
	DenyASNs []uint32

	// FailOpen controls behavior when the lookup database is nil or returns
	// ok == false for an address. When true, unknown addresses are allowed;
	// when false, unknown addresses are denied whenever any policy rule is set.
	FailOpen bool
}

// GeoASNPolicy evaluates allow and deny rules by ASN and ISO-3166-1 alpha-2
// country code with strict deny-overrides-allow precedence.
//
// All rule maps are immutable after construction by [NewGeoASNPolicy], so
// [GeoASNPolicy.Check] and [GeoASNPolicy.Allow] are lock-free and safe for
// concurrent use (as long as the supplied [IPLookup] is concurrency-safe).
type GeoASNPolicy struct {
	lookup         IPLookup
	failOpen       bool
	hasRules       bool
	hasAllowRules  bool
	allowCountries map[string]struct{}
	denyCountries  map[string]struct{}
	allowASNs      map[uint32]struct{}
	denyASNs       map[uint32]struct{}
}

// NewGeoASNPolicy validates cfg and constructs an immutable [GeoASNPolicy].
//
// # Parameters
//
//   - cfg: Country and ASN allow/deny lists plus fail-open setting. Input
//     slices are copied and normalized; later caller mutations have no effect.
//   - lookup: Narrow [IPLookup] provider; may be nil (handled per cfg.FailOpen).
//
// # Returns
//
// A ready-to-use *GeoASNPolicy, or an error matching [ErrInvalidCountryCode]
// or [ErrInvalidASN].
//
// # Example
//
//	pol, err := guard.NewGeoASNPolicy(guard.GeoASNConfig{
//	    DenyASNs: []uint32{64512},
//	    FailOpen: true,
//	}, lookup)
//	if err != nil {
//	    return err
//	}
//	_ = pol
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:540 (function value)
//   - internal/guard/fuzz_test.go:543 (function value)
//   - internal/guard/fuzz_test.go:567 (function value)
//   - internal/guard/fuzz_test.go:604 (function value)
//   - internal/guard/fuzz_test.go:618 (function value)
//   - internal/guard/guard_test.go:540 (direct call)
//   - internal/guard/guard_test.go:543 (direct call)
//   - internal/guard/guard_test.go:567 (direct call)
//   - internal/guard/guard_test.go:604 (direct call)
//   - internal/guard/guard_test.go:618 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func NewGeoASNPolicy(cfg GeoASNConfig, lookup IPLookup) (*GeoASNPolicy, error) {
	allowCC, err := normalizeCountrySet(cfg.AllowCountries)
	if err != nil {
		return nil, err
	}
	denyCC, err := normalizeCountrySet(cfg.DenyCountries)
	if err != nil {
		return nil, err
	}
	allowASN, err := normalizeASNSet(cfg.AllowASNs)
	if err != nil {
		return nil, err
	}
	denyASN, err := normalizeASNSet(cfg.DenyASNs)
	if err != nil {
		return nil, err
	}

	hasAllow := len(allowCC) > 0 || len(allowASN) > 0
	hasRules := hasAllow || len(denyCC) > 0 || len(denyASN) > 0

	return &GeoASNPolicy{
		lookup:         lookup,
		failOpen:       cfg.FailOpen,
		hasRules:       hasRules,
		hasAllowRules:  hasAllow,
		allowCountries: allowCC,
		denyCountries:  denyCC,
		allowASNs:      allowASN,
		denyASNs:       denyASN,
	}, nil
}

// Allow reports whether ip is permitted by the Geo/ASN policy. It is a
// convenience wrapper around [GeoASNPolicy.Check].
//
// # Parameters
//
//   - ip: Client IP address to evaluate.
//
// # Returns
//
// true if ip is allowed; false if denied.
//
// # Example
//
//	ok := pol.Allow(netip.MustParseAddr("198.51.100.2"))
//	_ = ok
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/fuzz_test.go:597 (function value)
//   - internal/guard/fuzz_test.go:611 (function value)
//   - internal/guard/fuzz_test.go:614 (function value)
//   - internal/guard/fuzz_test.go:625 (function value)
//   - internal/guard/guard_test.go:597 (direct call)
//   - internal/guard/guard_test.go:611 (direct call)
//   - internal/guard/guard_test.go:614 (direct call)
//   - internal/guard/guard_test.go:625 (direct call)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (p *GeoASNPolicy) Allow(ip netip.Addr) bool {
	allowed, _ := p.Check(ip)
	return allowed
}

// Check evaluates ip against the policy and returns whether it is permitted
// alongside a short machine-readable reason when denied or failed-open.
//
// Precedence:
//  1. Empty policy (no allow or deny rules configured) -> (true, "").
//  2. Invalid IP address -> (false, "invalid_ip").
//  3. Nil lookup or database miss (ok == false) -> allowed if FailOpen, else denied.
//  4. Deny ASN or deny country -> (false, "denied_asn" | "denied_country").
//     Deny strictly overrides allow.
//  5. If any allowlist is configured, IP must match AllowASNs or AllowCountries.
//  6. Otherwise -> (true, "").
//
// # Parameters
//
//   - ip: Client IP address; IPv4-mapped IPv6 addresses are unmapped and zones
//     are stripped before lookup.
//
// # Returns
//
// (allowed, reason). reason is empty on normal allow decisions.
//
// # Example
//
//	allowed, reason := pol.Check(netip.MustParseAddr("198.51.100.2"))
//	_, _ = allowed, reason
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:213 (function value)
//   - internal/guard/fuzz_test.go:593 (function value)
//   - internal/guard/geoasn.go:213 (direct call)
//   - internal/guard/guard_test.go:593 (direct call)
//   - internal/guard/queue_quota.go:213 (function value)
//   - internal/guard/ratelimit.go:213 (function value)
//   - internal/guard/secret.go:213 (function value)
//   - internal/guard/shedder.go:213 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func (p *GeoASNPolicy) Check(ip netip.Addr) (allowed bool, reason string) {
	if p == nil || !p.hasRules {
		return true, ""
	}
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return false, "invalid_ip"
	}
	if p.lookup == nil {
		if p.failOpen {
			return true, "lookup_unavailable_fail_open"
		}
		return false, "lookup_unavailable"
	}

	country, asn, ok := p.lookup.Lookup(ip)
	if !ok {
		if p.failOpen {
			return true, "unknown_ip_fail_open"
		}
		return false, "unknown_ip"
	}

	cc := strings.ToUpper(strings.TrimSpace(country))

	// Strict deny-overrides-allow precedence: check both deny lists before any allowlist.
	if asn != 0 {
		if _, denied := p.denyASNs[asn]; denied {
			return false, "denied_asn"
		}
	}
	if cc != "" {
		if _, denied := p.denyCountries[cc]; denied {
			return false, "denied_country"
		}
	}

	if p.hasAllowRules {
		if asn != 0 {
			if _, ok := p.allowASNs[asn]; ok {
				return true, ""
			}
		}
		if cc != "" {
			if _, ok := p.allowCountries[cc]; ok {
				return true, ""
			}
		}
		return false, "not_allowlisted"
	}

	return true, ""
}

// normalizeCountrySet validates and uppercases a slice of ISO-3166-1 alpha-2
// country codes into an immutable set map.
//
// # Parameters
//
//   - codes: Raw country code strings.
//
// # Returns
//
// Normalized uppercase set map, or an error matching [ErrInvalidCountryCode].
//
// # Example
//
//	set, err := normalizeCountrySet([]string{"us", "DE"})
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:149 (function value)
//   - internal/guard/challenge.go:153 (function value)
//   - internal/guard/geoasn.go:149 (direct call)
//   - internal/guard/geoasn.go:153 (direct call)
//   - internal/guard/queue_quota.go:149 (function value)
//   - internal/guard/queue_quota.go:153 (function value)
//   - internal/guard/ratelimit.go:149 (function value)
//   - internal/guard/ratelimit.go:153 (function value)
//   - internal/guard/secret.go:149 (function value)
//   - internal/guard/secret.go:153 (function value)
//   - internal/guard/shedder.go:149 (function value)
//   - internal/guard/shedder.go:153 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func normalizeCountrySet(codes []string) (map[string]struct{}, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	out := make(map[string]struct{}, len(codes))
	for _, raw := range codes {
		cc := strings.ToUpper(strings.TrimSpace(raw))
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			return nil, fmt.Errorf("%w: %q", ErrInvalidCountryCode, raw)
		}
		out[cc] = struct{}{}
	}
	return out, nil
}

// normalizeASNSet validates a slice of ASNs (rejecting 0) into an immutable set map.
//
// # Parameters
//
//   - asns: Raw autonomous system numbers.
//
// # Returns
//
// Set map of valid ASNs, or an error matching [ErrInvalidASN].
//
// # Example
//
//	set, err := normalizeASNSet([]uint32{13335, 15169})
//
// # Used By
//
// Generated from repository symbol references; do not hand-edit.
//
//   - internal/guard/challenge.go:157 (function value)
//   - internal/guard/challenge.go:161 (function value)
//   - internal/guard/geoasn.go:157 (direct call)
//   - internal/guard/geoasn.go:161 (direct call)
//   - internal/guard/queue_quota.go:157 (function value)
//   - internal/guard/queue_quota.go:161 (function value)
//   - internal/guard/ratelimit.go:157 (function value)
//   - internal/guard/ratelimit.go:161 (function value)
//   - internal/guard/secret.go:157 (function value)
//   - internal/guard/secret.go:161 (function value)
//   - internal/guard/shedder.go:157 (function value)
//   - internal/guard/shedder.go:161 (function value)
//
// Scope: internal/guard (including tests); build configuration: darwin/arm64, default tags.
// Interface/runtime/external uses are not exhaustive.
func normalizeASNSet(asns []uint32) (map[uint32]struct{}, error) {
	if len(asns) == 0 {
		return nil, nil
	}
	out := make(map[uint32]struct{}, len(asns))
	for _, asn := range asns {
		if asn == 0 {
			return nil, ErrInvalidASN
		}
		out[asn] = struct{}{}
	}
	return out, nil
}
