// Package fastlane implements Concert's x402 v2 resource server, direct
// on-ledger destination-tag/memo challenge flow, NFT collection and token
// trustline gating, and cross-edge sliding pass cookies. Chain signing,
// settlement and ledger verification are isolated behind an authenticated
// gateway. The proxy never receives a seed phrase or a payer's private key.
package fastlane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	Prefix        = "/_concert"
	Cookie        = "concert_fastlane"
	SessionHeader = "Concert-Session"
	CSRFHeader    = "X-Concert-CSRF"
	MaxBody       = 64 << 10
)

// Requirements follows the x402 v2 wire schema. Amount is an integer string in
// the asset's smallest unit (or canonical decimal string for XRPL IOUs); binary
// floating point is unused.
type Requirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// Offer describes one accepted paid fast-lane currency/token option, with
// optional NFT collection and token/trustline purchase prerequisites.
type Offer struct {
	Label              string       `json:"label"`
	Requirements       Requirements `json:"requirements"`
	DisplayAmount      string       `json:"display_amount,omitempty"`
	AssetSymbol        string       `json:"asset_symbol,omitempty"`
	AssetDecimals      int          `json:"asset_decimals,omitempty"`
	AssetType          string       `json:"asset_type,omitempty"` // native | iou | spl | token2022 | hts | stellar_asset | soroban_sac
	RequireCollections []string     `json:"require_collections,omitempty"`
	RequireTokenGates  []string     `json:"require_token_gates,omitempty"`
	GateMode           string       `json:"gate_mode,omitempty"` // "any" | "all" (default "all")
}

// EffectiveSymbol returns the human-readable ticker for display.
func (o Offer) EffectiveSymbol() string {
	if strings.TrimSpace(o.AssetSymbol) != "" {
		return strings.TrimSpace(o.AssetSymbol)
	}
	return DefaultSymbolForAsset(o.Requirements.Network, o.Requirements.Asset)
}

// EffectiveDecimals returns the decimal precision for formatting atomic amounts.
func (o Offer) EffectiveDecimals() int {
	if o.AssetDecimals > 0 {
		return o.AssetDecimals
	}
	return DefaultDecimalsForAsset(o.Requirements.Network, o.Requirements.Asset)
}

// EffectiveDisplayAmount returns the exact human-readable price string.
func (o Offer) EffectiveDisplayAmount() string {
	if strings.TrimSpace(o.DisplayAmount) != "" {
		return strings.TrimSpace(o.DisplayAmount)
	}
	if chain(o.Requirements.Network) == "xrpl" && o.Requirements.Asset != "XRP" {
		if strings.Contains(o.Requirements.Amount, ".") || o.AssetDecimals == 0 {
			return o.Requirements.Amount
		}
	}
	return FormatAtomicToDecimal(o.Requirements.Amount, o.EffectiveDecimals())
}

// Collection IDs are chain-specific, not names/symbols or metadata URLs.
// XRPL: issuer:taxon or issuer:*; Stellar: SEP-50 contract C... or CODE:ISSUER;
// Hedera: HTS token ID 0.0.N; Solana: verified Metaplex collection mint.
type Collection struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Network    string `json:"network"`
	Collection string `json:"collection"`
	Issuer     string `json:"issuer,omitempty"` // optional issuer/treasury address check
	Usage      string `json:"usage,omitempty"`  // "entry" (default) | "purchase_gate" | "both"
}

func (c Collection) EffectiveUsage() string {
	switch strings.ToLower(strings.TrimSpace(c.Usage)) {
	case "", "entry":
		return "entry"
	case "purchase_gate", "both":
		return strings.ToLower(strings.TrimSpace(c.Usage))
	default:
		return strings.ToLower(strings.TrimSpace(c.Usage))
	}
}

func (c Collection) AllowsEntry() bool {
	u := c.EffectiveUsage()
	return u == "entry" || u == "both"
}

// TokenGate requires a wallet to hold a minimum balance of a native coin or
// issued token/trustline on XRPL, Stellar, Solana, or Hedera.
type TokenGate struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	Network          string `json:"network"`
	Asset            string `json:"asset"`
	AssetSymbol      string `json:"asset_symbol,omitempty"`
	AssetDecimals    int    `json:"asset_decimals,omitempty"`
	MinAmount        string `json:"min_amount"`
	DisplayMinAmount string `json:"display_min_amount,omitempty"`
	Usage            string `json:"usage,omitempty"` // "entry" | "purchase_gate" (default "both")
}

func (g TokenGate) EffectiveUsage() string {
	switch strings.ToLower(strings.TrimSpace(g.Usage)) {
	case "", "both":
		return "both"
	case "entry", "purchase_gate":
		return strings.ToLower(strings.TrimSpace(g.Usage))
	default:
		return strings.ToLower(strings.TrimSpace(g.Usage))
	}
}

func (g TokenGate) AllowsEntry() bool {
	u := g.EffectiveUsage()
	return u == "entry" || u == "both"
}

type Config struct {
	Enabled                bool              `json:"enabled"`
	Origin                 string            `json:"origin"`
	GatewayURL             string            `json:"gateway_url,omitempty"` // ignored: the gateway runs inside Concert
	PolicyMode             string            `json:"policy_mode,omitempty"` // "webhook" | "blocklist" | "none"
	PolicyURL              string            `json:"policy_url,omitempty"`
	PolicyBlocklistFile    string            `json:"policy_blocklist_file,omitempty"`
	AllowUnscreenedMainnet bool              `json:"allow_unscreened_mainnet,omitempty"`
	TestMode               bool              `json:"test_mode"`
	PassSeconds            int               `json:"pass_seconds"`
	PassIdleSeconds        int               `json:"pass_idle_seconds,omitempty"`
	PassMaxSeconds         int               `json:"pass_max_seconds,omitempty"`
	PassSliding            *bool             `json:"pass_sliding,omitempty"`
	NFTPassSeconds         int               `json:"nft_pass_seconds"`
	DirectPayEnabled       *bool             `json:"direct_pay_enabled,omitempty"`
	DirectChallengeSeconds int               `json:"direct_challenge_seconds,omitempty"`
	VerifyAddresses        map[string]string `json:"verify_addresses,omitempty"`
	MaxRecords             int               `json:"max_records"`
	Merchant               string            `json:"merchant"`
	TermsURL               string            `json:"terms_url"`
	PrivacyURL             string            `json:"privacy_url"`
	RefundURL              string            `json:"refund_url"`
	Offers                 []Offer           `json:"offers"`
	Collections            []Collection      `json:"collections"`
	TokenGates             []TokenGate       `json:"token_gates,omitempty"`
}

func (c Config) IsSliding() bool {
	if c.PassSliding == nil {
		return true
	}
	return *c.PassSliding
}

func (c Config) IsDirectPayEnabled() bool {
	if c.DirectPayEnabled == nil {
		return true
	}
	return *c.DirectPayEnabled
}

// EffectivePolicyMode returns the normalized compliance screening mode.
func (c Config) EffectivePolicyMode() string {
	m := strings.ToLower(strings.TrimSpace(c.PolicyMode))
	if m != "" {
		return m
	}
	if strings.TrimSpace(c.PolicyURL) != "" {
		return PolicyModeWebhook
	}
	if strings.TrimSpace(c.PolicyBlocklistFile) != "" {
		return PolicyModeBlocklist
	}
	if c.TestMode {
		return PolicyModeNone
	}
	return PolicyModeWebhook
}

func Load(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 2<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("unexpected trailing configuration data")
	}
	return c, c.Validate()
}

// SaveAtomic validates c and persists it atomically to path with mode 0600.
func SaveAtomic(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(path) == "" {
		return errors.New("fastlane config path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := writeBytesAtomic(path, data); err != nil {
		return err
	}
	_ = syncDir(filepath.Dir(path))
	return nil
}

var atomicAmount = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var entityID = regexp.MustCompile(`^0\.0\.[0-9]+$`)
var xrplAddress = regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{24,34}$`)
var xrplCollection = regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{24,34}:(\*|[0-9]{1,10})$`)
var xrplIOUAsset = regexp.MustCompile(`^[!-~]{3,40}:r[1-9A-HJ-NP-Za-km-z]{24,34}$`)
var stellarAccount = regexp.MustCompile(`^[GC][A-Z2-7]{55}$`)
var stellarContract = regexp.MustCompile(`^C[A-Z2-7]{55}$`)
var stellarIssuedAsset = regexp.MustCompile(`^[A-Za-z0-9]{1,12}:G[A-Z2-7]{55}$`)
var solAddress = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)

func chain(network string) string { s, _, _ := strings.Cut(network, ":"); return s }

func supportedNetwork(n string) bool {
	switch n {
	case "xrpl:0", "xrpl:1", "xrpl:2", "stellar:pubnet", "stellar:testnet", "hedera:mainnet", "hedera:testnet",
		"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1":
		return true
	}
	return false
}

func isTestNetwork(n string) bool {
	return n == "xrpl:1" || n == "xrpl:2" || n == "stellar:testnet" || n == "hedera:testnet" || n == "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
}

func validURL(s string, local bool) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return local && u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()))
}

func validAssetForNetwork(network, asset string) bool {
	switch chain(network) {
	case "xrpl":
		return asset == "XRP" || xrplIOUAsset.MatchString(asset)
	case "stellar":
		return strings.EqualFold(asset, "XLM") || stellarContract.MatchString(asset) || stellarIssuedAsset.MatchString(asset)
	case "hedera":
		return entityID.MatchString(asset)
	case "solana":
		return asset == "SOL" || solAddress.MatchString(asset)
	}
	return false
}

func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !validURL(c.Origin, c.TestMode) {
		return errors.New("origin must be HTTPS (loopback HTTP is allowed only in test mode)")
	}
	u, _ := url.Parse(c.Origin)
	if u.Path != "" && u.Path != "/" {
		return errors.New("origin cannot contain a path")
	}
	c.Origin = strings.TrimRight(c.Origin, "/")
	if c.PolicyURL != "" && !validURL(c.PolicyURL, true) {
		return errors.New("policy_url must be HTTPS or loopback HTTP")
	}
	mode := c.EffectivePolicyMode()
	switch mode {
	case PolicyModeWebhook:
		if !c.TestMode && c.PolicyURL == "" {
			return errors.New("production admission requires a policy_url (or set policy_mode to \"blocklist\" or explicit \"none\")")
		}
	case PolicyModeBlocklist:
		if strings.TrimSpace(c.PolicyBlocklistFile) == "" {
			return errors.New("policy_mode \"blocklist\" requires policy_blocklist_file")
		}
	case PolicyModeNone:
		// Explicitly acknowledged by operator.
	default:
		return fmt.Errorf("invalid policy_mode %q (supported: webhook, blocklist, none)", c.PolicyMode)
	}
	if c.PassSeconds == 0 {
		c.PassSeconds = 300
	}
	if c.PassIdleSeconds == 0 {
		c.PassIdleSeconds = c.PassSeconds
	}
	if c.PassMaxSeconds == 0 {
		c.PassMaxSeconds = max(c.PassSeconds, 1800)
	}
	if c.NFTPassSeconds == 0 {
		c.NFTPassSeconds = 300
	}
	if c.DirectChallengeSeconds == 0 {
		c.DirectChallengeSeconds = 600
	}
	if c.MaxRecords == 0 {
		c.MaxRecords = 100000
	}
	if c.PassSeconds < 30 || c.PassSeconds > 3600 || c.NFTPassSeconds < 5 || c.NFTPassSeconds > 3600 {
		return errors.New("paid pass must be 30–3600 seconds; NFT/token pass 5–3600 seconds")
	}
	if c.PassIdleSeconds < 30 || c.PassIdleSeconds > 3600 || c.PassMaxSeconds < c.PassIdleSeconds || c.PassMaxSeconds > 86400 {
		return errors.New("pass_idle_seconds must be 30–3600 and pass_max_seconds between pass_idle_seconds and 86400")
	}
	if c.DirectChallengeSeconds < 60 || c.DirectChallengeSeconds > 1800 {
		return errors.New("direct_challenge_seconds must be 60–1800")
	}
	if c.MaxRecords < 100 || c.MaxRecords > 1000000 {
		return errors.New("max_records must be 100–1000000")
	}
	if strings.TrimSpace(c.Merchant) == "" || len(c.Merchant) > 120 {
		return errors.New("merchant must be 1–120 characters")
	}
	for _, s := range []string{c.TermsURL, c.PrivacyURL, c.RefundURL} {
		if !validURL(s, c.TestMode) {
			return errors.New("terms_url, privacy_url and refund_url are required HTTPS URLs")
		}
	}
	if len(c.Offers)+len(c.Collections)+len(c.TokenGates) == 0 || len(c.Offers) > 32 || len(c.Collections) > 32 || len(c.TokenGates) > 32 {
		return errors.New("configure at least 1 payment offer, NFT collection, or token gate (max 32 each)")
	}
	for netKey, addr := range c.VerifyAddresses {
		if addr == "" {
			continue
		}
		checkNet := netKey
		if !strings.Contains(checkNet, ":") {
			switch netKey {
			case "xrpl":
				checkNet = "xrpl:0"
			case "stellar":
				checkNet = "stellar:pubnet"
			case "hedera":
				checkNet = "hedera:mainnet"
			case "solana":
				checkNet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
			}
		}
		if !validAddressForNetwork(checkNet, addr) {
			return fmt.Errorf("invalid verify_addresses entry for %s", netKey)
		}
	}

	colIDs := map[string]bool{}
	for i := range c.Collections {
		r := &c.Collections[i]
		if r.ID == "" || len(r.ID) > 64 || colIDs[r.ID] || r.Label == "" {
			return errors.New("collection rule IDs must be unique and labeled")
		}
		colIDs[r.ID] = true
		if !supportedNetwork(r.Network) || (c.TestMode && !isTestNetwork(r.Network)) {
			return errors.New("unsupported collection network or mainnet in test mode")
		}
		u := r.EffectiveUsage()
		if u != "entry" && u != "purchase_gate" && u != "both" {
			return fmt.Errorf("invalid collection usage %q", r.Usage)
		}
		ok := false
		switch chain(r.Network) {
		case "xrpl":
			ok = xrplCollection.MatchString(r.Collection)
		case "stellar":
			ok = stellarContract.MatchString(r.Collection) || stellarIssuedAsset.MatchString(r.Collection)
		case "hedera":
			ok = entityID.MatchString(r.Collection)
		case "solana":
			ok = solAddress.MatchString(r.Collection)
		}
		if !ok {
			return fmt.Errorf("invalid collection identifier for %s", r.Network)
		}
		if r.Issuer != "" && !validAddressForNetwork(r.Network, r.Issuer) {
			return fmt.Errorf("invalid collection issuer for %s", r.Network)
		}
	}

	tokIDs := map[string]bool{}
	for i := range c.TokenGates {
		tg := &c.TokenGates[i]
		if tg.ID == "" || len(tg.ID) > 64 || tokIDs[tg.ID] || tg.Label == "" {
			return errors.New("token_gates IDs must be unique and labeled")
		}
		tokIDs[tg.ID] = true
		if !supportedNetwork(tg.Network) || (c.TestMode && !isTestNetwork(tg.Network)) {
			return errors.New("unsupported token gate network or mainnet in test mode")
		}
		if !validAssetForNetwork(tg.Network, tg.Asset) {
			return fmt.Errorf("invalid token gate asset %q for %s", tg.Asset, tg.Network)
		}
		u := tg.EffectiveUsage()
		if u != "entry" && u != "purchase_gate" && u != "both" {
			return fmt.Errorf("invalid token gate usage %q", tg.Usage)
		}
		if tg.MinAmount == "" && tg.DisplayMinAmount != "" {
			if chain(tg.Network) == "xrpl" && tg.Asset != "XRP" {
				norm, err := NormalizePositiveDecimal(tg.DisplayMinAmount)
				if err != nil {
					return fmt.Errorf("token gate %s: %w", tg.ID, err)
				}
				tg.MinAmount = norm
			} else {
				decs := tg.AssetDecimals
				if decs == 0 {
					decs = DefaultDecimalsForAsset(tg.Network, tg.Asset)
				}
				atomic, err := ParseDecimalToAtomic(tg.DisplayMinAmount, decs)
				if err != nil {
					return fmt.Errorf("token gate %s: %w", tg.ID, err)
				}
				tg.MinAmount = atomic
			}
		}
		if chain(tg.Network) == "xrpl" && tg.Asset != "XRP" {
			if _, err := NormalizePositiveDecimal(tg.MinAmount); err != nil {
				return fmt.Errorf("token gate %s: invalid XRPL decimal min_amount", tg.ID)
			}
		} else if !atomicAmount.MatchString(tg.MinAmount) {
			return fmt.Errorf("token gate %s: min_amount must be a positive integer string in atomic units", tg.ID)
		}
	}

	seen := map[string]bool{}
	for i := range c.Offers {
		o := &c.Offers[i]
		r := &o.Requirements
		if !supportedNetwork(r.Network) || (c.TestMode && !isTestNetwork(r.Network)) {
			return fmt.Errorf("unsupported network or mainnet in test mode: %s", r.Network)
		}
		if !validAssetForNetwork(r.Network, r.Asset) {
			return fmt.Errorf("unsupported asset %q for %s", r.Asset, r.Network)
		}
		isXRPLIOU := chain(r.Network) == "xrpl" && r.Asset != "XRP"
		// Auto-derive atomic amount from display_amount when configured in human decimal form.
		if r.Amount == "" && o.DisplayAmount != "" {
			if isXRPLIOU {
				norm, err := NormalizePositiveDecimal(o.DisplayAmount)
				if err != nil {
					return fmt.Errorf("offer %s: %w", o.Label, err)
				}
				r.Amount = norm
			} else {
				atomic, err := ParseDecimalToAtomic(o.DisplayAmount, o.EffectiveDecimals())
				if err != nil {
					return fmt.Errorf("offer %s: %w", o.Label, err)
				}
				r.Amount = atomic
			}
		}
		if isXRPLIOU {
			norm, err := NormalizePositiveDecimal(r.Amount)
			if err != nil {
				return fmt.Errorf("XRPL IOU amount must be a positive decimal string: %w", err)
			}
			r.Amount = norm
		} else {
			if !atomicAmount.MatchString(r.Amount) {
				return errors.New("amount must be a positive integer string in atomic units")
			}
			n, _ := new(big.Int).SetString(r.Amount, 10)
			if !n.IsInt64() {
				return errors.New("invalid amount")
			}
		}
		if r.PayTo == "" || len(r.PayTo) > 100 || r.MaxTimeoutSeconds < 30 || r.MaxTimeoutSeconds > 300 {
			return errors.New("invalid amount, recipient or payment timeout")
		}
		if r.Extra == nil {
			r.Extra = map[string]any{"areFeesSponsored": false}
		}
		switch chain(r.Network) {
		case "xrpl":
			if r.Scheme != "exact" || r.Extra["areFeesSponsored"] != false || !xrplAddress.MatchString(r.PayTo) {
				return errors.New("XRPL requires exact / areFeesSponsored=false and a classic r-address recipient")
			}
		case "stellar":
			sponsored, hasSpon := r.Extra["areFeesSponsored"].(bool)
			if !hasSpon {
				sponsored = false
				r.Extra["areFeesSponsored"] = false
			}
			if r.Scheme != "exact" || !stellarAccount.MatchString(r.PayTo) {
				return errors.New("Stellar requires exact and a G… or C… recipient")
			}
			if sponsored && !stellarContract.MatchString(r.Asset) {
				return errors.New("sponsored Stellar offers require a Soroban SAC C… asset contract (use areFeesSponsored=false for classic CODE:ISSUER or XLM)")
			}
		case "hedera":
			feePayer, _ := r.Extra["feePayer"].(string)
			sponsored := feePayer != ""
			if r.Scheme != "exact" || !entityID.MatchString(r.PayTo) {
				return errors.New("Hedera requires exact and a numeric 0.0.N recipient")
			}
			if sponsored {
				if !entityID.MatchString(feePayer) || feePayer == r.PayTo {
					return errors.New("sponsored Hedera offers require a distinct numeric extra.feePayer sponsor")
				}
			} else if r.Extra["areFeesSponsored"] != false {
				return errors.New("Hedera requires either a distinct numeric extra.feePayer sponsor or areFeesSponsored=false for payer-paid fees")
			}
		case "solana":
			if r.Asset == "SOL" {
				if (r.Scheme != "concert-native-sol" && r.Scheme != "exact") || r.Extra["areFeesSponsored"] != false || !solAddress.MatchString(r.PayTo) {
					return errors.New("native SOL uses concert-native-sol or exact / SOL / areFeesSponsored=false and a base58 recipient")
				}
			} else {
				if r.Scheme != "exact" || r.Extra["areFeesSponsored"] != false || !solAddress.MatchString(r.PayTo) {
					return errors.New("SPL token offers require exact / mint pubkey / areFeesSponsored=false and a base58 recipient")
				}
			}
		}
		if o.GateMode != "" && o.GateMode != "any" && o.GateMode != "all" {
			return fmt.Errorf("offer %s: invalid gate_mode %q (must be any or all)", o.Label, o.GateMode)
		}
		for _, cid := range o.RequireCollections {
			if !colIDs[cid] {
				return fmt.Errorf("offer %s references unknown collection %q", o.Label, cid)
			}
		}
		for _, tid := range o.RequireTokenGates {
			if !tokIDs[tid] {
				return fmt.Errorf("offer %s references unknown token gate %q", o.Label, tid)
			}
		}
		key := r.Scheme + ":" + r.Network + ":" + r.Asset
		if seen[key] {
			return errors.New("duplicate payment offer")
		}
		seen[key] = true
	}
	return nil
}
