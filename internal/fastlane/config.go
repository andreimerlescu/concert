// Package fastlane implements Concert's x402 v2 resource server. Chain signing,
// settlement and NFT verification are isolated behind an authenticated gateway.
// The proxy never receives a seed phrase or a payer's private key.
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

// Requirements follows the x402 v2 wire schema. Amount is always an integer
// string in the native asset's smallest unit; binary floating point is unused.
type Requirements struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Asset             string         `json:"asset"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds"`
	Extra             map[string]any `json:"extra,omitempty"`
}

type Offer struct {
	Label        string       `json:"label"`
	Requirements Requirements `json:"requirements"`
	// DepositOnly sells the pass only for a plain payment to PayTo, matched by
	// a per-visitor amount, tag or memo. No x402 authorization is accepted, so
	// no scheme, asset or sponsor is needed.
	DepositOnly bool `json:"deposit_only,omitempty"`
}

// Collection IDs are chain-specific, not names/symbols or metadata URLs.
// XRPL: issuer:taxon; Stellar: SEP-50 contract; Hedera: HTS token ID;
// Solana: a verified Metaplex Token Metadata collection mint.
type Collection struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Network    string `json:"network"`
	Collection string `json:"collection"`
}

type Config struct {
	Enabled        bool         `json:"enabled"`
	Origin         string       `json:"origin"`
	GatewayURL     string       `json:"gateway_url,omitempty"` // ignored: the gateway runs inside Concert
	PolicyURL      string       `json:"policy_url,omitempty"`
	TestMode       bool         `json:"test_mode"`
	PassSeconds    int          `json:"pass_seconds"`
	NFTPassSeconds int          `json:"nft_pass_seconds"`
	MaxRecords     int          `json:"max_records"`
	Merchant       string       `json:"merchant"`
	TermsURL       string       `json:"terms_url"`
	PrivacyURL     string       `json:"privacy_url"`
	RefundURL      string       `json:"refund_url"`
	Offers         []Offer      `json:"offers"`
	Collections    []Collection `json:"collections"`
}

func Load(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("unexpected trailing configuration data")
	}
	return c, c.Validate()
}

var atomicAmount = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var entityID = regexp.MustCompile(`^0\.0\.[0-9]+$`)
var xrplAddress = regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{24,34}$`)
var xrplCollection = regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{24,34}:[0-9]{1,10}$`)
var stellarAccount = regexp.MustCompile(`^[GC][A-Z2-7]{55}$`)
var stellarContract = regexp.MustCompile(`^C[A-Z2-7]{55}$`)
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
	if !c.TestMode && c.PolicyURL == "" {
		return errors.New("production admission requires a policy_url; screening failures deny admission")
	}
	if c.PassSeconds == 0 {
		c.PassSeconds = 300
	}
	if c.NFTPassSeconds == 0 {
		c.NFTPassSeconds = 30
	}
	if c.MaxRecords == 0 {
		c.MaxRecords = 100000
	}
	if c.PassSeconds < 30 || c.PassSeconds > 3600 || c.NFTPassSeconds < 5 || c.NFTPassSeconds > 60 {
		return errors.New("paid pass must be 30–3600 seconds; NFT proof lease 5–60 seconds")
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
	if len(c.Offers)+len(c.Collections) == 0 || len(c.Offers) > 8 || len(c.Collections) > 32 {
		return errors.New("configure 1–8 payment offers and/or 1–32 NFT collections")
	}
	seen := map[string]bool{}
	for _, o := range c.Offers {
		r := o.Requirements
		if o.DepositOnly {
			if err := validDepositOffer(c, o); err != nil {
				return err
			}
			key := "deposit:" + r.Network
			if seen[key] {
				return errors.New("duplicate payment offer")
			}
			seen[key] = true
			continue
		}
		if !supportedNetwork(r.Network) || (c.TestMode && !isTestNetwork(r.Network)) {
			return fmt.Errorf("unsupported network or mainnet in test mode: %s", r.Network)
		}
		if !atomicAmount.MatchString(r.Amount) {
			return errors.New("amount must be a positive integer string in atomic units")
		}
		n, _ := new(big.Int).SetString(r.Amount, 10)
		if !n.IsInt64() || r.PayTo == "" || len(r.PayTo) > 100 || r.MaxTimeoutSeconds < 30 || r.MaxTimeoutSeconds > 300 {
			return errors.New("invalid amount, recipient or payment timeout")
		}
		if r.Extra == nil {
			return errors.New("payment requirements.extra must contain chain-specific parameters")
		}
		switch chain(r.Network) {
		case "xrpl":
			if r.Scheme != "exact" || r.Asset != "XRP" || r.Extra["areFeesSponsored"] != false || !xrplAddress.MatchString(r.PayTo) {
				return errors.New("XRP requires exact / XRP / areFeesSponsored=false and a classic r-address recipient")
			}
		case "stellar":
			if r.Scheme != "exact" || !stellarContract.MatchString(r.Asset) || r.Extra["areFeesSponsored"] != true || !stellarAccount.MatchString(r.PayTo) {
				return errors.New("XLM requires exact with the native XLM Stellar Asset Contract, sponsored fees and a G… or C… recipient")
			}
		case "hedera":
			// The sponsor pays network fees and must never be the recipient.
			feePayer, _ := r.Extra["feePayer"].(string)
			if r.Scheme != "exact" || r.Asset != "0.0.0" || !entityID.MatchString(r.PayTo) || !entityID.MatchString(feePayer) || feePayer == r.PayTo {
				return errors.New("HBAR requires exact / 0.0.0 / numeric recipient and a distinct numeric extra.feePayer sponsor")
			}
		case "solana":
			if r.Scheme != "concert-native-sol" || r.Asset != "SOL" || r.Extra["areFeesSponsored"] != false || !solAddress.MatchString(r.PayTo) {
				return errors.New("native SOL uses concert-native-sol / SOL (not the standard SPL-token exact scheme) and a base58 recipient")
			}
		}
		key := r.Scheme + ":" + r.Network + ":" + r.Asset
		if seen[key] {
			return errors.New("duplicate payment offer")
		}
		seen[key] = true
	}
	seen = map[string]bool{}
	for _, r := range c.Collections {
		if r.ID == "" || len(r.ID) > 64 || seen[r.ID] || r.Label == "" {
			return errors.New("collection rule IDs must be unique and labeled")
		}
		seen[r.ID] = true
		if !supportedNetwork(r.Network) || (c.TestMode && !isTestNetwork(r.Network)) {
			return errors.New("unsupported collection network or mainnet in test mode")
		}
		ok := false
		switch chain(r.Network) {
		case "xrpl":
			ok = xrplCollection.MatchString(r.Collection)
		case "stellar":
			ok = stellarContract.MatchString(r.Collection)
		case "hedera":
			ok = entityID.MatchString(r.Collection)
		case "solana":
			ok = solAddress.MatchString(r.Collection)
		}
		if !ok {
			return fmt.Errorf("invalid collection identifier for %s", r.Network)
		}
	}
	return nil
}

// validDepositOffer checks a deposit-only offer: a supported network, a price
// and a receiving address in that chain's format. Nothing else applies.
func validDepositOffer(c *Config, o Offer) error {
	r := o.Requirements
	if !supportedNetwork(r.Network) || (c.TestMode && !isTestNetwork(r.Network)) {
		return fmt.Errorf("unsupported network or mainnet in test mode: %s", r.Network)
	}
	if !atomicAmount.MatchString(r.Amount) {
		return errors.New("amount must be a positive integer string in atomic units")
	}
	if n, _ := new(big.Int).SetString(r.Amount, 10); !n.IsInt64() {
		return errors.New("amount is too large")
	}
	ok := false
	switch chain(r.Network) {
	case "xrpl":
		ok = xrplAddress.MatchString(r.PayTo)
	case "stellar":
		ok = stellarAccount.MatchString(r.PayTo) && r.PayTo[0] == 'G' // Horizon lists a classic account's payments only
	case "hedera":
		ok = entityID.MatchString(r.PayTo)
	case "solana":
		ok = solAddress.MatchString(r.PayTo)
	}
	if !ok {
		return fmt.Errorf("invalid receiving address for %s", r.Network)
	}
	return nil
}
