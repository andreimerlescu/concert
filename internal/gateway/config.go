// Package gateway is Concert's chain gateway: an authenticated,
// loopback-only HTTP service that verifies and settles x402 payments,
// verifies direct destination-tag/memo ledger payments, and checks NFT
// ownership and minimum token/trustline balances. Payer keys never reach it.
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/andreimerlescu/concert/internal/chain/hedera"
	"github.com/andreimerlescu/concert/internal/chain/solana"
	"github.com/andreimerlescu/concert/internal/chain/stellar"
	"github.com/andreimerlescu/concert/internal/chain/xrpl"
	"github.com/andreimerlescu/concert/internal/fastlane"
)

// Network is one entry of the networks file, keyed by CAIP-2 network.
type Network struct {
	RPC               string      `json:"rpc"`               // Solana, XRPL (rippled JSON-RPC), Stellar RPC
	DASRPC            string      `json:"das_rpc,omitempty"` // Optional Solana DAS RPC for Metaplex Core / cNFTs
	Horizon           string      `json:"horizon"`           // Stellar
	Mirror            string      `json:"mirror"`            // Hedera
	FeePayer          string      `json:"fee_payer"`
	SecretEnv         string      `json:"secret_env"`
	MaxFee            json.Number `json:"max_fee"`          // drops, stroops or tinybars
	MaxFeeHB          json.Number `json:"max_fee_tinybars"` // accepted for Hedera
	MaxSponsorPerMin  json.Number `json:"max_sponsor_spend_per_min,omitempty"`
	MinSponsorBalance json.Number `json:"min_sponsor_balance,omitempty"`
	WS                string      `json:"ws"` // no longer used
}

// chain holds what one network needs; payment schemes exist for networks with
// an offer, and read-only clients exist for networks with collections or token gates.
type chain struct {
	family string
	sol    *solana.Scheme
	xrp    *xrpl.Scheme
	xlm    *stellar.Scheme
	hbar   *hedera.Scheme
	pay    mechanism // the payment scheme, for networks with an offer
}

func family(network string) string { f, _, _ := strings.Cut(network, ":"); return f }

func checkEndpoint(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("invalid chain endpoint %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if allowHTTP && u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("chain endpoints must use HTTPS: %q", raw)
}

func number(n json.Number) (uint64, error) {
	if n == "" {
		return 0, nil
	}
	return strconv.ParseUint(n.String(), 10, 64)
}

// LoadNetworks reads the networks file.
func LoadNetworks(path string) (map[string]Network, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	d.UseNumber()
	var n map[string]Network
	if err := d.Decode(&n); err != nil {
		return nil, fmt.Errorf("networks file: %w", err)
	}
	return n, nil
}

// build creates the chain mechanisms for every network the configuration
// uses. getenv supplies optional sponsor secrets. allowHTTP permits loopback
// HTTP endpoints (tests only).
func build(cfg fastlane.Config, networks map[string]Network, getenv func(string) string, allowHTTP bool) (map[string]*chain, error) {
	chains := map[string]*chain{}
	need := func(network string) (*chain, Network, error) {
		if c, ok := chains[network]; ok {
			return c, networks[network], nil
		}
		n, ok := networks[network]
		if !ok {
			return nil, n, fmt.Errorf("missing network configuration: %s", network)
		}
		if n.WS != "" && n.RPC == "" {
			return nil, n, fmt.Errorf("%s: set rpc to rippled's JSON-RPC URL (https://…:51234/); ws is no longer used", network)
		}
		for _, e := range []string{n.RPC, n.DASRPC, n.Horizon, n.Mirror} {
			if e != "" {
				if err := checkEndpoint(e, allowHTTP); err != nil {
					return nil, n, err
				}
			}
		}
		c := &chain{family: family(network)}
		chains[network] = c
		return c, n, nil
	}
	for _, o := range cfg.Offers {
		r := o.Requirements
		c, n, err := need(r.Network)
		if err != nil {
			return nil, err
		}
		maxFee, err := number(n.MaxFee)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid max_fee", r.Network)
		}
		switch c.family {
		case "solana":
			if n.RPC == "" {
				return nil, fmt.Errorf("%s: rpc is required", r.Network)
			}
			if c.sol == nil {
				c.sol = solana.New(r.Network, n.RPC)
			}
		case "xrpl":
			if n.RPC == "" {
				return nil, fmt.Errorf("%s: rpc is required", r.Network)
			}
			if maxFee == 0 {
				maxFee = 50000 // 0.05 XRP ceiling handles mainnet open-ledger fee spikes
			}
			if c.xrp == nil {
				c.xrp = xrpl.New(r.Network, n.RPC, maxFee)
			}
		case "stellar":
			sponsored, _ := r.Extra["areFeesSponsored"].(bool)
			if sponsored {
				secret := getenv(or(n.SecretEnv, "CONCERT_STELLAR_FEE_SECRET"))
				if secret == "" || n.RPC == "" {
					return nil, fmt.Errorf("%s: sponsored Stellar offer requires rpc and sponsor secret", r.Network)
				}
				if c.xlm == nil || c.xlm.Sponsor == nil {
					if c.xlm, err = stellar.New(r.Network, n.RPC, n.Horizon, secret, int64(maxFee)); err != nil {
						return nil, err
					}
				}
			} else {
				if n.Horizon == "" && n.RPC == "" {
					return nil, fmt.Errorf("%s: Stellar horizon or rpc is required", r.Network)
				}
				if c.xlm == nil {
					if c.xlm, err = stellar.NewUnsponsored(r.Network, n.RPC, n.Horizon, int64(maxFee)); err != nil {
						return nil, err
					}
				}
			}
		case "hedera":
			fp, _ := r.Extra["feePayer"].(string)
			sponsored := fp != ""
			if maxFee == 0 {
				if maxFee, err = number(n.MaxFeeHB); err != nil {
					return nil, fmt.Errorf("%s: invalid max_fee_tinybars", r.Network)
				}
			}
			if sponsored {
				secret := getenv(or(n.SecretEnv, "CONCERT_HEDERA_FEE_SECRET"))
				if secret == "" || n.FeePayer == "" || n.Mirror == "" {
					return nil, fmt.Errorf("%s: sponsored Hedera offer requires mirror, fee_payer and sponsor secret", r.Network)
				}
				if fp != n.FeePayer {
					return nil, errors.New("Hedera feePayer must match the managed sponsor")
				}
				if c.hbar == nil || c.hbar.FeePayer == "" {
					if c.hbar, err = hedera.New(r.Network, n.Mirror, n.FeePayer, secret, maxFee); err != nil {
						return nil, err
					}
				}
			} else {
				if n.Mirror == "" {
					return nil, fmt.Errorf("%s: Hedera mirror is required", r.Network)
				}
				if c.hbar == nil {
					if c.hbar, err = hedera.NewUnsponsored(r.Network, n.Mirror, maxFee); err != nil {
						return nil, err
					}
				}
			}
		default:
			return nil, fmt.Errorf("unsupported network %s", r.Network)
		}
	}
	for _, c := range chains {
		switch c.family {
		case "solana":
			c.pay = c.sol
		case "xrpl":
			c.pay = c.xrp
		case "stellar":
			c.pay = c.xlm
		case "hedera":
			c.pay = c.hbar
		}
	}
	initReadOnly := func(network string) error {
		c, n, err := need(network)
		if err != nil {
			return err
		}
		switch c.family {
		case "solana":
			if c.sol == nil {
				if n.RPC == "" {
					return fmt.Errorf("%s: rpc is required", network)
				}
				c.sol = solana.New(network, n.RPC)
			}
		case "xrpl":
			if c.xrp == nil {
				if n.RPC == "" {
					return fmt.Errorf("%s: rpc is required", network)
				}
				c.xrp = xrpl.New(network, n.RPC, 50000)
			}
		case "stellar":
			if c.xlm == nil {
				if c.xlm, err = stellar.NewUnsponsored(network, n.RPC, n.Horizon, 0); err != nil {
					return err
				}
			}
		case "hedera":
			if c.hbar == nil {
				if n.Mirror == "" {
					return fmt.Errorf("%s: mirror is required", network)
				}
				if c.hbar, err = hedera.NewUnsponsored(network, n.Mirror, 0); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, col := range cfg.Collections {
		if err := initReadOnly(col.Network); err != nil {
			return nil, err
		}
	}
	for _, tg := range cfg.TokenGates {
		if err := initReadOnly(tg.Network); err != nil {
			return nil, err
		}
	}
	return chains, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
