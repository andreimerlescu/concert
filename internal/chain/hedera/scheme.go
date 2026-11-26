package hedera

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andreimerlescu/concert/internal/chain/httpx"
	"github.com/andreimerlescu/concert/internal/x402"
	"github.com/hiero-ledger/hiero-sdk-go/v2/proto/services"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	"google.golang.org/protobuf/proto"
)

const (
	Mainnet = "hedera:mainnet"
	Testnet = "hedera:testnet"
	// DefaultMaxFeeTinybars is what the official x402 Hedera client
	// authorizes; the sponsor pays it, so larger payloads are refused.
	DefaultMaxFeeTinybars = 100_000_000
)

// Mirror is a Hedera mirror node REST client.
type Mirror struct{ URL string }

type MirrorKey struct {
	Type string `json:"_type"`
	Key  string `json:"key"`
}

type MirrorAccount struct {
	Key     *MirrorKey `json:"key"`
	Deleted bool       `json:"deleted"`
	Balance struct {
		Balance json.Number `json:"balance"`
	} `json:"balance"`
}

func (m Mirror) get(ctx context.Context, path string, out any) error {
	return httpx.GetJSON(ctx, strings.TrimRight(m.URL, "/")+path, out)
}

func (m Mirror) Account(ctx context.Context, id string) (*MirrorAccount, error) {
	var a MirrorAccount
	if err := m.get(ctx, "/api/v1/accounts/"+url.PathEscape(id), &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// keyNode is a mirror key reconstructed for signature evaluation.
type keyNode struct {
	pub       *hiero.PublicKey
	raw       []byte
	threshold int
	children  []keyNode
}

func fromProtoKey(k *services.Key, depth int) (keyNode, error) {
	if depth > 8 || k == nil {
		return keyNode{}, errors.New("unsupported key")
	}
	switch v := k.Key.(type) {
	case *services.Key_Ed25519:
		pk, err := hiero.PublicKeyFromBytesEd25519(v.Ed25519)
		return keyNode{pub: &pk, raw: v.Ed25519}, err
	case *services.Key_ECDSASecp256K1:
		pk, err := hiero.PublicKeyFromBytesECDSA(v.ECDSASecp256K1)
		return keyNode{pub: &pk, raw: v.ECDSASecp256K1}, err
	case *services.Key_KeyList:
		n := keyNode{}
		for _, c := range v.KeyList.GetKeys() {
			child, err := fromProtoKey(c, depth+1)
			if err != nil {
				return n, err
			}
			n.children = append(n.children, child)
		}
		n.threshold = len(n.children)
		return n, nil
	case *services.Key_ThresholdKey:
		n := keyNode{threshold: int(v.ThresholdKey.GetThreshold())}
		for _, c := range v.ThresholdKey.GetKeys().GetKeys() {
			child, err := fromProtoKey(c, depth+1)
			if err != nil {
				return n, err
			}
			n.children = append(n.children, child)
		}
		if n.threshold <= 0 {
			n.threshold = len(n.children)
		}
		return n, nil
	}
	return keyNode{}, errors.New("unsupported key type")
}

func parseMirrorKey(k *MirrorKey) (keyNode, error) {
	if k == nil || k.Key == "" {
		return keyNode{}, errors.New("could not resolve payer key")
	}
	raw, err := hex.DecodeString(k.Key)
	if err != nil {
		return keyNode{}, err
	}
	switch k.Type {
	case "ED25519":
		return fromProtoKey(&services.Key{Key: &services.Key_Ed25519{Ed25519: raw}}, 0)
	case "ECDSA_SECP256K1":
		return fromProtoKey(&services.Key{Key: &services.Key_ECDSASecp256K1{ECDSASecp256K1: raw}}, 0)
	case "ProtobufEncoded":
		var pk services.Key
		if err := proto.Unmarshal(raw, &pk); err != nil {
			return keyNode{}, err
		}
		return fromProtoKey(&pk, 0)
	}
	return keyNode{}, errors.New("unsupported key type")
}

func (n keyNode) signs(st *services.SignedTransaction) bool {
	if n.pub != nil {
		for _, pair := range st.GetSigMap().GetSigPair() {
			if !bytes.Equal(pair.PubKeyPrefix, n.raw) {
				continue
			}
			var sig []byte
			switch s := pair.Signature.(type) {
			case *services.SignaturePair_Ed25519:
				sig = s.Ed25519
			case *services.SignaturePair_ECDSASecp256K1:
				sig = s.ECDSASecp256K1
			}
			return sig != nil && n.pub.VerifySignedMessage(st.BodyBytes, sig)
		}
		return false
	}
	got := 0
	for _, c := range n.children {
		if c.signs(st) {
			got++
		}
	}
	return len(n.children) > 0 && got >= n.threshold
}

// signsAll reports whether the key signed every node's body.
func (n keyNode) signsAll(p *Parsed) bool {
	for _, st := range p.Signed {
		if !n.signs(st) {
			return false
		}
	}
	return len(p.Signed) > 0
}

// Submitter adds the sponsor's signature and submits, returning the
// transaction ID once a receipt reports SUCCESS.
type Submitter func(ctx context.Context, p *Parsed, network string) (string, error)

// Scheme verifies and settles "exact" HBAR and HTS fungible token payments
// (either payer-pays-fees with zero hot keys or with one managed sponsor).
type Scheme struct {
	Network    string
	FeePayer   string
	Mirror     Mirror
	MaxFee     uint64
	Submit     Submitter
	sponsorKey hiero.PrivateKey
	hasSponsor bool
}

// New builds a scheme that signs as feePayer with the DER sponsor key.
func New(network, mirror, feePayer, sponsorKeyDER string, maxFee uint64) (*Scheme, error) {
	if network != Mainnet && network != Testnet {
		return nil, errors.New("unsupported Hedera network")
	}
	if maxFee == 0 {
		maxFee = DefaultMaxFeeTinybars
	}
	s := &Scheme{Network: network, FeePayer: feePayer, Mirror: Mirror{URL: mirror}, MaxFee: maxFee}
	if strings.TrimSpace(sponsorKeyDER) != "" {
		key, err := hiero.PrivateKeyFromStringDer(sponsorKeyDER)
		if err != nil {
			return nil, errors.New("invalid Hedera sponsor key")
		}
		s.sponsorKey = key
		s.hasSponsor = true
	}
	s.Submit = s.submit
	return s, nil
}

// NewUnsponsored creates a zero-hot-key Hedera scheme for payer-pays-fees
// HBAR/HTS payments, direct memo proofs, token balance gating, and NFT checks.
func NewUnsponsored(network, mirror string, maxFee uint64) (*Scheme, error) {
	return New(network, mirror, "", "", maxFee)
}

func isPayerPaid(r x402.Requirements) bool {
	if r.Extra == nil {
		return false
	}
	if fp, _ := r.Extra["feePayer"].(string); fp != "" {
		return false
	}
	if v, ok := r.Extra["areFeesSponsored"].(bool); ok && !v {
		return true
	}
	return false
}

func invalid(reason, payer string) x402.VerifyResponse { return x402.Invalid(reason, payer) }

func (s *Scheme) requirements(p x402.Payload, r x402.Requirements) string {
	a := p.Accepted
	switch {
	case a.Scheme != "exact" || r.Scheme != "exact":
		return "unsupported_scheme"
	case a.Network != r.Network:
		return "network_mismatch"
	case a.Asset != r.Asset || a.Amount != r.Amount || a.PayTo != r.PayTo || a.MaxTimeoutSeconds != r.MaxTimeoutSeconds || a.Extra["feePayer"] != r.Extra["feePayer"]:
		return "accepted_payment_requirements_mismatch"
	case r.Network != s.Network:
		return "network_mismatch"
	case !ValidEntityID(r.Asset):
		return "invalid_asset"
	case !ValidEntityID(r.PayTo):
		return "invalid_exact_hedera_payload_pay_to"
	}
	if _, ok := new(big.Int).SetString(r.Amount, 10); !ok || strings.HasPrefix(r.Amount, "-") {
		return "invalid_amount"
	}
	if isPayerPaid(r) {
		return ""
	}
	fp, _ := r.Extra["feePayer"].(string)
	if !ValidEntityID(fp) {
		return "invalid_exact_hedera_payload_missing_fee_payer"
	}
	if fp != s.FeePayer {
		return "fee_payer_not_managed_by_facilitator"
	}
	return ""
}

func payloadTransaction(p x402.Payload) (string, error) {
	var body struct {
		Transaction string `json:"transaction"`
	}
	if err := json.Unmarshal(p.Payload, &body); err != nil || body.Transaction == "" {
		return "", errors.New("invalid_exact_hedera_payload_transaction")
	}
	return body.Transaction, nil
}

func net(ts []Transfer, account string) *big.Int {
	sum := new(big.Int)
	for _, t := range ts {
		if t.Account == account {
			sum.Add(sum, big.NewInt(t.Amount))
		}
	}
	return sum
}

func sum(ts []Transfer) *big.Int {
	s := new(big.Int)
	for _, t := range ts {
		s.Add(s, big.NewInt(t.Amount))
	}
	return s
}

func (s *Scheme) verify(ctx context.Context, p x402.Payload, r x402.Requirements) (*Parsed, x402.VerifyResponse) {
	if reason := s.requirements(p, r); reason != "" {
		return nil, invalid(reason, "")
	}
	payerPaid := isPayerPaid(r)
	feePayer, _ := r.Extra["feePayer"].(string)
	enc, err := payloadTransaction(p)
	if err != nil {
		return nil, invalid("invalid_exact_hedera_payload_transaction_could_not_be_decoded", "")
	}
	tx, err := Parse(enc)
	if errors.Is(err, errNotTransfer) {
		return nil, invalid("invalid_exact_hedera_payload_contains_non_transfer_ops", "")
	}
	if err != nil {
		return nil, invalid("invalid_exact_hedera_payload_transaction_could_not_be_decoded", "")
	}
	if wantMemo, ok := r.Extra["memo"].(string); ok && wantMemo != "" && tx.Memo != wantMemo {
		return nil, invalid("invalid_exact_hedera_payload_memo_mismatch", "")
	}
	var ts []Transfer
	isHBAR := r.Asset == "0.0.0"
	if isHBAR {
		ts = tx.Transfers
		if tx.TokenTransfer {
			return nil, invalid("invalid_exact_hedera_payload_asset_mismatch", "")
		}
	} else {
		if len(tx.Transfers) > 0 || len(tx.TokenTransfers) != 1 || tx.TokenTransfers[0].Token != r.Asset {
			return nil, invalid("invalid_exact_hedera_payload_asset_mismatch", "")
		}
		ts = tx.TokenTransfers[0].Transfers
	}
	if sum(ts).Sign() != 0 {
		return nil, invalid("invalid_exact_hedera_payload_hbar_sum_non_zero", "")
	}
	if !payerPaid {
		if tx.FeePayer != feePayer {
			return nil, invalid("invalid_exact_hedera_payload_fee_payer_mismatch", "")
		}
		if net(ts, feePayer).Sign() < 0 {
			return nil, invalid("invalid_exact_hedera_payload_fee_payer_transferring_hbar", "")
		}
	}
	want, _ := new(big.Int).SetString(r.Amount, 10)
	if net(ts, r.PayTo).Cmp(want) != 0 {
		return nil, invalid("invalid_exact_hedera_payload_amount_mismatch", "")
	}
	for _, t := range ts {
		if t.Amount > 0 && t.Account != r.PayTo {
			return nil, invalid("invalid_exact_hedera_payload_extra_positive_transfers", "")
		}
	}
	var payers []Transfer
	for _, t := range ts {
		if t.Amount < 0 {
			payers = append(payers, Transfer{t.Account, -t.Amount})
		}
	}
	payer := ""
	if len(payers) > 0 {
		payer = payers[0].Account
	}
	// Stricter than @x402/hedera: every debited wallet would need screening,
	// so one payer only; and the sponsor's fee exposure is capped.
	if len(payers) != 1 {
		return nil, invalid("invalid_exact_hedera_payload_multiple_payers", payer)
	}
	if payerPaid && tx.FeePayer != payer {
		return nil, invalid("invalid_exact_hedera_payload_fee_payer_mismatch", payer)
	}
	if tx.MaxFee > s.MaxFee {
		return nil, invalid("invalid_exact_hedera_payload_max_fee_too_high", payer)
	}
	account, err := s.Mirror.Account(ctx, payer)
	if err != nil {
		return nil, invalid("invalid_exact_hedera_payload_signature_invalid", payer)
	}
	key, err := parseMirrorKey(account.Key)
	if err != nil || !key.signsAll(tx) {
		return nil, invalid("invalid_exact_hedera_payload_signature_invalid", payer)
	}
	if isHBAR {
		balance, ok := new(big.Int).SetString(account.Balance.Balance.String(), 10)
		if !ok || balance.Cmp(big.NewInt(payers[0].Amount)) < 0 {
			return nil, invalid("invalid_exact_hedera_payload_preflight_failed", payer)
		}
	} else {
		tokBal, err := s.TokenBalance(ctx, payer, r.Asset)
		if err != nil || tokBal.Cmp(big.NewInt(payers[0].Amount)) < 0 {
			return nil, invalid("invalid_exact_hedera_payload_preflight_failed", payer)
		}
	}
	return tx, x402.Valid(payer)
}

func (s *Scheme) Verify(ctx context.Context, p x402.Payload, r x402.Requirements) x402.VerifyResponse {
	_, v := s.verify(ctx, p, r)
	return v
}

// Settle re-verifies, then the sponsor signs and submits.
func (s *Scheme) Settle(ctx context.Context, p x402.Payload, r x402.Requirements) (x402.SettleResponse, error) {
	tx, v := s.verify(ctx, p, r)
	if !v.Valid {
		return x402.SettleResponse{Network: r.Network, Payer: v.Payer, ErrorReason: v.Reason}, nil
	}
	id, err := s.Submit(ctx, tx, r.Network)
	if err != nil {
		return x402.SettleResponse{}, err
	}
	return x402.SettleResponse{Success: true, Transaction: id, Network: r.Network, Payer: v.Payer}, nil
}

// Nodes maps node account IDs to their plaintext gRPC endpoints, from the
// mirror node. hiero-sdk-go v2.84.0's embedded address books do not decode
// (the published .pb files are corrupted), so its preconfigured clients have
// no nodes; the mirror's live list is authoritative anyway.
func (m Mirror) Nodes(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	next := "/api/v1/network/nodes?limit=25"
	for page := 0; next != "" && page < 20; page++ {
		var resp struct {
			Nodes []struct {
				Account   string `json:"node_account_id"`
				Endpoints []struct {
					Domain string `json:"domain_name"`
					IP     string `json:"ip_address_v4"`
					Port   int    `json:"port"`
				} `json:"service_endpoints"`
			} `json:"nodes"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := m.get(ctx, next, &resp); err != nil {
			return nil, err
		}
		for _, n := range resp.Nodes {
			for _, e := range n.Endpoints {
				host := e.IP
				if host == "" {
					host = e.Domain
				}
				if host != "" && e.Port == 50211 && ValidEntityID(n.Account) {
					out[n.Account] = fmt.Sprintf("%s:%d", host, e.Port)
					break
				}
			}
		}
		next = resp.Links.Next
	}
	if len(out) == 0 {
		return nil, errors.New("mirror node listed no consensus nodes")
	}
	return out, nil
}

// TLSNodes maps node account IDs to their TLS gRPC endpoints (:50212), falling
// back to :50211 only if no TLS endpoints are advertised. Returns whether TLS
// endpoints were selected.
func (m Mirror) TLSNodes(ctx context.Context) (map[string]string, bool, error) {
	tlsOut := map[string]string{}
	plainOut := map[string]string{}
	next := "/api/v1/network/nodes?limit=25"
	for page := 0; next != "" && page < 20; page++ {
		var resp struct {
			Nodes []struct {
				Account   string `json:"node_account_id"`
				Endpoints []struct {
					Domain string `json:"domain_name"`
					IP     string `json:"ip_address_v4"`
					Port   int    `json:"port"`
				} `json:"service_endpoints"`
			} `json:"nodes"`
			Links struct {
				Next string `json:"next"`
			} `json:"links"`
		}
		if err := m.get(ctx, next, &resp); err != nil {
			return nil, false, err
		}
		for _, n := range resp.Nodes {
			if !ValidEntityID(n.Account) {
				continue
			}
			for _, e := range n.Endpoints {
				host := e.Domain
				if host == "" {
					host = e.IP
				}
				if host == "" {
					continue
				}
				if e.Port == 50212 {
					if _, exists := tlsOut[n.Account]; !exists {
						tlsOut[n.Account] = fmt.Sprintf("%s:%d", host, e.Port)
					}
				} else if e.Port == 50211 {
					if _, exists := plainOut[n.Account]; !exists {
						plainOut[n.Account] = fmt.Sprintf("%s:%d", host, e.Port)
					}
				}
			}
		}
		next = resp.Links.Next
	}
	if len(tlsOut) > 0 {
		return tlsOut, true, nil
	}
	if len(plainOut) > 0 {
		return plainOut, false, nil
	}
	return nil, false, errors.New("mirror node listed no consensus nodes")
}

func ledgerID(network string) (*hiero.LedgerID, error) {
	switch network {
	case Mainnet:
		return hiero.NewLedgerIDMainnet(), nil
	case Testnet:
		return hiero.NewLedgerIDTestnet(), nil
	}
	return nil, errors.New("unsupported Hedera network")
}

// client connects to the nodes a transaction was frozen for, preferring TLS (:50212).
func (s *Scheme) client(ctx context.Context, network string, want []string) (*hiero.Client, error) {
	ledger, err := ledgerID(network)
	if err != nil {
		return nil, err
	}
	nodes, useTLS, err := s.Mirror.TLSNodes(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string]hiero.AccountID{}
	for _, id := range want {
		addr, ok := nodes[id]
		if !ok {
			continue
		}
		acct, err := hiero.AccountIDFromString(id)
		if err != nil {
			return nil, err
		}
		m[addr] = acct
	}
	if len(m) == 0 {
		return nil, errors.New("none of the transaction's nodes are known to the mirror")
	}
	c := hiero.ClientForNetwork(m)
	c.SetLedgerID(*ledger)
	if useTLS {
		c.SetTransportSecurity(true)
	}
	return c, nil
}

func (s *Scheme) submit(ctx context.Context, p *Parsed, network string) (string, error) {
	tx, err := hiero.TransactionFromBytes(p.Raw)
	if err != nil {
		return "", err
	}
	c, err := s.client(ctx, network, p.Nodes)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if s.hasSponsor && s.FeePayer != "" && p.FeePayer == s.FeePayer {
		fp, err := hiero.AccountIDFromString(s.FeePayer)
		if err != nil {
			return "", err
		}
		c.SetOperator(fp, s.sponsorKey)
		if tx, err = hiero.TransactionSign(tx, s.sponsorKey); err != nil {
			return "", err
		}
	}
	resp, err := hiero.TransactionExecute(tx, c)
	if err != nil {
		return "", err
	}
	receipt, err := resp.GetReceipt(c)
	if err != nil {
		return "", err
	}
	if receipt.Status != hiero.StatusSuccess {
		return "", fmt.Errorf("receipt status %s", receipt.Status)
	}
	return p.TransactionID, nil
}

// Reconcile confirms a journaled payment (HBAR or HTS fungible token) on the
// mirror node without submitting anything.
func (s *Scheme) Reconcile(ctx context.Context, p x402.Payload, r x402.Requirements, payer string) (string, error) {
	enc, err := payloadTransaction(p)
	if err != nil {
		return "", err
	}
	tx, err := Parse(enc)
	if err != nil {
		return "", err
	}
	at := strings.SplitN(tx.TransactionID, "@", 2)
	secs, nanos, _ := strings.Cut(at[1], ".")
	var data struct {
		Transactions []struct {
			Result    string `json:"result"`
			Nonce     int    `json:"nonce"`
			Scheduled bool   `json:"scheduled"`
			Name      string `json:"name"`
			Tokens    []struct {
				TokenID string      `json:"token_id"`
				Account string      `json:"account"`
				Amount  json.Number `json:"amount"`
			} `json:"token_transfers"`
			Transfers []struct {
				Account string      `json:"account"`
				Amount  json.Number `json:"amount"`
			} `json:"transfers"`
		} `json:"transactions"`
	}
	if err := s.Mirror.get(ctx, "/api/v1/transactions/"+at[0]+"-"+secs+"-"+nanos, &data); err != nil {
		return "", err
	}
	isHBAR := r.Asset == "0.0.0"
	want, _ := new(big.Int).SetString(r.Amount, 10)
	for _, t := range data.Transactions {
		if t.Result != "SUCCESS" || t.Nonce != 0 || t.Scheduled || t.Name != "CRYPTOTRANSFER" {
			continue
		}
		if isHBAR {
			if len(t.Tokens) > 0 {
				continue
			}
			var ts []Transfer
			for _, x := range t.Transfers {
				n, err := strconv.ParseInt(x.Amount.String(), 10, 64)
				if err != nil {
					return "", errors.New("unparseable mirror amount")
				}
				ts = append(ts, Transfer{x.Account, n})
			}
			if net(ts, payer).Cmp(new(big.Int).Neg(want)) == 0 && net(ts, r.PayTo).Cmp(want) == 0 {
				return tx.TransactionID, nil
			}
			return "", errors.New("ledger transfer does not match exact payment")
		}
		var ts []Transfer
		for _, x := range t.Tokens {
			if x.TokenID != r.Asset {
				continue
			}
			n, err := strconv.ParseInt(x.Amount.String(), 10, 64)
			if err != nil {
				return "", errors.New("unparseable mirror token amount")
			}
			ts = append(ts, Transfer{x.Account, n})
		}
		if net(ts, payer).Cmp(new(big.Int).Neg(want)) == 0 && net(ts, r.PayTo).Cmp(want) == 0 {
			return tx.TransactionID, nil
		}
		return "", errors.New("ledger token transfer does not match exact payment")
	}
	return "", errors.New("Hedera payment not finalized")
}

// NewPayment builds and signs the payer's part of an HBAR or HTS token payment:
// uses extra.feePayer when fee-sponsored, or payer itself when payer-pays-fees.
func NewPayment(ctx context.Context, mirror Mirror, payer string, key hiero.PrivateKey, r x402.Requirements) (string, error) {
	amount, err := strconv.ParseInt(r.Amount, 10, 64)
	if err != nil || amount <= 0 {
		return "", errors.New("invalid amount")
	}
	feePayer, _ := r.Extra["feePayer"].(string)
	if feePayer == "" {
		feePayer = payer
	}
	from, err := hiero.AccountIDFromString(payer)
	if err != nil {
		return "", err
	}
	to, err := hiero.AccountIDFromString(r.PayTo)
	if err != nil {
		return "", err
	}
	fp, err := hiero.AccountIDFromString(feePayer)
	if err != nil {
		return "", err
	}
	nodes, _, err := mirror.TLSNodes(ctx)
	if err != nil {
		return "", err
	}
	if len(nodes) < 3 {
		if plain, perr := mirror.Nodes(ctx); perr == nil {
			for k, v := range plain {
				if _, ok := nodes[k]; !ok {
					nodes[k] = v
				}
			}
		}
	}
	var ids []hiero.AccountID
	for id := range nodes { // map order is random: spread payments over nodes
		acct, err := hiero.AccountIDFromString(id)
		if err != nil {
			return "", err
		}
		if ids = append(ids, acct); len(ids) == 3 {
			break
		}
	}
	builder := hiero.NewTransferTransaction().
		SetTransactionID(hiero.TransactionIDGenerate(fp)).
		SetNodeAccountIDs(ids).
		SetMaxTransactionFee(hiero.HbarFromTinybar(DefaultMaxFeeTinybars)).
		SetTransactionValidDuration(120 * time.Second)
	if r.Asset == "0.0.0" {
		builder.AddHbarTransfer(from, hiero.HbarFromTinybar(-amount)).
			AddHbarTransfer(to, hiero.HbarFromTinybar(amount))
	} else {
		tid, err := hiero.TokenIDFromString(r.Asset)
		if err != nil {
			return "", err
		}
		builder.AddTokenTransfer(tid, from, -amount).
			AddTokenTransfer(tid, to, amount)
	}
	if memo, ok := r.Extra["memo"].(string); ok && memo != "" {
		builder.SetTransactionMemo(memo)
	}
	tx, err := builder.Freeze()
	if err != nil {
		return "", err
	}
	b, err := tx.Sign(key).ToBytes()
	if err != nil {
		return "", err
	}
	return encode(b), nil
}
