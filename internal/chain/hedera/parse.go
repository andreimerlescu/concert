// Package hedera implements the x402 "exact" Hedera scheme for HBAR, ported
// rule for rule from @x402/hedera, plus NFT ownership checks against a
// mirror node. Transactions are parsed from the official Hiero protobuf
// types; every transfer entry is kept, so nothing is merged away.
package hedera

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	sdkproto "github.com/hiero-ledger/hiero-sdk-go/v2/proto/sdk"
	"github.com/hiero-ledger/hiero-sdk-go/v2/proto/services"
	"google.golang.org/protobuf/proto"
)

var entityID = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func ValidEntityID(s string) bool { return entityID.MatchString(s) }

// Transfer is one HBAR account amount, in tinybars.
type Transfer struct {
	Account string
	Amount  int64
}

// Parsed is a validated, payer-signed transfer transaction.
type Parsed struct {
	Raw           []byte
	Signed        []*services.SignedTransaction
	Body          *services.TransactionBody // the first node's body
	TransactionID string                    // account@seconds.nanos, nanos zero-padded
	FeePayer      string
	Transfers     []Transfer
	TokenTransfer bool
	MaxFee        uint64
	Nodes         []string
}

func accountString(a *services.AccountID) (string, error) {
	if a == nil {
		return "", errors.New("missing account")
	}
	n, ok := a.Account.(*services.AccountID_AccountNum)
	if !ok {
		return "", errors.New("account aliases are not accepted")
	}
	return fmt.Sprintf("%d.%d.%d", a.ShardNum, a.RealmNum, n.AccountNum), nil
}

func noUnknown(m proto.Message) error {
	if len(m.ProtoReflect().GetUnknown()) > 0 {
		return errors.New("unknown transaction fields")
	}
	return nil
}

// Parse decodes a base64 TransactionList (one frozen body per node) or a
// single Transaction. Every body must be identical apart from its node, a
// plain CryptoTransfer with no approvals, hooks, batch key, custom fee
// limits or unknown fields.
func Parse(b64 string) (*Parsed, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return nil, errors.New("invalid transaction encoding")
	}
	var list sdkproto.TransactionList
	if err := proto.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	if err := noUnknown(&list); err != nil {
		return nil, err
	}
	txs := list.TransactionList
	if len(txs) == 0 {
		var one services.Transaction
		if err := proto.Unmarshal(raw, &one); err != nil {
			return nil, err
		}
		if err := noUnknown(&one); err != nil {
			return nil, err
		}
		txs = []*services.Transaction{&one}
	}
	if len(txs) > 64 {
		return nil, errors.New("too many node transactions")
	}
	p := &Parsed{Raw: raw}
	var reference *services.TransactionBody
	nodes := map[string]bool{}
	for _, tx := range txs {
		if len(tx.SignedTransactionBytes) == 0 || tx.Body != nil || tx.Sigs != nil || tx.SigMap != nil || len(tx.BodyBytes) > 0 {
			return nil, errors.New("only signedTransactionBytes transactions are accepted")
		}
		if err := noUnknown(tx); err != nil {
			return nil, err
		}
		var st services.SignedTransaction
		if err := proto.Unmarshal(tx.SignedTransactionBytes, &st); err != nil {
			return nil, err
		}
		if err := noUnknown(&st); err != nil {
			return nil, err
		}
		var body services.TransactionBody
		if err := proto.Unmarshal(st.BodyBytes, &body); err != nil {
			return nil, err
		}
		if err := noUnknown(&body); err != nil {
			return nil, err
		}
		node, err := accountString(body.NodeAccountID)
		if err != nil || nodes[node] {
			return nil, errors.New("invalid or repeated node account")
		}
		nodes[node] = true
		p.Nodes = append(p.Nodes, node)
		cmp := proto.Clone(&body).(*services.TransactionBody)
		cmp.NodeAccountID = nil
		if reference == nil {
			reference = cmp
			p.Body = &body
		} else if !proto.Equal(reference, cmp) {
			return nil, errors.New("node transactions differ")
		}
		p.Signed = append(p.Signed, &st)
	}
	b := p.Body
	id := b.TransactionID
	if id == nil || id.TransactionValidStart == nil || id.Scheduled || id.Nonce != 0 {
		return nil, errors.New("invalid transaction ID")
	}
	if p.FeePayer, err = accountString(id.AccountID); err != nil {
		return nil, err
	}
	p.TransactionID = fmt.Sprintf("%s@%d.%09d", p.FeePayer, id.TransactionValidStart.Seconds, id.TransactionValidStart.Nanos)
	if b.BatchKey != nil || len(b.MaxCustomFees) > 0 || b.HighVolume {
		return nil, errors.New("unsupported transaction options")
	}
	ct, ok := b.Data.(*services.TransactionBody_CryptoTransfer)
	if !ok || ct.CryptoTransfer == nil {
		return nil, errNotTransfer
	}
	if err := noUnknown(ct.CryptoTransfer); err != nil {
		return nil, err
	}
	p.TokenTransfer = len(ct.CryptoTransfer.TokenTransfers) > 0
	seen := map[string]bool{}
	if tl := ct.CryptoTransfer.Transfers; tl != nil {
		for _, aa := range tl.AccountAmounts {
			if aa.IsApproval || aa.HookCall != nil {
				return nil, errors.New("approved or hooked transfers are not accepted")
			}
			acct, err := accountString(aa.AccountID)
			if err != nil || seen[acct] {
				return nil, errors.New("invalid or repeated transfer account")
			}
			seen[acct] = true
			p.Transfers = append(p.Transfers, Transfer{acct, aa.Amount})
		}
	}
	p.MaxFee = b.TransactionFee
	return p, nil
}

var errNotTransfer = errors.New("not a transfer transaction")
