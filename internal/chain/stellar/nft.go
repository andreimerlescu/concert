package stellar

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// SEP53Hash is the digest a SEP-53 wallet signs for message.
func SEP53Hash(message string) []byte {
	h := sha256.Sum256([]byte("Stellar Signed Message:\n" + message))
	return h[:]
}

// VerifySEP53 checks a SEP-53 signed message: Ed25519 over
// SHA-256("Stellar Signed Message:\n" + message) by a G… account key.
func VerifySEP53(address, message string, signature []byte) bool {
	kp, err := keypair.ParseAddress(address)
	if err != nil {
		return false
	}
	return kp.Verify(SEP53Hash(message), signature) == nil
}

func scNumber(v xdr.ScVal) (*big.Int, bool) {
	switch v.Type {
	case xdr.ScValTypeScvU32:
		return big.NewInt(int64(*v.U32)), true
	case xdr.ScValTypeScvI32:
		return big.NewInt(int64(*v.I32)), true
	case xdr.ScValTypeScvU64:
		return new(big.Int).SetUint64(uint64(*v.U64)), true
	case xdr.ScValTypeScvI64:
		return big.NewInt(int64(*v.I64)), true
	case xdr.ScValTypeScvI128:
		return i128Of(v)
	case xdr.ScValTypeScvU128:
		p := *v.U128
		n := new(big.Int).Lsh(new(big.Int).SetUint64(uint64(p.Hi)), 64)
		return n.Add(n, new(big.Int).SetUint64(uint64(p.Lo))), true
	}
	return nil, false
}

// OwnsNFT verifies a SEP-53 signature by address, requires its master key
// to carry at least the medium threshold (so one key of a multisignature
// account does not authenticate it alone), and simulates the allowlisted
// SEP-50 collection contract's balance(address) > 0. A token-specific rule
// is refused: balance() proves collection membership only.
func (s *Scheme) OwnsNFT(ctx context.Context, address, collection, token, message string, signature []byte) (string, error) {
	if token != "" {
		return "", errors.New("Stellar proofs cover the collection, not a specific token")
	}
	if !VerifySEP53(address, message, signature) {
		return "", errors.New("invalid signature")
	}
	acct, err := s.Horizon.Account(ctx, address)
	if err != nil {
		return "", err
	}
	weight := -1
	for _, sg := range acct.Signers {
		if sg.Key == address {
			weight = sg.Weight
		}
	}
	if weight < max(1, acct.Thresholds.Med) {
		return "", errors.New("insufficient master-key authority")
	}
	rp, err := s.RPC.Passphrase(ctx)
	if err != nil {
		return "", err
	}
	hp, err := s.Horizon.Passphrase(ctx)
	if err != nil {
		return "", err
	}
	if rp != s.passphrase || hp != s.passphrase {
		return "", errors.New("RPC network mismatch")
	}
	seq, err := atoi64(acct.Sequence)
	if err != nil {
		return "", err
	}
	contract, err := contractAddress(collection)
	if err != nil {
		return "", err
	}
	owner, err := scAddress(address)
	if err != nil {
		return "", err
	}
	src, err := xdr.AddressToMuxedAccount(address)
	if err != nil {
		return "", err
	}
	bounds := xdr.TimeBounds{MaxTime: xdr.TimePoint(time.Now().Add(30 * time.Second).Unix())}
	tx := xdr.Transaction{SourceAccount: src, Fee: inclusionFeeStroops, SeqNum: xdr.SequenceNumber(seq + 1),
		Cond: xdr.Preconditions{Type: xdr.PreconditionTypePrecondTime, TimeBounds: &bounds},
		Operations: []xdr.Operation{{Body: xdr.OperationBody{Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionOp: &xdr.InvokeHostFunctionOp{
			HostFunction: xdr.HostFunction{Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract, InvokeContract: &xdr.InvokeContractArgs{
				ContractAddress: contract, FunctionName: "balance", Args: []xdr.ScVal{owner}}}}}}}}
	env, err := xdr.MarshalBase64(xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: tx}})
	if err != nil {
		return "", err
	}
	sim, err := s.RPC.Simulate(ctx, env)
	if err != nil || !sim.Success() || len(sim.Results) == 0 {
		return "", errors.New("balance simulation failed")
	}
	var ret xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(sim.Results[0].XDR, &ret); err != nil {
		return "", err
	}
	if n, ok := scNumber(ret); !ok || n.Sign() <= 0 {
		return "", errors.New("no NFT balance")
	}
	return "collection-balance", nil
}

func contractAddress(c string) (xdr.ScAddress, error) {
	var a xdr.ScAddress
	id, err := decodeContract(c)
	if err != nil {
		return a, err
	}
	cid := xdr.ContractId(id)
	return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &cid}, nil
}

func scAddress(account string) (xdr.ScVal, error) {
	id, err := xdr.AddressToAccountId(account)
	if err != nil {
		return xdr.ScVal{}, err
	}
	a := xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &id}
	return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &a}, nil
}
