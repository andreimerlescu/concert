package solana

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
)

var (
	tokenProgram    = mustKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	metadataProgram = mustKey("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")
)

// VerifyMessage checks a wallet's Ed25519 signature over raw message bytes.
func VerifyMessage(address, message string, signature []byte) bool {
	k, err := ParsePublicKey(address)
	return err == nil && len(signature) == ed25519.SignatureSize && ed25519.Verify(k[:], []byte(message), signature)
}

// FindProgramAddress derives a program address the way the Solana runtime
// does: the first bump, from 255 down, whose hash is not a curve point.
func FindProgramAddress(seeds [][]byte, program PublicKey) (PublicKey, error) {
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)})
		h.Write(program[:])
		h.Write([]byte("ProgramDerivedAddress"))
		var k PublicKey
		copy(k[:], h.Sum(nil))
		if _, err := new(edwards25519.Point).SetBytes(k[:]); err != nil {
			return k, nil
		}
	}
	return PublicKey{}, errors.New("no program address")
}

// Collection is the collection field of Token Metadata.
type Collection struct {
	Verified bool
	Key      PublicKey
}

// ReadCollection decodes only the fields needed from a MetadataV1 account,
// rejecting truncation, a different mint and fungible token standards.
func ReadCollection(data []byte, mint PublicKey) (*Collection, error) {
	i := 0
	take := func(n int) ([]byte, error) {
		if n < 0 || i+n > len(data) {
			return nil, errors.New("truncated metadata")
		}
		b := data[i : i+n]
		i += n
		return b, nil
	}
	byteAt := func() (byte, error) {
		b, err := take(1)
		if err != nil {
			return 0, err
		}
		return b[0], nil
	}
	str := func() error {
		b, err := take(4)
		if err != nil {
			return err
		}
		n := binary.LittleEndian.Uint32(b)
		if n > 4096 {
			return errors.New("invalid metadata string")
		}
		_, err = take(int(n))
		return err
	}
	option := func() (bool, error) {
		tag, err := byteAt()
		if err != nil {
			return false, err
		}
		if tag > 1 {
			return false, errors.New("invalid option")
		}
		return tag == 1, nil
	}
	if k, err := byteAt(); err != nil || k != 4 {
		return nil, errors.New("not a MetadataV1 account")
	}
	if _, err := take(32); err != nil { // update authority
		return nil, err
	}
	m, err := take(32)
	if err != nil {
		return nil, err
	}
	if PublicKey(m) != mint {
		return nil, errors.New("wrong metadata mint")
	}
	for n := 0; n < 3; n++ { // name, symbol, uri
		if err := str(); err != nil {
			return nil, err
		}
	}
	if _, err := take(2); err != nil { // seller fee basis points
		return nil, err
	}
	if some, err := option(); err != nil {
		return nil, err
	} else if some {
		b, err := take(4)
		if err != nil {
			return nil, err
		}
		n := binary.LittleEndian.Uint32(b)
		if n > 5 {
			return nil, errors.New("invalid creators")
		}
		if _, err := take(int(n) * 34); err != nil {
			return nil, err
		}
	}
	if _, err := take(2); err != nil { // primary sale, mutable
		return nil, err
	}
	if some, err := option(); err != nil { // edition nonce
		return nil, err
	} else if some {
		if _, err := byteAt(); err != nil {
			return nil, err
		}
	}
	if some, err := option(); err != nil { // token standard
		return nil, err
	} else if some {
		std, err := byteAt()
		if err != nil {
			return nil, err
		}
		if std != 0 && std != 3 && std != 4 && std != 5 {
			return nil, errors.New("not a nonfungible token")
		}
	}
	some, err := option()
	if err != nil || !some {
		return nil, err
	}
	v, err := byteAt()
	if err != nil {
		return nil, err
	}
	k, err := take(32)
	if err != nil {
		return nil, err
	}
	return &Collection{Verified: v == 1, Key: PublicKey(k)}, nil
}

// OwnsNFT checks, at finalized commitment, that owner holds the one-supply
// zero-decimal SPL mint and that its Token Metadata names collection as a
// verified collection. It returns the mint.
func (s *Scheme) OwnsNFT(ctx context.Context, owner, collection, mint string) (string, error) {
	if mint == "" {
		return "", errors.New("NFT mint is required")
	}
	n, err := s.RPC.Network(ctx)
	if err != nil {
		return "", err
	}
	if n != s.Network {
		return "", errors.New("RPC network mismatch")
	}
	mintKey, err := ParsePublicKey(mint)
	if err != nil {
		return "", err
	}
	ownerKey, err := ParsePublicKey(owner)
	if err != nil {
		return "", err
	}
	info, err := s.RPC.Account(ctx, mintKey)
	if err != nil {
		return "", err
	}
	if info == nil || info.Owner != tokenProgram || len(info.Data) != 82 || binary.LittleEndian.Uint64(info.Data[36:]) != 1 || info.Data[44] != 0 || info.Data[45] != 1 {
		return "", errors.New("not a one-supply SPL NFT")
	}
	var owned struct {
		Value []struct {
			Account struct {
				Owner string `json:"owner"`
				Data  struct {
					Parsed struct {
						Info struct {
							Owner       string `json:"owner"`
							TokenAmount struct {
								Amount string `json:"amount"`
							} `json:"tokenAmount"`
						} `json:"info"`
					} `json:"parsed"`
				} `json:"data"`
			} `json:"account"`
		} `json:"value"`
	}
	params := []any{ownerKey.String(), map[string]string{"mint": mintKey.String()}, map[string]string{"encoding": "jsonParsed", "commitment": "finalized"}}
	if err := s.RPC.call(ctx, "getTokenAccountsByOwner", params, &owned); err != nil {
		return "", err
	}
	holds := false
	for _, a := range owned.Value {
		i := a.Account.Data.Parsed.Info
		if a.Account.Owner == tokenProgram.String() && i.Owner == ownerKey.String() && i.TokenAmount.Amount == "1" {
			holds = true
		}
	}
	if !holds {
		return "", errors.New("wallet does not own this mint")
	}
	pda, err := FindProgramAddress([][]byte{[]byte("metadata"), metadataProgram[:], mintKey[:]}, metadataProgram)
	if err != nil {
		return "", err
	}
	meta, err := s.RPC.Account(ctx, pda)
	if err != nil {
		return "", err
	}
	if meta == nil || meta.Owner != metadataProgram {
		return "", errors.New("metadata not owned by Metaplex")
	}
	c, err := ReadCollection(meta.Data, mintKey)
	if err != nil {
		return "", err
	}
	if c == nil || !c.Verified || c.Key.String() != collection {
		return "", errors.New("collection is not verified")
	}
	return mintKey.String(), nil
}
