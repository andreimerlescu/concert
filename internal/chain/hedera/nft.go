package hedera

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
)

var serial = regexp.MustCompile(`^[1-9]\d*$`)

// VerifyMessage checks a signature by a single-key Hedera account over the
// raw challenge bytes. Threshold and contract keys fail closed: accepting
// one member's signature would not prove control of the account.
func VerifyMessage(k *MirrorKey, message string, signature []byte) bool {
	if k == nil || (k.Type != "ED25519" && k.Type != "ECDSA_SECP256K1") {
		return false
	}
	n, err := parseMirrorKey(k)
	return err == nil && n.pub != nil && n.pub.VerifySignedMessage([]byte(message), signature)
}

// OwnsNFT checks the account's current key signed the challenge and that it
// holds a serial of the HTS nonfungible collection (a specific serial when
// token is given). Mirror-node lag is a trust assumption. Returns the serial.
func (s *Scheme) OwnsNFT(ctx context.Context, address, collection, token, message string, signature []byte) (string, error) {
	if !ValidEntityID(address) || !ValidEntityID(collection) {
		return "", errors.New("invalid entity ID")
	}
	a, err := s.Mirror.Account(ctx, address)
	if err != nil {
		return "", err
	}
	if a.Deleted || !VerifyMessage(a.Key, message, signature) {
		return "", errors.New("invalid signature")
	}
	var meta struct {
		Deleted bool   `json:"deleted"`
		Type    string `json:"type"`
	}
	if err := s.Mirror.get(ctx, "/api/v1/tokens/"+url.PathEscape(collection), &meta); err != nil {
		return "", err
	}
	if meta.Deleted || meta.Type != "NON_FUNGIBLE_UNIQUE" {
		return "", errors.New("not an NFT collection")
	}
	if token != "" {
		if !serial.MatchString(token) {
			return "", errors.New("invalid serial")
		}
		var nft struct {
			Deleted bool   `json:"deleted"`
			Account string `json:"account_id"`
		}
		if err := s.Mirror.get(ctx, "/api/v1/tokens/"+collection+"/nfts/"+token, &nft); err != nil {
			return "", err
		}
		if nft.Deleted || nft.Account != address {
			return "", errors.New("NFT is not owned")
		}
		return token, nil
	}
	var owned struct {
		NFTs []struct {
			Token   string `json:"token_id"`
			Account string `json:"account_id"`
			Serial  int64  `json:"serial_number"`
			Deleted bool   `json:"deleted"`
		} `json:"nfts"`
	}
	if err := s.Mirror.get(ctx, "/api/v1/accounts/"+address+"/nfts?token.id="+collection+"&limit=1", &owned); err != nil {
		return "", err
	}
	for _, n := range owned.NFTs {
		if n.Token == collection && n.Account == address && !n.Deleted {
			return strconv.FormatInt(n.Serial, 10), nil
		}
	}
	return "", errors.New("no matching NFT")
}
