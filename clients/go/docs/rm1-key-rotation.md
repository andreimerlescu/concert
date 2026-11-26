# Stateless `rm1` Ed25519 Passes & Key Rotation

Concert (`room v1.8+` split verify-only mode) lets an external checkout or control-plane service mint short-lived Ed25519-signed VIP passes (`X-Room-Pass`) and leases (`X-Room-Lease`) while Concert edge replicas hold **only public verification keys** (`-room-verify-keys` / `CONCERT_ROOM_VERIFY_KEYS`).

## Wire Format

```text
rm1.<base64url-nopad(JSON(RM1Claims))>.<base64url-nopad(Ed25519Sign(priv, "rm1." + payloadB64))>
```

Claims payload:

```json
{"kid":"k1","kind":"pass","scope":"shop.example.com","key":"agent-42","iat":1795651200,"exp":1795651500}
```

- `kind` is `"pass"` or `"lease"` (`lease` requires a non-empty `key`).
- `scope` must match Concert's configured `-room-scope` (auto-set to each virtual host's primary hostname in `Concertfile` mode).
- Maximum token TTL is `1h` (`RM1MaxTTL`).

## Issuing Passes (Issuer Service)

Load the 64-byte Ed25519 private key from a secret manager or `0600` secret file at runtime — never hardcode private keys in source code.

```go
pass, err := concert.MintRM1Pass(privKey, "k1", "shop.example.com", "", 5*time.Minute)
if err != nil {
	return err
}
req.Header.Set(concert.HeaderRoomPass, pass)
```

For a key-bound lease:

```go
lease, err := concert.MintRM1Lease(privKey, "k1", "shop.example.com", "agent-42", 5*time.Minute)
```

## Verifying Passes

`VerifyRM1` enforces security-first ordering: framing and JSON validation run first, **Ed25519 signature verification runs before scope/kind/expiry** (so forged tokens are never misclassified as expired), followed by scope, kind, key binding, clock skew (`30s` default), and expiry checks:

```go
claims, err := concert.VerifyRM1(token, verifyKeys, concert.RM1VerifyOptions{
	Scope: "shop.example.com",
	Kind:  concert.RM1KindPass,
})
if err != nil {
	// Match with errors.Is(err, concert.ErrRM1Expired), ErrRM1InvalidSignature, etc.
	return err
}
_ = claims
```

## Zero-Downtime Key Rotation

1. **Generate `k2`** on the issuer service (do not start signing with `k2` yet).
2. **Publish both public keys** to Concert replicas using `FormatVerifyKeysFlag`:

   ```go
   spec, err := concert.FormatVerifyKeysFlag(map[string]ed25519.PublicKey{
       "k1": pubK1,
       "k2": pubK2,
   })
   // Configure CONCERT_ROOM_VERIFY_KEYS_FILE with spec (0600 permissions) and reload Concert.
   ```

3. **Switch the issuer** to sign new tokens with `kid: "k2"`. Existing `k1` tokens continue verifying cleanly until they expire (at most `1h`).
4. **Retire `k1`** after the maximum TTL (`1h`) plus clock skew (`5m`) has elapsed by removing `k1` from `CONCERT_ROOM_VERIFY_KEYS_FILE` and reloading Concert.
