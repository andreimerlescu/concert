package acme

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	accountKeyFilename = "account.key"
	maxDiskFileBytes   = 4 << 20 // 4 MiB bound on persisted key/cert files (R3)

	bundleCipherVersion byte = 1
	bundleSaltLen            = 16
	bundleNonceLen           = 12
	bundleKeyLen             = 32
	bundleHKDFInfo           = "concert-acme-kv-bundle-v1"
)

// KVBundleSync defines the optional distributed key-value port used to share
// encrypted TLS certificate bundles across multi-edge deployments (such as
// concert-kv). Implementations must be safe for concurrent use.
type KVBundleSync interface {
	// Get retrieves the encrypted bundle stored under key. ok is false when the
	// key does not exist.
	Get(ctx context.Context, key string) (val []byte, ok bool, err error)
	// Set stores the encrypted bundle under key with an expiration ttl.
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
}

// DiskStore persists ACME account ECDSA P-256 keys and domain/wildcard PEM
// certificate bundles inside a single cache directory with atomic 0600 writes
// and strict sanitized filename derivation (S8/S9). It is safe for concurrent
// use.
type DiskStore struct {
	dir string
	mu  sync.RWMutex
}

// NewDiskStore initializes a DiskStore rooted at cacheDir, creating the
// directory with 0700 permissions if it does not exist.
//
// # Parameters
//
//   - cacheDir: Filesystem path to the cache directory. Must be non-empty.
//
// # Returns
//
// A ready *DiskStore, or an error if cacheDir is empty or cannot be created.
//
// # Example
//
//	store, err := acme.NewDiskStore("/var/lib/concert/acme")
//	if err != nil {
//		return err
//	}
//	_ = store
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:781 (direct call)
//   - internal/acme/manager.go:253 (direct call)
//   - internal/acme/manager.go:253 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewDiskStore(cacheDir string) (*DiskStore, error) {
	cleaned := strings.TrimSpace(cacheDir)
	if cleaned == "" {
		return nil, errors.New("acme: cache directory must not be empty")
	}
	absDir, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve cache dir %q: %w", cleaned, err)
	}
	if err := os.MkdirAll(absDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir %q: %w", absDir, err)
	}
	return &DiskStore{dir: absDir}, nil
}

// Dir returns the absolute path of the store's cache directory.
//
// # Parameters
//
// None.
//
// # Returns
//
// The absolute directory path owned by the DiskStore.
//
// # Example
//
//	fmt.Println(store.Dir())
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) Dir() string {
	return s.dir
}

// LoadAccountKey loads the persisted ACME account ECDSA private key from disk.
//
// # Parameters
//
// None.
//
// # Returns
//
// The parsed *ecdsa.PrivateKey, or an error wrapping ErrNotFound if no account
// key has been persisted yet, or ErrCorruptBundle if the PEM file is invalid.
//
// # Example
//
//	key, err := store.LoadAccountKey()
//	if errors.Is(err, acme.ErrNotFound) {
//		// Generate and persist a new account key.
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1009 (direct call)
//   - internal/acme/manager.go:1009 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) LoadAccountKey() (*ecdsa.PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	raw, err := s.readFileBoundedLocked(accountKeyFilename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("decode account key pem: %w", ErrCorruptBundle)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", ErrCorruptBundle)
	}
	ecKey, ok := pkcs8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("account key is not ecdsa: %w", ErrCorruptBundle)
	}
	return ecKey, nil
}

// SaveAccountKey atomically persists key to disk with 0600 permissions.
//
// # Parameters
//
//   - key: Non-nil ECDSA private key to encode as PKCS#8 PEM and save.
//
// # Returns
//
// nil on success, or an error if marshaling or atomic persistence fails.
//
// # Example
//
//	if err := store.SaveAccountKey(accountKey); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1018 (direct call)
//   - internal/acme/manager.go:1018 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) SaveAccountKey(key *ecdsa.PrivateKey) error {
	if key == nil {
		return errors.New("acme: account key must not be nil")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal account key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeFileAtomicLocked(accountKeyFilename, pemBytes)
}

// LoadBundlePEM reads the raw combined PEM certificate+key bundle for pattern.
//
// # Parameters
//
//   - pattern: Normalized domain or wildcard pattern (e.g. "*.example.com").
//
// # Returns
//
// The raw PEM bundle bytes, or an error wrapping ErrInvalidDomain, ErrNotFound,
// or an I/O error.
//
// # Example
//
//	raw, err := store.LoadBundlePEM("*.example.com")
//	if err != nil {
//		return err
//	}
//	_ = raw
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/store.go:336 (direct call)
//   - internal/acme/store.go:336 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) LoadBundlePEM(pattern string) ([]byte, error) {
	filename, err := safeBundleFilename(pattern)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readFileBoundedLocked(filename)
}

// SaveBundlePEM validates and atomically persists a combined PEM certificate
// and private key bundle for pattern with 0600 permissions.
//
// # Parameters
//
//   - pattern: Normalized domain or wildcard pattern (e.g. "*.example.com").
//   - bundlePEM: Combined PEM containing private key and certificate chain.
//
// # Returns
//
// nil on success, or an error if pattern is invalid, bundlePEM does not parse
// as a valid keypair, or atomic write fails.
//
// # Example
//
//	if err := store.SaveBundlePEM("*.example.com", bundlePEM); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:834 (direct call)
//   - internal/acme/manager.go:834 (function value)
//   - internal/acme/manager.go:965 (direct call)
//   - internal/acme/manager.go:965 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) SaveBundlePEM(pattern string, bundlePEM []byte) error {
	filename, err := safeBundleFilename(pattern)
	if err != nil {
		return err
	}
	if _, err := ParseBundlePEM(bundlePEM); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeFileAtomicLocked(filename, bundlePEM)
}

// LoadCertificate loads and parses the cached *tls.Certificate (with Leaf
// populated) for pattern.
//
// # Parameters
//
//   - pattern: Normalized domain or wildcard pattern (e.g. "*.example.com").
//
// # Returns
//
// A parsed *tls.Certificate with Leaf populated, or an error wrapping
// ErrNotFound, ErrInvalidDomain, or ErrCorruptBundle.
//
// # Example
//
//	cert, err := store.LoadCertificate("*.example.com")
//	if err != nil {
//		return err
//	}
//	_ = cert
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:822 (direct call)
//   - internal/acme/manager.go:822 (function value)
//   - internal/acme/manager.go:1331 (direct call)
//   - internal/acme/manager.go:1331 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) LoadCertificate(pattern string) (*tls.Certificate, error) {
	raw, err := s.LoadBundlePEM(pattern)
	if err != nil {
		return nil, err
	}
	return ParseBundlePEM(raw)
}

// BundlePath returns the sanitized on-disk file path for pattern inside the
// store directory. It never traverses outside s.dir.
//
// # Parameters
//
//   - pattern: Domain or wildcard pattern.
//
// # Returns
//
// The absolute file path within s.dir, or an error wrapping ErrInvalidDomain.
//
// # Example
//
//	p, err := store.BundlePath("*.example.com")
//	if err != nil {
//		return err
//	}
//	_ = p
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:788 (direct call)
//   - internal/acme/acme_test.go:821 (direct call)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) BundlePath(pattern string) (string, error) {
	name, err := safeBundleFilename(pattern)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, name), nil
}

// readFileBoundedLocked reads filename strictly confined inside s.dir via
// os.OpenInRoot to prevent symlink escapes or path traversal (S9). Caller must
// hold s.mu.
//
// # Parameters
//
//   - filename: Base filename inside s.dir (must not contain path separators).
//
// # Returns
//
// File contents bounded by maxDiskFileBytes, or an error wrapping ErrNotFound.
//
// # Example
//
//	data, err := s.readFileBoundedLocked("account.key")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/store.go:158 (direct call)
//   - internal/acme/store.go:158 (function value)
//   - internal/acme/store.go:258 (direct call)
//   - internal/acme/store.go:258 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) readFileBoundedLocked(filename string) ([]byte, error) {
	f, err := os.OpenInRoot(s.dir, filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("open %q: %w", filename, ErrNotFound)
		}
		return nil, fmt.Errorf("open %q: %w", filename, err)
	}
	defer f.Close() // read side; close error not material

	data, err := io.ReadAll(io.LimitReader(f, maxDiskFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", filename, err)
	}
	if len(data) > maxDiskFileBytes {
		return nil, fmt.Errorf("file %q exceeds %d bytes: %w", filename, maxDiskFileBytes, ErrCorruptBundle)
	}
	return data, nil
}

// writeFileAtomicLocked writes data to filename inside s.dir using CreateTemp,
// explicit Chmod(0600), Sync, Close, Rename, and directory Sync. Caller must
// hold s.mu write lock.
//
// # Parameters
//
//   - filename: Sanitized base filename inside s.dir.
//   - data: File bytes to persist durably.
//
// # Returns
//
// nil on durable replacement, or an error with best-effort temp cleanup.
//
// # Example
//
//	err := s.writeFileAtomicLocked("account.key", pemBytes)
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/store.go:220 (direct call)
//   - internal/acme/store.go:220 (function value)
//   - internal/acme/store.go:301 (direct call)
//   - internal/acme/store.go:301 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (s *DiskStore) writeFileAtomicLocked(filename string, data []byte) (err error) {
	if filename == "" || filepath.Base(filename) != filename || strings.ContainsAny(filename, `/\`) {
		return fmt.Errorf("invalid store filename %q: %w", filename, ErrInvalidDomain)
	}
	tmp, err := os.CreateTemp(s.dir, ".acme-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %q: %w", s.dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()        // best effort; primary error already set
			_ = os.Remove(tmpName) // best effort cleanup of temp file
		}
	}()

	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	dst := filepath.Join(s.dir, filename)
	if err = os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename to %q: %w", dst, err)
	}
	dirHandle, derr := os.Open(s.dir)
	if derr == nil {
		// Sync the parent directory so the rename is durable across power loss.
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

// safeBundleFilename derives a collision-resistant, path-traversal-proof base
// filename for a domain or wildcard pattern (S9).
//
// # Parameters
//
//   - pattern: Domain or wildcard pattern to normalize and sanitize.
//
// # Returns
//
// A base filename containing only ASCII letters, digits, underscores, hyphens,
// and dots (never path separators or ".."), or ErrInvalidDomain.
//
// # Example
//
//	name, err := safeBundleFilename("*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/store.go:252 (direct call)
//   - internal/acme/store.go:252 (function value)
//   - internal/acme/store.go:292 (direct call)
//   - internal/acme/store.go:292 (function value)
//   - internal/acme/store.go:372 (direct call)
//   - internal/acme/store.go:372 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func safeBundleFilename(pattern string) (string, error) {
	norm, err := normalizeDomainPattern(pattern)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("cert-")
	for i := 0; i < len(norm); i++ {
		c := norm[i]
		switch {
		case c == '*':
			b.WriteString("_wildcard_")
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.':
			b.WriteByte(c)
		default:
			return "", fmt.Errorf("unexpected character in pattern %q: %w", pattern, ErrInvalidDomain)
		}
	}
	// Append a truncated SHA-256 digest of the canonical pattern so sanitized
	// names can never collide even across punctuation encodings.
	sum := sha256.Sum256([]byte(norm))
	b.WriteByte('-')
	b.WriteString(hex.EncodeToString(sum[:8]))
	b.WriteString(".pem")
	return b.String(), nil
}

// EncodeBundlePEM encodes a certificate DER chain and an ECDSA private key into
// a single PEM bundle suitable for DiskStore persistence and KV sync.
//
// # Parameters
//
//   - derChain: One or more DER-encoded X.509 certificates, leaf first.
//   - key: Non-nil ECDSA private key corresponding to the leaf certificate.
//
// # Returns
//
// Combined PEM bytes, or an error if inputs are empty or key marshaling fails.
//
// # Example
//
//	bundlePEM, err := acme.EncodeBundlePEM(derChain, certKey)
//	if err != nil {
//		return err
//	}
//	_ = bundlePEM
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:957 (direct call)
//   - internal/acme/manager.go:957 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func EncodeBundlePEM(derChain [][]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	if len(derChain) == 0 || key == nil {
		return nil, fmt.Errorf("encode bundle: empty chain or nil key: %w", ErrCorruptBundle)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal cert key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, fmt.Errorf("encode key pem: %w", err)
	}
	for _, certDER := range derChain {
		if len(certDER) == 0 {
			return nil, fmt.Errorf("empty der certificate in chain: %w", ErrCorruptBundle)
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			return nil, fmt.Errorf("encode cert pem: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// ParseBundlePEM splits a combined PEM bundle into certificate chain and
// private key blocks, validates that the key matches the leaf certificate, and
// returns a *tls.Certificate with Leaf populated.
//
// # Parameters
//
//   - bundlePEM: Combined PEM containing CERTIFICATE blocks and one PRIVATE KEY
//     block. Not mutated.
//
// # Returns
//
// A validated *tls.Certificate with Leaf non-nil, or an error wrapping
// ErrCorruptBundle.
//
// # Example
//
//	cert, err := acme.ParseBundlePEM(rawBundle)
//	if err != nil {
//		return err
//	}
//	_ = cert.Leaf.NotAfter
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:961 (direct call)
//   - internal/acme/manager.go:961 (function value)
//   - internal/acme/manager.go:1181 (direct call)
//   - internal/acme/manager.go:1181 (function value)
//   - internal/acme/store.go:296 (direct call)
//   - internal/acme/store.go:296 (function value)
//   - internal/acme/store.go:340 (direct call)
//   - internal/acme/store.go:340 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func ParseBundlePEM(bundlePEM []byte) (*tls.Certificate, error) {
	var certBlocks, keyBlocks bytes.Buffer
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "CERTIFICATE":
			if err := pem.Encode(&certBlocks, block); err != nil {
				return nil, fmt.Errorf("re-encode cert block: %w", ErrCorruptBundle)
			}
		case strings.Contains(block.Type, "PRIVATE KEY"):
			if err := pem.Encode(&keyBlocks, block); err != nil {
				return nil, fmt.Errorf("re-encode key block: %w", ErrCorruptBundle)
			}
		}
	}
	if certBlocks.Len() == 0 || keyBlocks.Len() == 0 {
		return nil, fmt.Errorf("bundle missing certificate or private key: %w", ErrCorruptBundle)
	}
	tlsCert, err := tls.X509KeyPair(certBlocks.Bytes(), keyBlocks.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse keypair: %w", ErrCorruptBundle)
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("bundle contains no leaf certificate: %w", ErrCorruptBundle)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", ErrCorruptBundle)
	}
	tlsCert.Leaf = leaf
	return &tlsCert, nil
}

// BundleCipher encrypts and authenticates certificate+key bundles using
// AES-256-GCM with per-message 32-byte HKDF-SHA256 derived subkeys so multi-edge
// KV stores never observe plaintext private keys. It is safe for concurrent use.
type BundleCipher struct {
	secret Secret
}

// NewBundleCipher constructs a BundleCipher bound to an operator secret.
//
// # Parameters
//
//   - secret: Non-empty operator secret used as HKDF-SHA256 input keying
//     material. Fails closed with ErrEmptySecret if zero.
//
// # Returns
//
// A ready *BundleCipher, or ErrEmptySecret when secret is empty.
//
// # Example
//
//	c, err := acme.NewBundleCipher(acme.NewSecret(os.Getenv("CONCERT_ACME_KV_SECRET")))
//	if err != nil {
//		return err
//	}
//	_ = c
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:937 (direct call)
//   - internal/acme/acme_test.go:958 (direct call)
//   - internal/acme/manager.go:262 (direct call)
//   - internal/acme/manager.go:262 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func NewBundleCipher(secret Secret) (*BundleCipher, error) {
	if secret.IsZero() {
		return nil, fmt.Errorf("bundle cipher secret: %w", ErrEmptySecret)
	}
	return &BundleCipher{secret: secret}, nil
}

// Encrypt seals plaintext under a fresh random salt and nonce using HKDF-SHA256
// and AES-256-GCM, authenticating contextLabel as associated data (AAD) so
// ciphertext cannot be transplanted across domain keys.
//
// # Parameters
//
//   - contextLabel: Domain pattern or KV key bound as GCM AAD.
//   - plaintext: Raw PEM bundle bytes to encrypt. Must be non-empty.
//
// # Returns
//
// A versioned wire envelope `[version(1) || salt(16) || nonce(12) || ciphertext+tag]`,
// or an error.
//
// # Example
//
//	sealed, err := cipher.Encrypt("*.example.com", bundlePEM)
//	if err != nil {
//		return err
//	}
//	_ = sealed
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/manager.go:1216 (direct call)
//   - internal/acme/manager.go:1216 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (c *BundleCipher) Encrypt(contextLabel string, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("encrypt empty bundle: %w", ErrCorruptBundle)
	}
	salt := make([]byte, bundleSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	nonce := make([]byte, bundleNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	subkey, err := hkdf.Key(sha256.New, c.secret.RevealBytes(), salt, bundleHKDFInfo, bundleKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive bundle key: %w", err)
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, fmt.Errorf("init aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init aes-gcm: %w", err)
	}

	// Bind both envelope version and contextLabel into AAD so modifying the
	// version byte or swapping ciphertexts between domains fails GCM verification.
	aad := buildBundleAAD(bundleCipherVersion, contextLabel)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, 1+bundleSaltLen+bundleNonceLen+len(ciphertext))
	out = append(out, bundleCipherVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt verifies and decrypts a sealed bundle produced by Encrypt.
//
// # Parameters
//
//   - contextLabel: Expected domain pattern or KV key bound as GCM AAD.
//   - sealed: Ciphertext envelope returned by Encrypt.
//
// # Returns
//
// The authenticated plaintext bundle bytes, or an error wrapping
// ErrCorruptBundle if the envelope is truncated, uses an unknown version, or
// fails AES-GCM authentication.
//
// # Example
//
//	plain, err := cipher.Decrypt("*.example.com", sealed)
//	if err != nil {
//		return err
//	}
//	_ = plain
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/acme_test.go:944 (direct call)
//   - internal/acme/acme_test.go:950 (direct call)
//   - internal/acme/acme_test.go:954 (direct call)
//   - internal/acme/acme_test.go:962 (direct call)
//   - internal/acme/manager.go:1177 (direct call)
//   - internal/acme/manager.go:1177 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func (c *BundleCipher) Decrypt(contextLabel string, sealed []byte) ([]byte, error) {
	headerLen := 1 + bundleSaltLen + bundleNonceLen
	if len(sealed) <= headerLen {
		return nil, fmt.Errorf("bundle envelope too short: %w", ErrCorruptBundle)
	}
	version := sealed[0]
	if version != bundleCipherVersion {
		return nil, fmt.Errorf("unsupported bundle version %d: %w", version, ErrCorruptBundle)
	}
	salt := sealed[1 : 1+bundleSaltLen]
	nonce := sealed[1+bundleSaltLen : headerLen]
	ciphertext := sealed[headerLen:]

	subkey, err := hkdf.Key(sha256.New, c.secret.RevealBytes(), salt, bundleHKDFInfo, bundleKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive bundle key: %w", err)
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, fmt.Errorf("init aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init aes-gcm: %w", err)
	}

	aad := buildBundleAAD(version, contextLabel)
	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("authenticate bundle: %w", ErrCorruptBundle)
	}
	return plain, nil
}

// buildBundleAAD constructs the canonical GCM associated data binding the
// envelope version and logical bundle context label.
//
// # Parameters
//
//   - version: Wire format version byte.
//   - contextLabel: Domain pattern or KV key associated with the bundle.
//
// # Returns
//
// Deterministic AAD byte slice.
//
// # Example
//
//	aad := buildBundleAAD(bundleCipherVersion, "*.example.com")
//
// # Used By
//
// Generated from repository symbol references; do not edit these lines.
//
//   - internal/acme/store.go:781 (direct call)
//   - internal/acme/store.go:781 (function value)
//   - internal/acme/store.go:852 (direct call)
//   - internal/acme/store.go:852 (function value)
//
// Scope: internal/acme package and tests; build configuration: darwin/arm64, default tags.
// Runtime/interface/external uses are not exhaustive.
func buildBundleAAD(version byte, contextLabel string) []byte {
	aad := make([]byte, 0, 1+len(bundleHKDFInfo)+1+len(contextLabel))
	aad = append(aad, version)
	aad = append(aad, bundleHKDFInfo...)
	aad = append(aad, ':')
	aad = append(aad, contextLabel...)
	return aad
}
