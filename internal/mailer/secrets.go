package mailer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// SecretsFileName is the encrypted secret vault stored in -data-dir.
	SecretsFileName = "email-secrets.json"

	secretsEnvelopeVersion = 1
	secretsKDFDomain       = "concert/email/secrets-v1"
)

// Secret origin labels surfaced in the Admin Portal (never the values).
const (
	SecretSourceNone = "none"
	SecretSourceEnv  = "env"
	SecretSourceFile = "encrypted_file"
)

// Secrets holds provider credentials in memory only.
type Secrets struct {
	SMTPPass        string `json:"smtp_pass,omitempty"`
	ResendAPIKey    string `json:"resend_api_key,omitempty"`
	SendPandaAPIKey string `json:"sendpanda_api_key,omitempty"`
}

func (s Secrets) empty() bool {
	return s.SMTPPass == "" && s.ResendAPIKey == "" && s.SendPandaAPIKey == ""
}

// SecretsPatch updates only non-nil credential fields in the encrypted vault.
// An empty string pointer deletes that field from the vault.
type SecretsPatch struct {
	SMTPPass        *string
	ResendAPIKey    *string
	SendPandaAPIKey *string
}

// SecretStatus reports where each credential is sourced from without ever
// returning credential material.
type SecretStatus struct {
	SMTPPass        string `json:"smtp_pass"`
	ResendAPIKey    string `json:"resend_api_key"`
	SendPandaAPIKey string `json:"sendpanda_api_key"`
	CanPersist      bool   `json:"can_persist"`
	PersistNote     string `json:"persist_note,omitempty"`
	LoadError       string `json:"load_error,omitempty"`
}

type encryptedEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// SecretStore manages AES-256-GCM encrypted email credentials on disk overlaid
// by higher-priority environment / *_FILE secrets.
type SecretStore struct {
	mu          sync.RWMutex
	path        string
	primaryKey  []byte
	prevKey     []byte
	canPersist  bool
	persistNote string
	loadErr     string
	env         Secrets
	file        Secrets
}

// NewSecretStore initializes the secret store. When dataDir is non-empty and
// email-secrets.json exists, it attempts to decrypt the file with admitSecret
// (falling back to admitSecretPrev during secret rotation). A corrupt or
// wrong-key file fails closed (empty file secrets) and returns the error so
// callers can surface or handle it explicitly.
func NewSecretStore(dataDir string, admitSecret, admitSecretPrev []byte, canPersist bool, persistNote string, envSecrets Secrets) (*SecretStore, error) {
	st := &SecretStore{
		canPersist:  canPersist && dataDir != "",
		persistNote: persistNote,
		env:         envSecrets,
	}
	if len(admitSecret) > 0 {
		st.primaryKey = deriveKey(admitSecret, secretsKDFDomain)
	}
	if len(admitSecretPrev) > 0 {
		st.prevKey = deriveKey(admitSecretPrev, secretsKDFDomain)
	}
	if dataDir != "" {
		st.path = filepath.Join(dataDir, SecretsFileName)
	}
	if !st.canPersist && st.persistNote == "" {
		if dataDir == "" {
			st.persistNote = "-data-dir is empty; supply credentials via CONCERT_* environment variables"
		} else {
			st.persistNote = "set a stable CONCERT_ADMIT_SECRET to encrypt and save credentials from the portal, or supply them via CONCERT_* environment variables"
		}
	}
	if st.path != "" {
		if err := st.loadLocked(); err != nil {
			st.loadErr = err.Error()
			return st, err
		}
	}
	return st, nil
}

// SetPersistPolicy updates whether portal writes are allowed (for example when
// -read-only-settings is active).
func (s *SecretStore) SetPersistPolicy(canPersist bool, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.canPersist = canPersist && s.path != ""
	s.persistNote = note
}

// Resolve returns the effective credentials with environment / *_FILE values
// taking strict precedence over portal-encrypted file credentials.
func (s *SecretStore) Resolve() Secrets {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.file
	if s.env.SMTPPass != "" {
		out.SMTPPass = s.env.SMTPPass
	}
	if s.env.ResendAPIKey != "" {
		out.ResendAPIKey = s.env.ResendAPIKey
	}
	if s.env.SendPandaAPIKey != "" {
		out.SendPandaAPIKey = s.env.SendPandaAPIKey
	}
	return out
}

// Status reports non-sensitive credential source badges.
func (s *SecretStore) Status() SecretStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := func(envVal, fileVal string) string {
		if envVal != "" {
			return SecretSourceEnv
		}
		if fileVal != "" {
			return SecretSourceFile
		}
		return SecretSourceNone
	}
	return SecretStatus{
		SMTPPass:        src(s.env.SMTPPass, s.file.SMTPPass),
		ResendAPIKey:    src(s.env.ResendAPIKey, s.file.ResendAPIKey),
		SendPandaAPIKey: src(s.env.SendPandaAPIKey, s.file.SendPandaAPIKey),
		CanPersist:      s.canPersist,
		PersistNote:     s.persistNote,
		LoadError:       s.loadErr,
	}
}

// Update modifies the encrypted on-disk vault atomically. Returns an error if
// persistence is disabled (ephemeral CONCERT_ADMIT_SECRET, empty -data-dir, or
// read-only settings).
func (s *SecretStore) Update(patch SecretsPatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canPersist || s.path == "" || len(s.primaryKey) != 32 {
		if s.persistNote != "" {
			return errors.New(s.persistNote)
		}
		return errors.New("persisting email credentials requires a stable CONCERT_ADMIT_SECRET and writable -data-dir")
	}
	next := s.file
	if patch.SMTPPass != nil {
		next.SMTPPass = *patch.SMTPPass
	}
	if patch.ResendAPIKey != nil {
		next.ResendAPIKey = *patch.ResendAPIKey
	}
	if patch.SendPandaAPIKey != nil {
		next.SendPandaAPIKey = *patch.SendPandaAPIKey
	}
	if err := s.saveLocked(next); err != nil {
		return err
	}
	s.file = next
	s.loadErr = ""
	return nil
}

// Delete clears one named credential ("smtp_pass", "resend_api_key",
// "sendpanda_api_key") or "all" from the encrypted vault.
func (s *SecretStore) Delete(field string) error {
	empty := ""
	switch field {
	case "smtp_pass":
		return s.Update(SecretsPatch{SMTPPass: &empty})
	case "resend_api_key":
		return s.Update(SecretsPatch{ResendAPIKey: &empty})
	case "sendpanda_api_key":
		return s.Update(SecretsPatch{SendPandaAPIKey: &empty})
	case "all":
		return s.Update(SecretsPatch{SMTPPass: &empty, ResendAPIKey: &empty, SendPandaAPIKey: &empty})
	default:
		return fmt.Errorf("unknown secret field %q", field)
	}
}

func (s *SecretStore) loadLocked() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.file = Secrets{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", SecretsFileName, err)
	}
	var env encryptedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("parse %s: %w", SecretsFileName, err)
	}
	if env.Version != secretsEnvelopeVersion {
		return fmt.Errorf("unsupported %s version %d", SecretsFileName, env.Version)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return fmt.Errorf("decode %s nonce: %w", SecretsFileName, err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode %s ciphertext: %w", SecretsFileName, err)
	}

	plaintext, err := decryptAESGCM(s.primaryKey, nonce, ct, []byte(secretsKDFDomain))
	if err != nil && len(s.prevKey) == 32 {
		plaintext, err = decryptAESGCM(s.prevKey, nonce, ct, []byte(secretsKDFDomain))
	}
	if err != nil {
		return fmt.Errorf("decrypt %s: authentication failed (wrong CONCERT_ADMIT_SECRET or tampered file)", SecretsFileName)
	}
	var dec Secrets
	if err := json.Unmarshal(plaintext, &dec); err != nil {
		return fmt.Errorf("decode %s payload: %w", SecretsFileName, err)
	}
	s.file = dec
	return nil
}

func (s *SecretStore) saveLocked(sec Secrets) error {
	if sec.empty() {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", SecretsFileName, err)
		}
		return nil
	}
	plaintext, err := json.Marshal(sec)
	if err != nil {
		return err
	}
	nonce, ct, err := encryptAESGCM(s.primaryKey, plaintext, []byte(secretsKDFDomain))
	if err != nil {
		return err
	}
	env := encryptedEnvelope{
		Version:    secretsEnvelopeVersion,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic0600(s.path, append(data, '\n'))
}

func deriveKey(secret []byte, domain string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(domain))
	return mac.Sum(nil)
}

func encryptAESGCM(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ct, nil
}

func decryptAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("missing encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce length")
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
