package capacity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileName is the capacity file's name in -data-dir.
const FileName = "capacity.json"

// fileVersion is the format written by Save.
const fileVersion = 1

// File is a measured host capacity: what the benchmark found this host's
// application can serve while staying under its latency and error limits.
type File struct {
	Version  int       `json:"version"`
	At       time.Time `json:"at"`
	Target   string    `json:"target"`           // URL the benchmark crawled
	HostCap  int       `json:"host_cap"`         // page slots to allow at once
	Lemmings int       `json:"lemmings"`         // largest passing concurrency
	P95Ms    float64   `json:"p95_ms"`           // p95 at that concurrency
	LimitMs  float64   `json:"limit_ms"`         // the p95 limit the run used
	Pages    int       `json:"pages"`            // distinct pages the crawl covered
	Safety   float64   `json:"safety"`           // HostCap = Lemmings × Safety
	Report   string    `json:"report,omitempty"` // path of the full benchmark report
}

// Path is the capacity file's location in dataDir.
func Path(dataDir string) string {
	return filepath.Join(dataDir, FileName)
}

// Validate checks a file read from disk.
func (f File) Validate() error {
	switch {
	case f.Version != fileVersion:
		return fmt.Errorf("unsupported version %d", f.Version)
	case f.HostCap < 1:
		return errors.New("host_cap must be at least 1")
	case f.At.IsZero():
		return errors.New("missing at")
	}
	return nil
}

// Load reads and validates the capacity file at path. A missing file is
// os.ErrNotExist.
func Load(path string) (File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Save writes f to path atomically with mode 0600.
func Save(path string, f File) error {
	f.Version = fileVersion
	if err := f.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".capacity-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
