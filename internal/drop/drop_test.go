package drop_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andreimerlescu/concert/internal/drop"
)

// baseTimes returns a fixed UTC schedule (beforeLobby, lobbyAt, midLobby, opensAt, afterOpen)
// for deterministic unit tests without wall-clock dependence.
func baseTimes() (beforeLobby, lobbyAt, midLobby, opensAt, afterOpen time.Time) {
	lobbyAt = time.Date(2026, 12, 1, 17, 45, 0, 0, time.UTC)
	beforeLobby = lobbyAt.Add(-5 * time.Minute)
	midLobby = lobbyAt.Add(5 * time.Minute)
	opensAt = lobbyAt.Add(15 * time.Minute)
	afterOpen = opensAt.Add(30 * time.Second)
	return beforeLobby, lobbyAt, midLobby, opensAt, afterOpen
}

// memStateSync is a thread-safe in-memory StateSync double modeling concert-kv
// including key storage, TTL capture, and injectable Save/Load failures (T4).
type memStateSync struct {
	mu      sync.RWMutex
	entries map[string]memEntry
	saveErr error
	loadErr error
}

type memEntry struct {
	payload []byte
	ttl     time.Duration
}

// newMemStateSync creates an empty memStateSync test double.
func newMemStateSync() *memStateSync {
	return &memStateSync{entries: make(map[string]memEntry)}
}

// Save stores a copy of payload under key unless saveErr is set or ctx is done.
func (m *memStateSync) Save(ctx context.Context, key string, payload []byte, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.entries[key] = memEntry{
		payload: bytes.Clone(payload),
		ttl:     ttl,
	}
	return nil
}

// Load returns a copy of the stored payload for key, or (nil, false, nil) if absent.
func (m *memStateSync) Load(ctx context.Context, key string) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.loadErr != nil {
		return nil, false, m.loadErr
	}
	ent, ok := m.entries[key]
	if !ok {
		return nil, false, nil
	}
	return bytes.Clone(ent.payload), true, nil
}

// failAfterReader succeeds for the first remaining bytes from src and then
// returns errFail on any subsequent Read.
type failAfterReader struct {
	src       io.Reader
	remaining int
	errFail   error
}

// Read delegates to src until remaining reaches zero, then returns errFail.
func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.errFail
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.src.Read(p)
	r.remaining -= n
	return n, err
}

// zeroReader returns zero bytes deterministically for reproducible examples.
type zeroReader struct{}

// Read fills p with zero bytes.
func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestConfigValidation verifies boundary validation and defaults in New.
// Invoke with: go test -run '^TestConfigValidation$' ./internal/drop
func TestConfigValidation(t *testing.T) {
	_, lobbyAt, _, opensAt, _ := baseTimes()

	tests := []struct {
		name      string
		cfg       drop.Config
		wantErr   error
		wantPhase drop.Phase
	}{
		{
			name: "valid defaults",
			cfg: drop.Config{
				EventID: "tour-2026",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
			},
			wantPhase: drop.PhaseIdle,
		},
		{
			name: "starts paused when configured",
			cfg: drop.Config{
				EventID: "tour-paused",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
				Paused:  true,
			},
			wantPhase: drop.PhasePaused,
		},
		{
			name: "sold out overrides paused",
			cfg: drop.Config{
				EventID:        "tour-sold-out",
				LobbyAt:        lobbyAt,
				OpensAt:        opensAt,
				Paused:         true,
				SoldOut:        true,
				SoldOutMessage: "Gone in 60s",
			},
			wantPhase: drop.PhaseSoldOut,
		},
		{
			name: "empty event ID",
			cfg: drop.Config{
				EventID: "   ",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "control char in event ID",
			cfg: drop.Config{
				EventID: "tour\n2026",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "event ID exceeds max length",
			cfg: drop.Config{
				EventID: strings.Repeat("a", drop.MaxEventIDLength+1),
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "zero lobby time",
			cfg: drop.Config{
				EventID: "tour-2026",
				OpensAt: opensAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "zero opens time",
			cfg: drop.Config{
				EventID: "tour-2026",
				LobbyAt: lobbyAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "lobby equal to opens",
			cfg: drop.Config{
				EventID: "tour-2026",
				LobbyAt: lobbyAt,
				OpensAt: lobbyAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "lobby after opens",
			cfg: drop.Config{
				EventID: "tour-2026",
				LobbyAt: opensAt,
				OpensAt: lobbyAt,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "negative max lobby tickets",
			cfg: drop.Config{
				EventID:         "tour-2026",
				LobbyAt:         lobbyAt,
				OpensAt:         opensAt,
				MaxLobbyTickets: -1,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "excessive max lobby tickets",
			cfg: drop.Config{
				EventID:         "tour-2026",
				LobbyAt:         lobbyAt,
				OpensAt:         opensAt,
				MaxLobbyTickets: drop.HardMaxLobbyTickets + 1,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "excessive max post-open tickets",
			cfg: drop.Config{
				EventID:            "tour-2026",
				LobbyAt:            lobbyAt,
				OpensAt:            opensAt,
				MaxPostOpenTickets: drop.HardMaxLobbyTickets + 1,
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "sold out message too long",
			cfg: drop.Config{
				EventID:        "tour-2026",
				LobbyAt:        lobbyAt,
				OpensAt:        opensAt,
				SoldOutMessage: strings.Repeat("x", drop.MaxMessageLength+1),
			},
			wantErr: drop.ErrInvalidConfig,
		},
		{
			name: "negative sync TTL",
			cfg: drop.Config{
				EventID: "tour-2026",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
				SyncTTL: -time.Second,
			},
			wantErr: drop.ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := drop.New(tt.cfg)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("New() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if d != nil {
					t.Fatalf("New() returned non-nil *Drop on error")
				}
				return
			}
			snap := d.Snapshot(lobbyAt.Add(-time.Minute))
			if snap.Phase != tt.wantPhase {
				t.Errorf("initial phase = %s, want %s", snap.Phase, tt.wantPhase)
			}
			if snap.MaxLobbyTickets != drop.DefaultMaxLobbyTickets {
				t.Errorf("MaxLobbyTickets = %d, want %d", snap.MaxLobbyTickets, drop.DefaultMaxLobbyTickets)
			}
			if snap.AuditSeq != 1 {
				t.Errorf("AuditSeq = %d, want 1", snap.AuditSeq)
			}
		})
	}
}

// TestLifecycleAndCountdown verifies time-driven transitions, CountdownSeconds
// rounding, direct idle -> open catch-up, and injected Clock fallback.
// Invoke with: go test -run '^TestLifecycleAndCountdown$' ./internal/drop
func TestLifecycleAndCountdown(t *testing.T) {
	beforeLobby, lobbyAt, midLobby, opensAt, afterOpen := baseTimes()
	clockNow := beforeLobby

	d, err := drop.New(drop.Config{
		EventID: "drop-lifecycle",
		LobbyAt: lobbyAt,
		OpensAt: opensAt,
		Clock:   func() time.Time { return clockNow },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 5 minutes before lobby using injected Clock (zero now argument).
	snap := d.Snapshot(time.Time{})
	if snap.Phase != drop.PhaseIdle || snap.CountdownSeconds != 300 {
		t.Fatalf("idle snapshot = (%s, %ds), want (idle, 300s)", snap.Phase, snap.CountdownSeconds)
	}

	// Fractional second before LobbyAt rounds up to 1s.
	snap = d.Snapshot(lobbyAt.Add(-250 * time.Millisecond))
	if snap.CountdownSeconds != 1 {
		t.Errorf("fractional countdown = %d, want 1", snap.CountdownSeconds)
	}

	// Advance before LobbyAt is a no-op.
	ev, err := d.Advance(beforeLobby)
	if err != nil || ev.Changed || ev.To != drop.PhaseIdle {
		t.Fatalf("Advance(beforeLobby) = (%+v, %v), want unchanged idle", ev, err)
	}

	// Advance at LobbyAt enters PhaseLobby.
	ev, err = d.Advance(lobbyAt)
	if err != nil || !ev.Changed || ev.From != drop.PhaseIdle || ev.To != drop.PhaseLobby {
		t.Fatalf("Advance(lobbyAt) = (%+v, %v), want idle->lobby", ev, err)
	}

	// Countdown in PhaseLobby targets OpensAt (10 minutes from midLobby).
	snap = d.Snapshot(midLobby)
	if snap.Phase != drop.PhaseLobby || snap.CountdownSeconds != 600 {
		t.Fatalf("lobby snapshot = (%s, %ds), want (lobby, 600s)", snap.Phase, snap.CountdownSeconds)
	}

	// Advance at OpensAt shuffles and opens.
	ev, err = d.Advance(opensAt)
	if err != nil || !ev.Changed || ev.From != drop.PhaseLobby || ev.To != drop.PhaseOpen {
		t.Fatalf("Advance(opensAt) = (%+v, %v), want lobby->open", ev, err)
	}

	// Repeated Advance after open is idempotent.
	ev2, err := d.Advance(afterOpen)
	if err != nil || ev2.Changed || ev2.To != drop.PhaseOpen {
		t.Fatalf("Advance(afterOpen) = (%+v, %v), want unchanged open", ev2, err)
	}
	snap = d.Snapshot(afterOpen)
	if snap.CountdownSeconds != 0 {
		t.Errorf("open CountdownSeconds = %d, want 0", snap.CountdownSeconds)
	}

	// Late-starting drop calling Advance directly at afterOpen catches up idle -> open.
	late, err := drop.New(drop.Config{
		EventID: "drop-late",
		LobbyAt: lobbyAt,
		OpensAt: opensAt,
	})
	if err != nil {
		t.Fatalf("New(late): %v", err)
	}
	evLate, err := late.Advance(afterOpen)
	if err != nil || !evLate.Changed || evLate.From != drop.PhaseIdle || evLate.To != drop.PhaseOpen {
		t.Fatalf("late Advance = (%+v, %v), want idle->open", evLate, err)
	}
}

// TestJoinLobbyIdempotencyAndCap verifies duplicate idempotency, MaxLobbyTickets
// bound enforcement (R3), input validation, and phase rejections.
// Invoke with: go test -run '^TestJoinLobbyIdempotencyAndCap$' ./internal/drop
func TestJoinLobbyIdempotencyAndCap(t *testing.T) {
	beforeLobby, lobbyAt, midLobby, opensAt, _ := baseTimes()

	d, err := drop.New(drop.Config{
		EventID:         "drop-cap",
		LobbyAt:         lobbyAt,
		OpensAt:         opensAt,
		MaxLobbyTickets: 3,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// JoinLobby rejected in PhaseIdle.
	if _, err := d.JoinLobby("t-1", beforeLobby); !errors.Is(err, drop.ErrLobbyNotOpen) {
		t.Fatalf("JoinLobby(idle) error = %v, want ErrLobbyNotOpen", err)
	}

	if _, err := d.Advance(lobbyAt); err != nil {
		t.Fatalf("Advance(lobbyAt): %v", err)
	}

	// Invalid ticket IDs rejected.
	for _, bad := range []string{"", "   ", "bad\x00id", strings.Repeat("z", drop.MaxTicketIDLength+1)} {
		if _, err := d.JoinLobby(bad, lobbyAt); !errors.Is(err, drop.ErrInvalidTicketID) {
			t.Errorf("JoinLobby(%q) error = %v, want ErrInvalidTicketID", bad, err)
		}
	}

	// Fill lobby to capacity 3.
	t0 := lobbyAt.Add(10 * time.Second)
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("ticket-%d", i)
		rec, err := d.JoinLobby(id, t0.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("JoinLobby(%s): %v", id, err)
		}
		if rec.Duplicate || rec.LobbyCount != i || rec.Phase != drop.PhaseLobby {
			t.Fatalf("JoinLobby(%s) receipt = %+v", id, rec)
		}
	}

	// New ticket rejected at MaxLobbyTickets (R3).
	if _, err := d.JoinLobby("ticket-4", midLobby); !errors.Is(err, drop.ErrLobbyFull) {
		t.Fatalf("JoinLobby(overflow) error = %v, want ErrLobbyFull", err)
	}

	// Duplicate ticket remains idempotent EVEN when lobby is full and keeps original JoinedAt.
	seqBefore := d.Snapshot(midLobby).AuditSeq
	dupRec, err := d.JoinLobby("ticket-1", midLobby)
	if err != nil {
		t.Fatalf("JoinLobby(duplicate at full cap): %v", err)
	}
	if !dupRec.Duplicate || dupRec.LobbyCount != 3 || !dupRec.JoinedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("duplicate receipt = %+v, want Duplicate=true LobbyCount=3 JoinedAt=%v", dupRec, t0.Add(time.Second))
	}
	if gotSeq := d.Snapshot(midLobby).AuditSeq; gotSeq != seqBefore {
		t.Errorf("duplicate JoinLobby mutated AuditSeq: got %d, want %d", gotSeq, seqBefore)
	}

	// Before shuffle, Position returns (0, false).
	if pos, ok := d.Position("ticket-1"); ok || pos != 0 {
		t.Errorf("Position before shuffle = (%d, %v), want (0, false)", pos, ok)
	}

	// Once open, JoinLobby is rejected.
	if _, err := d.Advance(opensAt); err != nil {
		t.Fatalf("Advance(opensAt): %v", err)
	}
	if _, err := d.JoinLobby("ticket-5", opensAt); !errors.Is(err, drop.ErrLobbyNotOpen) {
		t.Fatalf("JoinLobby(open) error = %v, want ErrLobbyNotOpen", err)
	}
}

// TestFisherYatesCompletenessAndUniformity proves that the CSPRNG Fisher-Yates
// shuffle assigns complete 1..N bijections, is statistically uniform across
// permutations and positions, and rolls back cleanly on entropy failures.
// Invoke with: go test -run '^TestFisherYatesCompletenessAndUniformity$' ./internal/drop
func TestFisherYatesCompletenessAndUniformity(t *testing.T) {
	_, lobbyAt, _, opensAt, _ := baseTimes()

	t.Run("bijection and slice isolation", func(t *testing.T) {
		const n = 250
		d, err := drop.New(drop.Config{
			EventID:         "drop-bijection",
			LobbyAt:         lobbyAt,
			OpensAt:         opensAt,
			MaxLobbyTickets: n,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := d.Advance(lobbyAt); err != nil {
			t.Fatalf("Advance(lobbyAt): %v", err)
		}
		expected := make([]string, n)
		for i := range n {
			id := fmt.Sprintf("ticket-%04d", i)
			expected[i] = id
			if _, err := d.JoinLobby(id, lobbyAt.Add(time.Duration(i)*time.Millisecond)); err != nil {
				t.Fatalf("JoinLobby(%s): %v", id, err)
			}
		}

		ev, err := d.Advance(opensAt)
		if err != nil {
			t.Fatalf("Advance(opensAt): %v", err)
		}
		if ev.ShuffledCount != n {
			t.Fatalf("ShuffledCount = %d, want %d", ev.ShuffledCount, n)
		}

		order := d.QueueOrder()
		if len(order) != n {
			t.Fatalf("len(QueueOrder) = %d, want %d", len(order), n)
		}

		// Verify exact bijection 1..N with zero duplicates and zero missing tickets.
		seenPos := make([]bool, n+1)
		seenID := make(map[string]bool, n)
		for idx, id := range order {
			if seenID[id] {
				t.Fatalf("duplicate ticket %q in QueueOrder", id)
			}
			seenID[id] = true
			pos, ok := d.Position(id)
			if !ok || pos != idx+1 {
				t.Fatalf("Position(%q) = (%d, %v), want (%d, true)", id, pos, ok, idx+1)
			}
			if seenPos[pos] {
				t.Fatalf("duplicate position %d", pos)
			}
			seenPos[pos] = true
		}
		for _, id := range expected {
			if !seenID[id] {
				t.Fatalf("missing ticket %q after shuffle", id)
			}
		}

		// Mutating returned copies must not affect internal Drop state.
		order[0] = "MUTATED"
		lobbyCopy := d.LobbyTickets()
		lobbyCopy[0] = "MUTATED"
		if d.QueueOrder()[0] == "MUTATED" {
			t.Fatal("QueueOrder returned aliased slice")
		}
		if d.LobbyTickets()[0] == "MUTATED" {
			t.Fatal("LobbyTickets returned aliased slice")
		}
	})

	t.Run("permutation uniformity K=3 catches naive-shuffle bias", func(t *testing.T) {
		const trials = 12_000
		tickets := []string{"A", "B", "C"}
		permCounts := make(map[string]int, 6)

		for range trials {
			d, err := drop.New(drop.Config{
				EventID: "uniform-k3",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := d.Advance(lobbyAt); err != nil {
				t.Fatalf("Advance(lobbyAt): %v", err)
			}
			for _, id := range tickets {
				if _, err := d.JoinLobby(id, lobbyAt); err != nil {
					t.Fatalf("JoinLobby(%s): %v", id, err)
				}
			}
			if _, err := d.Advance(opensAt); err != nil {
				t.Fatalf("Advance(opensAt): %v", err)
			}
			permCounts[strings.Join(d.QueueOrder(), "")]++
		}

		if len(permCounts) != 6 {
			t.Fatalf("observed %d distinct permutations, want 6: %v", len(permCounts), permCounts)
		}
		// Pearson chi-square test across 6 equiprobable permutations (df = 5).
		// Under uniform Fisher-Yates E[chi2]=5; naive biased shuffle yields chi2~148.
		// Critical value 45.0 has p < 1.5e-8 (virtually zero flake rate across -count=10).
		expected := float64(trials) / 6.0
		chi2 := 0.0
		for _, c := range permCounts {
			diff := float64(c) - expected
			chi2 += (diff * diff) / expected
		}
		if chi2 > 45.0 {
			t.Fatalf("permutation chi-square = %.2f (exceeds 45.0): counts=%v", chi2, permCounts)
		}
	})

	t.Run("positional uniformity K=6 catches Sattolo off-by-one", func(t *testing.T) {
		const (
			k      = 6
			trials = 6_000
		)
		tickets := []string{"t0", "t1", "t2", "t3", "t4", "t5"}
		var freq [k][k]int

		for range trials {
			d, err := drop.New(drop.Config{
				EventID: "uniform-k6",
				LobbyAt: lobbyAt,
				OpensAt: opensAt,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := d.Advance(lobbyAt); err != nil {
				t.Fatalf("Advance(lobbyAt): %v", err)
			}
			for _, id := range tickets {
				if _, err := d.JoinLobby(id, lobbyAt); err != nil {
					t.Fatalf("JoinLobby(%s): %v", id, err)
				}
			}
			if _, err := d.Advance(opensAt); err != nil {
				t.Fatalf("Advance(opensAt): %v", err)
			}
			for ti, id := range tickets {
				pos, ok := d.Position(id)
				if !ok || pos < 1 || pos > k {
					t.Fatalf("Position(%s) = (%d, %v)", id, pos, ok)
				}
				freq[ti][pos-1]++
			}
		}

		expected := float64(trials) / float64(k)
		for ti := range k {
			chi2 := 0.0
			for p := range k {
				if freq[ti][p] == 0 {
					t.Fatalf("ticket %s never landed in position %d", tickets[ti], p+1)
				}
				diff := float64(freq[ti][p]) - expected
				chi2 += (diff * diff) / expected
			}
			if math.IsNaN(chi2) || chi2 > 45.0 {
				t.Fatalf("ticket %s positional chi-square = %.2f (> 45.0): %v", tickets[ti], chi2, freq[ti])
			}
		}
	})

	t.Run("CSPRNG failure rolls back cleanly to PhaseLobby", func(t *testing.T) {
		entropyErr := errors.New("simulated entropy exhaustion")
		d, err := drop.New(drop.Config{
			EventID:    "drop-csprng-fail",
			LobbyAt:    lobbyAt,
			OpensAt:    opensAt,
			RandReader: &failAfterReader{src: rand.Reader, remaining: 1, errFail: entropyErr},
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := d.Advance(lobbyAt); err != nil {
			t.Fatalf("Advance(lobbyAt): %v", err)
		}
		for i := range 20 {
			if _, err := d.JoinLobby(fmt.Sprintf("t-%d", i), lobbyAt); err != nil {
				t.Fatalf("JoinLobby: %v", err)
			}
		}

		_, err = d.Advance(opensAt)
		if !errors.Is(err, drop.ErrShuffleFailed) || !errors.Is(err, entropyErr) {
			t.Fatalf("Advance(failing entropy) error = %v, want ErrShuffleFailed + entropyErr", err)
		}

		// Verify clean rollback: still PhaseLobby, all 20 lobby tickets preserved, 0 positions published.
		snap := d.Snapshot(opensAt)
		if snap.Phase != drop.PhaseLobby {
			t.Fatalf("phase after shuffle error = %s, want lobby", snap.Phase)
		}
		if snap.LobbyCount != 20 || snap.ShuffledCount != 0 || snap.TotalQueueCount != 0 {
			t.Fatalf("snapshot after rollback = %+v", snap)
		}
		if len(d.QueueOrder()) != 0 {
			t.Fatalf("partial queue order published after failure: %v", d.QueueOrder())
		}
	})
}

// TestPostOpenFIFOOrderingAndCap verifies that post-open arrivals append strictly
// FIFO at N+1, N+2, ... behind the shuffled lobby cohort, preserve idempotency
// for both shuffled and post-open tickets, and enforce MaxPostOpenTickets.
// Invoke with: go test -run '^TestPostOpenFIFOOrderingAndCap$' ./internal/drop
func TestPostOpenFIFOOrderingAndCap(t *testing.T) {
	beforeLobby, lobbyAt, _, opensAt, afterOpen := baseTimes()

	const (
		lobbyN    = 20
		postOpenN = 10
	)
	d, err := drop.New(drop.Config{
		EventID:            "drop-fifo",
		LobbyAt:            lobbyAt,
		OpensAt:            opensAt,
		MaxLobbyTickets:    lobbyN,
		MaxPostOpenTickets: postOpenN,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// EnqueuePostOpen rejected before open.
	if _, err := d.EnqueuePostOpen("early-1", beforeLobby); !errors.Is(err, drop.ErrDropNotOpen) {
		t.Fatalf("EnqueuePostOpen(idle) error = %v, want ErrDropNotOpen", err)
	}

	if _, err := d.Advance(lobbyAt); err != nil {
		t.Fatalf("Advance(lobbyAt): %v", err)
	}
	if _, err := d.EnqueuePostOpen("early-2", lobbyAt); !errors.Is(err, drop.ErrDropNotOpen) {
		t.Fatalf("EnqueuePostOpen(lobby) error = %v, want ErrDropNotOpen", err)
	}

	for i := range lobbyN {
		if _, err := d.JoinLobby(fmt.Sprintf("lobby-%02d", i), lobbyAt); err != nil {
			t.Fatalf("JoinLobby: %v", err)
		}
	}
	if _, err := d.Advance(opensAt); err != nil {
		t.Fatalf("Advance(opensAt): %v", err)
	}

	shuffledBefore := d.QueueOrder()
	if len(shuffledBefore) != lobbyN {
		t.Fatalf("len(shuffledBefore) = %d, want %d", len(shuffledBefore), lobbyN)
	}

	// Enqueue post-open tickets and assert strict FIFO positions N+1 .. N+postOpenN.
	for i := range postOpenN {
		id := fmt.Sprintf("post-%02d", i)
		rec, err := d.EnqueuePostOpen(id, afterOpen.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("EnqueuePostOpen(%s): %v", id, err)
		}
		wantPos := lobbyN + i + 1
		if rec.Position != wantPos || rec.Duplicate || !rec.PostOpen {
			t.Fatalf("EnqueuePostOpen(%s) = %+v, want pos=%d Duplicate=false PostOpen=true", id, rec, wantPos)
		}
	}

	// Overflow rejected with ErrQueueFull (R3).
	if _, err := d.EnqueuePostOpen("post-overflow", afterOpen); !errors.Is(err, drop.ErrQueueFull) {
		t.Fatalf("EnqueuePostOpen(overflow) error = %v, want ErrQueueFull", err)
	}

	// Re-enqueuing an existing lobby ticket returns its original 1..N position idempotently.
	existingLobby := shuffledBefore[0]
	recLobby, err := d.EnqueuePostOpen(existingLobby, afterOpen)
	if err != nil {
		t.Fatalf("EnqueuePostOpen(existing lobby): %v", err)
	}
	if recLobby.Position != 1 || !recLobby.Duplicate || recLobby.PostOpen {
		t.Fatalf("existing lobby receipt = %+v, want pos=1 Duplicate=true PostOpen=false", recLobby)
	}

	// Re-enqueuing an existing post-open ticket returns its exact FIFO position idempotently.
	recPost, err := d.EnqueuePostOpen("post-04", afterOpen)
	if err != nil {
		t.Fatalf("EnqueuePostOpen(existing post): %v", err)
	}
	if recPost.Position != lobbyN+5 || !recPost.Duplicate || !recPost.PostOpen {
		t.Fatalf("existing post receipt = %+v, want pos=%d Duplicate=true PostOpen=true", recPost, lobbyN+5)
	}

	// Verify prefix 1..N is untouched and suffix N+1..N+postOpenN is strictly FIFO.
	finalOrder := d.QueueOrder()
	if !slices.Equal(finalOrder[:lobbyN], shuffledBefore) {
		t.Fatalf("shuffled cohort prefix mutated after post-open enqueues")
	}
	for i := range postOpenN {
		wantID := fmt.Sprintf("post-%02d", i)
		if finalOrder[lobbyN+i] != wantID {
			t.Fatalf("finalOrder[%d] = %q, want %q", lobbyN+i, finalOrder[lobbyN+i], wantID)
		}
	}
}

// TestInvalidStateTransitions verifies the full CanTransition matrix and that
// operator actions reject illegal transitions with typed sentinel errors.
// Invoke with: go test -run '^TestInvalidStateTransitions$' ./internal/drop
func TestInvalidStateTransitions(t *testing.T) {
	allPhases := []drop.Phase{
		drop.PhaseIdle,
		drop.PhaseLobby,
		drop.PhaseShuffling,
		drop.PhaseOpen,
		drop.PhasePaused,
		drop.PhaseSoldOut,
	}

	allowed := map[[2]drop.Phase]bool{
		{drop.PhaseIdle, drop.PhaseLobby}:      true,
		{drop.PhaseIdle, drop.PhasePaused}:     true,
		{drop.PhaseIdle, drop.PhaseSoldOut}:    true,
		{drop.PhaseLobby, drop.PhaseShuffling}: true,
		{drop.PhaseLobby, drop.PhasePaused}:    true,
		{drop.PhaseLobby, drop.PhaseSoldOut}:   true,
		{drop.PhaseShuffling, drop.PhaseOpen}:  true,
		{drop.PhaseOpen, drop.PhasePaused}:     true,
		{drop.PhaseOpen, drop.PhaseSoldOut}:    true,
		{drop.PhasePaused, drop.PhaseIdle}:     true,
		{drop.PhasePaused, drop.PhaseLobby}:    true,
		{drop.PhasePaused, drop.PhaseOpen}:     true,
		{drop.PhasePaused, drop.PhaseSoldOut}:  true,
	}

	for _, from := range allPhases {
		if !from.Valid() {
			t.Errorf("%q.Valid() = false, want true", from)
		}
		for _, to := range allPhases {
			got := drop.CanTransition(from, to)
			want := allowed[[2]drop.Phase{from, to}]
			if got != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}
	if drop.Phase("unknown").Valid() {
		t.Error(`Phase("unknown").Valid() = true, want false`)
	}
	if drop.CanTransition(drop.Phase("unknown"), drop.PhaseIdle) {
		t.Error("CanTransition(unknown, idle) = true, want false")
	}

	_, lobbyAt, _, opensAt, _ := baseTimes()
	d, err := drop.New(drop.Config{
		EventID: "drop-transitions",
		LobbyAt: lobbyAt,
		OpensAt: opensAt,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Resume while idle -> ErrInvalidTransition.
	if err := d.Resume(lobbyAt); !errors.Is(err, drop.ErrInvalidTransition) {
		t.Fatalf("Resume(idle) error = %v, want ErrInvalidTransition", err)
	}

	// Double Pause -> ErrInvalidTransition.
	if err := d.Pause("maintenance", lobbyAt); err != nil {
		t.Fatalf("Pause(idle): %v", err)
	}
	if err := d.Pause("again", lobbyAt); !errors.Is(err, drop.ErrInvalidTransition) {
		t.Fatalf("Pause(paused) error = %v, want ErrInvalidTransition", err)
	}
	if err := d.Resume(lobbyAt); err != nil {
		t.Fatalf("Resume(paused): %v", err)
	}

	// Overlong Pause reason and SoldOut message rejected.
	if err := d.Pause(strings.Repeat("r", drop.MaxMessageLength+1), lobbyAt); !errors.Is(err, drop.ErrInvalidConfig) {
		t.Fatalf("Pause(long reason) error = %v, want ErrInvalidConfig", err)
	}
	if err := d.MarkSoldOut(strings.Repeat("m", drop.MaxMessageLength+1), lobbyAt); !errors.Is(err, drop.ErrInvalidConfig) {
		t.Fatalf("MarkSoldOut(long message) error = %v, want ErrInvalidConfig", err)
	}

	// MarkSoldOut is terminal until Reset.
	if err := d.MarkSoldOut("Sold out", lobbyAt); err != nil {
		t.Fatalf("MarkSoldOut: %v", err)
	}
	if err := d.MarkSoldOut("Again", lobbyAt); !errors.Is(err, drop.ErrInvalidTransition) || !errors.Is(err, drop.ErrSoldOut) {
		t.Fatalf("MarkSoldOut(sold_out) error = %v, want ErrInvalidTransition+ErrSoldOut", err)
	}
	if err := d.Pause("hold", lobbyAt); !errors.Is(err, drop.ErrInvalidTransition) || !errors.Is(err, drop.ErrSoldOut) {
		t.Fatalf("Pause(sold_out) error = %v, want ErrInvalidTransition+ErrSoldOut", err)
	}
	if err := d.Resume(lobbyAt); !errors.Is(err, drop.ErrInvalidTransition) || !errors.Is(err, drop.ErrSoldOut) {
		t.Fatalf("Resume(sold_out) error = %v, want ErrInvalidTransition+ErrSoldOut", err)
	}
}

// TestPauseResumePreservesPositions verifies that Pause and Resume in both
// PhaseLobby and PhaseOpen preserve every lobby entry and every assigned queue
// position identically without dropping anyone.
// Invoke with: go test -run '^TestPauseResumePreservesPositions$' ./internal/drop
func TestPauseResumePreservesPositions(t *testing.T) {
	_, lobbyAt, midLobby, opensAt, afterOpen := baseTimes()

	d, err := drop.New(drop.Config{
		EventID: "drop-pause-resume",
		LobbyAt: lobbyAt,
		OpensAt: opensAt,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Enter lobby and admit 10 tickets.
	if _, err := d.Advance(lobbyAt); err != nil {
		t.Fatalf("Advance(lobbyAt): %v", err)
	}
	for i := range 10 {
		if _, err := d.JoinLobby(fmt.Sprintf("L-%02d", i), midLobby); err != nil {
			t.Fatalf("JoinLobby: %v", err)
		}
	}

	// Pause during PhaseLobby.
	if err := d.Pause("inventory sync", midLobby); err != nil {
		t.Fatalf("Pause(lobby): %v", err)
	}
	if _, err := d.JoinLobby("L-new", midLobby); !errors.Is(err, drop.ErrPaused) || !errors.Is(err, drop.ErrLobbyNotOpen) {
		t.Fatalf("JoinLobby(paused) error = %v, want ErrPaused+ErrLobbyNotOpen", err)
	}
	// Advance at OpensAt MUST NOT transition while paused.
	ev, err := d.Advance(opensAt)
	if err != nil || ev.Changed || ev.To != drop.PhasePaused {
		t.Fatalf("Advance(opensAt while paused) = (%+v, %v), want unchanged paused", ev, err)
	}
	snap := d.Snapshot(midLobby)
	if snap.Phase != drop.PhasePaused || snap.PausedFrom != drop.PhaseLobby || snap.LobbyCount != 10 {
		t.Fatalf("paused lobby snapshot = %+v", snap)
	}

	// Resume back to PhaseLobby and verify all 10 tickets survive, then shuffle.
	if err := d.Resume(opensAt); err != nil {
		t.Fatalf("Resume(lobby): %v", err)
	}
	if got := len(d.LobbyTickets()); got != 10 {
		t.Fatalf("LobbyTickets after resume = %d, want 10", got)
	}
	if _, err := d.Advance(opensAt); err != nil {
		t.Fatalf("Advance(opensAt after resume): %v", err)
	}

	// Enqueue 5 post-open tickets.
	for i := range 5 {
		if _, err := d.EnqueuePostOpen(fmt.Sprintf("P-%02d", i), afterOpen); err != nil {
			t.Fatalf("EnqueuePostOpen: %v", err)
		}
	}
	orderBeforePause := d.QueueOrder()
	positionsBefore := make(map[string]int, len(orderBeforePause))
	for _, id := range orderBeforePause {
		pos, ok := d.Position(id)
		if !ok {
			t.Fatalf("Position(%q) missing before pause", id)
		}
		positionsBefore[id] = pos
	}

	// Pause during PhaseOpen.
	if err := d.Pause("checkout throttle", afterOpen); err != nil {
		t.Fatalf("Pause(open): %v", err)
	}
	if _, err := d.EnqueuePostOpen("P-blocked", afterOpen); !errors.Is(err, drop.ErrPaused) || !errors.Is(err, drop.ErrDropNotOpen) {
		t.Fatalf("EnqueuePostOpen(paused) error = %v, want ErrPaused+ErrDropNotOpen", err)
	}

	// Positions remain intact while paused AND after Resume.
	if !slices.Equal(d.QueueOrder(), orderBeforePause) {
		t.Fatal("QueueOrder changed while paused")
	}
	if err := d.Resume(afterOpen.Add(time.Minute)); err != nil {
		t.Fatalf("Resume(open): %v", err)
	}
	if !slices.Equal(d.QueueOrder(), orderBeforePause) {
		t.Fatal("QueueOrder changed after resume")
	}
	for id, wantPos := range positionsBefore {
		if gotPos, ok := d.Position(id); !ok || gotPos != wantPos {
			t.Fatalf("Position(%q) after resume = (%d, %v), want (%d, true)", id, gotPos, ok, wantPos)
		}
	}

	// Next post-open arrival seamlessly gets position 16.
	rec, err := d.EnqueuePostOpen("P-05", afterOpen.Add(2*time.Minute))
	if err != nil || rec.Position != 16 {
		t.Fatalf("EnqueuePostOpen after resume = (%+v, %v), want pos=16", rec, err)
	}
}

// TestSoldOutShortCircuitAndReset verifies sold-out short-circuiting across all
// admission and time-advancement paths, atomic Reset failure preservation, and
// successful Reset into a fresh drop.
// Invoke with: go test -run '^TestSoldOutShortCircuitAndReset$' ./internal/drop
func TestSoldOutShortCircuitAndReset(t *testing.T) {
	_, lobbyAt, midLobby, opensAt, afterOpen := baseTimes()

	d, err := drop.New(drop.Config{
		EventID:        "drop-sellout",
		LobbyAt:        lobbyAt,
		OpensAt:        opensAt,
		SoldOutMessage: "Default sold out",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := d.Advance(lobbyAt); err != nil {
		t.Fatalf("Advance(lobbyAt): %v", err)
	}
	if _, err := d.JoinLobby("t-1", midLobby); err != nil {
		t.Fatalf("JoinLobby: %v", err)
	}

	if err := d.MarkSoldOut("All VIP seats claimed.", midLobby); err != nil {
		t.Fatalf("MarkSoldOut: %v", err)
	}

	// Short-circuit: Advance at OpensAt does NOT shuffle or open.
	ev, err := d.Advance(opensAt)
	if err != nil || ev.Changed || ev.To != drop.PhaseSoldOut {
		t.Fatalf("Advance(sold_out) = (%+v, %v), want unchanged sold_out", ev, err)
	}
	if _, err := d.JoinLobby("t-2", midLobby); !errors.Is(err, drop.ErrSoldOut) {
		t.Fatalf("JoinLobby(sold_out) error = %v, want ErrSoldOut", err)
	}
	if _, err := d.EnqueuePostOpen("t-3", afterOpen); !errors.Is(err, drop.ErrSoldOut) {
		t.Fatalf("EnqueuePostOpen(sold_out) error = %v, want ErrSoldOut", err)
	}

	snap := d.Snapshot(midLobby)
	if snap.Phase != drop.PhaseSoldOut || snap.CountdownSeconds != 0 || snap.SoldOutMessage != "All VIP seats claimed." {
		t.Fatalf("sold-out snapshot = %+v", snap)
	}

	// Failed Reset leaves sold-out state untouched.
	if err := d.Reset(drop.Config{EventID: ""}, afterOpen); !errors.Is(err, drop.ErrInvalidConfig) {
		t.Fatalf("Reset(invalid) error = %v, want ErrInvalidConfig", err)
	}
	if got := d.Snapshot(afterOpen).Phase; got != drop.PhaseSoldOut {
		t.Fatalf("phase after failed Reset = %s, want sold_out", got)
	}

	// Valid Reset reinitializes cleanly with monotonic AuditSeq.
	seqBeforeReset := d.Snapshot(afterOpen).AuditSeq
	nextLobby := opensAt.Add(24 * time.Hour)
	nextOpen := nextLobby.Add(15 * time.Minute)
	if err := d.Reset(drop.Config{
		EventID:         "drop-night-2",
		LobbyAt:         nextLobby,
		OpensAt:         nextOpen,
		MaxLobbyTickets: 50,
	}, afterOpen); err != nil {
		t.Fatalf("Reset(valid): %v", err)
	}
	snapReset := d.Snapshot(afterOpen)
	if snapReset.EventID != "drop-night-2" || snapReset.Phase != drop.PhaseIdle ||
		snapReset.LobbyCount != 0 || snapReset.TotalQueueCount != 0 || snapReset.AuditSeq <= seqBeforeReset {
		t.Fatalf("snapshot after Reset = %+v (prev AuditSeq=%d)", snapReset, seqBeforeReset)
	}
}

// TestStateSyncMultiEdgeRoundTrip proves multi-edge replication through StateSync
// (matching exact shuffled and post-open queue order) and boundary rejection of
// corrupt, oversized, or invariant-violating payloads.
// Invoke with: go test -run '^TestStateSyncMultiEdgeRoundTrip$' ./internal/drop
func TestStateSyncMultiEdgeRoundTrip(t *testing.T) {
	_, lobbyAt, midLobby, opensAt, afterOpen := baseTimes()
	kv := newMemStateSync()

	// Edge A: populate lobby, shuffle at OpensAt, append post-open FIFO tickets, save to StateSync.
	edgeA, err := drop.New(drop.Config{
		EventID:         "multi-edge-drop",
		LobbyAt:         lobbyAt,
		OpensAt:         opensAt,
		MaxLobbyTickets: 50,
		Sync:            kv,
		SyncTTL:         2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New(edgeA): %v", err)
	}
	if _, err := edgeA.Advance(lobbyAt); err != nil {
		t.Fatalf("edgeA.Advance(lobbyAt): %v", err)
	}
	for i := range 25 {
		if _, err := edgeA.JoinLobby(fmt.Sprintf("lobby-%02d", i), midLobby); err != nil {
			t.Fatalf("edgeA.JoinLobby: %v", err)
		}
	}
	if _, err := edgeA.Advance(opensAt); err != nil {
		t.Fatalf("edgeA.Advance(opensAt): %v", err)
	}
	for i := range 5 {
		if _, err := edgeA.EnqueuePostOpen(fmt.Sprintf("post-%02d", i), afterOpen); err != nil {
			t.Fatalf("edgeA.EnqueuePostOpen: %v", err)
		}
	}

	ctx := t.Context()
	if err := edgeA.SaveState(ctx, nil, 0); err != nil {
		t.Fatalf("edgeA.SaveState: %v", err)
	}

	// Edge B: fresh node loads canonical state from shared StateSync.
	edgeB, err := drop.New(drop.Config{
		EventID: "multi-edge-drop",
		LobbyAt: lobbyAt,
		OpensAt: opensAt,
		Sync:    kv,
	})
	if err != nil {
		t.Fatalf("New(edgeB): %v", err)
	}
	loaded, err := edgeB.LoadState(ctx, nil)
	if err != nil || !loaded {
		t.Fatalf("edgeB.LoadState = (%v, %v), want (true, nil)", loaded, err)
	}

	snapA := edgeA.Snapshot(afterOpen)
	snapB := edgeB.Snapshot(afterOpen)
	if snapA.Phase != snapB.Phase || snapA.ShuffledCount != snapB.ShuffledCount ||
		snapA.PostOpenCount != snapB.PostOpenCount || snapA.AuditSeq != snapB.AuditSeq {
		t.Fatalf("edge snapshots diverged:\nA=%+v\nB=%+v", snapA, snapB)
	}

	orderA := edgeA.QueueOrder()
	orderB := edgeB.QueueOrder()
	if !slices.Equal(orderA, orderB) {
		t.Fatalf("edge queue orders diverged:\nA=%v\nB=%v", orderA, orderB)
	}
	for _, id := range orderA {
		posA, okA := edgeA.Position(id)
		posB, okB := edgeB.Position(id)
		if !okA || !okB || posA != posB {
			t.Fatalf("Position(%q): edgeA=(%d,%v), edgeB=(%d,%v)", id, posA, okA, posB, okB)
		}
	}

	// Edge B continues accepting post-open FIFO arrivals seamlessly at position 31.
	rec31, err := edgeB.EnqueuePostOpen("post-edge-b", afterOpen.Add(time.Minute))
	if err != nil || rec31.Position != 31 {
		t.Fatalf("edgeB.EnqueuePostOpen = (%+v, %v), want pos=31", rec31, err)
	}

	// Missing key returns (false, nil).
	emptyKV := newMemStateSync()
	found, err := edgeB.LoadState(ctx, emptyKV)
	if err != nil || found {
		t.Fatalf("LoadState(missing key) = (%v, %v), want (false, nil)", found, err)
	}

	// Unconfigured StateSync returns ErrSyncNotConfigured.
	noSync, err := drop.New(drop.Config{EventID: "no-sync", LobbyAt: lobbyAt, OpensAt: opensAt})
	if err != nil {
		t.Fatalf("New(noSync): %v", err)
	}
	if err := noSync.SaveState(ctx, nil, time.Minute); !errors.Is(err, drop.ErrSyncNotConfigured) {
		t.Fatalf("SaveState(nil) error = %v, want ErrSyncNotConfigured", err)
	}
	if _, err := noSync.LoadState(ctx, nil); !errors.Is(err, drop.ErrSyncNotConfigured) {
		t.Fatalf("LoadState(nil) error = %v, want ErrSyncNotConfigured", err)
	}

	// Context cancellation honored.
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := edgeA.SaveState(cancelledCtx, kv, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("SaveState(canceled) error = %v, want context.Canceled", err)
	}
	if _, err := edgeB.LoadState(cancelledCtx, kv); !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadState(canceled) error = %v, want context.Canceled", err)
	}

	// Backend errors propagate wrapped.
	backendErr := errors.New("kv connection refused")
	kv.saveErr = backendErr
	if err := edgeA.SaveState(ctx, kv, time.Minute); !errors.Is(err, backendErr) {
		t.Fatalf("SaveState(backend error) = %v, want %v", err, backendErr)
	}
	kv.saveErr = nil
	kv.loadErr = backendErr
	if _, err := edgeB.LoadState(ctx, kv); !errors.Is(err, backendErr) {
		t.Fatalf("LoadState(backend error) = %v, want %v", err, backendErr)
	}
	kv.loadErr = nil

	// UnmarshalState boundary checks: every malformed/inconsistent payload fails
	// with ErrInvalidState and leaves receiver state unchanged.
	validPayload, err := edgeA.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState: %v", err)
	}
	var validStruct drop.PersistedState
	if err := json.Unmarshal(validPayload, &validStruct); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	corruptCases := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "bad json", payload: []byte("{not-json")},
		{name: "trailing json", payload: append(bytes.Clone(validPayload), []byte(` {"extra":1}`)...)},
		{name: "wrong version", payload: mustMarshalState(t, func(s *drop.PersistedState) { s.Version = 99 }, validStruct)},
		{name: "persisted shuffling phase", payload: mustMarshalState(t, func(s *drop.PersistedState) { s.Phase = drop.PhaseShuffling }, validStruct)},
		{name: "paused without paused_from", payload: mustMarshalState(t, func(s *drop.PersistedState) { s.Phase = drop.PhasePaused; s.PausedFrom = "" }, validStruct)},
		{name: "duplicate queue ticket", payload: mustMarshalState(t, func(s *drop.PersistedState) { s.QueueOrder = []string{"a", "a"}; s.ShuffledCount = 2 }, validStruct)},
		{name: "duplicate lobby ticket", payload: mustMarshalState(t, func(s *drop.PersistedState) { s.LobbyOrder = []string{"a", "a"} }, validStruct)},
		{name: "shuffled count > queue len", payload: mustMarshalState(t, func(s *drop.PersistedState) { s.ShuffledCount = len(s.QueueOrder) + 1 }, validStruct)},
	}
	seqBeforeCorrupt := edgeB.Snapshot(afterOpen).AuditSeq
	for _, tc := range corruptCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			if err := edgeB.UnmarshalState(tc.payload); !errors.Is(err, drop.ErrInvalidState) {
				t.Fatalf("UnmarshalState(%s) error = %v, want ErrInvalidState", tc.name, err)
			}
			if got := edgeB.Snapshot(afterOpen).AuditSeq; got != seqBeforeCorrupt {
				t.Fatalf("corrupt UnmarshalState mutated state: AuditSeq=%d, want %d", got, seqBeforeCorrupt)
			}
		})
	}
}

// mustMarshalState clones base, applies mutate, and marshals to JSON for tests.
func mustMarshalState(t *testing.T, mutate func(*drop.PersistedState), base drop.PersistedState) []byte {
	t.Helper()
	cp := base
	cp.LobbyOrder = slices.Clone(base.LobbyOrder)
	cp.QueueOrder = slices.Clone(base.QueueOrder)
	mutate(&cp)
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return raw
}

// TestConcurrentStressRace exercises Drop under heavy concurrent lobby joins,
// simultaneous Advance calls, post-open enqueues, operator pause/resume,
// Snapshot/Position reads, and StateSync saves using a start barrier (no time.Sleep).
// Invoke with: go test -race -count=10 -run '^TestConcurrentStressRace$' ./internal/drop
func TestConcurrentStressRace(t *testing.T) {
	_, lobbyAt, midLobby, opensAt, afterOpen := baseTimes()
	kv := newMemStateSync()

	const (
		lobbyWorkers   = 16
		lobbyPerWorker = 40
		postWorkers    = 12
		postPerWorker  = 30
		advanceWorkers = 8
		readerWorkers  = 8
	)

	d, err := drop.New(drop.Config{
		EventID:            "drop-race-stress",
		LobbyAt:            lobbyAt,
		OpensAt:            opensAt,
		MaxLobbyTickets:    lobbyWorkers * lobbyPerWorker,
		MaxPostOpenTickets: postWorkers * postPerWorker,
		Sync:               kv,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := d.Advance(lobbyAt); err != nil {
		t.Fatalf("Advance(lobbyAt): %v", err)
	}

	// Phase 1: concurrent lobby registrations + readers + state saves.
	startLobby := make(chan struct{})
	var lobbyWG sync.WaitGroup
	for w := range lobbyWorkers {
		lobbyWG.Go(func() {
			<-startLobby
			for i := range lobbyPerWorker {
				id := fmt.Sprintf("L-%02d-%03d", w, i)
				if _, err := d.JoinLobby(id, midLobby); err != nil {
					t.Errorf("JoinLobby(%s): %v", id, err)
				}
				// Idempotent retry under contention.
				if _, err := d.JoinLobby(id, midLobby); err != nil {
					t.Errorf("JoinLobby duplicate(%s): %v", id, err)
				}
			}
		})
	}
	for range readerWorkers {
		lobbyWG.Go(func() {
			<-startLobby
			for range 50 {
				_ = d.Snapshot(midLobby)
				_ = d.LobbyTickets()
				if err := d.SaveState(t.Context(), kv, time.Hour); err != nil {
					t.Errorf("SaveState(lobby): %v", err)
				}
			}
		})
	}
	close(startLobby)
	lobbyWG.Wait()

	wantLobby := lobbyWorkers * lobbyPerWorker
	if got := d.Snapshot(midLobby).LobbyCount; got != wantLobby {
		t.Fatalf("LobbyCount after concurrent joins = %d, want %d", got, wantLobby)
	}

	// Phase 2: simultaneous Advance(opensAt) racers — exactly ONE must report Changed=true.
	startShuffle := make(chan struct{})
	changedCh := make(chan bool, advanceWorkers)
	var advWG sync.WaitGroup
	for range advanceWorkers {
		advWG.Go(func() {
			<-startShuffle
			ev, err := d.Advance(opensAt)
			if err != nil {
				t.Errorf("Advance(opensAt): %v", err)
				return
			}
			changedCh <- ev.Changed
		})
	}
	close(startShuffle)
	advWG.Wait()
	close(changedCh)

	transitions := 0
	for ch := range changedCh {
		if ch {
			transitions++
		}
	}
	if transitions != 1 {
		t.Fatalf("concurrent Advance transitions = %d, want exactly 1", transitions)
	}

	// Phase 3: concurrent post-open FIFO enqueues + readers + state snapshots.
	startPost := make(chan struct{})
	var postWG sync.WaitGroup
	for w := range postWorkers {
		postWG.Go(func() {
			<-startPost
			for i := range postPerWorker {
				id := fmt.Sprintf("P-%02d-%03d", w, i)
				rec, err := d.EnqueuePostOpen(id, afterOpen)
				if err != nil {
					t.Errorf("EnqueuePostOpen(%s): %v", id, err)
					return
				}
				if rec.Position <= wantLobby {
					t.Errorf("post-open ticket %s got position %d <= lobby size %d", id, rec.Position, wantLobby)
				}
			}
		})
	}
	for range readerWorkers {
		postWG.Go(func() {
			<-startPost
			for range 50 {
				_ = d.Snapshot(afterOpen)
				_ = d.QueueOrder()
				_, _ = d.Position("L-00-000")
				if _, err := d.MarshalState(); err != nil {
					t.Errorf("MarshalState: %v", err)
				}
			}
		})
	}
	close(startPost)
	postWG.Wait()

	// Final invariant verification across the entire queue.
	wantTotal := wantLobby + postWorkers*postPerWorker
	order := d.QueueOrder()
	if len(order) != wantTotal {
		t.Fatalf("final len(QueueOrder) = %d, want %d", len(order), wantTotal)
	}
	seen := make(map[string]struct{}, wantTotal)
	for idx, id := range order {
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ticket %q in final queue", id)
		}
		seen[id] = struct{}{}
		pos, ok := d.Position(id)
		if !ok || pos != idx+1 {
			t.Fatalf("Position(%q) = (%d, %v), want (%d, true)", id, pos, ok, idx+1)
		}
		if idx < wantLobby && !strings.HasPrefix(id, "L-") {
			t.Fatalf("non-lobby ticket %q placed inside shuffled prefix at index %d", id, idx)
		}
		if idx >= wantLobby && !strings.HasPrefix(id, "P-") {
			t.Fatalf("lobby ticket %q placed in post-open suffix at index %d", id, idx)
		}
	}
}

// ExampleNew demonstrates the complete scheduled drop lifecycle: opening the
// pre-queue lobby, registering lobby tickets, shuffling at OpensAt, and
// appending a post-open FIFO ticket behind the shuffled cohort.
func ExampleNew() {
	lobbyAt := time.Date(2026, 12, 1, 17, 45, 0, 0, time.UTC)
	opensAt := lobbyAt.Add(15 * time.Minute)

	d, err := drop.New(drop.Config{
		EventID:         "summer-tour-2026",
		LobbyAt:         lobbyAt,
		OpensAt:         opensAt,
		MaxLobbyTickets: 1000,
		RandReader:      zeroReader{}, // Deterministic reader for example output; omit in production for crypto/rand.Reader.
	})
	if err != nil {
		panic(err)
	}

	if _, err := d.Advance(lobbyAt); err != nil {
		panic(err)
	}
	for _, id := range []string{"ticket-a", "ticket-b", "ticket-c"} {
		if _, err := d.JoinLobby(id, lobbyAt.Add(time.Minute)); err != nil {
			panic(err)
		}
	}

	ev, err := d.Advance(opensAt)
	if err != nil {
		panic(err)
	}
	late, err := d.EnqueuePostOpen("ticket-late", opensAt.Add(10*time.Second))
	if err != nil {
		panic(err)
	}

	fmt.Printf("phase=%s shuffled=%d late_pos=%d\n", ev.To, ev.ShuffledCount, late.Position)
	// Output:
	// phase=open shuffled=3 late_pos=4
}
