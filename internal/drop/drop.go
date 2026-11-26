// Package drop implements the Scheduled Drops and Pre-Queue Randomized Lobby
// bounded context for Concert.
//
// A scheduled drop progresses through a validated lifecycle:
//
//   - [PhaseIdle]: before LobbyAt; visitors wait for the pre-queue lobby to open.
//   - [PhaseLobby]: between LobbyAt and OpensAt; visitors register unique ticket
//     IDs idempotently up to Config.MaxLobbyTickets.
//   - [PhaseShuffling]: transient phase at OpensAt while a cryptographically
//     unbiased CSPRNG Fisher-Yates shuffle (crypto/rand.Int) assigns queue
//     positions 1..N to the lobby cohort.
//   - [PhaseOpen]: after shuffling completes; shuffled lobby tickets hold
//     positions 1..N and post-open arrivals enqueue strictly FIFO at N+1, N+2, ...
//   - [PhasePaused]: operator-suspended state preserving all lobby registrations
//     and assigned queue positions until Resume.
//   - [PhaseSoldOut]: terminal short-circuit state rejecting new admissions until
//     an operator calls Reset with a new drop configuration.
//
// Multi-edge deployments may persist and load canonical JSON state snapshots
// through the optional [StateSync] port (for example, backed by concert-kv) so
// every edge enforces one authoritative shuffled queue order.
package drop

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
)

// Phase represents the lifecycle state of a scheduled drop.
type Phase string

const (
	// PhaseIdle indicates the drop is scheduled in the future (now < LobbyAt).
	PhaseIdle Phase = "idle"
	// PhaseLobby indicates the pre-queue randomized lobby is accepting unique
	// ticket registrations (LobbyAt <= now < OpensAt).
	PhaseLobby Phase = "lobby"
	// PhaseShuffling indicates the drop is executing the CSPRNG Fisher-Yates
	// shuffle over lobby tickets at OpensAt.
	PhaseShuffling Phase = "shuffling"
	// PhaseOpen indicates shuffling is complete and the drop queue is live.
	PhaseOpen Phase = "open"
	// PhasePaused indicates an operator has paused the drop while preserving
	// all lobby entries and assigned queue positions.
	PhasePaused Phase = "paused"
	// PhaseSoldOut indicates the drop is sold out and short-circuits admissions
	// until Reset is called.
	PhaseSoldOut Phase = "sold_out"
)

// Resource bounds and defaults enforced at package boundaries (R3, S9).
const (
	// DefaultMaxLobbyTickets is applied when Config.MaxLobbyTickets is zero.
	DefaultMaxLobbyTickets = 100_000
	// DefaultMaxPostOpenTickets is applied when Config.MaxPostOpenTickets is zero.
	DefaultMaxPostOpenTickets = 100_000
	// HardMaxLobbyTickets is the upper ceiling on configured lobby or post-open
	// queue capacities to prevent unbounded memory growth under hostile load.
	HardMaxLobbyTickets = 1_000_000
	// MaxTicketIDLength bounds accepted ticket identifiers in bytes.
	MaxTicketIDLength = 256
	// MaxEventIDLength bounds Config.EventID in bytes.
	MaxEventIDLength = 128
	// MaxMessageLength bounds operator pause reasons and sold-out messages in bytes.
	MaxMessageLength = 512
	// MaxSyncPayloadBytes caps serialized state payloads accepted by
	// UnmarshalState and LoadState.
	MaxSyncPayloadBytes = 64 << 20
	// DefaultSyncTTL is used by SaveState when no positive TTL is supplied.
	DefaultSyncTTL = 24 * time.Hour
	// DefaultSyncKeyPrefix namespaces drop state keys in StateSync backends.
	DefaultSyncKeyPrefix = "concert:drop:"
)

// Sentinel errors returned by Drop operations. Match them with errors.Is.
var (
	// ErrInvalidConfig indicates that Config failed validation.
	ErrInvalidConfig = errors.New("drop: invalid config")
	// ErrInvalidTransition indicates that a requested phase transition or
	// operator action is not valid in the current Phase.
	ErrInvalidTransition = errors.New("drop: invalid state transition")
	// ErrInvalidTicketID indicates that a ticket ID is empty, exceeds
	// MaxTicketIDLength, or contains ASCII control characters.
	ErrInvalidTicketID = errors.New("drop: invalid ticket ID")
	// ErrLobbyNotOpen indicates that JoinLobby was called outside PhaseLobby.
	ErrLobbyNotOpen = errors.New("drop: lobby is not open")
	// ErrDropNotOpen indicates that EnqueuePostOpen was called outside PhaseOpen.
	ErrDropNotOpen = errors.New("drop: drop is not open")
	// ErrLobbyFull indicates that the pre-queue lobby reached MaxLobbyTickets.
	ErrLobbyFull = errors.New("drop: lobby capacity reached")
	// ErrQueueFull indicates that the post-open FIFO queue reached MaxPostOpenTickets.
	ErrQueueFull = errors.New("drop: post-open queue capacity reached")
	// ErrSoldOut indicates that an operation was rejected because the drop is sold out.
	ErrSoldOut = errors.New("drop: event is sold out")
	// ErrPaused indicates that an admission was rejected because the drop is paused.
	ErrPaused = errors.New("drop: event is paused")
	// ErrShuffleFailed indicates that the CSPRNG failed during Fisher-Yates shuffling.
	ErrShuffleFailed = errors.New("drop: shuffle entropy failure")
	// ErrInvalidState indicates that a persisted state JSON payload is malformed
	// or violates aggregate invariants.
	ErrInvalidState = errors.New("drop: invalid persisted state")
	// ErrSyncNotConfigured indicates that SaveState or LoadState was invoked
	// without a StateSync implementation.
	ErrSyncNotConfigured = errors.New("drop: state sync not configured")
)

// StateSync is an optional persistence port (for example, backed by concert-kv)
// used to replicate one canonical drop state and shuffled queue order across
// multiple Concert edges.
type StateSync interface {
	// Save stores payload under key with the requested ttl.
	// Implementations must honor ctx cancellation and deadlines.
	Save(ctx context.Context, key string, payload []byte, ttl time.Duration) error
	// Load retrieves the payload stored under key.
	// It returns (nil, false, nil) when key does not exist.
	Load(ctx context.Context, key string) ([]byte, bool, error)
}

// Config configures a scheduled [Drop] aggregate.
type Config struct {
	// EventID uniquely identifies the scheduled drop. Required; must be non-empty,
	// at most MaxEventIDLength bytes, and free of ASCII control characters.
	EventID string
	// LobbyAt is the instant when the pre-queue lobby opens. Must be non-zero
	// and strictly before OpensAt.
	LobbyAt time.Time
	// OpensAt is the instant when the lobby closes, shuffling runs, and the
	// drop opens. Must be non-zero and strictly after LobbyAt.
	OpensAt time.Time
	// MaxLobbyTickets bounds the number of unique tickets accepted during
	// PhaseLobby. Zero defaults to DefaultMaxLobbyTickets; values below 0 or
	// above HardMaxLobbyTickets are rejected.
	MaxLobbyTickets int
	// MaxPostOpenTickets bounds the number of unique tickets accepted via
	// EnqueuePostOpen after OpensAt. Zero defaults to DefaultMaxPostOpenTickets;
	// values below 0 or above HardMaxLobbyTickets are rejected.
	MaxPostOpenTickets int
	// Paused starts the drop in PhasePaused (with pausedFrom = PhaseIdle) when
	// true and SoldOut is false.
	Paused bool
	// SoldOut starts the drop in PhaseSoldOut when true (takes precedence over Paused).
	SoldOut bool
	// SoldOutMessage is the operator-facing message exposed in Snapshot when
	// the drop is sold out. At most MaxMessageLength bytes.
	SoldOutMessage string
	// Clock supplies the current time when callers pass a zero time.Time.
	// Defaults to time.Now when nil.
	Clock func() time.Time
	// RandReader supplies cryptographic randomness for the Fisher-Yates shuffle.
	// Defaults to crypto/rand.Reader when nil.
	RandReader io.Reader
	// Sync is an optional default StateSync port used by SaveState and LoadState
	// when a nil syncer parameter is passed.
	Sync StateSync
	// SyncKey optionally overrides the StateSync storage key.
	// Defaults to DefaultSyncKeyPrefix + EventID.
	SyncKey string
	// SyncTTL optionally overrides the default TTL passed to StateSync.Save.
	// Zero defaults to DefaultSyncTTL; negative values are rejected.
	SyncTTL time.Duration
}

// LobbyReceipt describes the outcome of a successful [Drop.JoinLobby] call.
type LobbyReceipt struct {
	// EventID is the identifier of the drop.
	EventID string `json:"event_id"`
	// TicketID is the registered ticket identifier.
	TicketID string `json:"ticket_id"`
	// JoinedAt is the UTC timestamp when TicketID first entered the lobby.
	JoinedAt time.Time `json:"joined_at"`
	// Duplicate is true when TicketID was already registered in the lobby.
	Duplicate bool `json:"duplicate"`
	// LobbyCount is the total number of unique tickets in the lobby after this call.
	LobbyCount int `json:"lobby_count"`
	// Phase is the active drop phase (PhaseLobby).
	Phase Phase `json:"phase"`
}

// QueueReceipt describes the outcome of a successful [Drop.EnqueuePostOpen] call.
type QueueReceipt struct {
	// EventID is the identifier of the drop.
	EventID string `json:"event_id"`
	// TicketID is the enqueued ticket identifier.
	TicketID string `json:"ticket_id"`
	// Position is the assigned 1-based queue position. Positions 1..ShuffledCount
	// belong to the shuffled lobby cohort; positions > ShuffledCount are post-open FIFO.
	Position int `json:"position"`
	// EnqueuedAt is the UTC timestamp when the ticket entered the queue.
	EnqueuedAt time.Time `json:"enqueued_at"`
	// Duplicate is true when TicketID already held a queue position (either from
	// the shuffled lobby cohort or an earlier post-open enqueue).
	Duplicate bool `json:"duplicate"`
	// PostOpen is true when Position is strictly behind the shuffled cohort.
	PostOpen bool `json:"post_open"`
	// Phase is the active drop phase (PhaseOpen).
	Phase Phase `json:"phase"`
}

// TransitionEvent reports the result of calling [Drop.Advance].
type TransitionEvent struct {
	// EventID is the identifier of the drop.
	EventID string `json:"event_id"`
	// From is the phase before Advance ran.
	From Phase `json:"from"`
	// To is the phase after Advance ran.
	To Phase `json:"to"`
	// Changed is true when Advance performed at least one phase transition.
	Changed bool `json:"changed"`
	// ShuffledCount is the number of lobby tickets assigned randomized 1..N
	// positions (populated when the shuffle has completed).
	ShuffledCount int `json:"shuffled_count"`
	// AuditSeq is the monotonic state revision after Advance.
	AuditSeq uint64 `json:"audit_seq"`
	// Timestamp is the UTC evaluation instant used by Advance.
	Timestamp time.Time `json:"timestamp"`
}

// Snapshot is an immutable point-in-time view of a [Drop] aggregate.
type Snapshot struct {
	// EventID is the identifier of the drop.
	EventID string `json:"event_id"`
	// Phase is the current lifecycle phase.
	Phase Phase `json:"phase"`
	// PausedFrom records the phase to which Resume will return when Phase is PhasePaused.
	PausedFrom Phase `json:"paused_from,omitempty"`
	// PauseReason records the operator reason supplied to Pause when Phase is PhasePaused.
	PauseReason string `json:"pause_reason,omitempty"`
	// LobbyAt is the scheduled lobby opening instant in UTC.
	LobbyAt time.Time `json:"lobby_at"`
	// OpensAt is the scheduled drop opening instant in UTC.
	OpensAt time.Time `json:"opens_at"`
	// CountdownSeconds is whole seconds (rounded up, clamped at 0) until the next
	// scheduled transition (LobbyAt in PhaseIdle, OpensAt in PhaseLobby, or the
	// suspended target in PhasePaused; 0 in PhaseShuffling, PhaseOpen, PhaseSoldOut).
	CountdownSeconds int64 `json:"countdown_seconds"`
	// LobbyCount is the number of unique tickets registered in the lobby.
	LobbyCount int `json:"lobby_count"`
	// ShuffledCount is the number of lobby tickets assigned randomized positions 1..N.
	ShuffledCount int `json:"shuffled_count"`
	// PostOpenCount is the number of tickets enqueued FIFO behind the shuffled cohort.
	PostOpenCount int `json:"post_open_count"`
	// TotalQueueCount is ShuffledCount + PostOpenCount.
	TotalQueueCount int `json:"total_queue_count"`
	// MaxLobbyTickets is the configured lobby capacity cap.
	MaxLobbyTickets int `json:"max_lobby_tickets"`
	// SoldOutMessage is the operator sold-out message.
	SoldOutMessage string `json:"sold_out_message,omitempty"`
	// AuditSeq is the monotonic state mutation sequence number.
	AuditSeq uint64 `json:"audit_seq"`
	// GeneratedAt is the UTC timestamp at which the snapshot was evaluated.
	GeneratedAt time.Time `json:"generated_at"`
}

// PersistedState is the versioned canonical JSON wire format used by
// [Drop.MarshalState], [Drop.UnmarshalState], [Drop.SaveState], and [Drop.LoadState]
// to replicate drop state across Concert edges.
type PersistedState struct {
	// Version identifies the schema version. Currently always 1.
	Version int `json:"version"`
	// EventID identifies the scheduled drop.
	EventID string `json:"event_id"`
	// LobbyAt is the scheduled lobby opening instant in UTC.
	LobbyAt time.Time `json:"lobby_at"`
	// OpensAt is the scheduled drop opening instant in UTC.
	OpensAt time.Time `json:"opens_at"`
	// MaxLobbyTickets is the configured lobby capacity bound.
	MaxLobbyTickets int `json:"max_lobby_tickets"`
	// MaxPostOpenTickets is the configured post-open queue capacity bound.
	MaxPostOpenTickets int `json:"max_post_open_tickets"`
	// Phase is the active lifecycle phase.
	Phase Phase `json:"phase"`
	// PausedFrom is the phase recorded prior to entering PhasePaused.
	PausedFrom Phase `json:"paused_from,omitempty"`
	// PauseReason is the operator reason recorded when paused.
	PauseReason string `json:"pause_reason,omitempty"`
	// SoldOutMessage is the operator sold-out message.
	SoldOutMessage string `json:"sold_out_message,omitempty"`
	// LobbyOrder holds registered lobby ticket IDs in first-seen join order.
	LobbyOrder []string `json:"lobby_order,omitempty"`
	// LobbyJoinedAt maps each ticket in LobbyOrder to its UTC join instant.
	LobbyJoinedAt map[string]time.Time `json:"lobby_joined_at,omitempty"`
	// QueueOrder holds canonical queue ticket IDs in 1-based position order:
	// indices [0, ShuffledCount) are the CSPRNG-shuffled lobby cohort and
	// indices [ShuffledCount, len) are strictly FIFO post-open arrivals.
	QueueOrder []string `json:"queue_order,omitempty"`
	// EnqueuedAt maps each ticket in QueueOrder to its UTC queue admission instant.
	EnqueuedAt map[string]time.Time `json:"enqueued_at,omitempty"`
	// ShuffledCount is the count of shuffled lobby tickets at the front of QueueOrder.
	ShuffledCount int `json:"shuffled_count"`
	// OpenedAt is the UTC instant when shuffling completed and PhaseOpen began.
	OpenedAt time.Time `json:"opened_at,omitempty"`
	// AuditSeq is the monotonic mutation sequence number.
	AuditSeq uint64 `json:"audit_seq"`
}

const persistedStateVersion = 1

// Drop is the aggregate root managing a scheduled drop lifecycle, pre-queue
// randomized lobby, CSPRNG Fisher-Yates shuffle, post-open FIFO queue, operator
// controls, and multi-edge state synchronization.
//
// Drop is safe for concurrent use by multiple goroutines. Construct instances
// with [New]; do not copy a Drop value after creation. All returned slices and
// structs are independent copies of internal state.
type Drop struct {
	mu sync.RWMutex

	// All fields below are guarded by mu.
	cfg            Config
	clock          func() time.Time
	randReader     io.Reader
	sync           StateSync
	syncKey        string
	syncTTL        time.Duration
	phase          Phase
	pausedFrom     Phase
	pauseReason    string
	soldOutMessage string
	lobbyOrder     []string
	lobbyJoined    map[string]time.Time
	queueOrder     []string
	positions      map[string]int
	enqueuedAt     map[string]time.Time
	shuffledCount  int
	openedAt       time.Time
	auditSeq       uint64
}

// Valid reports whether p is one of the six defined [Phase] constants.
//
// # Parameters
//
// Receiver p is the phase value to inspect.
//
// # Returns
//
// true if p is PhaseIdle, PhaseLobby, PhaseShuffling, PhaseOpen, PhasePaused,
// or PhaseSoldOut; false otherwise.
//
// # Example
//
//	if !drop.PhaseLobby.Valid() {
//		return drop.ErrInvalidState
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:2013 (direct call)
//   - internal/drop/drop_test.go:794 (direct call)
//   - internal/drop/drop_test.go:805 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (p Phase) Valid() bool {
	switch p {
	case PhaseIdle, PhaseLobby, PhaseShuffling, PhaseOpen, PhasePaused, PhaseSoldOut:
		return true
	default:
		return false
	}
}

// String returns the canonical lowercase wire representation of p.
//
// # Parameters
//
// Receiver p is the phase value to format.
//
// # Returns
//
// The underlying string value of p.
//
// # Example
//
//	fmt.Println(drop.PhaseOpen.String())
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (p Phase) String() string {
	return string(p)
}

// CanTransition reports whether moving directly from phase from to phase to is
// permitted by the scheduled drop state machine.
//
// # Parameters
//
//   - from: Current lifecycle phase.
//   - to: Proposed target lifecycle phase.
//
// # Returns
//
// true when the direct transition from -> to is legal; false for unknown phases,
// self-transitions, skipped shuffle phases (such as idle -> open or lobby -> open),
// or any transition out of terminal PhaseSoldOut (which requires Reset).
//
// # Example
//
//	ok := drop.CanTransition(drop.PhaseLobby, drop.PhaseShuffling)
//	fmt.Println(ok)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:926 (direct call)
//   - internal/drop/drop.go:987 (direct call)
//   - internal/drop/drop.go:1005 (direct call)
//   - internal/drop/drop.go:1277 (direct call)
//   - internal/drop/drop.go:1334 (direct call)
//   - internal/drop/drop.go:1394 (direct call)
//   - internal/drop/drop_test.go:798 (direct call)
//   - internal/drop/drop_test.go:808 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func CanTransition(from, to Phase) bool {
	switch from {
	case PhaseIdle:
		return to == PhaseLobby || to == PhasePaused || to == PhaseSoldOut
	case PhaseLobby:
		return to == PhaseShuffling || to == PhasePaused || to == PhaseSoldOut
	case PhaseShuffling:
		return to == PhaseOpen
	case PhaseOpen:
		return to == PhasePaused || to == PhaseSoldOut
	case PhasePaused:
		return to == PhaseIdle || to == PhaseLobby || to == PhaseOpen || to == PhaseSoldOut
	case PhaseSoldOut:
		return false
	default:
		return false
	}
}

// New validates cfg and constructs a ready-to-use [Drop] aggregate.
//
// # Parameters
//
//   - cfg: Drop schedule, bounds, initial flags, and optional Clock, RandReader,
//     and StateSync dependencies. LobbyAt must strictly precede OpensAt.
//
// # Returns
//
// A configured *Drop with AuditSeq initialized to 1, or a nil *Drop and an error
// matching ErrInvalidConfig when validation fails.
//
// # Concurrency
//
// The returned *Drop is safe for concurrent use by multiple goroutines.
//
// # Example
//
//	lobbyAt := time.Date(2026, 12, 1, 17, 45, 0, 0, time.UTC)
//	opensAt := lobbyAt.Add(15 * time.Minute)
//	d, err := drop.New(drop.Config{
//		EventID:         "summer-tour-2026",
//		LobbyAt:         lobbyAt,
//		OpensAt:         opensAt,
//		MaxLobbyTickets: 5000,
//	})
//	if err != nil {
//		return err
//	}
//	_ = d.Snapshot(lobbyAt)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:272 (direct call)
//   - internal/drop/drop_test.go:303 (direct call)
//   - internal/drop/drop_test.go:360 (direct call)
//   - internal/drop/drop_test.go:380 (direct call)
//   - internal/drop/drop_test.go:460 (direct call)
//   - internal/drop/drop_test.go:535 (direct call)
//   - internal/drop/drop_test.go:583 (direct call)
//   - internal/drop/drop_test.go:629 (direct call)
//   - internal/drop/drop_test.go:677 (direct call)
//   - internal/drop/drop_test.go:813 (direct call)
//   - internal/drop/drop_test.go:868 (direct call)
//   - internal/drop/drop_test.go:969 (direct call)
//   - internal/drop/drop_test.go:1042 (direct call)
//   - internal/drop/drop_test.go:1076 (direct call)
//   - internal/drop/drop_test.go:1124 (direct call)
//   - internal/drop/drop_test.go:1227 (direct call)
//   - internal/drop/drop_test.go:1376 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func New(cfg Config) (*Drop, error) {
	norm, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	d := &Drop{}
	d.applyNormalizedConfigLocked(norm)
	d.auditSeq = 1
	return d, nil
}

// normalizeConfig validates user-supplied Config values and fills safe defaults.
//
// # Parameters
//
//   - cfg: Raw configuration passed to New or Reset.
//
// # Returns
//
// A normalized Config with UTC timestamps and defaulted capacities, Clock,
// RandReader, SyncKey, and SyncTTL, or an error wrapping ErrInvalidConfig.
//
// # Example
//
//	norm, err := normalizeConfig(cfg)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:506 (direct call)
//   - internal/drop/drop.go:1444 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func normalizeConfig(cfg Config) (Config, error) {
	if err := validateID(cfg.EventID, MaxEventIDLength); err != nil {
		return Config{}, fmt.Errorf("%w: event_id: %v", ErrInvalidConfig, err)
	}
	if cfg.LobbyAt.IsZero() {
		return Config{}, fmt.Errorf("%w: lobby_at must be non-zero", ErrInvalidConfig)
	}
	if cfg.OpensAt.IsZero() {
		return Config{}, fmt.Errorf("%w: opens_at must be non-zero", ErrInvalidConfig)
	}
	cfg.LobbyAt = cfg.LobbyAt.UTC()
	cfg.OpensAt = cfg.OpensAt.UTC()
	if !cfg.LobbyAt.Before(cfg.OpensAt) {
		return Config{}, fmt.Errorf("%w: lobby_at (%s) must be strictly before opens_at (%s)",
			ErrInvalidConfig, cfg.LobbyAt.Format(time.RFC3339), cfg.OpensAt.Format(time.RFC3339))
	}
	if cfg.MaxLobbyTickets < 0 || cfg.MaxLobbyTickets > HardMaxLobbyTickets {
		return Config{}, fmt.Errorf("%w: max_lobby_tickets %d out of range [0, %d]",
			ErrInvalidConfig, cfg.MaxLobbyTickets, HardMaxLobbyTickets)
	}
	if cfg.MaxLobbyTickets == 0 {
		cfg.MaxLobbyTickets = DefaultMaxLobbyTickets
	}
	if cfg.MaxPostOpenTickets < 0 || cfg.MaxPostOpenTickets > HardMaxLobbyTickets {
		return Config{}, fmt.Errorf("%w: max_post_open_tickets %d out of range [0, %d]",
			ErrInvalidConfig, cfg.MaxPostOpenTickets, HardMaxLobbyTickets)
	}
	if cfg.MaxPostOpenTickets == 0 {
		cfg.MaxPostOpenTickets = DefaultMaxPostOpenTickets
	}
	if len(cfg.SoldOutMessage) > MaxMessageLength {
		return Config{}, fmt.Errorf("%w: sold_out_message exceeds %d bytes", ErrInvalidConfig, MaxMessageLength)
	}
	if cfg.SyncTTL < 0 {
		return Config{}, fmt.Errorf("%w: sync_ttl must be non-negative", ErrInvalidConfig)
	}
	if cfg.SyncTTL == 0 {
		cfg.SyncTTL = DefaultSyncTTL
	}
	if cfg.SyncKey != "" {
		if err := validateID(cfg.SyncKey, MaxTicketIDLength); err != nil {
			return Config{}, fmt.Errorf("%w: sync_key: %v", ErrInvalidConfig, err)
		}
	} else {
		cfg.SyncKey = DefaultSyncKeyPrefix + cfg.EventID
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.RandReader == nil {
		cfg.RandReader = rand.Reader
	}
	return cfg, nil
}

// applyNormalizedConfigLocked installs a pre-validated Config onto d and resets
// all runtime collections. Caller must hold d.mu.Lock().
//
// # Parameters
//
//   - norm: Config previously validated by normalizeConfig.
//
// # Returns
//
// None. Mutates d in place under d.mu.
//
// # Example
//
//	d.applyNormalizedConfigLocked(norm)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:511 (direct call)
//   - internal/drop/drop.go:1452 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) applyNormalizedConfigLocked(norm Config) {
	d.cfg = norm
	d.clock = norm.Clock
	d.randReader = norm.RandReader
	d.sync = norm.Sync
	d.syncKey = norm.SyncKey
	d.syncTTL = norm.SyncTTL
	d.soldOutMessage = norm.SoldOutMessage
	d.pauseReason = ""
	d.pausedFrom = ""
	d.lobbyOrder = nil
	d.lobbyJoined = make(map[string]time.Time)
	d.queueOrder = nil
	d.positions = make(map[string]int)
	d.enqueuedAt = make(map[string]time.Time)
	d.shuffledCount = 0
	d.openedAt = time.Time{}

	// SoldOut takes precedence over Paused so a sold-out drop cannot accidentally
	// resume into an active phase.
	switch {
	case norm.SoldOut:
		d.phase = PhaseSoldOut
	case norm.Paused:
		d.phase = PhasePaused
		d.pausedFrom = PhaseIdle
	default:
		d.phase = PhaseIdle
	}
}

// validateID enforces non-empty, length-bounded, control-character-free IDs at
// trust boundaries (S9).
//
// # Parameters
//
//   - id: Candidate identifier string.
//   - maxLen: Maximum permitted byte length, inclusive.
//
// # Returns
//
// nil when id is valid; otherwise a descriptive validation error.
//
// # Example
//
//	if err := validateID("ticket-42", MaxTicketIDLength); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:540 (direct call)
//   - internal/drop/drop.go:579 (direct call)
//   - internal/drop/drop.go:793 (direct call)
//   - internal/drop/drop.go:1168 (direct call)
//   - internal/drop/drop.go:1997 (direct call)
//   - internal/drop/drop.go:2045 (direct call)
//   - internal/drop/drop.go:2059 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validateID(id string, maxLen int) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("must not be empty or whitespace")
	}
	if len(id) > maxLen {
		return fmt.Errorf("length %d exceeds max %d bytes", len(id), maxLen)
	}
	for i := range len(id) {
		b := id[i]
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("contains ASCII control byte 0x%02x", b)
		}
	}
	return nil
}

// resolveNowLocked normalizes now to UTC, falling back to the configured Clock
// when now is zero. Caller must hold at least d.mu.RLock().
//
// # Parameters
//
//   - now: Caller-provided instant, or zero time.Time to query d.clock.
//
// # Returns
//
// A UTC time.Time instant.
//
// # Example
//
//	ts := d.resolveNowLocked(now)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:828 (direct call)
//   - internal/drop/drop.go:918 (direct call)
//   - internal/drop/drop.go:1205 (direct call)
//   - internal/drop/drop.go:1281 (direct call)
//   - internal/drop/drop.go:1338 (direct call)
//   - internal/drop/drop.go:1398 (direct call)
//   - internal/drop/drop.go:1453 (direct call)
//   - internal/drop/drop.go:1641 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) resolveNowLocked(now time.Time) time.Time {
	if !now.IsZero() {
		return now.UTC()
	}
	if d.clock != nil {
		return d.clock().UTC()
	}
	return time.Now().UTC()
}

// JoinLobby registers ticketID in the pre-queue randomized lobby while the drop
// is in [PhaseLobby]. Duplicate registrations for the same ticketID are
// idempotent and return the original join timestamp without consuming extra
// lobby capacity.
//
// # Parameters
//
//   - ticketID: Unique visitor ticket identifier. Must be non-empty, at most
//     MaxTicketIDLength bytes, and free of ASCII control characters.
//   - now: Evaluation instant; zero falls back to Config.Clock.
//
// # Returns
//
// A [LobbyReceipt] describing the registration and current lobby count, or a
// zero LobbyReceipt and an error matching:
//   - ErrInvalidTicketID for malformed ticketID.
//   - ErrSoldOut and ErrLobbyNotOpen when the drop is in PhaseSoldOut.
//   - ErrPaused and ErrLobbyNotOpen when the drop is in PhasePaused.
//   - ErrLobbyNotOpen when the drop is in PhaseIdle, PhaseShuffling, or PhaseOpen.
//   - ErrLobbyFull when a new ticket would exceed Config.MaxLobbyTickets.
//
// # Concurrency
//
// Safe for concurrent calls from multiple goroutines; serialized by d.mu.
//
// # Example
//
//	receipt, err := d.JoinLobby("ticket-001", lobbyAt.Add(time.Minute))
//	if err != nil {
//		return err
//	}
//	fmt.Println(receipt.LobbyCount, receipt.Duplicate)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:391 (direct call)
//   - internal/drop/drop_test.go:401 (direct call)
//   - internal/drop/drop_test.go:410 (direct call)
//   - internal/drop/drop_test.go:420 (direct call)
//   - internal/drop/drop_test.go:426 (direct call)
//   - internal/drop/drop_test.go:446 (direct call)
//   - internal/drop/drop_test.go:476 (direct call)
//   - internal/drop/drop_test.go:547 (direct call)
//   - internal/drop/drop_test.go:595 (direct call)
//   - internal/drop/drop_test.go:642 (direct call)
//   - internal/drop/drop_test.go:701 (direct call)
//   - internal/drop/drop_test.go:882 (direct call)
//   - internal/drop/drop_test.go:891 (direct call)
//   - internal/drop/drop_test.go:981 (direct call)
//   - internal/drop/drop_test.go:994 (direct call)
//   - internal/drop/drop_test.go:1057 (direct call)
//   - internal/drop/drop_test.go:1250 (direct call)
//   - internal/drop/drop_test.go:1254 (direct call)
//   - internal/drop/drop_test.go:1391 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) JoinLobby(ticketID string, now time.Time) (LobbyReceipt, error) {
	if err := validateID(ticketID, MaxTicketIDLength); err != nil {
		return LobbyReceipt{}, fmt.Errorf("join lobby: %w: %v", ErrInvalidTicketID, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	switch d.phase {
	case PhaseLobby:
	case PhaseSoldOut:
		return LobbyReceipt{}, fmt.Errorf("join lobby: %w (%w)", ErrSoldOut, ErrLobbyNotOpen)
	case PhasePaused:
		return LobbyReceipt{}, fmt.Errorf("join lobby: %w (%w)", ErrPaused, ErrLobbyNotOpen)
	default:
		return LobbyReceipt{}, fmt.Errorf("join lobby in phase %s: %w", d.phase, ErrLobbyNotOpen)
	}

	// Check idempotency before capacity so an already-admitted ticket keeps
	// receiving its receipt even after the lobby reaches MaxLobbyTickets.
	if joinedAt, exists := d.lobbyJoined[ticketID]; exists {
		return LobbyReceipt{
			EventID:    d.cfg.EventID,
			TicketID:   ticketID,
			JoinedAt:   joinedAt,
			Duplicate:  true,
			LobbyCount: len(d.lobbyOrder),
			Phase:      d.phase,
		}, nil
	}

	if len(d.lobbyOrder) >= d.cfg.MaxLobbyTickets {
		return LobbyReceipt{}, fmt.Errorf("join lobby (%d/%d): %w",
			len(d.lobbyOrder), d.cfg.MaxLobbyTickets, ErrLobbyFull)
	}

	ts := d.resolveNowLocked(now)
	if d.lobbyJoined == nil {
		d.lobbyJoined = make(map[string]time.Time)
	}
	d.lobbyJoined[ticketID] = ts
	d.lobbyOrder = append(d.lobbyOrder, ticketID)
	d.auditSeq++

	return LobbyReceipt{
		EventID:    d.cfg.EventID,
		TicketID:   ticketID,
		JoinedAt:   ts,
		Duplicate:  false,
		LobbyCount: len(d.lobbyOrder),
		Phase:      d.phase,
	}, nil
}

// Advance evaluates time-driven lifecycle transitions at instant now.
//
// When in [PhaseIdle] and now >= LobbyAt, Advance transitions to [PhaseLobby].
// When in [PhaseLobby] (or directly from [PhaseIdle] if now >= OpensAt) and
// now >= OpensAt, Advance transitions through [PhaseShuffling], runs an
// unbiased CSPRNG Fisher-Yates shuffle over all lobby tickets to assign queue
// positions 1..N, and transitions to [PhaseOpen]. Calls in [PhaseOpen],
// [PhasePaused], or [PhaseSoldOut], or before the next scheduled timestamp, are
// no-ops with Changed == false.
//
// # Parameters
//
//   - now: Evaluation instant; zero falls back to Config.Clock.
//
// # Returns
//
// A [TransitionEvent] recording the before/after phases, Changed flag, shuffled
// count, and AuditSeq. If the CSPRNG fails during shuffling, Advance rolls back
// cleanly to PhaseLobby (preserving all lobby tickets with no partial positions)
// and returns an error matching ErrShuffleFailed.
//
// # Concurrency
//
// Safe for concurrent calls; serialized under d.mu so the Fisher-Yates shuffle
// executes at most once even under simultaneous Advance calls.
//
// # Example
//
//	ev, err := d.Advance(opensAt)
//	if err != nil {
//		return err
//	}
//	fmt.Println(ev.From, "->", ev.To, ev.ShuffledCount)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:326 (direct call)
//   - internal/drop/drop_test.go:332 (direct call)
//   - internal/drop/drop_test.go:344 (direct call)
//   - internal/drop/drop_test.go:350 (direct call)
//   - internal/drop/drop_test.go:368 (direct call)
//   - internal/drop/drop_test.go:395 (direct call)
//   - internal/drop/drop_test.go:443 (direct call)
//   - internal/drop/drop_test.go:469 (direct call)
//   - internal/drop/drop_test.go:481 (direct call)
//   - internal/drop/drop_test.go:543 (direct call)
//   - internal/drop/drop_test.go:551 (direct call)
//   - internal/drop/drop_test.go:591 (direct call)
//   - internal/drop/drop_test.go:599 (direct call)
//   - internal/drop/drop_test.go:638 (direct call)
//   - internal/drop/drop_test.go:647 (direct call)
//   - internal/drop/drop_test.go:693 (direct call)
//   - internal/drop/drop_test.go:705 (direct call)
//   - internal/drop/drop_test.go:878 (direct call)
//   - internal/drop/drop_test.go:895 (direct call)
//   - internal/drop/drop_test.go:911 (direct call)
//   - internal/drop/drop_test.go:978 (direct call)
//   - internal/drop/drop_test.go:990 (direct call)
//   - internal/drop/drop_test.go:1053 (direct call)
//   - internal/drop/drop_test.go:1061 (direct call)
//   - internal/drop/drop_test.go:1238 (direct call)
//   - internal/drop/drop_test.go:1287 (direct call)
//   - internal/drop/drop_test.go:1387 (direct call)
//   - internal/drop/drop_test.go:1396 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) Advance(now time.Time) (TransitionEvent, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ts := d.resolveNowLocked(now)
	startPhase := d.phase

	switch d.phase {
	case PhaseIdle:
		if ts.Before(d.cfg.LobbyAt) {
			return d.transitionEventLocked(startPhase, false, ts), nil
		}
		if !CanTransition(d.phase, PhaseLobby) {
			return TransitionEvent{}, fmt.Errorf("advance %s -> %s: %w", d.phase, PhaseLobby, ErrInvalidTransition)
		}
		d.phase = PhaseLobby
		d.auditSeq++

		// If evaluation occurs at or after OpensAt, continue directly through
		// shuffling into PhaseOpen so a late-waking node never stalls in lobby.
		if !ts.Before(d.cfg.OpensAt) {
			if err := d.shuffleAndOpenLocked(ts); err != nil {
				return TransitionEvent{}, err
			}
		}
		return d.transitionEventLocked(startPhase, true, ts), nil

	case PhaseLobby:
		if ts.Before(d.cfg.OpensAt) {
			return d.transitionEventLocked(startPhase, false, ts), nil
		}
		if err := d.shuffleAndOpenLocked(ts); err != nil {
			return TransitionEvent{}, err
		}
		return d.transitionEventLocked(startPhase, true, ts), nil

	case PhaseOpen, PhasePaused, PhaseSoldOut:
		return d.transitionEventLocked(startPhase, false, ts), nil

	default:
		return TransitionEvent{}, fmt.Errorf("advance in phase %s: %w", d.phase, ErrInvalidTransition)
	}
}

// shuffleAndOpenLocked performs the validated PhaseLobby -> PhaseShuffling ->
// PhaseOpen transition using an unbiased CSPRNG Fisher-Yates shuffle. Caller
// must hold d.mu.Lock() and d.phase must be PhaseLobby.
//
// # Parameters
//
//   - ts: Normalized UTC instant at which the drop opens.
//
// # Returns
//
// nil on success; on CSPRNG error, restores d.phase to PhaseLobby without
// modifying lobbyOrder or publishing partial positions, and returns an error
// matching ErrShuffleFailed.
//
// # Example
//
//	if err := d.shuffleAndOpenLocked(ts); err != nil {
//		return TransitionEvent{}, err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:935 (direct call)
//   - internal/drop/drop.go:945 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) shuffleAndOpenLocked(ts time.Time) error {
	if !CanTransition(d.phase, PhaseShuffling) {
		return fmt.Errorf("shuffle %s -> %s: %w", d.phase, PhaseShuffling, ErrInvalidTransition)
	}
	d.phase = PhaseShuffling

	reader := d.randReader
	if reader == nil {
		reader = rand.Reader
	}

	// Shuffle a copy so that an entropy read failure leaves d.lobbyOrder
	// completely untouched and allows a clean retry.
	shuffled, err := fisherYatesCSPRNG(d.lobbyOrder, reader)
	if err != nil {
		d.phase = PhaseLobby
		return err
	}

	if !CanTransition(d.phase, PhaseOpen) {
		d.phase = PhaseLobby
		return fmt.Errorf("open %s -> %s: %w", d.phase, PhaseOpen, ErrInvalidTransition)
	}

	positions := make(map[string]int, len(shuffled))
	enqueuedAt := make(map[string]time.Time, len(shuffled))
	for idx, id := range shuffled {
		positions[id] = idx + 1
		enqueuedAt[id] = ts
	}

	d.queueOrder = shuffled
	d.positions = positions
	d.enqueuedAt = enqueuedAt
	d.shuffledCount = len(shuffled)
	d.openedAt = ts
	d.phase = PhaseOpen
	d.auditSeq++
	return nil
}

// fisherYatesCSPRNG returns a newly allocated, uniformly shuffled permutation
// of items using the Durstenfeld Fisher-Yates algorithm backed by crypto/rand.Int.
//
// # Parameters
//
//   - items: Source slice to permute; not mutated.
//   - reader: Cryptographic random byte source; must be non-nil.
//
// # Returns
//
// A new slice containing the exact elements of items in uniformly random order,
// or nil and an error matching ErrShuffleFailed if reader fails.
//
// # Example
//
//	order, err := fisherYatesCSPRNG([]string{"a", "b", "c"}, rand.Reader)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:999 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func fisherYatesCSPRNG(items []string, reader io.Reader) ([]string, error) {
	shuffled := slices.Clone(items)
	if len(shuffled) <= 1 {
		return shuffled, nil
	}

	// Reuse a single big.Int upper bound across iterations to avoid O(N)
	// heap allocations during large lobby shuffles.
	var upper big.Int
	for i := len(shuffled) - 1; i > 0; i-- {
		upper.SetInt64(int64(i + 1))
		nBig, err := rand.Int(reader, &upper)
		if err != nil {
			return nil, fmt.Errorf("fisher-yates draw at index %d: %w: %w", i, ErrShuffleFailed, err)
		}
		j := int(nBig.Int64())
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	return shuffled, nil
}

// transitionEventLocked builds a TransitionEvent reflecting d's current state.
// Caller must hold at least d.mu.RLock().
//
// # Parameters
//
//   - from: Phase prior to Advance.
//   - changed: Whether Advance mutated d.phase.
//   - ts: Normalized UTC evaluation timestamp.
//
// # Returns
//
// A value-copy TransitionEvent.
//
// # Example
//
//	return d.transitionEventLocked(startPhase, true, ts), nil
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:924 (direct call)
//   - internal/drop/drop.go:939 (direct call)
//   - internal/drop/drop.go:943 (direct call)
//   - internal/drop/drop.go:948 (direct call)
//   - internal/drop/drop.go:951 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) transitionEventLocked(from Phase, changed bool, ts time.Time) TransitionEvent {
	return TransitionEvent{
		EventID:       d.cfg.EventID,
		From:          from,
		To:            d.phase,
		Changed:       changed,
		ShuffledCount: d.shuffledCount,
		AuditSeq:      d.auditSeq,
		Timestamp:     ts,
	}
}

// EnqueuePostOpen appends a post-open arrival strictly FIFO behind the shuffled
// lobby cohort (positions N+1, N+2, ...) while the drop is in [PhaseOpen].
//
// If ticketID already holds a queue position (either from the shuffled lobby
// cohort 1..N or an earlier post-open enqueue), EnqueuePostOpen is idempotent
// and returns the existing position without duplicating or moving the ticket.
//
// # Parameters
//
//   - ticketID: Unique visitor ticket identifier. Must be non-empty, at most
//     MaxTicketIDLength bytes, and free of ASCII control characters.
//   - now: Admission instant; zero falls back to Config.Clock.
//
// # Returns
//
// A [QueueReceipt] with the assigned 1-based Position, or a zero QueueReceipt
// and an error matching:
//   - ErrInvalidTicketID for malformed ticketID.
//   - ErrSoldOut and ErrDropNotOpen when the drop is in PhaseSoldOut.
//   - ErrPaused and ErrDropNotOpen when the drop is in PhasePaused.
//   - ErrDropNotOpen when the drop is in PhaseIdle, PhaseLobby, or PhaseShuffling.
//   - ErrQueueFull when post-open arrivals reach Config.MaxPostOpenTickets.
//
// # Concurrency
//
// Safe for concurrent calls from multiple goroutines; serialized by d.mu.
//
// # Example
//
//	receipt, err := d.EnqueuePostOpen("late-ticket-1", opensAt.Add(time.Second))
//	if err != nil {
//		return err
//	}
//	fmt.Println(receipt.Position, receipt.PostOpen)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:689 (direct call)
//   - internal/drop/drop_test.go:696 (direct call)
//   - internal/drop/drop_test.go:717 (direct call)
//   - internal/drop/drop_test.go:728 (direct call)
//   - internal/drop/drop_test.go:734 (direct call)
//   - internal/drop/drop_test.go:743 (direct call)
//   - internal/drop/drop_test.go:917 (direct call)
//   - internal/drop/drop_test.go:935 (direct call)
//   - internal/drop/drop_test.go:956 (direct call)
//   - internal/drop/drop_test.go:997 (direct call)
//   - internal/drop/drop_test.go:1065 (direct call)
//   - internal/drop/drop_test.go:1111 (direct call)
//   - internal/drop/drop_test.go:1317 (direct call)
//   - internal/drop/drop_test.go:1400 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) EnqueuePostOpen(ticketID string, now time.Time) (QueueReceipt, error) {
	if err := validateID(ticketID, MaxTicketIDLength); err != nil {
		return QueueReceipt{}, fmt.Errorf("enqueue post-open: %w: %v", ErrInvalidTicketID, err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	switch d.phase {
	case PhaseOpen:
	case PhaseSoldOut:
		return QueueReceipt{}, fmt.Errorf("enqueue post-open: %w (%w)", ErrSoldOut, ErrDropNotOpen)
	case PhasePaused:
		return QueueReceipt{}, fmt.Errorf("enqueue post-open: %w (%w)", ErrPaused, ErrDropNotOpen)
	default:
		return QueueReceipt{}, fmt.Errorf("enqueue post-open in phase %s: %w", d.phase, ErrDropNotOpen)
	}

	// Preserve existing positions idempotently so shuffled lobby members or
	// retried post-open clients never lose or duplicate their spot.
	if pos, exists := d.positions[ticketID]; exists {
		return QueueReceipt{
			EventID:    d.cfg.EventID,
			TicketID:   ticketID,
			Position:   pos,
			EnqueuedAt: d.enqueuedAt[ticketID],
			Duplicate:  true,
			PostOpen:   pos > d.shuffledCount,
			Phase:      d.phase,
		}, nil
	}

	postOpenCount := len(d.queueOrder) - d.shuffledCount
	if postOpenCount >= d.cfg.MaxPostOpenTickets {
		return QueueReceipt{}, fmt.Errorf("enqueue post-open (%d/%d): %w",
			postOpenCount, d.cfg.MaxPostOpenTickets, ErrQueueFull)
	}

	ts := d.resolveNowLocked(now)
	if d.positions == nil {
		d.positions = make(map[string]int)
	}
	if d.enqueuedAt == nil {
		d.enqueuedAt = make(map[string]time.Time)
	}
	pos := len(d.queueOrder) + 1
	d.queueOrder = append(d.queueOrder, ticketID)
	d.positions[ticketID] = pos
	d.enqueuedAt[ticketID] = ts
	d.auditSeq++

	return QueueReceipt{
		EventID:    d.cfg.EventID,
		TicketID:   ticketID,
		Position:   pos,
		EnqueuedAt: ts,
		Duplicate:  false,
		PostOpen:   true,
		Phase:      d.phase,
	}, nil
}

// Pause suspends the drop into [PhasePaused] while preserving every lobby
// registration and every assigned queue position without dropping anyone.
//
// # Parameters
//
//   - reason: Optional operator-facing reason (at most MaxMessageLength bytes).
//   - now: Operation instant; zero falls back to Config.Clock.
//
// # Returns
//
// nil on success, or an error matching:
//   - ErrInvalidConfig if reason exceeds MaxMessageLength bytes.
//   - ErrInvalidTransition and ErrSoldOut if the drop is in PhaseSoldOut.
//   - ErrInvalidTransition if the drop is already PhasePaused or in PhaseShuffling.
//
// # Concurrency
//
// Safe for concurrent calls; serialized by d.mu.
//
// # Example
//
//	if err := d.Pause("origin checkout maintenance", now); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:828 (direct call)
//   - internal/drop/drop_test.go:831 (direct call)
//   - internal/drop/drop_test.go:839 (direct call)
//   - internal/drop/drop_test.go:853 (direct call)
//   - internal/drop/drop_test.go:888 (direct call)
//   - internal/drop/drop_test.go:932 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) Pause(reason string, now time.Time) error {
	if len(reason) > MaxMessageLength {
		return fmt.Errorf("pause reason exceeds %d bytes: %w", MaxMessageLength, ErrInvalidConfig)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.phase == PhaseSoldOut {
		return fmt.Errorf("pause in phase %s: %w (%w)", d.phase, ErrInvalidTransition, ErrSoldOut)
	}
	if !CanTransition(d.phase, PhasePaused) {
		return fmt.Errorf("pause in phase %s: %w", d.phase, ErrInvalidTransition)
	}

	_ = d.resolveNowLocked(now)
	d.pausedFrom = d.phase
	d.pauseReason = reason
	d.phase = PhasePaused
	d.auditSeq++
	return nil
}

// Resume restores a paused drop back to the exact phase recorded prior to
// [Drop.Pause], preserving all lobby entries and assigned queue positions.
//
// Resume does not automatically advance past OpensAt if time elapsed while
// paused; callers should invoke [Drop.Advance] after Resume when driving
// time-based progression.
//
// # Parameters
//
//   - now: Operation instant; zero falls back to Config.Clock.
//
// # Returns
//
// nil on success, or an error matching:
//   - ErrInvalidTransition and ErrSoldOut if the drop is in PhaseSoldOut.
//   - ErrInvalidTransition if the drop is not currently in PhasePaused.
//
// # Concurrency
//
// Safe for concurrent calls; serialized by d.mu.
//
// # Example
//
//	if err := d.Resume(now.Add(2 * time.Minute)); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:823 (direct call)
//   - internal/drop/drop_test.go:834 (direct call)
//   - internal/drop/drop_test.go:856 (direct call)
//   - internal/drop/drop_test.go:905 (direct call)
//   - internal/drop/drop_test.go:943 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) Resume(now time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.phase == PhaseSoldOut {
		return fmt.Errorf("resume in phase %s: %w (%w)", d.phase, ErrInvalidTransition, ErrSoldOut)
	}
	if d.phase != PhasePaused || !CanTransition(d.phase, d.pausedFrom) {
		return fmt.Errorf("resume in phase %s: %w", d.phase, ErrInvalidTransition)
	}

	_ = d.resolveNowLocked(now)
	d.phase = d.pausedFrom
	d.pausedFrom = ""
	d.pauseReason = ""
	d.auditSeq++
	return nil
}

// MarkSoldOut transitions the drop into the terminal [PhaseSoldOut] state,
// short-circuiting all future lobby joins, post-open enqueues, and pause/resume
// controls until [Drop.Reset] is called.
//
// # Parameters
//
//   - message: Optional sold-out banner message (at most MaxMessageLength bytes).
//     When empty, the previously configured Config.SoldOutMessage is retained.
//   - now: Operation instant; zero falls back to Config.Clock.
//
// # Returns
//
// nil on success, or an error matching:
//   - ErrInvalidConfig if message exceeds MaxMessageLength bytes.
//   - ErrInvalidTransition and ErrSoldOut if the drop is already in PhaseSoldOut.
//   - ErrInvalidTransition if the current phase cannot transition to PhaseSoldOut.
//
// # Concurrency
//
// Safe for concurrent calls; serialized by d.mu.
//
// # Example
//
//	if err := d.MarkSoldOut("All tickets have been claimed.", now); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:842 (direct call)
//   - internal/drop/drop_test.go:847 (direct call)
//   - internal/drop/drop_test.go:850 (direct call)
//   - internal/drop/drop_test.go:985 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) MarkSoldOut(message string, now time.Time) error {
	if len(message) > MaxMessageLength {
		return fmt.Errorf("sold-out message exceeds %d bytes: %w", MaxMessageLength, ErrInvalidConfig)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.phase == PhaseSoldOut {
		return fmt.Errorf("mark sold out in phase %s: %w (%w)", d.phase, ErrInvalidTransition, ErrSoldOut)
	}
	if !CanTransition(d.phase, PhaseSoldOut) {
		return fmt.Errorf("mark sold out in phase %s: %w", d.phase, ErrInvalidTransition)
	}

	_ = d.resolveNowLocked(now)
	d.phase = PhaseSoldOut
	d.pausedFrom = ""
	d.pauseReason = ""
	if message != "" {
		d.soldOutMessage = message
	}
	d.auditSeq++
	return nil
}

// Reset validates cfg and reinitializes the drop aggregate for a new event or
// schedule, clearing lobby entries and queue positions while monotonically
// incrementing AuditSeq.
//
// If cfg fails validation, the existing aggregate state is left completely
// unchanged.
//
// # Parameters
//
//   - cfg: New drop configuration validated with the same rules as [New].
//   - now: Operation instant; zero falls back to cfg's Clock.
//
// # Returns
//
// nil on success, or an error matching ErrInvalidConfig when cfg is invalid.
//
// # Concurrency
//
// Safe for concurrent calls; serialized by d.mu.
//
// # Example
//
//	if err := d.Reset(nextCfg, now); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:1007 (direct call)
//   - internal/drop/drop_test.go:1018 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) Reset(cfg Config, now time.Time) error {
	norm, err := normalizeConfig(cfg)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.applyNormalizedConfigLocked(norm)
	_ = d.resolveNowLocked(now)
	d.auditSeq++
	return nil
}

// Position looks up the assigned 1-based queue position for ticketID.
//
// # Parameters
//
//   - ticketID: Ticket identifier to query.
//
// # Returns
//
// (pos, true) when ticketID has been assigned a queue position (1..ShuffledCount
// from the lobby shuffle or > ShuffledCount from post-open FIFO); (0, false)
// when ticketID is unknown or has only registered in the lobby prior to shuffling.
//
// # Concurrency
//
// Safe for concurrent calls; acquires d.mu.RLock().
//
// # Example
//
//	if pos, ok := d.Position("ticket-001"); ok {
//		fmt.Println("queue position:", pos)
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:438 (direct call)
//   - internal/drop/drop_test.go:502 (direct call)
//   - internal/drop/drop_test.go:603 (direct call)
//   - internal/drop/drop_test.go:924 (direct call)
//   - internal/drop/drop_test.go:950 (direct call)
//   - internal/drop/drop_test.go:1103 (direct call)
//   - internal/drop/drop_test.go:1104 (direct call)
//   - internal/drop/drop_test.go:1334 (direct call)
//   - internal/drop/drop_test.go:1356 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) Position(ticketID string) (int, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	pos, ok := d.positions[ticketID]
	return pos, ok
}

// QueueOrder returns an independent copy of all ticket IDs currently assigned
// queue positions in ascending 1-based position order (shuffled cohort 1..N
// followed by post-open FIFO arrivals N+1..M).
//
// # Parameters
//
// None.
//
// # Returns
//
// A cloned slice of ticket IDs (nil when the queue is empty). Mutating the
// returned slice does not affect the Drop.
//
// # Concurrency
//
// Safe for concurrent calls; acquires d.mu.RLock().
//
// # Example
//
//	order := d.QueueOrder()
//	fmt.Println("queued tickets:", len(order))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:489 (direct call)
//   - internal/drop/drop_test.go:521 (direct call)
//   - internal/drop/drop_test.go:554 (direct call)
//   - internal/drop/drop_test.go:660 (direct call)
//   - internal/drop/drop_test.go:661 (direct call)
//   - internal/drop/drop_test.go:709 (direct call)
//   - internal/drop/drop_test.go:752 (direct call)
//   - internal/drop/drop_test.go:921 (direct call)
//   - internal/drop/drop_test.go:940 (direct call)
//   - internal/drop/drop_test.go:946 (direct call)
//   - internal/drop/drop_test.go:1097 (direct call)
//   - internal/drop/drop_test.go:1098 (direct call)
//   - internal/drop/drop_test.go:1333 (direct call)
//   - internal/drop/drop_test.go:1346 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) QueueOrder() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return slices.Clone(d.queueOrder)
}

// LobbyTickets returns an independent copy of all ticket IDs registered in the
// pre-queue lobby in first-seen join order.
//
// # Parameters
//
// None.
//
// # Returns
//
// A cloned slice of lobby ticket IDs (nil when no lobby tickets are registered).
// Mutating the returned slice does not affect the Drop.
//
// # Concurrency
//
// Safe for concurrent calls; acquires d.mu.RLock().
//
// # Example
//
//	tickets := d.LobbyTickets()
//	fmt.Println("lobby count:", len(tickets))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:519 (direct call)
//   - internal/drop/drop_test.go:524 (direct call)
//   - internal/drop/drop_test.go:908 (direct call)
//   - internal/drop/drop_test.go:1265 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) LobbyTickets() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return slices.Clone(d.lobbyOrder)
}

// Snapshot returns a consistent, value-copied observation of the drop state at
// instant now, including CountdownSeconds to the next scheduled transition.
//
// # Parameters
//
//   - now: Observation instant; zero falls back to Config.Clock.
//
// # Returns
//
// A [Snapshot] containing Phase, CountdownSeconds, LobbyCount, ShuffledCount,
// PostOpenCount, TotalQueueCount, SoldOutMessage, and AuditSeq.
//
// # Concurrency
//
// Safe for concurrent calls; acquires d.mu.RLock().
//
// # Example
//
//	snap := d.Snapshot(lobbyAt.Add(5 * time.Minute))
//	fmt.Println(snap.Phase, snap.CountdownSeconds)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:282 (direct call)
//   - internal/drop/drop_test.go:314 (direct call)
//   - internal/drop/drop_test.go:320 (direct call)
//   - internal/drop/drop_test.go:338 (direct call)
//   - internal/drop/drop_test.go:354 (direct call)
//   - internal/drop/drop_test.go:425 (direct call)
//   - internal/drop/drop_test.go:433 (direct call)
//   - internal/drop/drop_test.go:653 (direct call)
//   - internal/drop/drop_test.go:899 (direct call)
//   - internal/drop/drop_test.go:1001 (direct call)
//   - internal/drop/drop_test.go:1010 (direct call)
//   - internal/drop/drop_test.go:1015 (direct call)
//   - internal/drop/drop_test.go:1026 (direct call)
//   - internal/drop/drop_test.go:1090 (direct call)
//   - internal/drop/drop_test.go:1091 (direct call)
//   - internal/drop/drop_test.go:1183 (direct call)
//   - internal/drop/drop_test.go:1189 (direct call)
//   - internal/drop/drop_test.go:1264 (direct call)
//   - internal/drop/drop_test.go:1276 (direct call)
//   - internal/drop/drop_test.go:1332 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) Snapshot(now time.Time) Snapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()

	ts := d.resolveNowLocked(now)
	postOpen := len(d.queueOrder) - d.shuffledCount
	if postOpen < 0 {
		postOpen = 0
	}

	return Snapshot{
		EventID:          d.cfg.EventID,
		Phase:            d.phase,
		PausedFrom:       d.pausedFrom,
		PauseReason:      d.pauseReason,
		LobbyAt:          d.cfg.LobbyAt,
		OpensAt:          d.cfg.OpensAt,
		CountdownSeconds: countdownSeconds(d.phase, d.pausedFrom, d.cfg.LobbyAt, d.cfg.OpensAt, ts),
		LobbyCount:       len(d.lobbyOrder),
		ShuffledCount:    d.shuffledCount,
		PostOpenCount:    postOpen,
		TotalQueueCount:  len(d.queueOrder),
		MaxLobbyTickets:  d.cfg.MaxLobbyTickets,
		SoldOutMessage:   d.soldOutMessage,
		AuditSeq:         d.auditSeq,
		GeneratedAt:      ts,
	}
}

// countdownSeconds computes whole seconds remaining (rounded up, clamped at 0)
// until the next scheduled transition for the given phase.
//
// # Parameters
//
//   - phase: Current drop phase.
//   - pausedFrom: Prior phase when phase is PhasePaused.
//   - lobbyAt: Scheduled lobby open timestamp.
//   - opensAt: Scheduled drop open timestamp.
//   - now: Current evaluation timestamp.
//
// # Returns
//
// Non-negative whole seconds until the next transition, or 0 when no future
// scheduled countdown applies.
//
// # Example
//
//	secs := countdownSeconds(PhaseIdle, "", lobbyAt, opensAt, now)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:1654 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func countdownSeconds(phase, pausedFrom Phase, lobbyAt, opensAt, now time.Time) int64 {
	effective := phase
	if phase == PhasePaused {
		effective = pausedFrom
	}

	var target time.Time
	switch effective {
	case PhaseIdle:
		target = lobbyAt
	case PhaseLobby:
		target = opensAt
	default:
		return 0
	}

	rem := target.Sub(now)
	if rem <= 0 {
		return 0
	}
	// Round up partial seconds so CountdownSeconds reaches 0 only once the
	// scheduled deadline has actually arrived.
	return int64((rem + time.Second - 1) / time.Second)
}

// SyncKey returns the storage key used when persisting or loading state via
// [StateSync].
//
// # Parameters
//
// None.
//
// # Returns
//
// The configured Config.SyncKey, or DefaultSyncKeyPrefix + Config.EventID when
// SyncKey was omitted.
//
// # Concurrency
//
// Safe for concurrent calls; acquires d.mu.RLock().
//
// # Example
//
//	key := d.SyncKey()
//	fmt.Println(key)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
// No statically resolvable in-repo references found in the stated scope.
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) SyncKey() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.syncKey != "" {
		return d.syncKey
	}
	return DefaultSyncKeyPrefix + d.cfg.EventID
}

// MarshalState encodes the complete canonical state of d (including lobby
// registrations and the authoritative shuffled/post-open queue order) into JSON
// suitable for multi-edge replication via [StateSync].
//
// # Parameters
//
// None.
//
// # Returns
//
// A JSON byte slice encoding [PersistedState], or an error if marshaling fails.
//
// # Concurrency
//
// Safe for concurrent calls. Copies internal state under d.mu.RLock() and runs
// JSON serialization after releasing the lock.
//
// # Example
//
//	payload, err := d.MarshalState()
//	if err != nil {
//		return err
//	}
//	fmt.Println(len(payload))
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:2159 (direct call)
//   - internal/drop/drop_test.go:1160 (direct call)
//   - internal/drop/drop_test.go:1335 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) MarshalState() ([]byte, error) {
	state := d.exportPersistedState()
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("marshal drop state: %w", err)
	}
	return payload, nil
}

// exportPersistedState snapshots d into an independent PersistedState copy
// under d.mu.RLock() so JSON encoding happens without holding the lock.
//
// # Parameters
//
// None.
//
// # Returns
//
// Deep-copied PersistedState ready for serialization.
//
// # Example
//
//	st := d.exportPersistedState()
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:1791 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) exportPersistedState() PersistedState {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var lobbyJoined map[string]time.Time
	if len(d.lobbyJoined) > 0 {
		lobbyJoined = make(map[string]time.Time, len(d.lobbyJoined))
		for k, v := range d.lobbyJoined {
			lobbyJoined[k] = v.UTC()
		}
	}

	var enqueuedAt map[string]time.Time
	if len(d.enqueuedAt) > 0 {
		enqueuedAt = make(map[string]time.Time, len(d.enqueuedAt))
		for k, v := range d.enqueuedAt {
			enqueuedAt[k] = v.UTC()
		}
	}

	return PersistedState{
		Version:            persistedStateVersion,
		EventID:            d.cfg.EventID,
		LobbyAt:            d.cfg.LobbyAt.UTC(),
		OpensAt:            d.cfg.OpensAt.UTC(),
		MaxLobbyTickets:    d.cfg.MaxLobbyTickets,
		MaxPostOpenTickets: d.cfg.MaxPostOpenTickets,
		Phase:              d.phase,
		PausedFrom:         d.pausedFrom,
		PauseReason:        d.pauseReason,
		SoldOutMessage:     d.soldOutMessage,
		LobbyOrder:         slices.Clone(d.lobbyOrder),
		LobbyJoinedAt:      lobbyJoined,
		QueueOrder:         slices.Clone(d.queueOrder),
		EnqueuedAt:         enqueuedAt,
		ShuffledCount:      d.shuffledCount,
		OpenedAt:           d.openedAt.UTC(),
		AuditSeq:           d.auditSeq,
	}
}

// UnmarshalState validates a canonical JSON [PersistedState] payload and
// atomically replaces d's state so a follower edge adopts the authoritative
// drop phase and shuffled queue order.
//
// If payload exceeds MaxSyncPayloadBytes, contains malformed/trailing JSON, or
// violates any aggregate invariant, d's existing state is left untouched.
//
// # Parameters
//
//   - payload: JSON bytes previously produced by [Drop.MarshalState]. Not
//     retained after return.
//
// # Returns
//
// nil on success, or an error matching ErrInvalidState.
//
// # Concurrency
//
// Safe for concurrent calls. Decoding and validation run outside d.mu; d.mu.Lock()
// is acquired only to commit the validated state.
//
// # Example
//
//	if err := follower.UnmarshalState(payload); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:2239 (direct call)
//   - internal/drop/drop_test.go:1186 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) UnmarshalState(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("%w: empty payload", ErrInvalidState)
	}
	if len(payload) > MaxSyncPayloadBytes {
		return fmt.Errorf("%w: payload size %d exceeds max %d bytes",
			ErrInvalidState, len(payload), MaxSyncPayloadBytes)
	}

	var st PersistedState
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&st); err != nil {
		return fmt.Errorf("%w: decode json: %v", ErrInvalidState, err)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: unexpected trailing data after JSON payload", ErrInvalidState)
	}

	validated, err := validatePersistedState(st)
	if err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.cfg.EventID = validated.eventID
	d.cfg.LobbyAt = validated.lobbyAt
	d.cfg.OpensAt = validated.opensAt
	d.cfg.MaxLobbyTickets = validated.maxLobbyTickets
	d.cfg.MaxPostOpenTickets = validated.maxPostOpenTickets
	d.cfg.SoldOutMessage = validated.soldOutMessage
	d.cfg.Paused = validated.phase == PhasePaused
	d.cfg.SoldOut = validated.phase == PhaseSoldOut
	if d.syncKey == "" {
		d.syncKey = DefaultSyncKeyPrefix + validated.eventID
	}
	d.phase = validated.phase
	d.pausedFrom = validated.pausedFrom
	d.pauseReason = validated.pauseReason
	d.soldOutMessage = validated.soldOutMessage
	d.lobbyOrder = validated.lobbyOrder
	d.lobbyJoined = validated.lobbyJoined
	d.queueOrder = validated.queueOrder
	d.positions = validated.positions
	d.enqueuedAt = validated.enqueuedAt
	d.shuffledCount = validated.shuffledCount
	d.openedAt = validated.openedAt
	d.auditSeq = validated.auditSeq
	return nil
}

// validatedState holds decoded, invariant-checked state ready to install under d.mu.
type validatedState struct {
	eventID            string
	lobbyAt            time.Time
	opensAt            time.Time
	maxLobbyTickets    int
	maxPostOpenTickets int
	phase              Phase
	pausedFrom         Phase
	pauseReason        string
	soldOutMessage     string
	lobbyOrder         []string
	lobbyJoined        map[string]time.Time
	queueOrder         []string
	positions          map[string]int
	enqueuedAt         map[string]time.Time
	shuffledCount      int
	openedAt           time.Time
	auditSeq           uint64
}

// validatePersistedState checks every structural and domain invariant of a
// decoded PersistedState before it can replace live Drop state (R3, S9).
//
// # Parameters
//
//   - st: Decoded PersistedState from an untrusted/external byte slice.
//
// # Returns
//
// A ready-to-install validatedState, or an error matching ErrInvalidState.
//
// # Example
//
//	vs, err := validatePersistedState(st)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop.go:1916 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func validatePersistedState(st PersistedState) (validatedState, error) {
	if st.Version != persistedStateVersion {
		return validatedState{}, fmt.Errorf("%w: unsupported version %d", ErrInvalidState, st.Version)
	}
	if err := validateID(st.EventID, MaxEventIDLength); err != nil {
		return validatedState{}, fmt.Errorf("%w: event_id: %v", ErrInvalidState, err)
	}
	if st.LobbyAt.IsZero() || st.OpensAt.IsZero() || !st.LobbyAt.UTC().Before(st.OpensAt.UTC()) {
		return validatedState{}, fmt.Errorf("%w: invalid schedule window", ErrInvalidState)
	}
	if st.MaxLobbyTickets <= 0 || st.MaxLobbyTickets > HardMaxLobbyTickets {
		return validatedState{}, fmt.Errorf("%w: max_lobby_tickets %d out of range", ErrInvalidState, st.MaxLobbyTickets)
	}
	maxPostOpen := st.MaxPostOpenTickets
	if maxPostOpen == 0 {
		maxPostOpen = DefaultMaxPostOpenTickets
	}
	if maxPostOpen < 0 || maxPostOpen > HardMaxLobbyTickets {
		return validatedState{}, fmt.Errorf("%w: max_post_open_tickets %d out of range", ErrInvalidState, maxPostOpen)
	}
	if !st.Phase.Valid() || st.Phase == PhaseShuffling {
		return validatedState{}, fmt.Errorf("%w: invalid persisted phase %q", ErrInvalidState, st.Phase)
	}
	if st.Phase == PhasePaused {
		if st.PausedFrom != PhaseIdle && st.PausedFrom != PhaseLobby && st.PausedFrom != PhaseOpen {
			return validatedState{}, fmt.Errorf("%w: invalid paused_from %q", ErrInvalidState, st.PausedFrom)
		}
	} else if st.PausedFrom != "" {
		return validatedState{}, fmt.Errorf("%w: paused_from set while phase is %s", ErrInvalidState, st.Phase)
	}
	if len(st.PauseReason) > MaxMessageLength {
		return validatedState{}, fmt.Errorf("%w: pause_reason exceeds %d bytes", ErrInvalidState, MaxMessageLength)
	}
	if len(st.SoldOutMessage) > MaxMessageLength {
		return validatedState{}, fmt.Errorf("%w: sold_out_message exceeds %d bytes", ErrInvalidState, MaxMessageLength)
	}
	if len(st.LobbyOrder) > st.MaxLobbyTickets {
		return validatedState{}, fmt.Errorf("%w: lobby_order len %d exceeds max %d",
			ErrInvalidState, len(st.LobbyOrder), st.MaxLobbyTickets)
	}
	if st.ShuffledCount < 0 || st.ShuffledCount > len(st.QueueOrder) {
		return validatedState{}, fmt.Errorf("%w: shuffled_count %d inconsistent with queue_order len %d",
			ErrInvalidState, st.ShuffledCount, len(st.QueueOrder))
	}
	if len(st.QueueOrder)-st.ShuffledCount > maxPostOpen {
		return validatedState{}, fmt.Errorf("%w: post-open count %d exceeds max %d",
			ErrInvalidState, len(st.QueueOrder)-st.ShuffledCount, maxPostOpen)
	}

	lobbyOrder := make([]string, 0, len(st.LobbyOrder))
	lobbyJoined := make(map[string]time.Time, len(st.LobbyOrder))
	for _, id := range st.LobbyOrder {
		if err := validateID(id, MaxTicketIDLength); err != nil {
			return validatedState{}, fmt.Errorf("%w: lobby ticket %q: %v", ErrInvalidState, id, err)
		}
		if _, dup := lobbyJoined[id]; dup {
			return validatedState{}, fmt.Errorf("%w: duplicate lobby ticket %q", ErrInvalidState, id)
		}
		lobbyOrder = append(lobbyOrder, id)
		lobbyJoined[id] = st.LobbyJoinedAt[id].UTC()
	}

	queueOrder := make([]string, 0, len(st.QueueOrder))
	positions := make(map[string]int, len(st.QueueOrder))
	enqueuedAt := make(map[string]time.Time, len(st.QueueOrder))
	for idx, id := range st.QueueOrder {
		if err := validateID(id, MaxTicketIDLength); err != nil {
			return validatedState{}, fmt.Errorf("%w: queue ticket %q: %v", ErrInvalidState, id, err)
		}
		if _, dup := positions[id]; dup {
			return validatedState{}, fmt.Errorf("%w: duplicate queue ticket %q", ErrInvalidState, id)
		}
		queueOrder = append(queueOrder, id)
		positions[id] = idx + 1
		enqueuedAt[id] = st.EnqueuedAt[id].UTC()
	}

	return validatedState{
		eventID:            st.EventID,
		lobbyAt:            st.LobbyAt.UTC(),
		opensAt:            st.OpensAt.UTC(),
		maxLobbyTickets:    st.MaxLobbyTickets,
		maxPostOpenTickets: maxPostOpen,
		phase:              st.Phase,
		pausedFrom:         st.PausedFrom,
		pauseReason:        st.PauseReason,
		soldOutMessage:     st.SoldOutMessage,
		lobbyOrder:         lobbyOrder,
		lobbyJoined:        lobbyJoined,
		queueOrder:         queueOrder,
		positions:          positions,
		enqueuedAt:         enqueuedAt,
		shuffledCount:      st.ShuffledCount,
		openedAt:           st.OpenedAt.UTC(),
		auditSeq:           st.AuditSeq,
	}, nil
}

// SaveState serializes d's canonical state to JSON and writes it to syncer
// (or Config.Sync when syncer is nil) under [Drop.SyncKey].
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for the StateSync.Save call.
//     Must be non-nil.
//   - syncer: Optional StateSync port overriding Config.Sync for this call.
//   - ttl: Expiration duration passed to StateSync.Save; zero or negative uses
//     Config.SyncTTL (default DefaultSyncTTL).
//
// # Returns
//
// nil on success, ctx.Err() if ctx is already cancelled, ErrSyncNotConfigured
// if neither syncer nor Config.Sync is set, or any wrapped error from
// MarshalState or StateSync.Save.
//
// # Concurrency
//
// Safe for concurrent calls. d.mu is NOT held during StateSync.Save I/O (C4).
//
// # Example
//
//	if err := d.SaveState(ctx, kvSync, time.Hour); err != nil {
//		return err
//	}
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:1071 (direct call)
//   - internal/drop/drop_test.go:1128 (direct call)
//   - internal/drop/drop_test.go:1138 (direct call)
//   - internal/drop/drop_test.go:1148 (direct call)
//   - internal/drop/drop_test.go:1266 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) SaveState(ctx context.Context, syncer StateSync, ttl time.Duration) error {
	if ctx == nil {
		return errors.New("drop: save state: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("drop: save state: %w", err)
	}

	d.mu.RLock()
	port := syncer
	if port == nil {
		port = d.sync
	}
	key := d.syncKey
	if key == "" {
		key = DefaultSyncKeyPrefix + d.cfg.EventID
	}
	effectiveTTL := ttl
	if effectiveTTL <= 0 {
		effectiveTTL = d.syncTTL
	}
	if effectiveTTL <= 0 {
		effectiveTTL = DefaultSyncTTL
	}
	d.mu.RUnlock()

	if port == nil {
		return ErrSyncNotConfigured
	}

	payload, err := d.MarshalState()
	if err != nil {
		return err
	}
	if err := port.Save(ctx, key, payload, effectiveTTL); err != nil {
		return fmt.Errorf("save drop state %q: %w", key, err)
	}
	return nil
}

// LoadState fetches canonical JSON state from syncer (or Config.Sync when
// syncer is nil) under [Drop.SyncKey] and installs it into d via
// [Drop.UnmarshalState].
//
// # Parameters
//
//   - ctx: Controls cancellation and deadlines for the StateSync.Load call.
//     Must be non-nil.
//   - syncer: Optional StateSync port overriding Config.Sync for this call.
//
// # Returns
//
// (true, nil) when canonical state was found and applied; (false, nil) when no
// state exists under SyncKey; or (false, err) on cancellation, missing syncer
// (ErrSyncNotConfigured), backend load failure, or corrupt payload
// (ErrInvalidState). On error, d's previous state remains unchanged.
//
// # Concurrency
//
// Safe for concurrent calls. d.mu is NOT held during StateSync.Load I/O (C4).
//
// # Example
//
//	loaded, err := follower.LoadState(ctx, kvSync)
//	if err != nil {
//		return err
//	}
//	fmt.Println("synced:", loaded)
//
// # Used By
//
// Generated from verified repository symbol references; do not hand-edit.
//
//   - internal/drop/drop_test.go:1085 (direct call)
//   - internal/drop/drop_test.go:1118 (direct call)
//   - internal/drop/drop_test.go:1131 (direct call)
//   - internal/drop/drop_test.go:1141 (direct call)
//   - internal/drop/drop_test.go:1153 (direct call)
//
// Scope: current module including tests (darwin/arm64, default tags). External/dynamic uses are not exhaustive.
func (d *Drop) LoadState(ctx context.Context, syncer StateSync) (bool, error) {
	if ctx == nil {
		return false, errors.New("drop: load state: nil context")
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("drop: load state: %w", err)
	}

	d.mu.RLock()
	port := syncer
	if port == nil {
		port = d.sync
	}
	key := d.syncKey
	if key == "" {
		key = DefaultSyncKeyPrefix + d.cfg.EventID
	}
	d.mu.RUnlock()

	if port == nil {
		return false, ErrSyncNotConfigured
	}

	payload, found, err := port.Load(ctx, key)
	if err != nil {
		return false, fmt.Errorf("load drop state %q: %w", key, err)
	}
	if !found {
		return false, nil
	}
	if err := d.UnmarshalState(payload); err != nil {
		return false, err
	}
	return true, nil
}
