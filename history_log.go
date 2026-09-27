package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The history log.
//
// With a history log (history.jsonl in -data-dir by default, -history-log to
// move or turn it off), the portal's history survives restarts: an attack
// that ended in a restart still shows who was banned and what they probed.
//
// The file holds one JSON object per line, each an event:
//
//	req   a recorded request, with the ess details of its address
//	agg   requests a banned client made past the first historyRawPerBan,
//	      counted per path once a second instead of written one by one
//	ban   a ban began or changed (the full state, so the latest line wins)
//	lift  a ban was lifted early
//	trig  the request that started a ban, when it was identified afterwards
//
// Writes go through a buffered channel to one goroutine, flushed every
// second, so a request never waits for the disk. When the channel is full
// the event is dropped and counted. The file rotates at historyLogMaxBytes,
// keeping historyLogKeep older files (history.jsonl.1 is the newest).
//
// On startup every file is replayed oldest first; requests older than the
// history retention are skipped, so the in-memory limits apply as before.

const (
	historyLogName     = "history.jsonl"
	historyLogMaxBytes = 64 << 20
	historyLogKeep     = 4
	historyLogQueue    = 16384
	historyLogLineMax  = 1 << 20
	historyLogRetry    = 10 * time.Second
)

const (
	evRequest = "req"
	evAgg     = "agg"
	evBan     = "ban"
	evLift    = "lift"
	evTrigger = "trig"
)

// historyEvent is one line of the history log.
type historyEvent struct {
	T  string    `json:"t"`
	At time.Time `json:"at"`

	// req and agg
	IP        string   `json:"ip,omitempty"`
	Method    string   `json:"method,omitempty"`
	Path      string   `json:"path,omitempty"`
	Status    int      `json:"status,omitempty"`
	LatencyUS int64    `json:"latency_us,omitempty"`
	UA        string   `json:"ua,omitempty"`
	Blocked   bool     `json:"blocked,omitempty"`
	Triggered bool     `json:"triggered,omitempty"`
	Rank      string   `json:"rank,omitempty"`
	Info      *logInfo `json:"ess,omitempty"`

	// every ban event, and requests attributed to a ban
	Ban uint64 `json:"ban,omitempty"`

	// ban
	Target    string     `json:"target,omitempty"`
	Scope     string     `json:"scope,omitempty"`
	Range     bool       `json:"range,omitempty"`
	Begin     *time.Time `json:"begin,omitempty"`
	Until     *time.Time `json:"until,omitempty"`
	Permanent bool       `json:"permanent,omitempty"`
	Changes   int        `json:"changes,omitempty"`
	Source    string     `json:"source,omitempty"`

	// lift
	By string `json:"by,omitempty"`

	// trig
	Trigger *logTrigger `json:"trigger,omitempty"`

	// agg
	First      *time.Time       `json:"first,omitempty"`
	Count      int64            `json:"count,omitempty"`
	Paths      map[string]int64 `json:"paths,omitempty"`
	OtherPaths int64            `json:"other_paths,omitempty"`
}

// logInfo is what ess said about a request's address when it was recorded.
type logInfo struct {
	CC      string `json:"cc,omitempty"`
	Country string `json:"country,omitempty"`
	N       uint32 `json:"n,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Desc    string `json:"desc,omitempty"`
	Range   string `json:"range,omitempty"`
	IP8     string `json:"ip8,omitempty"`
}

type logTrigger struct {
	Client string    `json:"client"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	At     time.Time `json:"at"`
}

// historyLogPath is where the history is logged, or "" for memory only.
func historyLogPath(cfg config) string {
	v := strings.TrimSpace(cfg.historyLog)
	switch strings.ToLower(v) {
	case "off", "none", "false", "0":
		return ""
	case "":
		if cfg.dataDir == "" {
			return ""
		}
		return filepath.Join(cfg.dataDir, historyLogName)
	}
	return v
}

// historyLog appends events to the log file from one goroutine.
type historyLog struct {
	path string
	max  int64
	keep int

	ch      chan *historyEvent
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	written atomic.Int64
	dropped atomic.Int64

	// Owned by run.
	f        *os.File
	w        *bufio.Writer
	size     int64
	failing  bool
	lastOpen time.Time
}

func openHistoryLog(path string, maxBytes int64, keep int) (*historyLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("history log %s: %w", path, err)
	}
	l := &historyLog{
		path: path, max: maxBytes, keep: keep,
		ch:   make(chan *historyEvent, historyLogQueue),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if err := l.reopen(); err != nil {
		return nil, fmt.Errorf("history log %s: %w", path, err)
	}
	go l.run()
	return l, nil
}

// emit queues ev without blocking. Safe on a nil log and for a nil event.
func (l *historyLog) emit(ev *historyEvent) {
	if l == nil || ev == nil {
		return
	}
	select {
	case l.ch <- ev:
	default:
		l.dropped.Add(1)
	}
}

func (l *historyLog) close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.stop)
		<-l.done
	})
}

func (l *historyLog) run() {
	defer close(l.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case ev := <-l.ch:
			l.write(ev)
		case <-t.C:
			l.flush()
		case <-l.stop:
			for {
				select {
				case ev := <-l.ch:
					l.write(ev)
				default:
					if l.f != nil {
						l.flush()
						_ = l.f.Sync()
						_ = l.f.Close()
						l.f, l.w = nil, nil
					}
					return
				}
			}
		}
	}
}

func (l *historyLog) reopen() error {
	l.lastOpen = time.Now()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f, l.w, l.size = f, bufio.NewWriterSize(f, 64<<10), st.Size()
	return nil
}

func (l *historyLog) fail(err error) {
	if !l.failing {
		l.failing = true
		log.Printf("history: cannot write %s: %v (retrying)", l.path, err)
	}
}

func (l *historyLog) closeFile() {
	if l.f == nil {
		return
	}
	_ = l.w.Flush()
	_ = l.f.Close()
	l.f, l.w = nil, nil
}

func (l *historyLog) flush() {
	if l.w == nil {
		return
	}
	if err := l.w.Flush(); err != nil {
		l.fail(err)
		l.closeFile()
	}
}

// rotate moves history.jsonl to history.jsonl.1, .1 to .2, and so on,
// dropping the oldest, and starts a new file.
func (l *historyLog) rotate() {
	l.closeFile()
	for i := l.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	if l.keep > 0 {
		_ = os.Rename(l.path, l.path+".1")
	} else {
		_ = os.Remove(l.path)
	}
	if err := l.reopen(); err != nil {
		l.fail(err)
	}
}

func (l *historyLog) write(ev *historyEvent) {
	if l.f == nil {
		if time.Since(l.lastOpen) < historyLogRetry {
			l.dropped.Add(1)
			return
		}
		if err := l.reopen(); err != nil {
			l.fail(err)
			l.dropped.Add(1)
			return
		}
	}
	data, err := json.Marshal(ev)
	if err != nil {
		l.dropped.Add(1)
		return
	}
	data = append(data, '\n')
	if l.size > 0 && l.size+int64(len(data)) > l.max {
		l.rotate()
		if l.f == nil {
			l.dropped.Add(1)
			return
		}
	}
	n, err := l.w.Write(data)
	l.size += int64(n)
	if err != nil {
		l.fail(err)
		l.closeFile()
		l.dropped.Add(1)
		return
	}
	l.written.Add(1)
	if l.failing {
		l.failing = false
		log.Printf("history: writing %s works again", l.path)
	}
}

type replayStats struct {
	files  int
	events int
	bad    int
	old    int
}

// replayHistoryLog feeds every event in the log and its rotated files to
// apply, oldest first. Requests older than cutoff are skipped; ban events
// are always applied. Unreadable lines are counted and skipped.
func replayHistoryLog(path string, keep int, cutoff time.Time, apply func(*historyEvent)) (replayStats, error) {
	var st replayStats
	names := make([]string, 0, keep+1)
	for i := keep; i >= 1; i-- {
		names = append(names, fmt.Sprintf("%s.%d", path, i))
	}
	names = append(names, path)
	for _, name := range names {
		f, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return st, err
		}
		st.files++
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), historyLogLineMax)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			var ev historyEvent
			if err := json.Unmarshal(line, &ev); err != nil || ev.T == "" {
				st.bad++
				continue
			}
			if (ev.T == evRequest || ev.T == evAgg) && ev.At.Before(cutoff) {
				st.old++
				continue
			}
			apply(&ev)
			st.events++
		}
		if sc.Err() != nil {
			st.bad++
		}
		_ = f.Close()
	}
	return st, nil
}
