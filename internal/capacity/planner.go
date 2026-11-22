package capacity

import (
	"sync"
	"time"
)

// Report is one leaf's capacity as an edge last heard it.
type Report struct {
	Leaf   string    // the leaf's control URL or node ID
	Share  int       // page slots this edge may plan on the leaf
	Usable bool      // healthy, not draining
	At     time.Time // when the edge received it; zero means never
}

// Planner turns leaf reports into the edge's room capacity. Set the
// exported fields before the first Plan; change Max and Lane later only
// through SetLimits.
//
// A fresh report counts in full. A report older than Stale fades linearly
// to nothing at Expire, so a control link that drops briefly does not
// collapse the edge's capacity, while a leaf that is really gone stops
// counting within Expire. Decreases apply at once; increases apply only
// after RaiseAfter consecutive plans agree, so a flapping leaf cannot thrash
// the room.
//
// Safe for concurrent use.
type Planner struct {
	// Max is the operator's -cap: the edge never admits more.
	Max int
	// Lane is the edge's priority-lane slots, which reach the leaves on
	// top of the room's capacity and are subtracted from it.
	Lane int
	// Stale and Expire bound how long a silent leaf keeps counting.
	Stale, Expire time.Duration
	// RaiseAfter is how many consecutive plans must allow a higher
	// capacity before it applies (values below 1 mean 1).
	RaiseAfter int

	mu      sync.Mutex
	current int
	raise   int // consecutive plans above current
	floor   int // smallest raise proposed during the current streak
}

// Plan is one planning result.
type Plan struct {
	Total   int // page slots the reachable leaves offer this edge
	Desired int // room capacity the reports call for, before hysteresis
	Cap     int // room capacity to apply now
	Leaves  int // leaves counted (fully or fading)
}

// weight is how much of a report counts at now, in [0, 1].
func (p *Planner) weight(r Report, now time.Time) float64 {
	if r.At.IsZero() || !r.Usable {
		return 0
	}
	age := now.Sub(r.At)
	switch {
	case age <= p.Stale:
		return 1
	case age >= p.Expire || p.Expire <= p.Stale:
		return 0
	default:
		return 1 - float64(age-p.Stale)/float64(p.Expire-p.Stale)
	}
}

// SetLimits changes Max and Lane between plans.
func (p *Planner) SetLimits(max, lane int) {
	p.mu.Lock()
	p.Max, p.Lane = max, lane
	p.mu.Unlock()
}

// Plan computes the capacity for reports at now and advances the
// hysteresis state.
func (p *Planner) Plan(reports []Report, now time.Time) Plan {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out Plan
	var sum float64
	for _, r := range reports {
		if r.Share <= 0 {
			continue
		}
		if w := p.weight(r, now); w > 0 {
			sum += w * float64(r.Share)
			out.Leaves++
		}
	}
	out.Total = int(sum)
	out.Desired = out.Total - p.Lane
	if p.Max > 0 && out.Desired > p.Max {
		out.Desired = p.Max
	}
	if out.Desired < 1 {
		out.Desired = 1
	}

	need := p.RaiseAfter
	if need < 1 {
		need = 1
	}
	switch {
	case p.current == 0 || out.Desired < p.current:
		p.current = out.Desired
		p.raise, p.floor = 0, 0
	case out.Desired > p.current:
		p.raise++
		if p.floor == 0 || out.Desired < p.floor {
			p.floor = out.Desired
		}
		if p.raise >= need {
			p.current = p.floor
			p.raise, p.floor = 0, 0
		}
	default:
		p.raise, p.floor = 0, 0
	}
	out.Cap = p.current
	return out
}

// Current is the capacity the last Plan applied (0 before the first).
func (p *Planner) Current() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}
