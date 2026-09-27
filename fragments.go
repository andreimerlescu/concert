package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Server-rendered tables for the admin portal.
//
// The Queue, Bans, Visitors and Ban log tabs are rendered by the templates in
// templates/fragments.tpl, one page at a time, with ess details built in
// through the ipcell template function. Each endpoint answers JSON: the HTML
// of the page's rows plus paging metadata. portal.js matches rows by their
// data-key, replaces only rows whose HTML changed, and animates the rest.
//
// ?keys= lists the keys the browser is showing; "where" answers which page
// each of them is on now (0: gone), so a row leaving the page can say where
// it went. Times are sent as unix milliseconds and formatted by the browser,
// so a row's HTML only changes when its data does.

const (
	templateFragments = "fragments.tpl"
	portalPageSize    = 25
	fragWhereMax      = 200
)

func (p *portal) templateFuncs() template.FuncMap {
	return template.FuncMap{
		"ipcell":      func(s string) ipCell { return p.a.ipinfo.cell(s) },
		"ipinfoOn":    func() bool { return p.a.ipinfo.enabled() },
		"num":         fmtCount,
		"ms":          unixMS,
		"statusBadge": statusBadgeClass,
		"latency":     fmtLatency,
		"plural":      plural,
		"counts":      newCountTable,
	}
}

// ─── template helpers ────────────────────────────────────────────────────────

// fmtCount formats whole numbers with thousands separators.
func fmtCount(v any) string {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int32:
		n = int64(x)
	case int64:
		n = x
	case uint32:
		n = int64(x)
	case uint64:
		n = int64(x)
	default:
		return fmt.Sprint(v)
	}
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unixMS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func ptrMS(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return unixMS(*t)
}

func statusBadgeClass(code int) string {
	switch {
	case code >= 500:
		return "text-bg-danger"
	case code >= 400:
		return "text-bg-warning"
	case code >= 300:
		return "text-bg-info"
	case code < 200:
		return "text-bg-secondary"
	}
	return "text-bg-success"
}

func fmtLatency(ms float64) string {
	switch {
	case ms < 1:
		return "<1 ms"
	case ms < 1000:
		return strconv.Itoa(int(ms+0.5)) + " ms"
	}
	return strconv.FormatFloat(ms/1000, 'f', 1, 64) + " s"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmtCount(n) + " " + word + "s"
}

// countTable is a list of paths or addresses with hit counts.
type countTable struct {
	Title      string
	Rows       []namedCount
	Other      int64
	OtherLabel string
	IPs        bool
}

func newCountTable(title string, rows []namedCount, other int64, otherLabel string, ips bool) countTable {
	return countTable{Title: title, Rows: rows, Other: other, OtherLabel: otherLabel, IPs: ips}
}

// ─── paging ──────────────────────────────────────────────────────────────────

func pageParams(c *gin.Context) (page, size int) {
	page, _ = strconv.Atoi(c.Query("page"))
	if page < 1 {
		page = 1
	}
	size, _ = strconv.Atoi(c.Query("size"))
	switch size {
	case 25, 50, 100:
	default:
		size = portalPageSize
	}
	return page, size
}

// paginate clamps page to the pages there are and returns the slice bounds.
func paginate(total, page, size int) (start, end, p, pages int) {
	pages = (total + size - 1) / size
	if pages < 1 {
		pages = 1
	}
	p = min(max(page, 1), pages)
	start = min((p-1)*size, total)
	end = min(start+size, total)
	return start, end, p, pages
}

func rangeText(start, end, total int) string {
	if total == 0 {
		return "0"
	}
	return fmtCount(start+1) + "–" + fmtCount(end)
}

// wherePages maps each key in keysParam to the page it is on now, or 0 when
// it is no longer listed.
func wherePages(keysParam string, size, n int, keyAt func(int) string) map[string]int {
	if keysParam == "" {
		return nil
	}
	want := map[string]bool{}
	for _, k := range strings.Split(keysParam, ",") {
		if k = strings.TrimSpace(k); k != "" && len(want) < fragWhereMax {
			want[k] = true
		}
	}
	out := make(map[string]int, len(want))
	for k := range want {
		out[k] = 0
	}
	for i := 0; i < n; i++ {
		if k := keyAt(i); want[k] {
			out[k] = i/size + 1
		}
	}
	return out
}

// detailPager pages a client's requests inside an expanded row.
type detailPager struct {
	Page, Pages, Total, From, To, Prev, Next int
	HasPrev, HasNext                         bool
}

func newDetailPager(total, page, pages, start, end int) detailPager {
	return detailPager{
		Page: page, Pages: pages, Total: total, From: min(start+1, total), To: end,
		Prev: page - 1, Next: page + 1, HasPrev: page > 1, HasNext: page < pages,
	}
}

// fragResponse is what every fragment endpoint answers.
type fragResponse struct {
	HTML    string          `json:"html"`
	Now     int64           `json:"now"`
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	Pages   int             `json:"pages"`
	Size    int             `json:"size"`
	Where   map[string]int  `json:"where,omitempty"`
	Summary string          `json:"summary"`
	Flags   map[string]bool `json:"flags,omitempty"`
}

func (p *portal) fragment(c *gin.Context, name string, data any, resp fragResponse) {
	var buf bytes.Buffer
	if err := p.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("portal: render %s: %v", name, err)
		jsonError(c, http.StatusInternalServerError, "template error")
		return
	}
	resp.HTML = buf.String()
	resp.Now = time.Now().UnixMilli()
	c.JSON(http.StatusOK, resp)
}

// ─── rows ────────────────────────────────────────────────────────────────────

// visitorRow is one client in the Visitors tab. RowClass tints the row:
// danger for a permanent ban, warning for a temporary one, success when the
// last response was 2xx and info otherwise.
type visitorRow struct {
	historyClientView
	RowClass string
	FirstMS  int64
	LastMS   int64
}

func newVisitorRow(v historyClientView) visitorRow {
	r := visitorRow{historyClientView: v, FirstMS: unixMS(v.FirstSeen), LastMS: unixMS(v.LastSeen)}
	switch {
	case v.BannedNow && v.BanPermanent:
		r.RowClass = "table-danger"
	case v.BannedNow:
		r.RowClass = "table-warning"
	case v.LastStatus >= 200 && v.LastStatus < 300:
		r.RowClass = "table-success"
	default:
		r.RowClass = "table-info"
	}
	return r
}

type visitorsData struct {
	Rows    []visitorRow
	AbuseOn bool
}

type visitorDetail struct {
	Client  visitorRow
	UAs     []string
	Bans    []banWindowView
	Entries []historyEntryView
	Pager   detailPager
}

func (v historyEntryView) AtMS() int64 { return unixMS(v.At) }

func (v historyEntryView) RowClass() string {
	switch {
	case v.Triggered:
		return "history-trigger"
	case v.Blocked:
		return "history-blocked"
	}
	return ""
}

func (v banWindowView) BeganMS() int64    { return ptrMS(v.Began) }
func (v banWindowView) UntilMS() int64    { return ptrMS(v.Until) }
func (v banWindowView) EndedMS() int64    { return ptrMS(v.Ended) }
func (v banWindowView) FirstHitMS() int64 { return ptrMS(v.FirstHit) }
func (v banWindowView) LastHitMS() int64  { return ptrMS(v.LastHit) }

func (v banWindowView) RowClass() string {
	switch {
	case !v.Active:
		return ""
	case v.Permanent:
		return "table-danger"
	}
	return "table-warning"
}

// TopPaths summarises the paths hit while banned for the ban log.
func (v banWindowView) TopPaths() string {
	parts := make([]string, 0, len(v.Paths))
	for _, x := range v.Paths {
		parts = append(parts, x.Name+" ×"+fmtCount(x.Hits))
	}
	s := strings.Join(parts, ", ")
	if more := v.DistinctPaths - len(v.Paths); more > 0 && s != "" {
		s += " and " + fmtCount(more) + " more"
	}
	return s
}

// StartedBy is the request that started the ban, or who issued it.
func (v banWindowView) StartedBy() string {
	if v.Trigger != nil {
		return v.Trigger.Method + " " + v.Trigger.Path
	}
	return v.Source
}

// queueRow is one waiting visitor in the Queue tab.
type queueRow struct {
	occupantView
	PosLabel string
	Idle     bool
	JoinedMS int64
	SeenMS   int64
}

func newQueueRow(o occupantView) queueRow {
	r := queueRow{occupantView: o, PosLabel: "—", Idle: !o.Ready && o.IdleSeconds > 15,
		JoinedMS: unixMS(o.Joined), SeenMS: unixMS(o.LastSeen)}
	if o.Position > 0 {
		r.PosLabel = "#" + strconv.FormatInt(o.Position, 10)
	}
	return r
}

// banRow is one ban in the Bans tab.
type banRow struct {
	banView
	UntilMS  int64
	RowClass string
}

func newBanRow(b banView) banRow {
	r := banRow{banView: b, UntilMS: unixMS(b.Until), RowClass: "table-warning"}
	if b.Permanent {
		r.RowClass = "table-danger"
	}
	return r
}

type bansData struct {
	Rows    []banRow
	AbuseOn bool
}

func addrOf(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().Addr(), true
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil
}

func windowAddrs(ws ...banWindowView) []netip.Addr {
	var out []netip.Addr
	for _, w := range ws {
		if a, ok := addrOf(w.Target); ok {
			out = append(out, a)
		}
		for _, c := range w.Clients {
			if a, ok := addrOf(c.Name); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// ─── handlers ────────────────────────────────────────────────────────────────

// fragVisitors is one page of the Visitors tab.
func (p *portal) fragVisitors(c *gin.Context) {
	now := time.Now()
	g := p.a.current()
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	all := p.history.sortedClients(q, c.Query("flagged") == "1", g.abuse, now)
	page, size := pageParams(c)
	start, end, page, pages := paginate(len(all), page, size)

	rows := make([]visitorRow, 0, end-start)
	addrs := make([]netip.Addr, 0, end-start)
	for _, v := range all[start:end] {
		rows = append(rows, newVisitorRow(v))
		addrs = append(addrs, v.addr)
	}
	p.a.ipinfo.warm(addrs)

	summary := fmt.Sprintf("%s of %s matching · %s addresses recorded",
		rangeText(start, end, len(all)), fmtCount(len(all)), fmtCount(p.history.count.Load()))
	if ev := p.history.evicted.Load(); ev > 0 {
		summary += " · " + fmtCount(ev) + " forgotten to make room"
	}
	p.fragment(c, "visitor-rows", visitorsData{Rows: rows, AbuseOn: g.abuse != nil}, fragResponse{
		Total: len(all), Page: page, Pages: pages, Size: size, Summary: summary,
		Where: wherePages(c.Query("keys"), size, len(all), func(i int) string { return all[i].Client }),
	})
}

// fragVisitor is one client's expanded row: what ess knows, its bans, and a
// page of its requests.
func (p *portal) fragVisitor(c *gin.Context) {
	ip, err := netip.ParseAddr(strings.TrimSpace(c.Query("client")))
	if err != nil {
		jsonError(c, http.StatusBadRequest, "client must be an IP address")
		return
	}
	ip = ip.Unmap().WithZone("")
	now := time.Now()
	v, entries, uas, ok := p.history.clientDetail(ip)
	if !ok {
		jsonError(c, http.StatusNotFound, "no requests recorded from that address")
		return
	}
	v.setBan(p.a.current().abuse, now)
	page, size := pageParams(c)
	start, end, page, pages := paginate(len(entries), page, size)
	bans := p.history.windowsFor(ip, now)
	p.a.ipinfo.warm(append([]netip.Addr{ip}, windowAddrs(bans...)...))

	data := visitorDetail{
		Client: newVisitorRow(v), UAs: uas, Bans: bans, Entries: entries[start:end],
		Pager: newDetailPager(len(entries), page, pages, start, end),
	}
	p.fragment(c, "visitor-detail", data, fragResponse{Total: len(entries), Page: page, Pages: pages, Size: size})
}

// fragBanLog is one page of the Ban log tab.
func (p *portal) fragBanLog(c *gin.Context) {
	now := time.Now()
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	page, size := pageParams(c)
	views, total, page, pages, where := p.history.windowPage(q, now, page, size, c.Query("keys"))
	p.a.ipinfo.warm(windowAddrs(views...))
	p.fragment(c, "banlog-rows", views, fragResponse{
		Total: total, Page: page, Pages: pages, Size: size, Where: where,
		Summary: fmt.Sprintf("%s of %s bans", rangeText((page-1)*size, (page-1)*size+len(views), total), fmtCount(total)),
		Flags:   map[string]bool{"abuse_enabled": p.a.current().abuse != nil},
	})
}

// fragBan is one ban's expanded row with every path and address it blocked.
func (p *portal) fragBan(c *gin.Context) {
	id, err := strconv.ParseUint(c.Query("id"), 10, 64)
	if err != nil {
		jsonError(c, http.StatusBadRequest, "id is required")
		return
	}
	v, ok := p.history.windowByID(id, time.Now())
	if !ok {
		jsonError(c, http.StatusNotFound, "that ban is no longer in the history")
		return
	}
	p.a.ipinfo.warm(windowAddrs(v))
	p.fragment(c, "ban-window", v, fragResponse{Total: 1, Page: 1, Pages: 1})
}

// fragQueue is one page of the Queue tab, from the front of the line.
func (p *portal) fragQueue(c *gin.Context) {
	now := time.Now()
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	list := p.queueViews(now)
	if q != "" {
		kept := list[:0]
		for _, o := range list {
			if strings.Contains(strings.ToLower(o.Client), q) || strings.Contains(strings.ToLower(o.Path), q) ||
				strings.Contains(strings.ToLower(o.UserAgent), q) {
				kept = append(kept, o)
			}
		}
		list = kept
	}
	page, size := pageParams(c)
	start, end, page, pages := paginate(len(list), page, size)
	rows := make([]queueRow, 0, end-start)
	var addrs []netip.Addr
	for _, o := range list[start:end] {
		rows = append(rows, newQueueRow(o))
		if a, ok := addrOf(o.Client); ok {
			addrs = append(addrs, a)
		}
	}
	p.a.ipinfo.warm(addrs)
	p.fragment(c, "queue-rows", rows, fragResponse{
		Total: len(list), Page: page, Pages: pages, Size: size,
		Summary: fmt.Sprintf("%s of %s listed · %s waiting · %s removed",
			rangeText(start, end, len(list)), fmtCount(len(list)),
			fmtCount(p.a.room.LiveQueueDepth()), fmtCount(p.kicked.count())),
		Where: wherePages(c.Query("keys"), size, len(list), func(i int) string { return list[i].ID }),
	})
}

// fragBans is one page of the Bans tab.
func (p *portal) fragBans(c *gin.Context) {
	now := time.Now()
	reg := p.a.current().abuse
	list := reg.bans(now)
	page, size := pageParams(c)
	start, end, page, pages := paginate(len(list), page, size)
	rows := make([]banRow, 0, end-start)
	var addrs []netip.Addr
	for _, b := range list[start:end] {
		rows = append(rows, newBanRow(b))
		if a, ok := addrOf(b.Client); ok {
			addrs = append(addrs, a)
		}
	}
	p.a.ipinfo.warm(addrs)
	p.fragment(c, "ban-rows", bansData{Rows: rows, AbuseOn: reg != nil}, fragResponse{
		Total: len(list), Page: page, Pages: pages, Size: size,
		Summary: fmt.Sprintf("%s of %s active bans · %s clients tracked · %s ranges",
			rangeText(start, end, len(list)), fmtCount(len(list)), fmtCount(reg.tracked()), fmtCount(reg.rangeCount())),
		Where: wherePages(c.Query("keys"), size, len(list), func(i int) string { return list[i].Client }),
		Flags: map[string]bool{"enabled": reg != nil, "persisted": p.a.bansPath != ""},
	})
}
