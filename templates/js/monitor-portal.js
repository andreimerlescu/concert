'use strict';
(() => {
    const $ = id => document.getElementById(id);
    if (!$('tab-monitor')) return;
    const NS = 'http://www.w3.org/2000/svg';
    const el = (tag, cls, text) => { const x = document.createElement(tag); if (cls) x.className = cls; if (text !== undefined) x.textContent = String(text); return x; };
    const nf = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
    const n0 = new Intl.NumberFormat();
    const fmt = (v, d = 1) => (typeof v === 'number' && isFinite(v)) ? new Intl.NumberFormat(undefined, { maximumFractionDigits: d }).format(v) : '–';
    const ms = v => v >= 1000 ? fmt(v / 1000, 2) + ' s' : fmt(v, 0) + ' ms';
    const dur = s => { s = Math.round(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`; };
    let timer = null, latest = null;

    // Sparkline: one or two series over the same time axis, scaled to zero.
    function chart(title, series, unit, key) {
        const col = el('div', 'col-md-6 col-xl-4'), card = el('div', 'card h-100 mon-chart'), body = el('div', 'card-body');
        const head = el('div', 'd-flex justify-content-between align-items-baseline mb-1');
        const t = el('h3', 'h6 mb-0', title);
        series.forEach((s, i) => { if (s.name) { t.append(el('span', 'mon-key ' + (i ? 'mon-b' : 'mon-a')), document.createTextNode(s.name)); } });
        const last = series.map(s => s.values.length ? s.values[s.values.length - 1] : NaN);
        head.append(t, el('strong', 'stat-value fs-5', last.map(v => fmt(v, unit === '%' ? 0 : 1) + (unit ? ' ' + unit : '')).join(' · ')));
        const all = series.flatMap(s => s.values).filter(v => isFinite(v));
        const max = Math.max(1e-9, ...all), n = Math.max(2, ...series.map(s => s.values.length));
        const svg = document.createElementNS(NS, 'svg');
        svg.setAttribute('viewBox', '0 0 300 80'); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', `${title}: now ${last.map(v => fmt(v)).join(', ')} ${unit}; peak ${fmt(max)} ${unit} over ${dur((n - 1) * (latest?.interval || 5))}`);
        for (const y of [0, 40, 80]) { const g = document.createElementNS(NS, 'line'); g.setAttribute('x1', 0); g.setAttribute('x2', 300); g.setAttribute('y1', y); g.setAttribute('y2', y); g.setAttribute('class', 'mon-grid'); svg.append(g); }
        series.forEach((s, i) => {
            if (!s.values.length) return;
            const pts = s.values.map((v, j) => `${(j / (n - 1)) * 300},${78 - (isFinite(v) ? v / max : 0) * 76}`);
            if (i === 0 && series.length === 1) { const a = document.createElementNS(NS, 'polygon'); a.setAttribute('points', `0,80 ${pts.join(' ')} ${((s.values.length - 1) / (n - 1)) * 300},80`); a.setAttribute('class', 'mon-area'); svg.append(a); }
            const p = document.createElementNS(NS, 'polyline'); p.setAttribute('points', pts.join(' ')); p.setAttribute('class', 'mon-line ' + (i ? 'mon-b' : 'mon-a')); svg.append(p);
        });
        const foot = el('div', 'd-flex justify-content-between small text-body-secondary');
        foot.append(el('span', '', '−' + dur((n - 1) * (latest?.interval || 5))), el('span', '', 'peak ' + fmt(max) + (unit ? ' ' + unit : '')), el('span', '', 'now'));
        body.append(head, svg, foot); card.append(body); col.append(card); return col;
    }

    function stat(label, value, sub, tone) {
        const col = el('div', 'col-6 col-lg-3'), card = el('div', 'card stat-card h-100'), body = el('div', 'card-body');
        body.append(el('div', 'small text-body-secondary', label), el('div', 'stat-value' + (tone ? ' text-' + tone : ''), value));
        if (sub) body.append(el('div', 'small text-body-secondary', sub));
        card.append(body); col.append(card); return col;
    }

    function dl(target, rows) {
        target.replaceChildren();
        for (const [k, v] of rows) { if (v === undefined || v === null || v === '–') continue; target.append(el('dt', '', k), el('dd', '', v)); }
    }

    function render(d) {
        latest = d;
        const h = d.history, cur = h.length ? h[h.length - 1] : null, t = d.traffic, m = d.memory, p = d.process;
        $('mon-updated').textContent = 'updated ' + new Date().toLocaleTimeString();
        $('mon-uptime').textContent = 'up ' + dur(p.uptime_s);
        const health = $('mon-health'); health.replaceChildren();
        for (const c of d.health) { const b = el('span', 'mon-badge'); const i = el('i', 'bi ' + (c.ok ? 'bi-circle-fill text-success' : 'bi-exclamation-triangle-fill text-danger')); i.setAttribute('aria-hidden', 'true'); b.append(i, el('strong', '', c.name), el('span', 'text-body-secondary', c.detail)); health.append(b); }
        const total = Object.values(t.status).reduce((a, b) => a + b, 0), errShare = total ? (t.status['5xx'] / total) * 100 : 0;
        const cards = $('mon-cards'); cards.replaceChildren(
            stat('Requests per second', cur ? fmt(cur.rps, 1) : '–', n0.format(t.requests_total) + ' since start'),
            stat('Response time p95', cur ? ms(cur.p95_ms) : '–', 'overall p50 ' + ms(t.p50_ms) + ' · p99 ' + ms(t.p99_ms), cur && cur.p95_ms >= 1000 ? 'warning' : ''),
            stat('Server errors (5xx)', fmt(errShare, 2) + '%', n0.format(t.status['5xx']) + ' of ' + n0.format(total), errShare >= 1 ? 'danger' : ''),
            stat('In flight now', n0.format(t.inflight), 'peak ' + n0.format(t.inflight_peak)),
            stat('CPU busy', cur ? fmt(cur.cpu_pct, 0) + '%' : '–', 'average ' + fmt(p.cpu_avg_pct, 1) + '% of ' + p.gomaxprocs + ' cores', cur && cur.cpu_pct >= 85 ? 'warning' : ''),
            stat('Heap in use', fmt(m.heap_alloc_mb, 1) + ' MB', 'next GC at ' + fmt(m.next_gc_mb, 0) + ' MB'),
            stat('Goroutines', n0.format(p.goroutines), p.threads ? p.threads + ' OS threads' : ''),
            stat('GC pause', fmt(m.gc_pause_last_ms, 2) + ' ms', n0.format(m.gc_cycles) + ' cycles · avg ' + fmt(m.gc_pause_avg_ms, 2) + ' ms'));
        const col = k => h.map(s => s[k]);
        $('mon-charts').replaceChildren(
            chart('Requests per second', [{ values: col('rps') }], 'req/s'),
            chart('Response time', [{ name: 'p50', values: col('p50_ms') }, { name: 'p95', values: col('p95_ms') }], 'ms'),
            chart('Server errors', [{ values: col('errors_per_s') }], 'err/s'),
            chart('CPU busy', [{ values: col('cpu_pct') }], '%'),
            chart('Heap in use', [{ values: col('heap_mb') }], 'MB'),
            chart('Goroutines', [{ values: col('goroutines') }], ''),
            chart('Waiting room', [{ name: 'in room', values: col('occupancy') }, { name: 'queued', values: col('queue_depth') }], ''),
            chart('Requests in flight', [{ values: col('inflight') }], ''));
        const hist = $('mon-histogram'); hist.replaceChildren();
        const maxB = Math.max(1, ...t.buckets);
        t.buckets.forEach((c, i) => {
            const label = i < t.bounds_ms.length ? '≤' + (t.bounds_ms[i] >= 1000 ? t.bounds_ms[i] / 1000 + 's' : t.bounds_ms[i] + 'ms') : '>' + t.bounds_ms[t.bounds_ms.length - 1] / 1000 + 's';
            const bar = el('div', 'mon-bar'), fill = el('div', 'mon-fill'); fill.style.height = (c / maxB * 100) + '%'; fill.title = n0.format(c) + ' requests';
            bar.append(el('span', '', n0.format(c)), fill, el('span', '', label)); hist.append(bar);
        });
        hist.setAttribute('aria-label', 'Response time histogram: ' + t.buckets.map((c, i) => `${i < t.bounds_ms.length ? '≤' + t.bounds_ms[i] + ' ms' : 'over ' + t.bounds_ms[t.bounds_ms.length - 1] + ' ms'}: ${c}`).join(', '));
        dl($('mon-status'), Object.entries(t.status).filter(([k, v]) => v || k !== 'other' && k !== '1xx').map(([k, v]) => [k, n0.format(v)]));
        dl($('mon-process'), [['Go', p.go_version], ['Platform', p.os_arch], ['CPUs', p.cpus + ' (' + p.gomaxprocs + ' used)'], ['Resident memory', p.rss_mb ? fmt(p.rss_mb, 0) + ' MB' : undefined], ['Open files', p.open_files], ['Runtime memory', fmt(m.sys_mb, 0) + ' MB'], ['Stacks', fmt(m.stack_mb, 1) + ' MB'], ['Heap objects', n0.format(m.heap_objects)], ['GC CPU share', fmt(m.gc_cpu_pct, 2) + '%'], ['Allocated since start', fmt(m.allocated_total_mb, 0) + ' MB']]);
    }

    async function poll() {
        try {
            const r = await fetch('/api/monitor', { credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
            if (r.status === 401) { location.reload(); return; }
            if (!r.ok) throw Error('HTTP ' + r.status);
            render(await r.json());
        } catch (e) { $('mon-updated').textContent = 'could not load: ' + e.message; }
    }
    // Poll only while the tab is showing and the browser tab is visible.
    const active = () => $('tab-monitor').classList.contains('active') && !document.hidden;
    function schedule() { clearInterval(timer); timer = setInterval(() => { if (active()) poll(); }, 5000); }
    $('tab-monitor-btn').addEventListener('shown.bs.tab', () => { poll(); schedule(); });
    document.addEventListener('visibilitychange', () => { if (active()) poll(); });
    if (active()) { poll(); schedule(); }
})();
