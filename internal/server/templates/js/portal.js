/* Concert admin portal. Loaded as a file: the CSP forbids inline scripts. */
(() => {
    'use strict';

    // The theme picker is js/theme.js, loaded from <head>.

    if (!document.getElementById('portal-app')) return; // sign-in page

    // ── Helpers ────────────────────────────────────────────────────────────
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';
    const numberFormat = new Intl.NumberFormat();
    const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Set once the portal has moved away from this page's address; stops polling.
    let portalMoved = false;
    let activeSite = '';
    let lastLiveQueueDepth = 0;

    function withSiteParam(url) {
        if (!activeSite || url.startsWith('/api/sites') || url.startsWith('/api/reload')) return url;
        const sep = url.includes('?') ? '&' : '?';
        return url + sep + 'site=' + encodeURIComponent(activeSite);
    }

    async function api(method, url, body) {
        const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
        if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrf;
        if (body !== undefined) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(withSiteParam(url), opts);
        if (res.status === 401) {
            window.location.reload();
            throw new Error('Your session expired.');
        }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
        return data;
    }

    // Values from the server outside the rendered fragments are attacker-
    // influenced (user agents, paths), so the DOM here is built with
    // textContent only. Fragments are escaped by Go's html/template.
    function node(tag, className, text) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (text !== undefined && text !== null) el.textContent = String(text);
        return el;
    }

    function byId(id) { return document.getElementById(id); }
    function setText(id, text) { const el = byId(id); if (el) el.textContent = text; }
    function fmtNum(v) { return typeof v === 'number' ? numberFormat.format(v) : '–'; }
    function fmtMoney(v) { return '$' + Number(v || 0).toFixed(2); }
    function fmtTime(v) {
        const d = new Date(v);
        return Number.isNaN(d.getTime()) ? '–' : dateFormat.format(d);
    }
    function plural(n, word) { return `${n} ${word}${n === 1 ? '' : 's'}`; }

    function fmtSeconds(total) {
        const s = Math.max(0, Math.round(total));
        if (s < 60) return s + 's';
        const m = Math.floor(s / 60);
        if (m < 60) return m + 'm ' + (s % 60) + 's';
        const h = Math.floor(m / 60);
        if (h < 48) return h + 'h ' + (m % 60) + 'm';
        return Math.floor(h / 24) + 'd ' + (h % 24) + 'h';
    }

    function toast(message, kind) {
        const wrap = byId('toasts');
        if (!wrap) return;
        const t = node('div', 'toast align-items-center border-0 text-bg-' + (kind || 'success'));
        t.setAttribute('role', 'status');
        t.setAttribute('aria-live', 'polite');
        t.setAttribute('aria-atomic', 'true');
        const row = node('div', 'd-flex');
        row.append(node('div', 'toast-body', message));
        const close = node('button', 'btn-close btn-close-white me-2 m-auto');
        close.type = 'button';
        close.setAttribute('data-bs-dismiss', 'toast');
        close.setAttribute('aria-label', 'Close');
        row.append(close);
        t.append(row);
        wrap.append(t);
        t.addEventListener('hidden.bs.toast', () => t.remove());
        bootstrap.Toast.getOrCreateInstance(t, { delay: 5500 }).show();
    }

    function setBar(id, used, cap) {
        const bar = byId(id);
        if (!bar) return;
        const pct = cap > 0 ? Math.min(100, Math.round((used / cap) * 100)) : 0;
        bar.style.width = pct + '%';
        bar.classList.remove('bg-success', 'bg-warning', 'bg-danger');
        bar.classList.add(pct >= 90 ? 'bg-danger' : pct >= 70 ? 'bg-warning' : 'bg-success');
        bar.parentElement.setAttribute('aria-valuenow', String(pct));
    }

    function emptyRowEl(cols, text) {
        const tr = node('tr', 'live-empty');
        const td = node('td', 'text-center text-body-secondary py-4', text);
        td.colSpan = cols;
        tr.append(td);
        return tr;
    }

    function iconButton(action, cls, icon, label, data) {
        const b = node('button', 'btn ' + cls);
        b.type = 'button';
        b.title = label;
        b.setAttribute('aria-label', label);
        b.dataset.action = action;
        Object.entries(data).forEach(([k, v]) => { b.dataset[k] = v; });
        b.append(node('i', 'bi ' + icon));
        return b;
    }

    function activeTab() {
        const pane = document.querySelector('.tab-pane.active');
        return pane ? pane.id : '';
    }

    function debounce(fn, ms) {
        let t = 0;
        return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    }

    // ── Tooltips and copying ───────────────────────────────────────────────
    // One delegated instance covers every tooltip, including rows rendered
    // later. Rows removed from a table dispose theirs first.
    new bootstrap.Tooltip(document.body, { selector: '[data-bs-toggle="tooltip"]', trigger: 'hover focus' });

    function disposeTips(el) {
        if (!el || !el.querySelectorAll) return;
        el.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((t) => {
            const inst = bootstrap.Tooltip.getInstance(t);
            if (inst) inst.dispose();
        });
    }

    document.addEventListener('click', async (ev) => {
        const el = ev.target.closest('[data-copy]');
        if (!el) return;
        ev.preventDefault();
        try {
            await navigator.clipboard.writeText(el.dataset.copy);
            toast('Copied ' + el.dataset.copy);
        } catch (err) {
            toast('Copy failed: the browser did not allow clipboard access.', 'danger');
        }
    });

    // ── Times ──────────────────────────────────────────────────────────────
    // Fragments carry unix milliseconds; the browser formats them, so a row's
    // HTML only changes when its data does.
    function tickRelative(scope, now) {
        scope.querySelectorAll('.js-ago').forEach((el) => {
            const ms = Number(el.dataset.ms);
            if (ms > 0) el.textContent = fmtSeconds((now - ms) / 1000) + ' ago';
        });
        scope.querySelectorAll('.js-since').forEach((el) => {
            const ms = Number(el.dataset.ms);
            if (ms > 0) el.textContent = fmtSeconds((now - ms) / 1000);
        });
        scope.querySelectorAll('.js-left').forEach((el) => {
            const ms = Number(el.dataset.ms);
            if (ms > 0) el.textContent = fmtSeconds((ms - now) / 1000);
        });
    }

    function decorate(scope) {
        scope.querySelectorAll('.js-time').forEach((el) => {
            const ms = Number(el.dataset.ms);
            if (!(ms > 0)) return;
            el.textContent = dateFormat.format(ms);
            if ('dateTime' in el) el.dateTime = new Date(ms).toISOString();
        });
        tickRelative(scope, Date.now());
    }

    // ── Live tables ────────────────────────────────────────────────────────
    // A LiveTable shows one page of a server-rendered fragment. Rows are
    // matched by data-key: unchanged rows are kept, changed rows replaced,
    // and with motion allowed rows slide to their new place (FLIP), rows
    // arriving say where they came from and rows leaving say where they went.
    const rowHTML = new WeakMap();
    const ROWS = ':scope > tr[data-key]:not(.row-leaving)';

    function addChip(row, label, kind) {
        if (!label) return;
        const cell = row.querySelector('[data-chip]') || row.cells[0];
        if (!cell) return;
        const chip = node('span', 'move-chip move-chip-' + kind, label);
        chip.setAttribute('aria-hidden', 'true');
        cell.prepend(chip);
        setTimeout(() => chip.remove(), 2600);
    }

    class LiveTable {
        constructor(o) {
            this.o = o;
            this.tbody = byId(o.tbody);
            this.pager = byId(o.pager);
            this.card = this.tbody.closest('.card');
            this.page = 1;
            this.pages = 1;
            this.total = 0;
            this.size = Number(localStorage.getItem('concert.portal.size.' + o.name)) || 25;
            this.prevNow = 0;
            this.loaded = false;
            this.busy = false;
            this.again = false;
            this.hover = false;
            this.pagerSig = '';

            this.card.addEventListener('mouseenter', () => { this.hover = true; this.showState(); });
            this.card.addEventListener('mouseleave', () => { this.hover = false; this.showState(); });
            this.pager.addEventListener('click', (ev) => {
                const b = ev.target.closest('button[data-page]');
                if (!b || b.disabled) return;
                this.go(Number(b.dataset.page));
            });
            this.pager.addEventListener('change', (ev) => {
                if (!ev.target.matches('select')) return;
                this.size = Number(ev.target.value);
                localStorage.setItem('concert.portal.size.' + o.name, String(this.size));
                this.go(1);
            });
            const sw = o.liveSwitch && byId(o.liveSwitch);
            if (sw) sw.addEventListener('change', () => { this.showState(); if (sw.checked) this.refresh(); });
            this.showState();
        }

        keys() { return [...this.tbody.querySelectorAll(ROWS)].map((r) => r.dataset.key); }

        live() {
            const sw = this.o.liveSwitch && byId(this.o.liveSwitch);
            return !sw || sw.checked;
        }

        showState() {
            const el = this.card.querySelector('.live-state');
            if (!el) return;
            let text = 'live';
            let cls = 'text-bg-success';
            let title = 'Updates every 3 seconds';
            if (!this.live()) {
                text = 'live off'; cls = 'text-bg-secondary'; title = 'Turn Live on, or press Refresh';
            } else if (this.hover) {
                text = 'paused'; cls = 'text-bg-warning'; title = 'Paused while the pointer is over the table';
            }
            el.className = 'badge live-state ' + cls;
            el.textContent = text;
            el.title = title;
        }

        poll() {
            if (this.hover || !this.live()) return;
            this.refresh();
        }

        // go loads another page, or the first page again after a filter
        // change, without movement animations: every row would be "new".
        go(page) {
            this.page = page;
            this.loaded = false;
            this.refresh();
        }

        async refresh() {
            if (portalMoved) return;
            if (this.busy) { this.again = true; return; }
            this.busy = true;
            try {
                const params = new URLSearchParams(this.o.params ? this.o.params() : {});
                params.set('page', String(this.page));
                params.set('size', String(this.size));
                const keys = this.keys();
                if (keys.length) params.set('keys', keys.join(','));
                const d = await api('GET', this.o.url + '?' + params.toString());
                this.page = d.page;
                this.pages = d.pages;
                this.size = d.size;
                this.total = d.total;
                this.apply(d);
                if (this.o.summary) setText(this.o.summary, d.summary || '');
                this.renderPager();
                if (this.o.after) this.o.after(d);
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                this.busy = false;
                if (this.again) { this.again = false; this.refresh(); }
            }
        }

        leaveLabel(where) {
            if (!where) return this.o.goneLabel || 'gone';
            if (where > this.page) return `↓ page ${where}`;
            if (where < this.page) return `↑ page ${where}`;
            return '';
        }

        arrival(row) {
            const first = Number(row.dataset.first || 0);
            const last = Number(row.dataset.last || 0);
            if (first && first > this.prevNow) return { label: 'new', from: -12 };
            if (this.o.arrival) return this.o.arrival(row, this);
            if (last && last > this.prevNow) return { label: '↑ moved up', from: 18 };
            if (this.page > 1) return { label: `↓ from page ${this.page - 1}`, from: -18 };
            return { label: 'moved', from: 12 };
        }

        apply(d) {
            const tpl = document.createElement('template');
            tpl.innerHTML = d.html || '';
            const incoming = [...tpl.content.children].filter((el) => el.tagName === 'TR' && el.hasAttribute('data-key'));
            const animate = this.loaded && !reduceMotion;

            const old = new Map();
            const firstTop = new Map();
            this.tbody.querySelectorAll(ROWS).forEach((r) => {
                old.set(r.dataset.key, r);
                if (animate) firstTop.set(r.dataset.key, r.getBoundingClientRect().top);
            });
            const details = new Map();
            this.tbody.querySelectorAll(':scope > tr[data-detail-for]').forEach((r) => details.set(r.dataset.detailFor, r));
            this.tbody.querySelectorAll(':scope > tr.row-leaving').forEach((r) => { disposeTips(r); r.remove(); });

            const next = [];
            const entered = [];
            const changed = [];
            for (const row of incoming) {
                const key = row.dataset.key;
                const html = row.outerHTML;
                const prev = old.get(key);
                if (prev && rowHTML.get(prev) === html) {
                    next.push(prev);
                    old.delete(key);
                    continue;
                }
                rowHTML.set(row, html);
                if (prev) {
                    old.delete(key);
                    disposeTips(prev);
                    changed.push(row);
                } else {
                    entered.push(row);
                }
                next.push(row);
            }
            const leaving = [...old.values()];

            const nodes = [];
            for (const r of next) {
                nodes.push(r);
                const det = details.get(r.dataset.key);
                if (det) { nodes.push(det); details.delete(r.dataset.key); }
            }
            details.forEach((det, key) => {
                disposeTips(det);
                if (this.o.details) this.o.details.gone(key);
            });
            if (!next.length) nodes.push(emptyRowEl(this.o.cols, this.o.empty ? this.o.empty() : 'Nothing to show.'));
            this.tbody.replaceChildren(...nodes);
            decorate(this.tbody);

            if (animate) {
                for (const r of leaving) {
                    const where = d.where ? d.where[r.dataset.key] : undefined;
                    r.classList.add('row-leaving');
                    this.tbody.append(r);
                    addChip(r, this.leaveLabel(where), 'leave');
                    const dx = where && where < this.page ? -28 : 28;
                    const done = () => { disposeTips(r); r.remove(); };
                    r.animate(
                        [{ opacity: 1, transform: 'translateX(0)' }, { opacity: 0, transform: `translateX(${dx}px)` }],
                        { duration: 700, easing: 'ease-in', fill: 'forwards' },
                    ).finished.then(done, done);
                }
                for (const r of next) {
                    const top0 = firstTop.get(r.dataset.key);
                    if (top0 === undefined) continue;
                    const dy = top0 - r.getBoundingClientRect().top;
                    if (Math.abs(dy) > 1) {
                        r.animate([{ transform: `translateY(${dy}px)` }, { transform: 'translateY(0)' }],
                            { duration: 450, easing: 'cubic-bezier(.2,.8,.2,1)' });
                    }
                }
                for (const r of entered) {
                    const a = this.arrival(r);
                    addChip(r, a.label, 'enter');
                    r.animate([{ opacity: 0, transform: `translateY(${a.from}px)` }, { opacity: 1, transform: 'translateY(0)' }],
                        { duration: 450, easing: 'ease-out' });
                }
                if (this.o.flash) {
                    for (const r of changed) {
                        r.classList.add('row-flash');
                        setTimeout(() => r.classList.remove('row-flash'), 1200);
                    }
                }
            } else {
                leaving.forEach(disposeTips);
                if (!this.loaded && !reduceMotion && next.length) {
                    this.tbody.animate([{ opacity: 0.35 }, { opacity: 1 }], { duration: 180, easing: 'ease-out' });
                }
            }

            this.loaded = true;
            this.prevNow = d.now || Date.now();
            if (this.o.details) this.o.details.afterApply(changed, entered);
        }

        renderPager() {
            const sig = [this.page, this.pages, this.size].join('/');
            if (sig === this.pagerSig) return;
            this.pagerSig = sig;
            const p = this.page;
            const n = this.pages;
            const wrap = node('div', 'd-flex align-items-center gap-2 flex-wrap');
            const group = node('div', 'btn-group btn-group-sm');
            group.setAttribute('role', 'group');
            group.setAttribute('aria-label', 'Pages');
            const btn = (page, icon, label, disabled) => {
                const b = node('button', 'btn btn-outline-secondary');
                b.type = 'button';
                b.dataset.page = String(page);
                b.disabled = disabled;
                b.title = label;
                b.setAttribute('aria-label', label);
                b.append(node('i', 'bi ' + icon));
                return b;
            };
            group.append(
                btn(1, 'bi-chevron-double-left', 'First page', p <= 1),
                btn(p - 1, 'bi-chevron-left', 'Previous page', p <= 1),
                node('span', 'btn btn-outline-secondary disabled pager-current', `Page ${fmtNum(p)} of ${fmtNum(n)}`),
                btn(p + 1, 'bi-chevron-right', 'Next page', p >= n),
                btn(n, 'bi-chevron-double-right', 'Last page', p >= n),
            );
            const sel = node('select', 'form-select form-select-sm pager-size');
            sel.setAttribute('aria-label', 'Rows per page');
            [25, 50, 100].forEach((s) => {
                const opt = node('option', null, s + ' per page');
                opt.value = String(s);
                opt.selected = s === this.size;
                sel.append(opt);
            });
            wrap.append(group, sel);
            this.pager.replaceChildren(wrap);
        }
    }

    // DetailRows manages expanded rows under a LiveTable. A detail row is
    // refetched only when its parent row's HTML changed, so an open row does
    // not cost a request on every poll.
    class DetailRows {
        constructor(table, cols, url) {
            this.table = table;
            this.cols = cols;
            this.url = url;
            this.open = new Map();
            table.o.details = this;
        }

        parentRow(key) {
            for (const r of this.table.tbody.children) {
                if (r.dataset.key === key && !r.classList.contains('row-leaving')) return r;
            }
            return null;
        }

        detailRow(key) {
            for (const r of this.table.tbody.children) if (r.dataset.detailFor === key) return r;
            return null;
        }

        setToggle(parent, open) {
            const b = parent && parent.querySelector('button[data-action="toggle"]');
            if (!b) return;
            b.setAttribute('aria-expanded', open ? 'true' : 'false');
            b.setAttribute('aria-label', open ? 'Hide details' : 'Show details');
            const i = b.querySelector('i');
            if (i) i.className = 'bi ' + (open ? 'bi-chevron-down' : 'bi-chevron-right');
        }

        ensure(parent, key) {
            let d = this.detailRow(key);
            if (!d) {
                d = node('tr', 'history-detail');
                d.dataset.detailFor = key;
                const td = node('td');
                td.colSpan = this.cols;
                td.append(node('div', 'small text-body-secondary py-2', 'Loading…'));
                d.append(td);
                parent.after(d);
            }
            return d;
        }

        toggle(key) {
            const parent = this.parentRow(key);
            if (!parent) return;
            if (this.open.has(key)) {
                this.open.delete(key);
                const d = this.detailRow(key);
                if (d) { disposeTips(d); d.remove(); }
                this.setToggle(parent, false);
                return;
            }
            this.open.set(key, { page: 1, seq: 0 });
            this.setToggle(parent, true);
            this.ensure(parent, key);
            this.load(key);
        }

        page(key, page) {
            const st = this.open.get(key);
            if (!st) return;
            st.page = page;
            this.load(key);
        }

        async load(key) {
            const st = this.open.get(key);
            if (!st) return;
            const seq = ++st.seq;
            try {
                const d = await api('GET', this.url(key, st.page));
                if (this.open.get(key) !== st || st.seq !== seq) return;
                st.page = d.page;
                const parent = this.parentRow(key);
                if (!parent) return;
                const row = this.ensure(parent, key);
                const tpl = document.createElement('template');
                tpl.innerHTML = d.html || '';
                const td = row.firstElementChild;
                disposeTips(td);
                td.replaceChildren(tpl.content);
                decorate(td);
            } catch (err) {
                const row = this.detailRow(key);
                if (row) row.firstElementChild.replaceChildren(node('div', 'small text-danger py-2', err.message));
            }
        }

        afterApply(changed, entered) {
            const touched = new Set([...changed, ...entered].map((r) => r.dataset.key));
            for (const key of [...this.open.keys()]) {
                const parent = this.parentRow(key);
                if (!parent) continue;
                this.setToggle(parent, true);
                if (!this.detailRow(key)) {
                    this.ensure(parent, key);
                    this.load(key);
                } else if (touched.has(key)) {
                    this.load(key);
                }
            }
        }

        gone(key) { this.open.delete(key); }
    }

    // ── Overview ───────────────────────────────────────────────────────────
    async function refreshOverview() {
        try {
            const d = await api('GET', '/api/overview');
            document.querySelectorAll('[data-stat]').forEach((el) => {
                const key = el.getAttribute('data-stat');
                if (key in d) el.textContent = fmtNum(d[key]);
            });
            setText('stat-occupancy', fmtNum(d.occupancy) + ' / ' + fmtNum(d.cap));
            const drainBadge = byId('badge-cap-draining');
            if (drainBadge) drainBadge.classList.toggle('d-none', !d.cap_draining);
            setBar('bar-occupancy', d.occupancy, d.cap);
            if (typeof d.live_queue_depth === 'number') lastLiveQueueDepth = d.live_queue_depth;
            setText('stat-queue', fmtNum(d.live_queue_depth));
            setText('stat-queue-depth', fmtNum(d.queue_depth));
            setText('stat-assets', fmtNum(d.asset_in_flight) + ' / ' + fmtNum(d.asset_cap));
            setBar('bar-assets', d.asset_in_flight, d.asset_cap);
            setText('stat-streams', fmtNum(d.stream_active) + ' / ' + fmtNum(d.stream_cap));
            setText('stat-bans', d.abuse_enabled ? fmtNum(d.active_bans) : 'off');
            setText('stat-price', d.skip_url ? fmtMoney(d.rate) + ' + ' + fmtMoney(d.surge) + ' per queued' : 'off');
            setText('queue-count', fmtNum(d.live_queue_depth));
            setText('ban-count', fmtNum(d.active_bans));
            setText('visitors-count', fmtNum(d.history_clients));
            if ('email_queued' in d) {
                setText('email-queue-count', fmtNum(d.email_queued));
                const eb = byId('email-queue-count');
                if (eb) {
                    eb.classList.remove('text-bg-secondary', 'text-bg-warning', 'text-bg-primary');
                    eb.classList.add(d.email_paused ? 'text-bg-warning' : d.email_queued > 0 ? 'text-bg-primary' : 'text-bg-secondary');
                }
            }
            renderTierOverview(d);
            setText('updated-at', 'updated ' + new Date().toLocaleTimeString());
        } catch (err) {
            setText('updated-at', 'update failed: ' + err.message);
        }
    }

    function renderTierOverview(d) {
        const sec = byId('tier-section');
        if (!sec) return;
        const role = d.role || 'standalone';
        if (role !== 'edge' && role !== 'leaf') {
            sec.classList.add('d-none');
            return;
        }
        sec.classList.remove('d-none');
        setText('tier-role-badge', role);
        setText('tier-node-id', d.node || '');
        const edgeEl = byId('tier-edge-view');
        const leafEl = byId('tier-leaf-view');
        const leafBtn = byId('tier-leaf-rebench-btn');

        if (role === 'edge' && d.edge) {
            const e = d.edge;
            edgeEl.classList.remove('d-none');
            leafEl.classList.add('d-none');
            leafBtn.classList.add('d-none');
            setText('edge-leaves-usable', e.leaves_usable != null ? fmtNum(e.leaves_usable) : '–');
            setText('edge-leaf-slots', e.leaf_slots != null ? fmtNum(e.leaf_slots) : '–');
            setText('edge-planned-cap', e.planned_cap != null ? fmtNum(e.planned_cap) : '–');
            setText('edge-backpressure', fmtNum(e.leaf_backpressure_total || 0));
            setText('edge-retries', fmtNum(e.upstream_retries_total || 0));
            setText('edge-polls', `${fmtNum(e.leaf_polls_total || 0)} (${fmtNum(e.leaf_poll_errors_total || 0)})`);
            setText('edge-pushes', `${fmtNum(e.ban_pushes_total || 0)} (${fmtNum(e.ban_push_errors_total || 0)})`);

            const tbody = byId('tier-edge-leaves');
            tbody.replaceChildren();
            const leaves = (e.leaves || []).slice().sort((a, b) => String(a.url || '').localeCompare(String(b.url || '')));
            if (leaves.length === 0) {
                tbody.append(emptyRowEl(8, 'No leaf nodes polled yet.'));
            } else {
                for (const lf of leaves) {
                    const tr = node('tr');
                    const tdName = node('td');
                    tdName.append(node('div', 'fw-semibold small', lf.node || '(unseen)'));
                    tdName.append(node('div', 'small font-monospace text-body-secondary', lf.url || ''));

                    const tdSt = node('td');
                    let stText = 'Healthy', stCls = 'text-bg-success';
                    if (lf.error) { stText = 'Unreachable'; stCls = 'text-bg-danger'; }
                    else if (lf.rebenchmarking) { stText = 'Calibrating'; stCls = 'text-bg-info'; }
                    else if (lf.draining) { stText = 'Draining'; stCls = 'text-bg-warning'; }
                    else if (!lf.usable) { stText = 'Unusable'; stCls = 'text-bg-danger'; }
                    tdSt.append(node('span', 'badge ' + stCls, stText));
                    if (lf.error) tdSt.append(node('div', 'small text-danger mt-1', lf.error));

                    const tdCap = node('td', 'text-end small', `${fmtNum(lf.host_cap || 0)} (${lf.cap_source || '–'})`);
                    const tdShare = node('td', 'text-end fw-semibold small', fmtNum(lf.share || 0));
                    const tdInF = node('td', 'text-end small', `${fmtNum(lf.hop_in_flight || 0)} hop / ${fmtNum(lf.direct_in_flight || 0)} dir`);
                    const tdLat = node('td', 'text-end small', lf.latency_ms ? `${Math.round(lf.latency_ms)}ms` : '–');

                    const tdNotes = node('td', 'small');
                    if (lf.last_silence) {
                        const s = lf.last_silence;
                        const active = !s.recovered;
                        tdNotes.append(node('div', active ? 'text-danger fw-semibold' : 'text-body-secondary',
                            (active ? 'SILENT: ' : 'Recovered silence: ') + (s.reason || 'app silent')));
                    }
                    if (lf.bench) {
                        tdNotes.append(node('div', 'text-body-secondary',
                            `Bench: ${lf.bench.lemmings} lemmings · p95 ${Math.round(lf.bench.p95_ms || 0)}ms`));
                    }
                    if (!lf.last_silence && !lf.bench) tdNotes.textContent = '–';

                    const tdAct = node('td', 'text-end');
                    const btn = node('button', 'btn btn-sm btn-outline-primary', 'Re-benchmark');
                    btn.type = 'button';
                    btn.disabled = Boolean(lf.rebenchmarking || lf.error);
                    btn.dataset.action = 'rebench-leaf';
                    btn.dataset.leaf = lf.node || lf.url || '';
                    tdAct.append(btn);

                    tr.append(tdName, tdSt, tdCap, tdShare, tdInF, tdLat, tdNotes, tdAct);
                    tbody.append(tr);
                }
            }
            return;
        }

        if (role === 'leaf' && d.leaf) {
            const lf = d.leaf;
            edgeEl.classList.add('d-none');
            leafEl.classList.remove('d-none');
            leafBtn.classList.remove('d-none');
            leafBtn.disabled = Boolean(lf.rebenchmarking);

            setText('leaf-host-cap', `${fmtNum(lf.host_cap || 0)} (${lf.host_cap_source || '–'})`);
            setText('leaf-hop-inflight', `${fmtNum(lf.hop_in_flight || 0)} (${fmtNum(lf.hop_waiting || 0)})`);
            setText('leaf-direct-inflight', `${fmtNum(lf.direct_in_flight || 0)} (${fmtNum(lf.direct_waiting || 0)})`);
            setText('leaf-latency', lf.latency_ms ? `${Math.round(lf.latency_ms)}ms` : '–');
            setText('leaf-hop-accepted', fmtNum(lf.hop_accepted_total || 0));
            setText('leaf-hop-rejected', fmtNum(lf.hop_rejected_total || 0));
            setText('leaf-hop-replayed', fmtNum(lf.hop_replayed_total || 0));
            setText('leaf-hop-mtls', fmtNum(lf.hop_mtls_rejected_total || 0));
            setText('leaf-hop-backpressure', fmtNum(lf.hop_backpressure_total || 0));

            const silEl = byId('tier-leaf-silence');
            if (lf.last_silence) {
                const s = lf.last_silence;
                const active = !s.recovered;
                silEl.className = 'alert mb-3 ' + (active ? 'alert-danger' : 'alert-warning');
                silEl.textContent = (active ? 'Application silent: ' : 'Previous application silence (recovered): ') +
                    `${s.reason || 'upstream failing'} · ${s.hop_in_flight || 0} hop + ${s.direct_in_flight || 0} direct of ${s.host_cap || 0} host slots (${fmtTime(s.at)}).`;
            } else {
                silEl.className = 'alert alert-danger d-none mb-3';
                silEl.textContent = '';
            }

            if (lf.bench) {
                setText('leaf-bench-summary', `Last benchmark (${fmtTime(lf.bench.at)}): ${lf.bench.lemmings} lemmings · p95 ${Math.round(lf.bench.p95_ms || 0)}ms · ${lf.bench.pages_covered} pages`);
            } else {
                setText('leaf-bench-summary', 'No benchmark recorded yet.');
            }

            const sharesEl = byId('leaf-edge-shares');
            sharesEl.replaceChildren();
            const entries = Object.entries(lf.edge_shares || {}).sort((a, b) => a[0].localeCompare(b[0]));
            if (entries.length === 0) {
                sharesEl.append(node('li', 'list-group-item px-0 py-1 text-body-secondary', 'No active edges polling.'));
            } else {
                for (const [edgeId, slots] of entries) {
                    const li = node('li', 'list-group-item d-flex justify-content-between px-0 py-1');
                    li.append(node('span', 'font-monospace', edgeId), node('span', 'fw-semibold', `${fmtNum(slots)} slots`));
                    sharesEl.append(li);
                }
            }
        }
    }

    async function runRebench(leaf, force) {
        const body = leaf ? { leaf, force: Boolean(force) } : { force: Boolean(force) };
        const res = await api('POST', '/api/topology/rebench', body);
        toast(`Re-benchmark complete on ${res.node}: host cap ${res.previous_cap} → ${res.new_cap} (${res.lemmings} lemmings, p95 ${Math.round(res.p95_ms || 0)}ms).`);
        refreshOverview();
    }

    if (byId('tier-leaf-rebench-btn')) {
        byId('tier-leaf-rebench-btn').addEventListener('click', async () => {
            if (!window.confirm('Drain this leaf and run a live lemmings benchmark against its upstream?')) return;
            const btn = byId('tier-leaf-rebench-btn');
            btn.disabled = true;
            try {
                await runRebench('', false);
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                btn.disabled = false;
            }
        });
    }

    if (byId('tier-edge-leaves')) {
        byId('tier-edge-leaves').addEventListener('click', async (ev) => {
            const btn = ev.target.closest('button[data-action="rebench-leaf"]');
            if (!btn) return;
            const leaf = btn.dataset.leaf;
            btn.disabled = true;
            try {
                await runRebench(leaf, false);
            } catch (err) {
                if (String(err.message || '').includes('last usable leaf')) {
                    if (window.confirm(`${err.message}\n\nDrain ${leaf} anyway (this will briefly pause site traffic)?`)) {
                        try {
                            await runRebench(leaf, true);
                            return;
                        } catch (err2) {
                            toast(err2.message, 'danger');
                            return;
                        }
                    }
                }
                toast(err.message, 'danger');
            } finally {
                btn.disabled = false;
            }
        });
    }

    // ── Ban modal ──────────────────────────────────────────────────────────
    const banModalEl = byId('ban-modal');

    function setPermanent(on) {
        byId('ban-permanent').checked = on;
        byId('ban-duration-group').disabled = on;
    }

    function openBanModal(client, duration, permanent, prefill) {
        const editing = Boolean(client);
        setText('ban-modal-title', editing ? 'Change ban' : 'Ban a client');
        setText('ban-submit-label', editing ? 'Save' : 'Ban');
        const clientInput = byId('ban-client');
        clientInput.value = client || prefill || '';
        clientInput.readOnly = editing;
        byId('ban-duration').value = duration || '1h';
        setPermanent(Boolean(permanent));
        bootstrap.Modal.getOrCreateInstance(banModalEl).show();
    }

    byId('ban-permanent').addEventListener('change', (ev) => setPermanent(ev.target.checked));
    byId('ban-presets').addEventListener('click', (ev) => {
        const b = ev.target.closest('[data-duration]');
        if (b) byId('ban-duration').value = b.dataset.duration;
    });

    byId('ban-form').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const client = byId('ban-client').value.trim();
        const permanent = byId('ban-permanent').checked;
        const duration = permanent ? '' : byId('ban-duration').value.trim();
        try {
            const r = await api('POST', '/api/bans', { client, duration, permanent });
            bootstrap.Modal.getOrCreateInstance(banModalEl).hide();
            let msg = r.permanent ? `${r.client} banned permanently.` : `${r.client} banned until ${fmtTime(r.until)}.`;
            if (r.dropped > 0) msg += ` ${plural(r.dropped, 'waiting visitor')} removed from the line.`;
            if (r.exempt_within && r.exempt_within.length) msg += ` Still reachable inside it: ${r.exempt_within.join(', ')}.`;
            toast(msg, 'warning');
            refreshOverview();
            const t = activeTable();
            if (t) t.refresh();
        } catch (err) {
            toast(err.message, 'danger');
        }
    });

    // ── Queue ──────────────────────────────────────────────────────────────
    const queueTable = new LiveTable({
        name: 'queue', url: '/api/frag/queue', tbody: 'queue-rows', pager: 'queue-pager',
        summary: 'queue-summary', liveSwitch: 'queue-live', cols: 8, goneLabel: 'left the line',
        params: () => ({ q: byId('queue-filter').value.trim() }),
        empty: () => (byId('queue-filter').value.trim() ? 'No visitors match the filter.' : 'Nobody is waiting in line.'),
        arrival: (row, t) => ({ label: `↑ from page ${t.page + 1}`, from: 18 }),
    });

    byId('queue-filter').addEventListener('input', debounce(() => queueTable.go(1), 300));
    byId('queue-refresh').addEventListener('click', () => queueTable.refresh());

    const clearStaleBtn = byId('queue-clear-stale');
    if (clearStaleBtn) {
        clearStaleBtn.addEventListener('click', async () => {
            const scope = activeSite ? ` for ${activeSite}` : '';
            if (!window.confirm(`Flush stale/idle tickets from the waiting room${scope}? Active polling visitors keep their places.`)) return;
            clearStaleBtn.disabled = true;
            try {
                const r = await api('POST', '/api/queue/clear', { mode: 'stale' });
                const n = Number(r.removed || 0);
                toast(n > 0 ? `Flushed ${plural(n, 'stale ticket')}${scope}.` : `No stale tickets found${scope}.`, n > 0 ? 'warning' : 'info');
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                clearStaleBtn.disabled = false;
                queueTable.refresh();
                refreshOverview();
            }
        });
    }

    const clearAllBtn = byId('queue-clear-all');
    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', async () => {
            const depth = typeof lastLiveQueueDepth === 'number' ? lastLiveQueueDepth : queueTable.total;
            const siteLabel = activeSite || 'this site';
            if (!window.confirm(`Clear all waiting tickets for ${siteLabel} (currently ${fmtNum(depth)} waiting)?\n\nCleared visitors are not banned or blocked and can transparently re-admit or rejoin at the back of the line.`)) return;
            clearAllBtn.disabled = true;
            try {
                const r = await api('POST', '/api/queue/clear', { mode: 'all' });
                const n = Number(r.removed || 0);
                toast(`Cleared ${plural(n, 'ticket')} from ${siteLabel}.`, 'warning');
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                clearAllBtn.disabled = false;
                queueTable.refresh();
                refreshOverview();
            }
        });
    }

    byId('queue-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn) return;
        const { action, id } = btn.dataset;
        const prompts = {
            promote: 'Move this visitor to the front of the line?',
            kick: 'Remove this visitor from the line? They can rejoin at the back.',
            ban: 'Remove this visitor and ban their address for the abuse cooldown? Everyone else waiting from that address is removed too.',
        };
        if (!prompts[action] || !window.confirm(prompts[action])) return;
        btn.disabled = true;
        try {
            if (action === 'promote') {
                await api('POST', '/api/queue/promote', { id });
                toast('Visitor moved to the front of the line.');
            } else {
                const r = await api('POST', '/api/queue/kick', { id, ban: action === 'ban' });
                let msg = 'Visitor removed from the line.';
                if (r.banned) msg = r.ban_seconds > 0 ? `Visitor removed and banned for ${fmtSeconds(r.ban_seconds)}.` : 'Visitor removed; their address is banned permanently.';
                toast(msg, 'warning');
            }
        } catch (err) {
            toast(err.message, 'danger');
        } finally {
            queueTable.refresh();
            refreshOverview();
        }
    });

    // ── Bans ───────────────────────────────────────────────────────────────
    const bansTable = new LiveTable({
        name: 'bans', url: '/api/frag/bans', tbody: 'ban-rows', pager: 'bans-pager',
        summary: 'bans-summary', liveSwitch: 'bans-live', cols: 5, goneLabel: 'lifted or expired',
        empty: () => 'No active bans.',
        after: (d) => {
            const f = d.flags || {};
            byId('bans-disabled').classList.toggle('d-none', Boolean(f.enabled));
            byId('bans-not-persisted').classList.toggle('d-none', Boolean(f.persisted));
            byId('ban-new').disabled = !f.enabled;
        },
    });

    byId('ban-new').addEventListener('click', () => openBanModal('', '1h', false));
    byId('bans-refresh').addEventListener('click', () => bansTable.refresh());

    byId('ban-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn) return;
        const { action, client } = btn.dataset;
        if (action === 'edit') {
            const mins = Math.max(1, Math.ceil((Number(btn.dataset.untilMs) - Date.now()) / 60000));
            openBanModal(client, mins + 'm', btn.dataset.permanent === '1');
            return;
        }
        if (action !== 'unban') return;
        if (!window.confirm(`Unban ${client}? Their offense history is forgotten.`)) return;
        btn.disabled = true;
        try {
            await api('DELETE', '/api/bans?client=' + encodeURIComponent(client));
            toast(`${client} unbanned.`);
        } catch (err) {
            toast(err.message, 'danger');
        } finally {
            bansTable.refresh();
            refreshOverview();
        }
    });

    // ── Visitors ───────────────────────────────────────────────────────────
    const visitorsTable = new LiveTable({
        name: 'visitors', url: '/api/frag/visitors', tbody: 'visitors-rows', pager: 'visitors-pager',
        summary: 'visitors-summary', liveSwitch: 'visitors-live', cols: 9, flash: true, goneLabel: 'forgotten',
        params: () => {
            const p = { q: byId('visitors-filter').value.trim() };
            if (byId('visitors-flagged').checked) p.flagged = '1';
            return p;
        },
        empty: () => (byId('visitors-filter').value.trim() || byId('visitors-flagged').checked
            ? 'No clients match.' : 'No requests recorded yet.'),
    });
    const visitorDetails = new DetailRows(visitorsTable, 9,
        (key, page) => `/api/frag/visitor?client=${encodeURIComponent(key)}&page=${page}`);

    byId('visitors-filter').addEventListener('input', debounce(() => visitorsTable.go(1), 300));
    byId('visitors-flagged').addEventListener('change', () => visitorsTable.go(1));
    byId('visitors-refresh').addEventListener('click', () => visitorsTable.refresh());

    byId('visitors-rows').addEventListener('click', (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn || btn.disabled) return;
        const { action } = btn.dataset;
        if (action === 'detail-page') {
            const det = btn.closest('tr[data-detail-for]');
            if (det) visitorDetails.page(det.dataset.detailFor, Number(btn.dataset.page));
            return;
        }
        const row = btn.closest('tr[data-key]');
        if (!row) return;
        if (action === 'toggle') visitorDetails.toggle(row.dataset.key);
        if (action === 'ban') openBanModal('', '1h', false, btn.dataset.client);
    });

    // ── Ban log ────────────────────────────────────────────────────────────
    const banlogTable = new LiveTable({
        name: 'banlog', url: '/api/frag/banlog', tbody: 'banlog-rows', pager: 'banlog-pager',
        summary: 'banlog-summary', liveSwitch: 'banlog-live', cols: 8, flash: true, goneLabel: 'gone',
        params: () => ({ q: byId('banlog-filter').value.trim() }),
        empty: () => (byId('banlog-filter').value.trim() ? 'No bans match the filter.' : 'No bans recorded.'),
    });
    const banlogDetails = new DetailRows(banlogTable, 8, (key) => `/api/frag/ban?id=${encodeURIComponent(key)}`);

    byId('banlog-filter').addEventListener('input', debounce(() => banlogTable.go(1), 300));
    byId('banlog-refresh').addEventListener('click', () => banlogTable.refresh());

    byId('banlog-rows').addEventListener('click', (ev) => {
        const btn = ev.target.closest('button[data-action="toggle"]');
        if (!btn) return;
        const row = btn.closest('tr[data-key]');
        if (row) banlogDetails.toggle(row.dataset.key);
    });

    // ── Settings ───────────────────────────────────────────────────────────
    const SOURCE_BADGES = {
        default: ['text-bg-light border', 'default', 'Built-in default'],
        env: ['text-bg-info', 'env', 'From the environment variable'],
        flag: ['text-bg-primary', 'flag', 'From the command-line flag'],
        file: ['text-bg-success', 'saved', 'Saved in settings.json; overrides flag and environment'],
    };
    let settingsData = null;

    // Address checks for the list editors. They mirror what the server's
    // netip parsing accepts closely enough to catch typos as they are
    // typed; the server validates every value again before saving.
    function validIPv4(s) {
        const p = s.split('.');
        return p.length === 4 && p.every((x) => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255);
    }

    function validIPv6(s) {
        if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
        try {
            new URL('http://[' + s + ']/');
            return true;
        } catch {
            return false;
        }
    }

    // List settings. A setting the server marks with a list kind is still one
    // comma-separated string on the server; here it is edited as one input per
    // entry, with a remove button on each and an add box below. Entries are
    // checked as they are typed and joined with "," when saved. norm, when
    // present, is what two entries must differ in to not be duplicates.
    const LIST_RULES = {
        path: {
            placeholder: 'Add a path, e.g. /.env or /static/*',
            noun: ['path', 'paths'],
            check(v) {
                if (!v.startsWith('/')) return `${v} must start with /.`;
                if (/[\s,]/.test(v)) return 'One path per box: no spaces or commas.';
                if (v === '/*') return '"/*" would capture every path.';
                return '';
            },
        },
        cidr: {
            placeholder: 'Add an address or range, e.g. 203.0.113.9 or 10.0.0.0/8',
            noun: ['address or range', 'addresses or ranges'],
            check(v) {
                if (/[\s,]/.test(v)) return 'One address or range per box: no spaces or commas.';
                const parts = v.split('/');
                if (parts.length > 2) return `${v} is not an address or CIDR range.`;
                const [addr, bits] = parts;
                const v4 = validIPv4(addr);
                if (!v4 && !validIPv6(addr)) return `${addr} is not an IPv4 or IPv6 address.`;
                if (bits !== undefined) {
                    const max = v4 ? 32 : 128;
                    if (!/^(0|[1-9]\d{0,2})$/.test(bits) || Number(bits) > max) {
                        return `/${bits} is not a valid prefix length for IPv${v4 ? 4 : 6} (0–${max}).`;
                    }
                }
                return '';
            },
        },
        host: {
            placeholder: 'Add a hostname, e.g. example.com',
            noun: ['hostname', 'hostnames'],
            norm: (v) => v.toLowerCase().replace(/\.$/, ''),
            check(v) {
                if (/[\s,]/.test(v)) return 'One hostname per box: no spaces or commas.';
                const h = v.toLowerCase().replace(/\.$/, '');
                if (/[/:*@]/.test(h)) return `${v}: list a bare hostname such as example.com, without scheme, port or wildcard.`;
                if (validIPv4(h)) return `${v}: certificates are issued for hostnames, not IP addresses.`;
                if (!h.includes('.')) return `${v} is not a fully qualified hostname.`;
                if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h)) return `${v} is not a valid hostname.`;
                return '';
            },
        },
    };

    function splitList(s) {
        return String(s === null || s === undefined ? '' : s)
            .split(',').map((x) => x.trim()).filter(Boolean);
    }

    function listButton(action, cls, icon, label) {
        const b = node('button', 'btn ' + cls);
        b.type = 'button';
        b.title = label;
        b.setAttribute('aria-label', label);
        b.dataset.listAction = action;
        b.append(node('i', 'bi ' + icon));
        return b;
    }

    function listTextInput() {
        const input = node('input', 'form-control font-monospace');
        input.type = 'text';
        input.autocomplete = 'off';
        input.spellcheck = false;
        return input;
    }

    // listItem is one existing entry: remove button, then its input.
    function listItem(value) {
        const row = node('div', 'input-group input-group-sm has-validation setting-list-item');
        const input = listTextInput();
        input.value = value;
        input.dataset.listItem = '';
        input.setAttribute('aria-label', 'Entry');
        row.append(listButton('remove', 'btn-outline-danger', 'bi-dash-lg', 'Remove this entry'), input,
            node('div', 'invalid-feedback'));
        return row;
    }

    function listInput(s) {
        const rule = LIST_RULES[s.list];
        const box = node('div', 'setting-list d-grid gap-1');
        box.dataset.key = s.key;
        box.dataset.kind = 'list';
        box.dataset.list = s.list;
        box.dataset.label = s.label;

        const items = node('div', 'setting-list-items d-grid gap-1');
        splitList(s.value).forEach((v) => items.append(listItem(v)));
        box.append(items);

        const addRow = node('div', 'input-group input-group-sm has-validation setting-list-new');
        const pending = listTextInput();
        pending.id = 'set-' + s.key;
        pending.placeholder = rule.placeholder;
        pending.dataset.listNew = '';
        pending.setAttribute('aria-label', 'New entry for ' + s.label);
        addRow.append(pending, listButton('add', 'btn-outline-primary', 'bi-plus-lg', 'Add entry'),
            node('div', 'invalid-feedback'));
        box.append(addRow);
        box.append(node('div', 'form-text setting-list-count'));

        box.dataset.original = inputValue(box);
        if (s.restart) {
            box.dataset.locked = '1';
            box.querySelectorAll('input, button').forEach((el) => { el.disabled = true; });
            box.title = `Set ${s.env} in concert.env and restart concert to change this.`;
        }
        validateList(box);
        return box;
    }

    // listParts is every entry in a list editor, in order: the existing
    // entries, then whatever is still typed in the add box (split on commas,
    // so a pasted list counts as several entries).
    function listParts(box) {
        const parts = [];
        box.querySelectorAll('[data-list-item]').forEach((input) => {
            const v = input.value.trim();
            if (v) parts.push({ input, value: v });
        });
        const pending = box.querySelector('[data-list-new]');
        if (pending) splitList(pending.value).forEach((v) => parts.push({ input: pending, value: v }));
        return parts;
    }

    // validateList marks each invalid or duplicated entry and returns the
    // first problem, or '' when the list is valid.
    function validateList(box) {
        const rule = LIST_RULES[box.dataset.list];
        const errors = new Map();
        const seen = new Set();
        for (const p of listParts(box)) {
            let msg = rule.check(p.value);
            const key = rule.norm ? rule.norm(p.value) : p.value;
            if (!msg && seen.has(key)) msg = `${p.value} is already listed.`;
            seen.add(key);
            if (msg && !errors.has(p.input)) errors.set(p.input, msg);
        }
        box.querySelectorAll('[data-list-item], [data-list-new]').forEach((input) => {
            const msg = errors.get(input) || '';
            input.classList.toggle('is-invalid', Boolean(msg));
            input.setAttribute('aria-invalid', msg ? 'true' : 'false');
            const fb = input.parentElement.querySelector('.invalid-feedback');
            if (fb) fb.textContent = msg;
        });
        const n = box.querySelectorAll('[data-list-item]').length;
        const [one, many] = rule.noun;
        setListCount(box, n ? `${n} ${n === 1 ? one : many}` : `No ${many} yet: add one below.`);
        return errors.size ? [...errors.values()][0] : '';
    }

    function setListCount(box, text) {
        const el = box.querySelector('.setting-list-count');
        if (el) el.textContent = text;
    }

    // addListEntries moves what is typed in the add box into the list, as
    // one entry per comma-separated value, if every value is valid.
    function addListEntries(box) {
        const pending = box.querySelector('[data-list-new]');
        const values = splitList(pending.value);
        if (!values.length) {
            pending.value = '';
            pending.focus();
            return;
        }
        validateList(box);
        if (pending.classList.contains('is-invalid')) {
            pending.focus();
            return;
        }
        const items = box.querySelector('.setting-list-items');
        values.forEach((v) => items.append(listItem(v)));
        pending.value = '';
        validateList(box);
        updateDirty();
        pending.focus();
    }

    function removeListRow(row, focusPrevious) {
        const box = row.closest('.setting-list');
        const sibling = focusPrevious ? row.previousElementSibling : row.nextElementSibling;
        const target = sibling ? sibling.querySelector('input') : box.querySelector('[data-list-new]');
        row.remove();
        validateList(box);
        updateDirty();
        if (target) target.focus();
    }

    function settingInput(s) {
        if (s.list && LIST_RULES[s.list]) return listInput(s);
        const id = 'set-' + s.key;
        let wrap;
        let input;
        if (s.kind === 'bool') {
            wrap = node('div', 'form-check form-switch mt-1');
            input = node('input', 'form-check-input');
            input.type = 'checkbox';
            input.setAttribute('role', 'switch');
            input.checked = s.value === true;
            wrap.append(input);
        } else {
            const mono = s.kind === 'string' || s.kind === 'duration' ? ' font-monospace' : '';
            input = node('input', 'form-control form-control-sm' + mono);
            if (s.kind === 'int') { input.type = 'number'; input.step = '1'; }
            else if (s.kind === 'float') { input.type = 'number'; input.step = 'any'; }
            else input.type = 'text';
            if (s.kind === 'duration') input.placeholder = 'e.g. 30s, 5m, 24h';
            input.value = s.value === null || s.value === undefined ? '' : String(s.value);
            wrap = input;
        }
        input.id = id;
        input.dataset.key = s.key;
        input.dataset.kind = s.kind;
        input.dataset.label = s.label;
        input.dataset.original = inputValue(input);
        if (s.restart) {
            input.disabled = true;
            input.title = `Set ${s.env} in concert.env and restart concert to change this.`;
        }
        return wrap;
    }

    function inputValue(input) {
        if (input.dataset.kind === 'list') return listParts(input).map((p) => p.value).join(',');
        return input.dataset.kind === 'bool' ? String(input.checked) : input.value.trim();
    }

    function typedValue(input) {
        const label = input.dataset.label;
        if (input.dataset.kind === 'list') {
            const problem = validateList(input);
            if (problem) throw new Error(`${label}: ${problem}`);
            return inputValue(input);
        }
        const raw = inputValue(input);
        switch (input.dataset.kind) {
            case 'bool':
                return input.checked;
            case 'int': {
                const n = Number(raw);
                if (raw === '' || !Number.isInteger(n)) throw new Error(`${label} must be a whole number.`);
                return n;
            }
            case 'float': {
                const n = Number(raw);
                if (raw === '' || !Number.isFinite(n)) throw new Error(`${label} must be a number.`);
                return n;
            }
            default:
                return raw;
        }
    }

    // settingRow stacks a setting's description above its input: the label,
    // where its value comes from and the reset button on top, then the help
    // text, flag and variable, then the input across the full column.
    function settingRow(s) {
        const row = node('div', 'py-3 border-top setting-row');
        row.dataset.search = [s.label, s.key, s.flag, s.env, s.help].join(' ').toLowerCase();

        const head = node('div', 'd-flex align-items-start gap-2');
        const info = node('div', 'setting-info flex-grow-1');
        const title = node('div', 'd-flex flex-wrap align-items-center gap-2');
        const label = node('label', 'form-label mb-0 fw-semibold', s.label);
        label.htmlFor = 'set-' + s.key;
        title.append(label);
        const [cls, text, tip] = SOURCE_BADGES[s.source] || SOURCE_BADGES.default;
        const src = node('span', 'badge ' + cls, text);
        src.title = tip;
        title.append(src);
        if (s.restart) {
            const r = node('span', 'badge bg-warning-subtle text-warning-emphasis border border-warning-subtle', 'restart');
            r.title = 'Changed only in concert.env; applies when concert restarts';
            title.append(r);
        }
        info.append(title);
        info.append(node('div', 'form-text mt-1', s.help));
        info.append(node('div', 'form-text font-monospace', '-' + s.flag + ' · ' + s.env));
        head.append(info);
        if (s.source === 'file') {
            head.append(iconButton('reset', 'btn-sm btn-outline-secondary flex-shrink-0', 'bi-arrow-counterclockwise',
                'Reset: remove from settings.json', { key: s.key }));
        }

        const input = node('div', 'setting-input mt-2');
        input.append(settingInput(s));
        row.append(head, input);
        return row;
    }

    function groupId(name) {
        return 'settings-group-' + String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    }

    function renderSettings(d) {
        settingsData = d;
        const groups = byId('settings-groups');
        groups.replaceChildren();
        const bodies = new Map();
        for (const s of d.settings) {
            let body = bodies.get(s.group);
            if (!body) {
                const card = node('section', 'card stat-card settings-group');
                card.id = groupId(s.group);
                card.dataset.group = s.group;
                body = node('div', 'card-body');
                const h = node('h2', 'h6 mb-2', s.group);
                h.id = card.id + '-title';
                card.setAttribute('aria-labelledby', h.id);
                body.append(h);
                card.append(body);
                groups.append(card);
                bodies.set(s.group, body);
            }
            body.append(settingRow(s));
        }
        renderSettingsNav();

        const dl = byId('settings-fixed');
        dl.replaceChildren();
        Object.keys(d.fixed).sort().forEach((k) => {
            dl.append(node('dt', 'col-sm-5 text-body-secondary fw-normal', k));
            dl.append(node('dd', 'col-sm-7 font-monospace text-break', d.fixed[k]));
        });
        setText('settings-file', d.persisted ? d.file : 'not saved (-data-dir is empty)');
        byId('settings-unsaved').classList.toggle('d-none', d.persisted);
        updateDirty();
        applySettingsFilter();
    }

    // ── Settings: section navigation ───────────────────────────────────────
    // One pill per settings card, in page order. The pill for the card at
    // the top of the viewport is highlighted as the page scrolls; clicking a
    // pill scrolls to its card. Each pill shows how many settings its card
    // lists (after the filter) and a dot while the card has unsaved changes.
    let spyActive = '';
    let spyFrame = 0;
    let spyPinned = false;
    let spyPinTimer = 0;

    function navLinkFor(cardId) {
        return document.querySelector(`#settings-nav a[data-target="${cardId}"]`);
    }

    function renderSettingsNav() {
        const nav = byId('settings-nav');
        if (!nav) return;
        const links = [...document.querySelectorAll('#settings-groups .settings-group')].map((card) => {
            const a = node('a', 'nav-link');
            a.href = '#' + card.id;
            a.dataset.target = card.id;
            a.append(node('span', 'settings-nav-label text-truncate', card.dataset.group));
            const meta = node('span', 'd-flex align-items-center gap-1 flex-shrink-0');
            const dot = node('span', 'settings-nav-dot');
            dot.setAttribute('aria-hidden', 'true');
            meta.append(dot, node('span', 'settings-nav-count'));
            a.append(meta);
            return a;
        });
        nav.replaceChildren(...links);
        spyActive = '';
    }

    function stickyOffset() {
        const bar = document.querySelector('.navbar.sticky-top');
        return bar ? bar.getBoundingClientRect().height : 0;
    }

    function setSpyActive(id) {
        if (id === spyActive) return;
        spyActive = id;
        const nav = byId('settings-nav');
        if (!nav) return;
        nav.querySelectorAll('a[data-target]').forEach((a) => {
            const on = a.dataset.target === id;
            a.classList.toggle('active', on);
            if (on) a.setAttribute('aria-current', 'true');
            else a.removeAttribute('aria-current');
        });
        // In the horizontal layout, keep the active pill in view without
        // scrolling the page itself.
        const active = nav.querySelector('a.active');
        if (active && nav.scrollWidth > nav.clientWidth) {
            nav.scrollLeft = active.offsetLeft - nav.clientWidth / 2 + active.offsetWidth / 2;
        }
    }

    function updateSpy() {
        spyFrame = 0;
        if (spyPinned || activeTab() !== 'tab-settings') return;
        const cards = [...document.querySelectorAll('#settings-groups .settings-group:not(.d-none)')];
        if (!cards.length) { setSpyActive(''); return; }
        const line = stickyOffset() + 32;
        let current = cards[0];
        for (const c of cards) {
            if (c.getBoundingClientRect().top <= line) current = c;
            else break;
        }
        // At the bottom of the page the last cards can never reach the top.
        const doc = document.documentElement;
        if (window.scrollY > 0 && window.innerHeight + window.scrollY >= doc.scrollHeight - 2) {
            current = cards[cards.length - 1];
        }
        setSpyActive(current.id);
    }

    function scheduleSpy() {
        if (!spyFrame) spyFrame = requestAnimationFrame(updateSpy);
    }

    // pinSpy keeps a clicked pill highlighted while the page scrolls to its
    // card, so the pills it passes do not flicker on the way.
    function pinSpy(id) {
        setSpyActive(id);
        spyPinned = true;
        clearTimeout(spyPinTimer);
        spyPinTimer = setTimeout(() => { spyPinned = false; }, 900);
    }

    window.addEventListener('scroll', () => {
        if (spyPinned) {
            clearTimeout(spyPinTimer);
            spyPinTimer = setTimeout(() => { spyPinned = false; }, 200);
            return;
        }
        scheduleSpy();
    }, { passive: true });
    window.addEventListener('resize', scheduleSpy);

    byId('settings-nav').addEventListener('click', (ev) => {
        const a = ev.target.closest('a[data-target]');
        if (!a) return;
        ev.preventDefault();
        const card = byId(a.dataset.target);
        if (!card) return;
        pinSpy(card.id);
        const top = card.getBoundingClientRect().top + window.scrollY - stickyOffset() - 12;
        window.scrollTo({ top: Math.max(0, top), behavior: reduceMotion ? 'auto' : 'smooth' });
        const heading = card.querySelector('h2');
        if (heading) {
            heading.tabIndex = -1;
            heading.focus({ preventScroll: true });
        }
    });

    function changedInputs() {
        return [...document.querySelectorAll('#settings-groups [data-original]')]
            .filter((i) => !i.disabled && i.dataset.locked !== '1' && inputValue(i) !== i.dataset.original);
    }

    function updateDirty() {
        const changed = changedInputs();
        document.querySelectorAll('.setting-row.setting-changed').forEach((r) => r.classList.remove('setting-changed'));
        changed.forEach((i) => i.closest('.setting-row').classList.add('setting-changed'));
        const n = changed.length;
        byId('settings-apply').disabled = n === 0;
        byId('settings-discard').disabled = n === 0;
        setText('settings-apply-label', n ? `Save ${plural(n, 'change')}` : 'Save changes');
        document.querySelectorAll('#settings-groups .settings-group').forEach((card) => {
            const a = navLinkFor(card.id);
            if (!a) return;
            const c = card.querySelectorAll('.setting-row.setting-changed').length;
            a.classList.toggle('settings-nav-changed', c > 0);
            a.title = c ? `${plural(c, 'unsaved change')} in ${card.dataset.group}` : card.dataset.group;
        });
    }

    function applySettingsFilter() {
        const f = byId('settings-filter').value.trim().toLowerCase();
        document.querySelectorAll('.settings-group').forEach((card) => {
            let visible = 0;
            card.querySelectorAll('.setting-row').forEach((r) => {
                const show = !f || r.dataset.search.includes(f);
                r.classList.toggle('d-none', !show);
                if (show) visible++;
            });
            card.classList.toggle('d-none', visible === 0);
            const a = navLinkFor(card.id);
            if (a) {
                a.classList.toggle('d-none', visible === 0);
                const count = a.querySelector('.settings-nav-count');
                if (count) count.textContent = String(visible);
            }
        });
        scheduleSpy();
    }

    async function loadSettings() {
        // Never clobber edits the operator hasn't saved yet.
        if (settingsData && changedInputs().length) return;
        try {
            renderSettings(await api('GET', '/api/settings'));
        } catch (err) {
            toast(err.message, 'danger');
        }
    }

    // listenURL turns a listen address such as ":8081" or "0.0.0.0:8081" into
    // a URL on the host this page was loaded from.
    function listenURL(addr) {
        const i = addr.lastIndexOf(':');
        let host = addr.slice(0, i);
        const port = addr.slice(i + 1);
        if (host === '' || host === '0.0.0.0' || host === '[::]' || host === '::') host = window.location.hostname;
        if (host.includes(':') && !host.startsWith('[')) host = '[' + host + ']';
        return `${window.location.protocol}//${host}:${port}/`;
    }

    // showPortalMoved replaces the dashboard's live updates with a pointer to
    // the portal's new address: this page's address stops answering.
    function showPortalMoved(addr) {
        portalMoved = true;
        const box = byId('portal-moved');
        box.replaceChildren();
        box.append(node('i', 'bi bi-signpost-split'), ' ');
        if (addr) {
            const url = listenURL(addr);
            box.append('The portal moved to ');
            const link = node('a', 'alert-link font-monospace', url);
            link.href = url;
            box.append(link, '. This page no longer updates; open the new address to continue (you may need to sign in again).');
        } else {
            box.append('The portal is now off. To turn it back on, set portal_listen in settings.json (or remove it there) and restart concert.');
        }
        box.classList.remove('d-none');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    byId('settings-groups').addEventListener('input', (ev) => {
        const box = ev.target.closest && ev.target.closest('.setting-list');
        if (box) validateList(box);
        updateDirty();
    });
    byId('settings-groups').addEventListener('change', updateDirty);
    byId('settings-filter').addEventListener('input', applySettingsFilter);
    byId('settings-discard').addEventListener('click', () => { if (settingsData) renderSettings(settingsData); });

    // List editors: the add (+) and remove (−) buttons.
    byId('settings-groups').addEventListener('click', (ev) => {
        const btn = ev.target.closest('button[data-list-action]');
        if (!btn || btn.disabled) return;
        if (btn.dataset.listAction === 'add') addListEntries(btn.closest('.setting-list'));
        else removeListRow(btn.closest('.setting-list-item'), false);
    });

    // List editors, from the keyboard. In the add box, Enter adds and Escape
    // clears. In an entry, Enter moves to the next one (never submitting the
    // form) and Backspace in an empty entry removes it.
    byId('settings-groups').addEventListener('keydown', (ev) => {
        const input = ev.target;
        if (!input.matches || !input.closest('.setting-list')) return;
        const box = input.closest('.setting-list');
        if (input.matches('[data-list-new]')) {
            if (ev.key === 'Enter') {
                ev.preventDefault();
                addListEntries(box);
            } else if (ev.key === 'Escape' && input.value) {
                ev.preventDefault();
                input.value = '';
                validateList(box);
                updateDirty();
            }
            return;
        }
        if (!input.matches('[data-list-item]')) return;
        const row = input.closest('.setting-list-item');
        if (ev.key === 'Enter') {
            ev.preventDefault();
            const next = row.nextElementSibling;
            (next ? next.querySelector('input') : box.querySelector('[data-list-new]')).focus();
        } else if (ev.key === 'Backspace' && input.value === '') {
            ev.preventDefault();
            removeListRow(row, true);
        }
    });

    // Leaving an entry tidies it: surrounding spaces go, and an emptied
    // entry is removed.
    byId('settings-groups').addEventListener('focusout', (ev) => {
        const input = ev.target;
        if (!input.matches || !input.matches('[data-list-item]')) return;
        const row = input.closest('.setting-list-item');
        const box = input.closest('.setting-list');
        if (!row || !box) return; // already removed
        const trimmed = input.value.trim();
        if (trimmed !== input.value) input.value = trimmed;
        if (!trimmed) {
            row.remove();
            validateList(box);
            updateDirty();
        }
    });

    byId('settings-groups').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action="reset"]');
        if (!btn) return;
        const s = settingsData.settings.find((x) => x.key === btn.dataset.key);
        if (!window.confirm(`Reset "${s.label}"? It is removed from settings.json and follows the flag, environment or default again, starting now.`)) return;
        btn.disabled = true;
        try {
            const d = await api('DELETE', '/api/settings?key=' + encodeURIComponent(s.key));
            if (s.key === 'portal_listen') {
                const now = d.settings.find((x) => x.key === 'portal_listen');
                if (now && now.value !== s.value) { showPortalMoved(now.value); return; }
            }
            renderSettings(d);
            toast(`${s.label} reset and applied.`);
            refreshOverview();
        } catch (err) {
            btn.disabled = false;
            toast(err.message, 'danger');
        }
    });

    byId('settings-form').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const changed = changedInputs();
        if (!changed.length) return;
        const body = {};
        try {
            for (const i of changed) body[i.dataset.key] = typedValue(i);
        } catch (err) {
            toast(err.message, 'danger');
            const bad = document.querySelector('#settings-groups .is-invalid');
            if (bad) bad.focus();
            return;
        }
        const portalChange = 'portal_listen' in body;
        if (portalChange && body.portal_listen === '' && !window.confirm(
            'Turn the admin portal off? You will not be able to turn it back on from here: '
            + 'that takes editing settings.json and restarting concert.')) return;

        const btn = byId('settings-apply');
        btn.disabled = true;
        try {
            const d = await api('POST', '/api/settings', body);
            if (portalChange) {
                showPortalMoved(body.portal_listen);
                return;
            }
            renderSettings(d);
            toast('listen' in body
                ? `Saved. The main listener moved to ${body.listen}; open connections finish on the old address.`
                : 'Settings saved and applied.');
            refreshOverview();
        } catch (err) {
            toast(err.message, 'danger');
            updateDirty();
        }
    });

    // ── Email delivery ─────────────────────────────────────────────────────
    let emailState = null;

    function selectOrCustom(selectEl, customEl, val) {
        const str = String(val);
        const hasOption = [...selectEl.options].some((o) => o.value === str);
        if (hasOption) {
            selectEl.value = str;
            customEl.classList.add('d-none');
            customEl.value = str;
        } else {
            selectEl.value = 'custom';
            customEl.classList.remove('d-none');
            customEl.value = str;
        }
    }

    function readSelectOrCustom(selectEl, customEl) {
        return selectEl.value === 'custom' ? Number(customEl.value) : Number(selectEl.value);
    }

    function syncEmailProviderFields() {
        const prov = byId('email-provider').value;
        byId('email-smtp-fields').classList.toggle('d-none', prov !== 'smtp');
        byId('email-resend-fields').classList.toggle('d-none', prov !== 'resend');
        byId('email-sendpanda-fields').classList.toggle('d-none', prov !== 'sendpanda');
    }

    function updateCadencePreview() {
        const maxEl = byId('email-cadence-max-select');
        const maxCust = byId('email-cadence-max-custom');
        const winEl = byId('email-cadence-window-select');
        const winCust = byId('email-cadence-window-custom');
        const unitEl = byId('email-cadence-unit');
        const prev = byId('email-cadence-preview');
        if (!maxEl || !prev) return;

        maxCust.classList.toggle('d-none', maxEl.value !== 'custom');
        winCust.classList.toggle('d-none', winEl.value !== 'custom');

        const maxN = readSelectOrCustom(maxEl, maxCust);
        const winV = readSelectOrCustom(winEl, winCust);
        const unit = unitEl.value;
        const mult = unit === 'days' ? 86400 : unit === 'hours' ? 3600 : 60;
        const winSec = winV * mult;

        prev.classList.remove('text-danger', 'text-body-secondary');
        if (!Number.isInteger(maxN) || maxN < 1 || maxN > 1000) {
            prev.classList.add('text-danger');
            prev.textContent = 'Email count must be a whole number between 1 and 1000.';
            return;
        }
        if (!Number.isInteger(winV) || winV < 1 || winSec < 900 || winSec > 30 * 86400) {
            prev.classList.add('text-danger');
            prev.textContent = 'Window must be between 15 minutes and 30 days.';
            return;
        }
        const paceSec = Math.floor(winSec / maxN);
        if (paceSec < 60) {
            prev.classList.add('text-danger');
            prev.textContent = `Schedule paces faster than 1 email/minute (${fmtSeconds(paceSec)}). Reduce count or lengthen window.`;
            return;
        }
        const uLabel = winV === 1 ? unit.replace(/s$/, '') : unit;
        prev.classList.add('text-body-secondary');
        prev.textContent = `Enforced schedule: send ${plural(maxN, 'email')} every ${winV} ${uLabel} · paced 1 digest per ${fmtSeconds(paceSec)} · rolling cap ${maxN} per ${fmtSeconds(winSec)}.`;
    }

    function applySecretBadge(badgeId, clearId, source, canClear) {
        const b = byId(badgeId);
        const btn = byId(clearId);
        if (!b) return;
        b.className = 'badge border';
        if (source === 'env') {
            b.classList.add('text-bg-info');
            b.textContent = 'env override';
        } else if (source === 'encrypted_file') {
            b.classList.add('text-bg-success');
            b.textContent = 'encrypted file';
        } else {
            b.classList.add('text-bg-light');
            b.textContent = 'not set';
        }
        if (btn) btn.classList.toggle('d-none', !(source === 'encrypted_file' && canClear));
    }

    function renderEmailStatus(d) {
        emailState = d;
        const st = d.status || {};
        const sec = st.secrets || {};
        const ro = Boolean(d.read_only_settings);

        byId('email-readonly-alert').classList.toggle('d-none', !ro);
        byId('email-paused-alert').classList.toggle('d-none', !st.paused);

        const noteEl = byId('email-secret-note');
        if (sec.load_error) {
            noteEl.textContent = 'Secret vault warning: ' + sec.load_error;
            noteEl.className = 'alert alert-danger';
        } else if (!sec.can_persist && sec.persist_note) {
            noteEl.textContent = sec.persist_note;
            noteEl.className = 'alert alert-info';
        } else {
            noteEl.className = 'alert alert-info d-none';
            noteEl.textContent = '';
        }

        const badge = byId('email-provider-badge');
        badge.className = 'badge';
        if (!st.enabled) {
            badge.classList.add('text-bg-secondary');
            badge.textContent = 'Disabled';
        } else if (st.paused) {
            badge.classList.add('text-bg-warning');
            badge.textContent = String(st.provider || '').toUpperCase() + ' · Paused';
        } else {
            badge.classList.add('text-bg-success');
            badge.textContent = String(st.provider || '').toUpperCase() + ' · Active';
        }

        const canClear = !ro && Boolean(sec.can_persist);
        applySecretBadge('email-badge-smtp-pass', 'email-clear-smtp-pass', sec.smtp_pass, canClear);
        applySecretBadge('email-badge-resend-key', 'email-clear-resend-key', sec.resend_api_key, canClear);
        applySecretBadge('email-badge-sendpanda-key', 'email-clear-sendpanda-key', sec.sendpanda_api_key, canClear);

        const maxE = (st.cadence && st.cadence.max_emails) || 1;
        const sentInWin = st.sent_in_window || 0;
        setText('email-budget-text', `${sentInWin} / ${maxE} sent (${st.cadence_text || ''})`);
        setBar('email-budget-bar', sentInWin, maxE);

        if (!st.enabled) {
            setText('email-next-send', 'disabled');
        } else if (st.paused) {
            setText('email-next-send', 'paused');
        } else if (st.backoff_until) {
            setText('email-next-send', 'backoff until ' + fmtTime(st.backoff_until));
        } else if (st.next_eligible_at) {
            setText('email-next-send', fmtTime(st.next_eligible_at));
        } else {
            setText('email-next-send', st.queued_total > 0 ? 'due on next tick' : 'ready (queue empty)');
        }

        const qText = st.overflow_count > 0
            ? `${fmtNum(st.queued_total)} total (${fmtNum(st.queued_unique)} unique + ${fmtNum(st.overflow_count)} overflow)`
            : `${fmtNum(st.queued_total)} total (${fmtNum(st.queued_unique)} unique)`;
        setText('email-queued-summary', qText);
        setText('email-totals', `${fmtNum(st.sent_total || 0)} / ${fmtNum(st.error_total || 0)}`);
        setText('email-queue-count', fmtNum(st.queued_total || 0));

        const ld = st.last_delivery;
        if (!ld) {
            setText('email-last-delivery', 'none yet');
        } else if (ld.error) {
            setText('email-last-delivery', `${fmtTime(ld.at)} · error: ${ld.error}`);
        } else {
            setText('email-last-delivery', `${fmtTime(ld.at)} · ${ld.event_count} event(s) to ${ld.recipients} recipient(s)`);
        }

        const pauseBtn = byId('email-pause-btn');
        pauseBtn.replaceChildren(
            node('i', st.paused ? 'bi bi-play-fill' : 'bi bi-pause-fill'),
            document.createTextNode(st.paused ? ' Resume' : ' Pause')
        );
        pauseBtn.classList.toggle('btn-outline-success', Boolean(st.paused));
        pauseBtn.classList.toggle('btn-outline-warning', !st.paused);

        // Unsubscribed recipients
        const unsubWrap = byId('email-unsubscribed-wrap');
        const unsubList = byId('email-unsubscribed-list');
        const unsubEntries = Object.entries(st.unsubscribed || {});
        unsubList.replaceChildren();
        unsubWrap.classList.toggle('d-none', unsubEntries.length === 0);
        for (const [rcpt, since] of unsubEntries) {
            const li = node('li', 'list-group-item d-flex align-items-center justify-content-between px-0 py-1');
            const left = node('div');
            left.append(node('span', 'font-monospace', rcpt), node('span', 'text-body-secondary ms-2', 'since ' + fmtTime(since)));
            const btn = node('button', 'btn btn-sm btn-outline-success', 'Re-enable');
            btn.type = 'button';
            btn.dataset.action = 'resubscribe';
            btn.dataset.recipient = rcpt;
            li.append(left, btn);
            unsubList.append(li);
        }

        // Pending events table
        const tbody = byId('email-queue-rows');
        tbody.replaceChildren();
        const pending = st.pending || [];
        if (pending.length === 0) {
            tbody.append(emptyRowEl(3, st.enabled ? 'No pending events queued.' : 'Select a provider and save to begin queuing runtime events.'));
        } else {
            for (const ev of pending) {
                const tr = node('tr');
                const tdSev = node('td');
                const sevCls = ev.severity === 'critical' ? 'text-bg-danger' : ev.severity === 'warn' ? 'text-bg-warning' : 'text-bg-info';
                tdSev.append(
                    node('span', 'badge ' + sevCls + ' text-uppercase me-1', ev.severity || 'info'),
                    node('span', 'badge text-bg-light border text-uppercase', ev.category || '')
                );
                const tdInfo = node('td');
                tdInfo.append(
                    node('div', 'fw-semibold small', ev.title || ''),
                    node('div', 'small text-body-secondary', ev.summary || ''),
                    node('div', 'small text-body-secondary', 'Last seen: ' + fmtTime(ev.last_at))
                );
                const tdCnt = node('td', 'text-end fw-semibold', '×' + fmtNum(ev.count || 1));
                tr.append(tdSev, tdInfo, tdCnt);
                tbody.append(tr);
            }
        }
    }

    function populateEmailForm(d) {
        const c = d.config || {};
        byId('email-provider').value = c.provider || '';
        byId('email-smtp-host').value = c.smtp_host || '';
        byId('email-smtp-port').value = c.smtp_port || 587;
        byId('email-smtp-tls').value = c.smtp_tls || 'starttls';
        byId('email-smtp-user').value = c.smtp_user || '';
        byId('email-smtp-pass').value = '';
        byId('email-resend-key').value = '';
        byId('email-resend-url').value = c.resend_base_url || '';
        byId('email-sendpanda-key').value = '';
        byId('email-sendpanda-url').value = c.sendpanda_base_url || '';
        byId('email-from-name').value = c.from_name || 'Concert';
        byId('email-from-addr').value = c.from_addr || '';
        byId('email-to').value = c.to_addrs || '';
        byId('email-dkim-selector').value = c.dkim_selector || '';

        selectOrCustom(byId('email-cadence-max-select'), byId('email-cadence-max-custom'), c.cadence_max || 1);
        selectOrCustom(byId('email-cadence-window-select'), byId('email-cadence-window-custom'), c.cadence_window || 15);
        byId('email-cadence-unit').value = c.cadence_unit || 'minutes';

        const cats = c.categories || {};
        document.querySelectorAll('#email-categories input[data-cat]').forEach((cb) => {
            cb.checked = Boolean(cats[cb.dataset.cat]);
        });

        byId('email-org-name').value = c.org_name || '';
        byId('email-postal-address').value = c.postal_address || '';
        byId('email-portal-url').value = c.portal_url || '';
        byId('email-public-base-url').value = c.public_base_url || '';
        byId('email-privacy-url').value = c.privacy_url || '';
        byId('email-terms-url').value = c.terms_url || '';

        const ro = Boolean(d.read_only_settings);
        byId('email-save').disabled = ro;
        syncEmailProviderFields();
        updateCadencePreview();
        renderEmailStatus(d);
    }

    async function loadEmail(includeForm) {
        try {
            const d = await api('GET', '/api/email');
            if (includeForm) {
                populateEmailForm(d);
            } else {
                renderEmailStatus(d);
            }
        } catch (err) {
            toast('Could not load email settings: ' + err.message, 'danger');
        }
    }

    if (byId('email-form')) {
        byId('email-provider').addEventListener('change', syncEmailProviderFields);
        byId('email-smtp-tls').addEventListener('change', (ev) => {
            const port = byId('email-smtp-port');
            if (ev.target.value === 'tls' && port.value === '587') port.value = '465';
            if (ev.target.value === 'starttls' && port.value === '465') port.value = '587';
        });

        ['email-cadence-max-select', 'email-cadence-max-custom', 'email-cadence-window-select', 'email-cadence-window-custom', 'email-cadence-unit']
            .forEach((id) => {
                byId(id).addEventListener('change', updateCadencePreview);
                byId(id).addEventListener('input', updateCadencePreview);
            });

        byId('email-cadence-presets').addEventListener('click', (ev) => {
            const btn = ev.target.closest('button[data-max]');
            if (!btn) return;
            selectOrCustom(byId('email-cadence-max-select'), byId('email-cadence-max-custom'), Number(btn.dataset.max));
            selectOrCustom(byId('email-cadence-window-select'), byId('email-cadence-window-custom'), Number(btn.dataset.win));
            byId('email-cadence-unit').value = btn.dataset.unit;
            updateCadencePreview();
        });

        byId('email-reload').addEventListener('click', () => loadEmail(true));
        byId('email-refresh-btn').addEventListener('click', () => loadEmail(false));

        [
            ['email-clear-smtp-pass', 'smtp_pass', 'SMTP password'],
            ['email-clear-resend-key', 'resend_api_key', 'Resend API key'],
            ['email-clear-sendpanda-key', 'sendpanda_api_key', 'SendPanda API key'],
        ].forEach(([btnId, field, label]) => {
            byId(btnId).addEventListener('click', async () => {
                if (!window.confirm(`Remove the stored ${label} from email-secrets.json?`)) return;
                try {
                    const d = await api('DELETE', '/api/email/secrets?field=' + encodeURIComponent(field));
                    renderEmailStatus(d);
                    toast(`${label} removed from encrypted vault.`);
                } catch (err) {
                    toast(err.message, 'danger');
                }
            });
        });

        byId('email-form').addEventListener('submit', async (ev) => {
            ev.preventDefault();
            const cats = {};
            document.querySelectorAll('#email-categories input[data-cat]').forEach((cb) => {
                cats[cb.dataset.cat] = cb.checked;
            });
            const body = {
                provider: byId('email-provider').value,
                smtp_host: byId('email-smtp-host').value.trim(),
                smtp_port: Number(byId('email-smtp-port').value) || 587,
                smtp_tls: byId('email-smtp-tls').value,
                smtp_user: byId('email-smtp-user').value.trim(),
                resend_base_url: byId('email-resend-url').value.trim(),
                sendpanda_base_url: byId('email-sendpanda-url').value.trim(),
                from_name: byId('email-from-name').value.trim(),
                from_addr: byId('email-from-addr').value.trim(),
                to_addrs: byId('email-to').value.trim(),
                dkim_selector: byId('email-dkim-selector').value.trim(),
                cadence_max: readSelectOrCustom(byId('email-cadence-max-select'), byId('email-cadence-max-custom')),
                cadence_window: readSelectOrCustom(byId('email-cadence-window-select'), byId('email-cadence-window-custom')),
                cadence_unit: byId('email-cadence-unit').value,
                categories: cats,
                org_name: byId('email-org-name').value.trim(),
                postal_address: byId('email-postal-address').value.trim(),
                portal_url: byId('email-portal-url').value.trim(),
                public_base_url: byId('email-public-base-url').value.trim(),
                privacy_url: byId('email-privacy-url').value.trim(),
                terms_url: byId('email-terms-url').value.trim(),
            };
            const secrets = {};
            const smtpPass = byId('email-smtp-pass').value;
            const resendKey = byId('email-resend-key').value.trim();
            const spKey = byId('email-sendpanda-key').value.trim();
            if (smtpPass) secrets.smtp_pass = smtpPass;
            if (resendKey) secrets.resend_api_key = resendKey;
            if (spKey) secrets.sendpanda_api_key = spKey;
            if (Object.keys(secrets).length > 0) body.secrets = secrets;

            const btn = byId('email-save');
            btn.disabled = true;
            setText('email-save-status', 'Saving…');
            try {
                const d = await api('POST', '/api/email/config', body);
                populateEmailForm(d);
                setText('email-save-status', 'Saved at ' + new Date().toLocaleTimeString());
                toast('Email delivery settings saved and applied.');
                refreshOverview();
            } catch (err) {
                setText('email-save-status', '');
                toast(err.message, 'danger');
            } finally {
                btn.disabled = Boolean(emailState && emailState.read_only_settings);
            }
        });

        byId('email-verify-btn').addEventListener('click', async () => {
            const btn = byId('email-verify-btn');
            const summaryEl = byId('email-verify-summary');
            const wrapEl = byId('email-verify-wrap');
            const tbody = byId('email-verify-rows');
            btn.disabled = true;
            summaryEl.className = 'alert alert-info py-2 small';
            summaryEl.textContent = 'Checking MX, SPF, DMARC, DKIM, and live provider connection…';
            try {
                const rep = await api('POST', '/api/email/verify', {});
                summaryEl.className = 'alert py-2 small ' + (rep.ok ? 'alert-success' : 'alert-danger');
                summaryEl.textContent = rep.ok
                    ? `All required DNS & ${String(rep.provider || '').toUpperCase()} connectivity checks passed (${fmtTime(rep.checked_at)}).`
                    : `One or more DNS or connectivity checks failed (${fmtTime(rep.checked_at)}). Review details below.`;
                tbody.replaceChildren();
                for (const chk of (rep.checks || [])) {
                    const tr = node('tr');
                    const tdName = node('td');
                    tdName.append(node('div', 'fw-semibold small', chk.name));
                    if (chk.target) tdName.append(node('div', 'small font-monospace text-body-secondary text-break', chk.target));
                    const tdSt = node('td');
                    const cls = chk.status === 'pass' ? 'text-bg-success' : chk.status === 'warn' ? 'text-bg-warning' : 'text-bg-danger';
                    tdSt.append(node('span', 'badge ' + cls + ' text-uppercase', chk.status));
                    const tdRes = node('td');
                    tdRes.append(node('div', 'small', chk.summary || ''));
                    if (chk.detail) tdRes.append(node('div', 'small font-monospace text-body-secondary text-break', chk.detail));
                    tr.append(tdName, tdSt, tdRes);
                    tbody.append(tr);
                }
                wrapEl.classList.remove('d-none');
            } catch (err) {
                summaryEl.className = 'alert alert-danger py-2 small';
                summaryEl.textContent = err.message;
            } finally {
                btn.disabled = false;
            }
        });

        byId('email-test-btn').addEventListener('click', async () => {
            const btn = byId('email-test-btn');
            const resEl = byId('email-test-result');
            const to = byId('email-test-to').value.trim();
            btn.disabled = true;
            resEl.className = 'small text-body-secondary mt-2';
            resEl.textContent = 'Sending test email…';
            try {
                const res = await api('POST', '/api/email/test', { to });
                resEl.className = 'small text-success mt-2';
                resEl.textContent = `Test email accepted by ${res.provider}` + (res.message_id ? ` (id: ${res.message_id})` : '') + '.';
                toast('Test email sent successfully.');
            } catch (err) {
                resEl.className = 'small text-danger mt-2';
                resEl.textContent = 'Test email failed: ' + err.message;
                toast(err.message, 'danger');
            } finally {
                btn.disabled = false;
            }
        });

        byId('email-pause-btn').addEventListener('click', async () => {
            const pausedNow = Boolean(emailState && emailState.status && emailState.status.paused);
            try {
                const d = await api('POST', '/api/email/pause', { paused: !pausedNow });
                renderEmailStatus(d);
                toast(!pausedNow ? 'Scheduled email digests paused.' : 'Scheduled email digests resumed.');
                refreshOverview();
            } catch (err) {
                toast(err.message, 'danger');
            }
        });

        byId('email-unsubscribed-list').addEventListener('click', async (ev) => {
            const btn = ev.target.closest('button[data-action="resubscribe"]');
            if (!btn) return;
            try {
                const d = await api('POST', '/api/email/pause', { recipient: btn.dataset.recipient, paused: false });
                renderEmailStatus(d);
                toast(`Re-enabled alerts for ${btn.dataset.recipient}.`);
            } catch (err) {
                toast(err.message, 'danger');
            }
        });

        byId('email-flush-btn').addEventListener('click', async () => {
            const btn = byId('email-flush-btn');
            btn.disabled = true;
            try {
                const res = await api('POST', '/api/email/flush', { bypass_cadence: true });
                if (res.email) renderEmailStatus(res.email);
                toast(`Dispatched ${res.delivery.event_count} queued event(s) to ${res.delivery.recipients} recipient(s).`);
                refreshOverview();
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                btn.disabled = false;
            }
        });
    }

    // ── Waiting Room Studio & Scheduled Drops ──────────────────────────────
    const ytIDRe = /^[A-Za-z0-9_-]{11}$/;
    function parseYouTubeIDClient(raw) {
        const s = String(raw || '').trim();
        if (!s) return '';
        if (ytIDRe.test(s)) return s;
        try {
            const u = new URL(s);
            if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
            const host = u.hostname.toLowerCase();
            const segs = u.pathname.split('/').filter(Boolean);
            let id = '';
            if (host === 'youtu.be' || host === 'www.youtu.be') {
                if (segs.length === 1) id = segs[0];
            } else if (host === 'youtube.com' || host === 'www.youtube.com' || host === 'm.youtube.com' || host === 'music.youtube.com') {
                if (segs.length === 1 && segs[0] === 'watch') id = u.searchParams.get('v') || '';
                else if (segs.length === 2 && (segs[0] === 'live' || segs[0] === 'embed' || segs[0] === 'shorts')) id = segs[1];
            } else if ((host === 'youtube-nocookie.com' || host === 'www.youtube-nocookie.com') && segs.length === 2 && segs[0] === 'embed') {
                id = segs[1];
            }
            return ytIDRe.test(id) ? id : '';
        } catch {
            return '';
        }
    }

    function updateYouTubePreview() {
        const input = byId('wr-youtube-input');
        const badge = byId('wr-youtube-parsed');
        if (!input || !badge) return;
        const raw = input.value.trim();
        if (!raw) {
            badge.textContent = 'none';
            return;
        }
        const parsed = parseYouTubeIDClient(raw);
        badge.textContent = parsed ? `ID: ${parsed}` : 'invalid';
    }

    function renderWaitingRoomStudio(d) {
        const cfg = (d && d.config) || {};
        const localeSel = byId('wr-locale');
        if (localeSel && Array.isArray(d && d.locales) && d.locales.length > 0) {
            localeSel.replaceChildren();
            for (const loc of d.locales) {
                const opt = document.createElement('option');
                opt.value = loc.code;
                const dirTag = loc.dir === 'rtl' ? ' · RTL' : '';
                opt.textContent = `${loc.native_name || loc.name || loc.code} (${loc.code}${dirTag})`;
                localeSel.append(opt);
            }
        }
        if (byId('wr-layout')) byId('wr-layout').value = cfg.layout || 'default';
        if (byId('wr-theme')) byId('wr-theme').value = cfg.theme || 'system';
        if (localeSel) localeSel.value = cfg.default_locale || 'en';
        if (byId('wr-brand')) byId('wr-brand').value = cfg.brand_name || '';
        if (byId('wr-accent')) byId('wr-accent').value = cfg.accent_color || '';
        if (byId('wr-logo-url')) byId('wr-logo-url').value = cfg.logo_url || '';
        if (byId('wr-hero-image-url')) byId('wr-hero-image-url').value = cfg.hero_image_url || '';
        if (byId('wr-headline')) byId('wr-headline').value = cfg.headline || '';
        if (byId('wr-subheadline')) byId('wr-subheadline').value = cfg.subheadline || '';
        if (byId('wr-youtube-input')) byId('wr-youtube-input').value = cfg.youtube_video_id || '';
        updateYouTubePreview();
        if (d && d.csp) setText('wr-csp-preview', d.csp);

        const bc = cfg.broadcast || {};
        if (byId('wr-broadcast-msg')) byId('wr-broadcast-msg').value = bc.message || '';
        setText('wr-broadcast-status', bc.message ? `Active (${fmtTime(bc.updated_at)})` : 'No active broadcast');
    }

    async function loadWaitingRoomStudio() {
        if (!byId('wr-studio-form')) return;
        try {
            const d = await api('GET', '/api/waitingroom');
            renderWaitingRoomStudio(d);
        } catch (err) {
            toast(err.message, 'danger');
        }
    }

    function renderDropStatus(d) {
        const badge = byId('drop-phase-badge');
        const phase = (d && d.phase) || 'none';
        if (badge) {
            badge.textContent = phase;
            badge.className = 'badge ' + (
                phase === 'open' ? 'text-bg-success' :
                phase === 'lobby' ? 'text-bg-info' :
                phase === 'paused' ? 'text-bg-warning' :
                phase === 'sold_out' ? 'text-bg-danger' : 'text-bg-secondary'
            );
        }
        setText('drop-event-label', (d && d.configured && d.event_id) ? d.event_id : '–');
        setText('drop-countdown-label', (d && d.configured) ? fmtSeconds(d.countdown_seconds || 0) : '–');
        setText('drop-lobby-count', fmtNum((d && d.lobby_count) || 0));
        setText('drop-queue-count', `${fmtNum((d && d.shuffled_count) || 0)} / ${fmtNum((d && d.total_queue_count) || 0)}`);
        if (d && d.configured) {
            if (byId('drop-event-id') && !byId('drop-event-id').value) byId('drop-event-id').value = d.event_id || '';
            if (byId('drop-lobby-at') && !byId('drop-lobby-at').value) byId('drop-lobby-at').value = d.lobby_at || '';
            if (byId('drop-opens-at') && !byId('drop-opens-at').value) byId('drop-opens-at').value = d.opens_at || '';
            if (byId('drop-sold-out-msg') && !byId('drop-sold-out-msg').value && d.sold_out_message) {
                byId('drop-sold-out-msg').value = d.sold_out_message;
            }
        }
    }

    async function loadDropStatus() {
        if (!byId('drop-control-form')) return;
        try {
            const d = await api('GET', '/api/drop');
            renderDropStatus(d);
        } catch (_) {
            // Ignore transient poll errors.
        }
    }

    if (byId('wr-studio-form')) {
        byId('wr-youtube-input').addEventListener('input', updateYouTubePreview);
        byId('wr-refresh-btn').addEventListener('click', () => {
            loadWaitingRoomStudio();
            loadDropStatus();
        });
        byId('wr-studio-form').addEventListener('submit', async (ev) => {
            ev.preventDefault();
            const btn = byId('wr-save-btn');
            btn.disabled = true;
            try {
                const rawYT = byId('wr-youtube-input').value.trim();
                const res = await api('PUT', '/api/waitingroom', {
                    layout: byId('wr-layout').value,
                    theme: byId('wr-theme').value,
                    default_locale: byId('wr-locale').value,
                    brand_name: byId('wr-brand').value.trim(),
                    accent_color: byId('wr-accent').value.trim(),
                    logo_url: byId('wr-logo-url').value.trim(),
                    hero_image_url: byId('wr-hero-image-url').value.trim(),
                    headline: byId('wr-headline').value.trim(),
                    subheadline: byId('wr-subheadline').value.trim(),
                    youtube_video_id: rawYT,
                });
                if (res.csp) setText('wr-csp-preview', res.csp);
                if (res.config && byId('wr-youtube-input')) {
                    byId('wr-youtube-input').value = res.config.youtube_video_id || '';
                    updateYouTubePreview();
                }
                toast('Waiting room studio settings saved.');
            } catch (err) {
                toast(err.message, 'danger');
            } finally {
                btn.disabled = false;
            }
        });
    }

    if (byId('wr-broadcast-form')) {
        const sendBroadcast = async (message) => {
            try {
                const res = await api('POST', '/api/waitingroom/broadcast', { message });
                const bc = (res && res.broadcast) || {};
                byId('wr-broadcast-msg').value = bc.message || '';
                setText('wr-broadcast-status', bc.message ? `Active (${fmtTime(bc.updated_at)})` : 'No active broadcast');
                toast(bc.message ? 'Live broadcast published.' : 'Broadcast cleared.');
            } catch (err) {
                toast(err.message, 'danger');
            }
        };
        byId('wr-broadcast-form').addEventListener('submit', (ev) => {
            ev.preventDefault();
            sendBroadcast(byId('wr-broadcast-msg').value.trim());
        });
        byId('wr-broadcast-clear').addEventListener('click', () => sendBroadcast(''));
    }

    if (byId('drop-control-form')) {
        const sendDropAction = async (payload, label) => {
            try {
                const res = await api('POST', '/api/drop', payload);
                renderDropStatus(res);
                toast(label);
            } catch (err) {
                toast(err.message, 'danger');
            }
        };
        byId('drop-control-form').addEventListener('submit', (ev) => {
            ev.preventDefault();
            const maxLobby = parseInt(byId('drop-max-lobby').value, 10);
            sendDropAction({
                action: 'schedule',
                event_id: byId('drop-event-id').value.trim(),
                lobby_at: byId('drop-lobby-at').value.trim(),
                opens_at: byId('drop-opens-at').value.trim(),
                max_lobby_tickets: Number.isFinite(maxLobby) && maxLobby > 0 ? maxLobby : 0,
                sold_out_message: byId('drop-sold-out-msg').value.trim(),
            }, 'Drop scheduled.');
        });
        byId('drop-pause-btn').addEventListener('click', () => sendDropAction({ action: 'pause', reason: 'operator pause' }, 'Drop paused.'));
        byId('drop-resume-btn').addEventListener('click', () => sendDropAction({ action: 'resume' }, 'Drop resumed.'));
        byId('drop-sold-out-btn').addEventListener('click', () => sendDropAction({
            action: 'sold_out',
            sold_out_message: byId('drop-sold-out-msg').value.trim() || 'Sold out.',
        }, 'Drop marked sold out.'));
        byId('drop-reset-btn').addEventListener('click', () => {
            byId('drop-event-id').value = '';
            byId('drop-lobby-at').value = '';
            byId('drop-opens-at').value = '';
            sendDropAction({ action: 'reset' }, 'Drop reset.');
        });
    }

    // ── Polling ────────────────────────────────────────────────────────────
    // Only the visible tab's table updates, every 3 seconds; relative times
    // in the visible tab tick every second without a request.
    const tables = {
        'tab-queue': queueTable,
        'tab-bans': bansTable,
        'tab-visitors': visitorsTable,
        'tab-banlog': banlogTable,
    };
    function activeTable() { return tables[activeTab()]; }

    document.querySelectorAll('button[data-bs-toggle="tab"]').forEach((btn) => {
        btn.addEventListener('shown.bs.tab', (ev) => {
            if (portalMoved) return;
            const id = ev.target.getAttribute('data-bs-target').slice(1);
            const t = tables[id];
            if (t) { t.loaded = false; t.refresh(); }
            if (id === 'tab-email') loadEmail(true);
            if (id === 'tab-waitingroom') { loadWaitingRoomStudio(); loadDropStatus(); }
            if (id === 'tab-settings') loadSettings().then(scheduleSpy);
        });
    });

    // ── Multi-vhost site selector & All-Sites summary ──────────────────────
    async function refreshSites() {
        const bar = byId('vhost-bar');
        const sel = byId('site-selector');
        const sumEl = byId('vhost-summary');
        const ovBadge = byId('badge-runtime-override');
        const reloadBtn = byId('vhost-reload-btn');
        if (!bar || !sel) return;
        try {
            const d = await api('GET', '/api/sites');
            const sites = Array.isArray(d.sites) ? d.sites : [];
            const showBar = Boolean(d.config_managed) || sites.length > 1;
            bar.classList.toggle('d-none', !showBar);
            if (!showBar) return;
            if (!activeSite && sites.length > 0) activeSite = sites[0].host;
            if (sites.length > 0 && !sites.some((s) => s.host === activeSite)) {
                activeSite = sites[0].host;
            }
            const curOpts = Array.from(sel.options).map((o) => o.value).join('\n');
            const nextOpts = sites.map((s) => s.host).join('\n');
            if (curOpts !== nextOpts) {
                sel.replaceChildren();
                for (const s of sites) {
                    const opt = document.createElement('option');
                    opt.value = s.host;
                    opt.textContent = s.preset ? `${s.host} (${s.preset})` : s.host;
                    sel.append(opt);
                }
            }
            sel.value = activeSite;
            const cur = sites.find((s) => s.host === activeSite);
            if (ovBadge) ovBadge.classList.toggle('d-none', !(cur && cur.runtime_override));
            if (reloadBtn) reloadBtn.classList.toggle('d-none', !d.config_managed);
            if (sumEl && d.totals) {
                const t = d.totals;
                let text = `${plural(t.sites || sites.length, 'site')} · ${fmtNum(t.active || 0)}/${fmtNum(t.cap || 0)} active · ${fmtNum(t.queued || 0)} queued · ${fmtNum(t.static_served || 0)} static`;
                if ((t.microcache_hits || 0) > 0) text += ` · ${fmtNum(t.microcache_hits)} cache hits`;
                if ((t.unhealthy_sites || 0) > 0) text += ` · ${plural(t.unhealthy_sites, 'unhealthy site')}`;
                sumEl.textContent = text;
            }
        } catch (_) {
            // Single-site or older server without /api/sites: leave hidden.
        }
    }

    const siteSelector = byId('site-selector');
    if (siteSelector) {
        siteSelector.addEventListener('change', () => {
            activeSite = siteSelector.value;
            refreshOverview();
            const t = activeTable();
            if (t) { t.loaded = false; t.refresh(); }
            if (activeTab() === 'tab-settings') loadSettings();
            refreshSites();
        });
    }
    const vhostReloadBtn = byId('vhost-reload-btn');
    if (vhostReloadBtn) {
        vhostReloadBtn.addEventListener('click', async () => {
            vhostReloadBtn.disabled = true;
            try {
                const res = await api('POST', '/api/reload', {});
                toast(`Reloaded config (${plural((res.sites || []).length, 'site')}).`);
                await refreshSites();
                refreshOverview();
                if (activeTab() === 'tab-settings') loadSettings();
            } catch (err) {
                toast('Reload failed: ' + err.message, 'danger');
            } finally {
                vhostReloadBtn.disabled = false;
            }
        });
    }

    setInterval(() => {
        if (document.hidden || portalMoved) return;
        refreshSites();
        refreshOverview();
        const tab = activeTab();
        if (tab === 'tab-email') loadEmail(false);
        if (tab === 'tab-waitingroom') loadDropStatus();
        const t = tables[tab];
        if (t) t.poll();
    }, 3000);

    setInterval(() => {
        if (document.hidden) return;
        const pane = document.querySelector('.tab-pane.active');
        if (pane) tickRelative(pane, Date.now());
    }, 1000);

    refreshSites().then(() => refreshOverview());
})();