/* Concert admin portal. Loaded as a file: the CSP forbids inline scripts. */
(() => {
    'use strict';

    // ── Theme ──────────────────────────────────────────────────────────────
    const THEME_KEY = 'concert.portal.theme';
    const root = document.documentElement;

    function applyTheme(theme) {
        root.setAttribute('data-bs-theme', theme);
        const dark = document.getElementById('theme-dark');
        if (dark) dark.disabled = theme !== 'dark';
        const icon = document.querySelector('#theme-toggle i');
        if (icon) icon.className = theme === 'dark' ? 'bi bi-sun' : 'bi bi-moon-stars';
    }

    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyTheme(localStorage.getItem(THEME_KEY) || (prefersDark ? 'dark' : 'light'));

    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
            localStorage.setItem(THEME_KEY, next);
            applyTheme(next);
        });
    }

    if (!document.getElementById('portal-app')) return; // sign-in page

    // ── Helpers ────────────────────────────────────────────────────────────
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';
    const numberFormat = new Intl.NumberFormat();

    // Set once the portal has moved away from this page's address; stops polling.
    let portalMoved = false;

    async function api(method, url, body) {
        const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
        if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrf;
        if (body !== undefined) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(url, opts);
        if (res.status === 401) {
            window.location.reload();
            throw new Error('Your session expired.');
        }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `${res.status} ${res.statusText}`);
        return data;
    }

    // Every value from the server is attacker-influenced (user agents, paths),
    // so the DOM is built with textContent only — never innerHTML.
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
    function fmtTime(iso) { return new Date(iso).toLocaleString(); }
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

    function fmtAgo(iso) { return fmtSeconds((Date.now() - Date.parse(iso)) / 1000); }

    function fmtMS(ms) {
        if (ms < 1) return '<1 ms';
        if (ms < 1000) return Math.round(ms) + ' ms';
        return (ms / 1000).toFixed(1) + ' s';
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

    function emptyRow(tbody, cols, text) {
        const tr = node('tr');
        const td = node('td', 'text-center text-body-secondary py-4', text);
        td.colSpan = cols;
        tr.append(td);
        tbody.append(tr);
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

    // rankBadge shows a Concert-Priority rank granted by the application.
    function rankBadge(rank) {
        const b = node('span', 'badge text-bg-primary', rank);
        b.title = 'Priority rank granted by the application (Concert-Priority)';
        return b;
    }

    function activeTab() {
        const pane = document.querySelector('.tab-pane.active');
        return pane ? pane.id : '';
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
            setBar('bar-occupancy', d.occupancy, d.cap);
            setText('stat-queue', fmtNum(d.live_queue_depth));
            setText('stat-queue-depth', fmtNum(d.queue_depth));
            setText('stat-assets', fmtNum(d.asset_in_flight) + ' / ' + fmtNum(d.asset_cap));
            setBar('bar-assets', d.asset_in_flight, d.asset_cap);
            setText('stat-streams', fmtNum(d.stream_active) + ' / ' + fmtNum(d.stream_cap));
            setText('stat-bans', d.abuse_enabled ? fmtNum(d.active_bans) : 'off');
            setText('stat-price', d.skip_url ? fmtMoney(d.rate) + ' + ' + fmtMoney(d.surge) + ' per queued' : 'off');
            setText('queue-count', fmtNum(d.live_queue_depth));
            setText('ban-count', fmtNum(d.active_bans));
            setText('history-count', fmtNum(d.history_clients));
            setText('updated-at', 'updated ' + new Date().toLocaleTimeString());
        } catch (err) {
            setText('updated-at', 'update failed: ' + err.message);
        }
    }

    // ── Queue ──────────────────────────────────────────────────────────────
    let lastQueue = { occupants: [] };

    function renderQueue() {
        const tbody = byId('queue-rows');
        const filter = (byId('queue-filter').value || '').trim().toLowerCase();
        const rows = lastQueue.occupants.filter((o) => !filter
            || o.client.toLowerCase().includes(filter)
            || o.path.toLowerCase().includes(filter)
            || o.user_agent.toLowerCase().includes(filter));

        tbody.replaceChildren();
        if (rows.length === 0) {
            emptyRow(tbody, 8, lastQueue.occupants.length ? 'No visitors match the filter.' : 'Nobody is waiting in line.');
        }
        for (const o of rows) {
            const tr = node('tr');
            tr.append(node('td', 'fw-semibold', o.position > 0 ? '#' + o.position : '—'));
            tr.append(node('td', 'font-monospace', o.client || '—'));

            const state = node('td');
            if (o.ready) state.append(node('span', 'badge text-bg-success', 'ready'));
            else if (o.idle_seconds > 15) state.append(node('span', 'badge text-bg-secondary', 'idle'));
            else state.append(node('span', 'badge text-bg-primary', 'waiting'));
            if (o.promoted) { state.append(' '); state.append(node('span', 'badge text-bg-info', 'moved up')); }
            if (o.has_pass) { state.append(' '); state.append(node('span', 'badge text-bg-warning', 'VIP')); }
            if (o.rank) { state.append(' '); state.append(rankBadge(o.rank)); }
            tr.append(state);

            tr.append(node('td', 'text-nowrap', fmtAgo(o.joined)));
            tr.append(node('td', 'text-nowrap', fmtAgo(o.last_seen) + ' ago'));
            const pathCell = node('td', 'text-truncate cell-path font-monospace small', o.path || '—');
            pathCell.title = o.path;
            tr.append(pathCell);
            const uaCell = node('td', 'text-truncate cell-ua small', o.user_agent || '—');
            uaCell.title = o.user_agent;
            tr.append(uaCell);

            const actions = node('td', 'text-end text-nowrap');
            const group = node('div', 'btn-group btn-group-sm');
            group.setAttribute('role', 'group');
            group.append(iconButton('promote', 'btn-outline-success', 'bi-skip-start', 'Move to the front', { id: o.id }));
            group.append(iconButton('kick', 'btn-outline-warning', 'bi-person-dash', 'Remove from the line', { id: o.id }));
            group.append(iconButton('ban', 'btn-outline-danger', 'bi-slash-circle', 'Remove and ban', { id: o.id }));
            actions.append(group);
            tr.append(actions);
            tbody.append(tr);
        }
        setText('queue-summary',
            `${fmtNum(lastQueue.listed)} shown of ${fmtNum(lastQueue.live_queue_depth)} waiting · ${fmtNum(lastQueue.kicked)} removed`);
    }

    async function refreshQueue() {
        try {
            lastQueue = await api('GET', '/api/queue');
            renderQueue();
        } catch (err) {
            toast(err.message, 'danger');
        }
    }

    byId('queue-filter').addEventListener('input', renderQueue);
    byId('queue-refresh').addEventListener('click', refreshQueue);

    byId('queue-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn) return;
        const { action, id } = btn.dataset;
        const prompts = {
            promote: 'Move this visitor to the front of the line?',
            kick: 'Remove this visitor from the line? They can rejoin at the back.',
            ban: 'Remove this visitor and ban their address for the abuse cooldown? Everyone else waiting from that address is removed too.',
        };
        if (!window.confirm(prompts[action])) return;
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
            refreshQueue();
            refreshOverview();
        }
    });

    // ── Bans ───────────────────────────────────────────────────────────────
    const banModalEl = byId('ban-modal');

    function setPermanent(on) {
        byId('ban-permanent').checked = on;
        byId('ban-duration-group').disabled = on;
    }

    function openBanModal(client, duration, permanent) {
        const editing = Boolean(client);
        setText('ban-modal-title', editing ? 'Change ban' : 'Ban a client');
        setText('ban-submit-label', editing ? 'Save' : 'Ban');
        const clientInput = byId('ban-client');
        clientInput.value = client || '';
        clientInput.readOnly = editing;
        byId('ban-duration').value = duration || '1h';
        setPermanent(Boolean(permanent));
        bootstrap.Modal.getOrCreateInstance(banModalEl).show();
    }

    async function refreshBans() {
        const tbody = byId('ban-rows');
        let d;
        try {
            d = await api('GET', '/api/bans');
        } catch (err) {
            toast(err.message, 'danger');
            return;
        }
        byId('bans-disabled').classList.toggle('d-none', d.enabled);
        byId('bans-not-persisted').classList.toggle('d-none', d.persisted);
        byId('ban-new').disabled = !d.enabled;
        tbody.replaceChildren();
        if (!d.bans.length) emptyRow(tbody, 5, d.enabled ? 'No active bans.' : 'Bans are not enforced while the abuse registry is off.');
        for (const b of d.bans) {
            const tr = node('tr');
            const clientCell = node('td', 'font-monospace', b.client);
            if (b.range) { clientCell.append(' '); clientCell.append(node('span', 'badge text-bg-secondary', 'range')); }
            tr.append(clientCell);
            if (b.permanent) {
                const until = node('td');
                until.append(node('span', 'badge text-bg-danger', 'permanent'));
                tr.append(until);
                tr.append(node('td', 'text-nowrap text-body-secondary', '—'));
            } else {
                tr.append(node('td', 'text-nowrap', fmtTime(b.until)));
                tr.append(node('td', 'text-nowrap', fmtSeconds(b.remaining_seconds)));
            }
            tr.append(node('td', null, b.offenses));
            const actions = node('td', 'text-end text-nowrap');
            const group = node('div', 'btn-group btn-group-sm');
            group.setAttribute('role', 'group');
            group.append(iconButton('edit', 'btn-outline-secondary', 'bi-pencil', 'Change ban', {
                client: b.client, remaining: String(b.remaining_seconds), permanent: b.permanent ? '1' : '0',
            }));
            group.append(iconButton('unban', 'btn-outline-success', 'bi-unlock', 'Unban', { client: b.client }));
            actions.append(group);
            tr.append(actions);
            tbody.append(tr);
        }
    }

    byId('ban-new').addEventListener('click', () => openBanModal('', '1h', false));
    byId('bans-refresh').addEventListener('click', refreshBans);
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
            refreshBans();
            refreshOverview();
            if (activeTab() === 'tab-queue') refreshQueue();
            if (activeTab() === 'tab-history') refreshHistory();
        } catch (err) {
            toast(err.message, 'danger');
        }
    });

    byId('ban-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn) return;
        const { action, client, remaining, permanent } = btn.dataset;
        if (action === 'edit') {
            openBanModal(client, Math.max(1, Math.ceil(Number(remaining) / 60)) + 'm', permanent === '1');
            return;
        }
        if (!window.confirm(`Unban ${client}? Their offense history is forgotten.`)) return;
        btn.disabled = true;
        try {
            await api('DELETE', '/api/bans?client=' + encodeURIComponent(client));
            toast(`${client} unbanned.`);
        } catch (err) {
            toast(err.message, 'danger');
        } finally {
            refreshBans();
            refreshOverview();
        }
    });

    // ── History ────────────────────────────────────────────────────────────
    // Clients and bans the operator expanded, and their fetched details.
    // Details are refetched on every refresh so expanded rows stay live.
    const historyOpen = { clients: new Set(), bans: new Set() };
    const historyCache = { clients: new Map(), bans: new Map() };
    let historyData = null;
    let historyFilterTimer = 0;

    function statusBadge(code) {
        let cls = 'text-bg-success';
        if (code >= 500) cls = 'text-bg-danger';
        else if (code >= 400) cls = 'text-bg-warning';
        else if (code >= 300) cls = 'text-bg-info';
        else if (code < 200) cls = 'text-bg-secondary';
        return node('span', 'badge ' + cls, String(code));
    }

    function banStateBadge(w) {
        if (w.active) return node('span', 'badge text-bg-danger', w.permanent ? 'permanent' : 'active');
        return node('span', 'badge text-bg-light border', w.end_reason === 'lifted' ? 'lifted' : 'expired');
    }

    function banEndText(w) {
        if (w.active) {
            if (w.permanent) return 'Never: permanent until someone unbans it';
            return `${fmtTime(w.until)} (${fmtSeconds(w.remaining_seconds)} left)`;
        }
        if (w.end_reason === 'lifted') return `Lifted ${fmtTime(w.ended)}` + (w.lifted_by ? ` by ${w.lifted_by}` : '');
        return `Expired ${fmtTime(w.ended)}`;
    }

    function toggleButton(open, data) {
        return iconButton('toggle', 'btn-sm btn-link text-body p-0', open ? 'bi-chevron-down' : 'bi-chevron-right',
            open ? 'Hide details' : 'Show details', data);
    }

    function detailRow(cols, data, render) {
        const tr = node('tr', 'history-detail');
        const td = node('td');
        td.colSpan = cols;
        if (!data) td.append(node('div', 'small text-body-secondary py-2', 'Loading…'));
        else if (data.error) td.append(node('div', 'small text-danger py-2', data.error));
        else td.append(render(data));
        tr.append(td);
        return tr;
    }

    function countTable(title, rows, other, otherLabel) {
        const col = node('div', 'col-md-6');
        col.append(node('div', 'small fw-semibold mb-1', title));
        const table = node('table', 'table table-sm table-portal mb-0');
        const tbody = node('tbody');
        for (const r of rows) {
            const tr = node('tr');
            tr.append(node('td', 'small font-monospace text-break', r.name));
            tr.append(node('td', 'small text-end fw-semibold text-nowrap', fmtNum(r.hits)));
            tbody.append(tr);
        }
        if (other > 0) {
            const tr = node('tr');
            tr.append(node('td', 'small text-body-secondary', otherLabel));
            tr.append(node('td', 'small text-end fw-semibold', fmtNum(other)));
            tbody.append(tr);
        }
        if (!rows.length && !(other > 0)) emptyRow(tbody, 2, 'None');
        table.append(tbody);
        col.append(table);
        return col;
    }

    function renderWindow(w) {
        const card = node('div', 'history-ban border rounded p-3 mb-3');
        const head = node('div', 'd-flex flex-wrap align-items-center gap-2 mb-2');
        head.append(node('i', 'bi bi-slash-circle text-danger'));
        head.append(node('span', 'fw-semibold font-monospace', w.target));
        if (w.range) head.append(node('span', 'badge text-bg-secondary', 'range'));
        head.append(banStateBadge(w));
        card.append(head);

        const dl = node('dl', 'row small mb-2');
        const add = (k, v) => {
            dl.append(node('dt', 'col-sm-3 text-body-secondary fw-normal', k));
            dl.append(node('dd', 'col-sm-9 mb-1 text-break', v));
        };
        add('Began', w.began ? fmtTime(w.began) : 'Before concert last started (restored from bans.json)');
        add(w.active ? 'Ends' : 'Ended', banEndText(w));
        if (w.trigger) {
            add('Started by', `${w.trigger.method} ${w.trigger.path} → ${w.trigger.status}, from ${w.trigger.client} at ${fmtTime(w.trigger.at)}`);
        } else if (!w.source && w.began) {
            add('Started by', 'Strikes that added up over several requests; see the client\'s requests below the ban start');
        }
        if (w.source) add('Issued', w.source);
        if (w.changes) add('Changed', plural(w.changes, 'time') + ' while in force');
        add('Requests during ban', w.requests
            ? `${fmtNum(w.requests)} blocked · first ${fmtTime(w.first_hit)} · last ${fmtTime(w.last_hit)}`
            : 'None: nothing from this network arrived while it was banned');
        card.append(dl);

        if (w.requests) {
            const row = node('div', 'row g-3');
            row.append(countTable('Paths requested while banned', w.paths, w.other_paths, 'Other paths (not itemised)'));
            row.append(countTable('Addresses that made them', w.clients, w.other_clients, 'Other addresses (not itemised)'));
            card.append(row);
        }
        return card;
    }

    function renderClientDetail(d) {
        const box = node('div', 'py-2');
        const c = d.client;
        box.append(node('div', 'small text-body-secondary mb-1',
            `First seen ${fmtTime(c.first_seen)} · last seen ${fmtTime(c.last_seen)} · `
            + `${fmtNum(c.requests)} recorded, ${fmtNum(c.blocked)} blocked, ${fmtNum(c.errors)} errors`));
        if (d.user_agents.length) {
            box.append(node('div', 'small text-body-secondary mb-3 text-break',
                'Browsers: ' + d.user_agents.map((u) => u || '(none sent)').join(' · ')));
        }

        if (d.bans.length) {
            box.append(node('div', 'small fw-semibold mb-2', plural(d.bans.length, 'ban') + ' covering this address'));
            d.bans.forEach((w) => box.append(renderWindow(w)));
        }

        box.append(node('div', 'small fw-semibold mb-2', `Requests, newest first (last ${fmtNum(d.entries.length)} kept)`));
        const wrap = node('div', 'table-responsive');
        const table = node('table', 'table table-sm table-portal mb-0');
        const thead = node('thead');
        const hr = node('tr');
        ['Time', 'Request', 'Status', 'Response', 'Notes', 'Browser'].forEach((h) => hr.append(node('th', null, h)));
        thead.append(hr);
        table.append(thead);

        const tbody = node('tbody');
        if (!d.entries.length) emptyRow(tbody, 6, 'No requests kept.');
        for (const entry of d.entries) {
            const tr = node('tr', entry.triggered_ban ? 'history-trigger' : entry.blocked ? 'history-blocked' : '');

            tr.append(node('td', 'small text-nowrap', fmtTime(entry.at)));

            const req = node('td', 'small font-monospace text-truncate cell-hist-path', `${entry.method} ${entry.path}`);
            req.title = entry.path;
            tr.append(req);

            const status = node('td');
            status.append(statusBadge(entry.status));
            tr.append(status);

            tr.append(node('td', 'small text-nowrap', fmtMS(entry.latency_ms)));

            const notes = node('td', 'text-nowrap');
            if (entry.triggered_ban) notes.append(node('span', 'badge text-bg-danger', 'started ban'));
            else if (entry.blocked) notes.append(node('span', 'badge text-bg-warning', 'during ban'));
            if (entry.rank) {
                if (notes.childNodes.length) notes.append(' ');
                notes.append(rankBadge(entry.rank));
            }
            tr.append(notes);

            const ua = node('td', 'small text-truncate cell-ua', entry.user_agent || '—');
            ua.title = entry.user_agent;
            tr.append(ua);

            tbody.append(tr);
        }
        table.append(tbody);
        wrap.append(table);
        box.append(wrap);
        return box;
    }

    function renderBanLog() {
        const tbody = byId('history-ban-rows');
        tbody.replaceChildren();
        const bans = historyData.bans;
        if (!bans.length) {
            let text = 'No bans recorded since concert started.';
            if (byId('history-filter').value.trim()) text = 'No bans match the filter.';
            else if (!historyData.abuse_enabled) text = 'No bans recorded. The abuse registry is off.';
            emptyRow(tbody, 8, text);
        }
        for (const w of bans) {
            const key = String(w.id);
            const open = historyOpen.bans.has(key);
            const tr = node('tr');

            const tog = node('td', 'history-toggle');
            tog.append(toggleButton(open, { id: key }));
            tr.append(tog);

            const target = node('td', 'font-monospace text-nowrap', w.target);
            if (w.range) { target.append(' '); target.append(node('span', 'badge text-bg-secondary', 'range')); }
            tr.append(target);

            const state = node('td');
            state.append(banStateBadge(w));
            tr.append(state);

            tr.append(node('td', 'small text-nowrap', w.began ? fmtTime(w.began) : 'before restart'));
            tr.append(node('td', 'small', banEndText(w)));
            tr.append(node('td', w.requests ? 'fw-semibold text-danger' : 'text-body-secondary', fmtNum(w.requests)));

            let top = w.paths.map((x) => `${x.name} ×${fmtNum(x.hits)}`).join(', ');
            if (w.distinct_paths > w.paths.length) top += ` and ${fmtNum(w.distinct_paths - w.paths.length)} more`;
            const topCell = node('td', 'small font-monospace text-truncate cell-hist-path', top || '—');
            topCell.title = top;
            tr.append(topCell);

            const started = w.trigger ? `${w.trigger.method} ${w.trigger.path}` : (w.source || '—');
            const startedCell = node('td', 'small text-truncate cell-hist-path' + (w.trigger ? ' font-monospace' : ''), started);
            startedCell.title = started;
            tr.append(startedCell);

            tbody.append(tr);
            if (open) tbody.append(detailRow(8, historyCache.bans.get(key), renderWindow));
        }
    }

    function renderHistoryClients() {
        const tbody = byId('history-client-rows');
        tbody.replaceChildren();
        const d = historyData;
        if (!d.clients.length) {
            const filtered = byId('history-filter').value.trim() || byId('history-flagged').checked;
            emptyRow(tbody, 9, filtered ? 'No clients match.' : 'No requests recorded yet.');
        }
        for (const cl of d.clients) {
            const open = historyOpen.clients.has(cl.client);
            const tr = node('tr');

            const tog = node('td', 'history-toggle');
            tog.append(toggleButton(open, { client: cl.client }));
            tr.append(tog);

            tr.append(node('td', 'font-monospace text-nowrap', cl.client));

            const state = node('td', 'text-nowrap');
            if (cl.banned_now) {
                state.append(node('span', 'badge text-bg-danger',
                    cl.ban_permanent ? 'banned permanently' : 'banned · ' + fmtSeconds(cl.ban_remaining_seconds) + ' left'));
            } else if (cl.bans_triggered || cl.blocked) {
                state.append(node('span', 'badge text-bg-warning', 'was banned'));
            } else {
                state.append(node('span', 'badge text-bg-light border', 'ok'));
            }
            if (cl.rank) { state.append(' '); state.append(rankBadge(cl.rank)); }
            tr.append(state);

            tr.append(node('td', null, fmtNum(cl.requests)));
            tr.append(node('td', cl.blocked ? 'fw-semibold text-danger' : 'text-body-secondary', fmtNum(cl.blocked)));
            tr.append(node('td', cl.errors ? 'fw-semibold' : 'text-body-secondary', fmtNum(cl.errors)));
            tr.append(node('td', 'small text-nowrap', fmtAgo(cl.last_seen) + ' ago'));

            const last = node('td', 'small text-truncate cell-hist-path');
            last.title = cl.last_path;
            last.append(statusBadge(cl.last_status), ' ');
            last.append(node('span', 'font-monospace', `${cl.last_method} ${cl.last_path}`));
            tr.append(last);

            const actions = node('td', 'text-end text-nowrap');
            const ban = iconButton('ban', 'btn-sm btn-outline-danger', 'bi-slash-circle', 'Ban this address', { client: cl.client });
            ban.disabled = cl.banned_now || !d.abuse_enabled;
            actions.append(ban);
            tr.append(actions);

            tbody.append(tr);
            if (open) tbody.append(detailRow(9, historyCache.clients.get(cl.client), renderClientDetail));
        }
    }

    function renderHistory() {
        if (!historyData) return;
        const d = historyData;
        renderBanLog();
        renderHistoryClients();
        let summary = `${fmtNum(d.listed)} shown of ${fmtNum(d.matched)} matching · ${fmtNum(d.tracked)} addresses recorded`;
        if (d.evicted) summary += ` · ${fmtNum(d.evicted)} forgotten to make room`;
        setText('history-summary', summary);
        const l = d.limits;
        setText('history-limits',
            `Kept in memory: the last ${fmtNum(l.per_client)} requests from each of up to ${fmtNum(l.max_clients)} addresses, `
            + `until ${l.retention_hours}h after an address's last request; bans are kept ${l.retention_hours}h after they end. `
            + 'Requests from banned clients and every 4xx or 5xx response are always recorded; successful asset '
            + 'and waiting-room status requests are not, as in the access log. A restart starts the history again.');
    }

    async function loadClient(ip) {
        try {
            historyCache.clients.set(ip, await api('GET', '/api/history/client?client=' + encodeURIComponent(ip)));
        } catch (err) {
            historyCache.clients.set(ip, { error: err.message });
        }
    }

    async function loadBan(id) {
        try {
            historyCache.bans.set(id, (await api('GET', '/api/history/ban?id=' + encodeURIComponent(id))).ban);
        } catch (err) {
            historyCache.bans.set(id, { error: err.message });
        }
    }

    async function refreshHistory() {
        const params = new URLSearchParams();
        const q = byId('history-filter').value.trim();
        if (q) params.set('q', q);
        if (byId('history-flagged').checked) params.set('flagged', '1');
        try {
            const [d] = await Promise.all([
                api('GET', '/api/history?' + params.toString()),
                ...[...historyOpen.clients].map(loadClient),
                ...[...historyOpen.bans].map(loadBan),
            ]);
            historyData = d;
            renderHistory();
        } catch (err) {
            toast(err.message, 'danger');
        }
    }

    byId('history-refresh').addEventListener('click', refreshHistory);
    byId('history-flagged').addEventListener('change', refreshHistory);
    byId('history-filter').addEventListener('input', () => {
        clearTimeout(historyFilterTimer);
        historyFilterTimer = setTimeout(refreshHistory, 300);
    });

    byId('history-ban-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action="toggle"]');
        if (!btn) return;
        const id = btn.dataset.id;
        if (historyOpen.bans.delete(id)) {
            historyCache.bans.delete(id);
            renderHistory();
            return;
        }
        historyOpen.bans.add(id);
        renderHistory();
        await loadBan(id);
        renderHistory();
    });

    byId('history-client-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn) return;
        const { action, client } = btn.dataset;
        if (action === 'ban') {
            openBanModal('', '1h', false);
            byId('ban-client').value = client;
            return;
        }
        if (historyOpen.clients.delete(client)) {
            historyCache.clients.delete(client);
            renderHistory();
            return;
        }
        historyOpen.clients.add(client);
        renderHistory();
        await loadClient(client);
        renderHistory();
    });

    // ── Settings ───────────────────────────────────────────────────────────
    const SOURCE_BADGES = {
        default: ['text-bg-light border', 'default', 'Built-in default'],
        env: ['text-bg-info', 'env', 'From the environment variable'],
        flag: ['text-bg-primary', 'flag', 'From the command-line flag'],
        file: ['text-bg-success', 'saved', 'Saved in settings.json; overrides flag and environment'],
    };
    let settingsData = null;

    function settingInput(s) {
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
        return input.dataset.kind === 'bool' ? String(input.checked) : input.value.trim();
    }

    function typedValue(input) {
        const raw = inputValue(input);
        const label = input.dataset.label;
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

    function settingRow(s) {
        const row = node('div', 'row g-2 align-items-start py-2 border-top setting-row');
        row.dataset.search = [s.label, s.key, s.flag, s.env, s.help].join(' ').toLowerCase();

        const left = node('div', 'col-md-6');
        const label = node('label', 'form-label mb-0 fw-semibold', s.label);
        label.htmlFor = 'set-' + s.key;
        left.append(label);
        const [cls, text, title] = SOURCE_BADGES[s.source] || SOURCE_BADGES.default;
        const src = node('span', 'badge ms-2 align-middle ' + cls, text);
        src.title = title;
        left.append(src);
        if (s.restart) {
            const r = node('span', 'badge ms-1 align-middle bg-warning-subtle text-warning-emphasis border border-warning-subtle', 'restart');
            r.title = 'Changed only in concert.env; applies when concert restarts';
            left.append(r);
        }
        left.append(node('div', 'form-text mt-1', s.help));
        left.append(node('div', 'form-text font-monospace', '-' + s.flag + ' · ' + s.env));

        const mid = node('div', 'col-md-5');
        mid.append(settingInput(s));

        const right = node('div', 'col-md-1 text-md-end');
        if (s.source === 'file') {
            right.append(iconButton('reset', 'btn-sm btn-outline-secondary', 'bi-arrow-counterclockwise',
                'Reset: remove from settings.json', { key: s.key }));
        }
        row.append(left, mid, right);
        return row;
    }

    function renderSettings(d) {
        settingsData = d;
        const groups = byId('settings-groups');
        groups.replaceChildren();
        const bodies = new Map();
        for (const s of d.settings) {
            let body = bodies.get(s.group);
            if (!body) {
                const card = node('div', 'card stat-card settings-group');
                body = node('div', 'card-body');
                body.append(node('h2', 'h6 mb-2', s.group));
                card.append(body);
                groups.append(card);
                bodies.set(s.group, body);
            }
            body.append(settingRow(s));
        }

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

    function changedInputs() {
        return [...document.querySelectorAll('#settings-groups [data-original]')]
            .filter((i) => !i.disabled && inputValue(i) !== i.dataset.original);
    }

    function updateDirty() {
        const changed = changedInputs();
        document.querySelectorAll('.setting-row.setting-changed').forEach((r) => r.classList.remove('setting-changed'));
        changed.forEach((i) => i.closest('.setting-row').classList.add('setting-changed'));
        const n = changed.length;
        byId('settings-apply').disabled = n === 0;
        byId('settings-discard').disabled = n === 0;
        setText('settings-apply-label', n ? `Save ${plural(n, 'change')}` : 'Save changes');
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
        });
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

    byId('settings-groups').addEventListener('input', updateDirty);
    byId('settings-groups').addEventListener('change', updateDirty);
    byId('settings-filter').addEventListener('input', applySettingsFilter);
    byId('settings-discard').addEventListener('click', () => { if (settingsData) renderSettings(settingsData); });

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

    // ── Polling ────────────────────────────────────────────────────────────
    document.querySelectorAll('button[data-bs-toggle="tab"]').forEach((btn) => {
        btn.addEventListener('shown.bs.tab', (ev) => {
            if (portalMoved) return;
            const target = ev.target.getAttribute('data-bs-target');
            if (target === '#tab-queue') refreshQueue();
            if (target === '#tab-bans') refreshBans();
            if (target === '#tab-history') refreshHistory();
            if (target === '#tab-settings') loadSettings();
        });
    });

    setInterval(() => {
        if (document.hidden || portalMoved) return;
        refreshOverview();
        const tab = activeTab();
        if (tab === 'tab-queue') refreshQueue();
        if (tab === 'tab-bans') refreshBans();
        if (tab === 'tab-history' && byId('history-live').checked) refreshHistory();
    }, 3000);

    refreshOverview();
    refreshBans();
})();