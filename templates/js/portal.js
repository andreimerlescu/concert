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
        const e = document.createElement(tag);
        if (className) e.className = className;
        if (text !== undefined && text !== null) e.textContent = String(text);
        return e;
    }

    function byId(id) { return document.getElementById(id); }
    function setText(id, text) { const e = byId(id); if (e) e.textContent = text; }
    function fmtNum(v) { return typeof v === 'number' ? numberFormat.format(v) : '–'; }
    function fmtMoney(v) { return '$' + Number(v || 0).toFixed(2); }
    function fmtTime(iso) { return new Date(iso).toLocaleString(); }

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
        bootstrap.Toast.getOrCreateInstance(t, { delay: 4500 }).show();
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
            setText('stat-bans', d.abuse_enabled ? fmtNum(d.active_bans) : 'off');
            setText('stat-price', d.skip_url ? fmtMoney(d.rate) + ' + ' + fmtMoney(d.surge) + ' per queued' : 'off');
            setText('queue-count', fmtNum(d.occupants_tracked));
            setText('ban-count', fmtNum(d.active_bans));
            setText('updated-at', 'updated ' + new Date().toLocaleTimeString());
        } catch (e) {
            setText('updated-at', 'update failed: ' + e.message);
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
            tr.append(node('td', 'font-monospace', o.client));

            const state = node('td');
            if (o.ready) state.append(node('span', 'badge text-bg-success', 'ready'));
            else if (o.idle_seconds > 15) state.append(node('span', 'badge text-bg-secondary', 'idle'));
            else state.append(node('span', 'badge text-bg-primary', 'waiting'));
            if (o.has_pass) { state.append(' '); state.append(node('span', 'badge text-bg-warning', 'VIP')); }
            tr.append(state);

            tr.append(node('td', 'text-nowrap', fmtAgo(o.joined)));
            tr.append(node('td', 'text-nowrap', fmtAgo(o.last_seen) + ' ago'));
            const pathCell = node('td', 'text-truncate cell-path font-monospace small', o.path);
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
        setText('queue-summary', `${fmtNum(lastQueue.tracked)} tracked · ${fmtNum(lastQueue.live_queue_depth)} live tickets · ${fmtNum(lastQueue.kicked)} removed`);
    }

    async function refreshQueue() {
        try {
            lastQueue = await api('GET', '/api/queue');
            renderQueue();
        } catch (e) {
            toast(e.message, 'danger');
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
            ban: 'Remove this visitor and ban their address for the abuse cooldown?',
        };
        if (!window.confirm(prompts[action])) return;
        btn.disabled = true;
        try {
            if (action === 'promote') {
                await api('POST', '/api/queue/promote', { id });
                toast('Visitor moved to the front of the line.');
            } else {
                const r = await api('POST', '/api/queue/kick', { id, ban: action === 'ban' });
                toast(r.banned ? `Visitor removed and banned for ${fmtSeconds(r.ban_seconds)}.` : 'Visitor removed from the line.', 'warning');
            }
        } catch (e) {
            toast(e.message, 'danger');
        } finally {
            refreshQueue();
            refreshOverview();
        }
    });

    // ── Bans ───────────────────────────────────────────────────────────────
    const banModalEl = byId('ban-modal');

    function openBanModal(client, duration) {
        const editing = Boolean(client);
        setText('ban-modal-title', editing ? 'Change ban' : 'Ban a client');
        setText('ban-submit-label', editing ? 'Save' : 'Ban');
        const clientInput = byId('ban-client');
        clientInput.value = client || '';
        clientInput.readOnly = editing;
        byId('ban-duration').value = duration || '1h';
        bootstrap.Modal.getOrCreateInstance(banModalEl).show();
    }

    async function refreshBans() {
        const tbody = byId('ban-rows');
        let d;
        try {
            d = await api('GET', '/api/bans');
        } catch (e) {
            toast(e.message, 'danger');
            return;
        }
        byId('bans-disabled').classList.toggle('d-none', d.enabled);
        byId('ban-new').disabled = !d.enabled;
        tbody.replaceChildren();
        if (!d.bans.length) emptyRow(tbody, 5, d.enabled ? 'No active bans.' : 'Bans are unavailable.');
        for (const b of d.bans) {
            const tr = node('tr');
            tr.append(node('td', 'font-monospace', b.client));
            tr.append(node('td', 'text-nowrap', fmtTime(b.until)));
            tr.append(node('td', 'text-nowrap', fmtSeconds(b.remaining_seconds)));
            tr.append(node('td', null, b.offenses));
            const actions = node('td', 'text-end text-nowrap');
            const group = node('div', 'btn-group btn-group-sm');
            group.setAttribute('role', 'group');
            group.append(iconButton('edit', 'btn-outline-secondary', 'bi-pencil', 'Change duration', { client: b.client, remaining: String(b.remaining_seconds) }));
            group.append(iconButton('unban', 'btn-outline-success', 'bi-unlock', 'Unban', { client: b.client }));
            actions.append(group);
            tr.append(actions);
            tbody.append(tr);
        }
    }

    byId('ban-new').addEventListener('click', () => openBanModal('', '1h'));
    byId('bans-refresh').addEventListener('click', refreshBans);

    byId('ban-presets').addEventListener('click', (ev) => {
        const b = ev.target.closest('[data-duration]');
        if (b) byId('ban-duration').value = b.dataset.duration;
    });

    byId('ban-form').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const client = byId('ban-client').value.trim();
        const duration = byId('ban-duration').value.trim();
        try {
            const r = await api('POST', '/api/bans', { client, duration });
            bootstrap.Modal.getOrCreateInstance(banModalEl).hide();
            toast(`${r.client} banned until ${fmtTime(r.until)}.`, 'warning');
            refreshBans();
            refreshOverview();
        } catch (e) {
            toast(e.message, 'danger');
        }
    });

    byId('ban-rows').addEventListener('click', async (ev) => {
        const btn = ev.target.closest('button[data-action]');
        if (!btn) return;
        const { action, client, remaining } = btn.dataset;
        if (action === 'edit') {
            openBanModal(client, Math.max(1, Math.ceil(Number(remaining) / 60)) + 'm');
            return;
        }
        if (!window.confirm(`Unban ${client}? Their offense history is forgotten.`)) return;
        btn.disabled = true;
        try {
            await api('DELETE', '/api/bans?client=' + encodeURIComponent(client));
            toast(`${client} unbanned.`);
        } catch (e) {
            toast(e.message, 'danger');
        } finally {
            refreshBans();
            refreshOverview();
        }
    });

    // ── Settings ───────────────────────────────────────────────────────────
    async function loadSettings() {
        try {
            const s = await api('GET', '/api/settings');
            byId('set-cap').value = s.cap;
            byId('set-max-queue').value = s.max_queue;
            byId('set-token-ttl').value = s.token_ttl;
            byId('set-rate').value = s.rate;
            byId('set-surge').value = s.surge;
            byId('set-skip-url').value = s.skip_url;
            byId('set-pass-duration').value = s.pass_duration;

            const dl = byId('settings-readonly');
            dl.replaceChildren();
            Object.keys(s.readonly).sort().forEach((label) => {
                dl.append(node('dt', 'col-sm-5 text-body-secondary fw-normal', label));
                dl.append(node('dd', 'col-sm-7 font-monospace text-break', s.readonly[label]));
            });
        } catch (e) {
            toast(e.message, 'danger');
        }
    }

    byId('settings-form').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const body = {
            cap: parseInt(byId('set-cap').value, 10),
            max_queue: parseInt(byId('set-max-queue').value, 10),
            token_ttl: byId('set-token-ttl').value.trim(),
            rate: parseFloat(byId('set-rate').value),
            surge: parseFloat(byId('set-surge').value),
            skip_url: byId('set-skip-url').value.trim(),
            pass_duration: byId('set-pass-duration').value.trim(),
        };
        try {
            await api('POST', '/api/settings', body);
            toast('Settings applied.');
            loadSettings();
            refreshOverview();
        } catch (e) {
            toast(e.message, 'danger');
        }
    });

    // ── Polling ────────────────────────────────────────────────────────────
    document.querySelectorAll('button[data-bs-toggle="tab"]').forEach((btn) => {
        btn.addEventListener('shown.bs.tab', (ev) => {
            const target = ev.target.getAttribute('data-bs-target');
            if (target === '#tab-queue') refreshQueue();
            if (target === '#tab-bans') refreshBans();
            if (target === '#tab-settings') loadSettings();
        });
    });

    setInterval(() => {
        if (document.hidden) return;
        refreshOverview();
        const tab = activeTab();
        if (tab === 'tab-queue') refreshQueue();
        if (tab === 'tab-bans') refreshBans();
    }, 3000);

    refreshOverview();
    refreshBans();
})();