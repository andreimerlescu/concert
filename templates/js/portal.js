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
            tr.append(node('td', 'font-monospace', o.client || '—'));

            const state = node('td');
            if (o.ready) state.append(node('span', 'badge text-bg-success', 'ready'));
            else if (o.idle_seconds > 15) state.append(node('span', 'badge text-bg-secondary', 'idle'));
            else state.append(node('span', 'badge text-bg-primary', 'waiting'));
            if (o.promoted) { state.append(' '); state.append(node('span', 'badge text-bg-info', 'moved up')); }
            if (o.has_pass) { state.append(' '); state.append(node('span', 'badge text-bg-warning', 'VIP')); }
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
        } catch (e) {
            toast(e.message, 'danger');
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
        } catch (e) {
            toast(e.message, 'danger');
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
        } catch (e) {
            toast(e.message, 'danger');
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
        } catch (e) {
            toast(e.message, 'danger');
        } finally {
            refreshBans();
            refreshOverview();
        }
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
        } catch (e) {
            toast(e.message, 'danger');
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
        } catch (e) {
            btn.disabled = false;
            toast(e.message, 'danger');
        }
    });

    byId('settings-form').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const changed = changedInputs();
        if (!changed.length) return;
        const body = {};
        try {
            for (const i of changed) body[i.dataset.key] = typedValue(i);
        } catch (e) {
            toast(e.message, 'danger');
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
        } catch (e) {
            toast(e.message, 'danger');
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
            if (target === '#tab-settings') loadSettings();
        });
    });

    setInterval(() => {
        if (document.hidden || portalMoved) return;
        refreshOverview();
        const tab = activeTab();
        if (tab === 'tab-queue') refreshQueue();
        if (tab === 'tab-bans') refreshBans();
    }, 3000);

    refreshOverview();
    refreshBans();
})();