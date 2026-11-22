'use strict';
(() => {
    const $ = (id) => document.getElementById(id);
    if (!$('fastlane-state')) return;
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';
    const el = (tag, text, cls) => {
        const x = document.createElement(tag);
        if (text !== undefined && text !== null) x.textContent = String(text);
        if (cls) x.className = cls;
        return x;
    };
    const fmtDate = (v) => {
        const d = new Date(v);
        return Number.isNaN(d.getTime()) ? '–' : d.toLocaleString();
    };

    function renderHeadroom(d) {
        const card = $('fastlane-headroom-card');
        const alertEl = $('fastlane-capacity-alert');
        const used = Number(d.records_used ?? d.receipts ?? 0);
        const max = Number(d.max_records ?? d.capacity ?? 0);
        const pct = max > 0 ? Math.min(100, Math.round((used / max) * 100)) : 0;
        if (card) {
            card.classList.remove('d-none');
            const textEl = $('fastlane-headroom-text');
            if (textEl) textEl.textContent = `${used.toLocaleString()} / ${max.toLocaleString()} (${pct}%)`;
            const bar = $('fastlane-headroom-bar');
            if (bar) {
                bar.style.width = pct + '%';
                bar.classList.remove('bg-success', 'bg-warning', 'bg-danger');
                bar.classList.add(pct >= 95 ? 'bg-danger' : pct >= 80 ? 'bg-warning' : 'bg-success');
                if (bar.parentElement) bar.parentElement.setAttribute('aria-valuenow', String(pct));
            }
        }
        if (alertEl) {
            if (pct >= 95) {
                alertEl.className = 'alert alert-danger';
                alertEl.textContent = `Critical: fast-lane receipt journal is at ${pct}% capacity (${used}/${max}). Run concert archive-receipts during a maintenance window before new paid admissions halt at 100%.`;
            } else if (pct >= 80) {
                alertEl.className = 'alert alert-warning';
                alertEl.textContent = `Warning: fast-lane receipt journal is at ${pct}% capacity (${used}/${max}). Plan an offline archival window with concert archive-receipts.`;
            } else {
                alertEl.className = 'alert d-none';
                alertEl.textContent = '';
            }
        }
    }

    function renderUnresolved(d) {
        const card = $('fastlane-unresolved-card');
        const tbody = $('fastlane-unresolved-rows');
        if (!card || !tbody) return;
        const rows = Array.isArray(d.unresolved) ? d.unresolved : [];
        tbody.replaceChildren();
        if (rows.length === 0) {
            card.classList.add('d-none');
            return;
        }
        card.classList.remove('d-none');
        for (const r of rows) {
            const tr = el('tr');
            const tdSt = el('td');
            const badgeCls = r.state === 'unknown' ? 'text-bg-danger' : 'text-bg-warning';
            tdSt.append(el('span', r.state, 'badge text-uppercase ' + badgeCls));

            const tdNet = el('td', undefined, 'small');
            tdNet.append(el('div', r.network, 'fw-semibold font-monospace'), el('div', r.scheme || '', 'text-body-secondary'));

            const tdPay = el('td', undefined, 'small');
            tdPay.append(el('div', r.payer || '–', 'font-monospace text-break'), el('div', `${r.amount || ''} ${r.asset || ''}`.trim(), 'text-body-secondary'));

            const tdFp = el('td', r.fingerprint, 'small font-monospace text-break');
            const tdTime = el('td', fmtDate(r.started), 'small text-nowrap');

            const tdAct = el('td', undefined, 'text-end');
            const wrap = el('div', undefined, 'd-flex justify-content-end align-items-center gap-1 flex-wrap');
            let hashInput = null;
            if (r.needs_hash) {
                hashInput = el('input', undefined, 'form-control form-control-sm font-monospace');
                hashInput.type = 'text';
                hashInput.placeholder = 'Stellar tx hash';
                hashInput.setAttribute('aria-label', 'Stellar transaction hash');
                hashInput.style.maxWidth = '14rem';
                wrap.append(hashInput);
            }
            const btn = el('button', 'Reconcile', 'btn btn-sm btn-outline-primary');
            btn.type = 'button';
            btn.addEventListener('click', async () => {
                const statusEl = $('fastlane-reconcile-status');
                const stellarHash = hashInput ? hashInput.value.trim() : '';
                if (r.needs_hash && !stellarHash) {
                    if (statusEl) {
                        statusEl.className = 'small text-danger';
                        statusEl.textContent = 'Enter the Stellar sponsor transaction hash first.';
                    }
                    if (hashInput) hashInput.focus();
                    return;
                }
                btn.disabled = true;
                if (statusEl) {
                    statusEl.className = 'small text-body-secondary';
                    statusEl.textContent = `Checking final ledger state for ${r.fingerprint.slice(0, 12)}…`;
                }
                try {
                    const res = await fetch('/api/fastlane/reconcile', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            Accept: 'application/json',
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': csrf,
                        },
                        body: JSON.stringify({ fingerprint: r.fingerprint, stellar_hash: stellarHash }),
                    });
                    const out = await res.json().catch(() => ({}));
                    if (!res.ok) throw new Error(out.error || `${res.status} ${res.statusText}`);
                    if (statusEl) {
                        statusEl.className = 'small text-success';
                        const tx = out.settlement && out.settlement.transaction ? out.settlement.transaction : '';
                        statusEl.textContent = `Reconciled ${r.fingerprint.slice(0, 12)}…` + (tx ? ` (tx ${tx})` : '') + '. Payer session unlocked.';
                    }
                    await load();
                } catch (err) {
                    if (statusEl) {
                        statusEl.className = 'small text-danger';
                        statusEl.textContent = 'Reconcile failed: ' + err.message;
                    }
                    btn.disabled = false;
                }
            });
            wrap.append(btn);
            tdAct.append(wrap);

            tr.append(tdSt, tdNet, tdPay, tdFp, tdTime, tdAct);
            tbody.append(tr);
        }
    }

    async function load() {
        try {
            const r = await fetch('/api/fastlane', { credentials: 'same-origin', signal: AbortSignal.timeout(8000) });
            if (!r.ok) throw Error('Sign in again to view fast-lane configuration.');
            const d = await r.json();
            $('fastlane-stats').replaceChildren();
            $('fastlane-offers').replaceChildren();
            $('fastlane-collections').replaceChildren();
            if (!d.enabled) {
                $('fastlane-state').textContent = 'Wallet admission is off. Configure a fast-lane file to enable payments or NFT access.';
                if ($('fastlane-headroom-card')) $('fastlane-headroom-card').classList.add('d-none');
                if ($('fastlane-unresolved-card')) $('fastlane-unresolved-card').classList.add('d-none');
                if ($('fastlane-capacity-alert')) $('fastlane-capacity-alert').className = 'alert d-none';
                return;
            }
            $('fastlane-state').textContent = (d.test_mode ? 'TEST MODE · Test networks only. ' : 'LIVE CONFIGURATION · ') +
                (d.healthy ? 'Receipt journal healthy.' : 'Receipt journal needs attention; admission suspended.') +
                ' Merchant: ' + d.merchant;
            for (const [name, value] of [
                ['Settled sessions', d.states.settled],
                ['Needs reconciliation', d.states.pending + d.states.unknown],
                ['Paid pass', d.pass_seconds + 's'],
                ['NFT lease', d.nft_pass_seconds + 's'],
            ]) {
                const col = el('div', undefined, 'col-sm-6 col-xl-3');
                const card = el('div', undefined, 'card stat-card');
                const body = el('div', undefined, 'card-body');
                body.append(el('div', name, 'small text-body-secondary'), el('div', String(value), 'stat-value'));
                card.append(body);
                col.append(card);
                $('fastlane-stats').append(col);
            }
            renderHeadroom(d);
            renderUnresolved(d);
            for (const o of (d.offers || [])) {
                const c = el('article', undefined, 'fastlane-rule');
                c.append(
                    el('h4', o.label),
                    el('small', o.requirements.network + ' · ' + o.requirements.scheme),
                    el('code', o.requirements.amount + ' atomic units · ' + o.requirements.asset),
                    el('small', 'Recipient'),
                    el('code', o.requirements.payTo),
                );
                $('fastlane-offers').append(c);
            }
            for (const o of (d.collections || [])) {
                const c = el('article', undefined, 'fastlane-rule');
                c.append(
                    el('h4', o.label),
                    el('small', o.network + ' · rule ' + o.id),
                    el('code', o.collection),
                );
                $('fastlane-collections').append(c);
            }
        } catch (e) {
            $('fastlane-state').textContent = e.message;
        }
    }
    $('fastlane-refresh').addEventListener('click', load);
    $('tab-fastlane-btn').addEventListener('shown.bs.tab', load);
    load();
})();
