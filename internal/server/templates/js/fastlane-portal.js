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

    function withSite(url) {
        const sel = $('site-selector');
        const site = sel && sel.value ? sel.value.trim() : '';
        if (!site) return url;
        return url + (url.includes('?') ? '&' : '?') + 'site=' + encodeURIComponent(site);
    }

    async function postJSON(url, body) {
        const res = await fetch(withSite(url), {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrf,
            },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(30000),
        });
        const out = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(out.error || `${res.status} ${res.statusText}`);
        return out;
    }

    // Exact decimal string -> atomic integer string (no IEEE-754 float drift).
    function decimalToAtomic(decStr, decimals) {
        const s = String(decStr || '').trim();
        if (!s) return '';
        if (!/^\d+(\.\d+)?$/.test(s)) return s;
        if (decimals <= 0) return s.split('.')[0].replace(/^0+(?=\d)/, '') || '0';
        const [whole, frac = ''] = s.split('.');
        const padded = (frac + '0'.repeat(decimals)).slice(0, decimals);
        const joined = (whole + padded).replace(/^0+(?=\d)/, '');
        return joined || '0';
    }

    function networkChain(net) {
        return String(net || '').split(':')[0].toLowerCase();
    }

    function defaultDecimals(net, asset) {
        const c = networkChain(net);
        if (c === 'xrpl') return asset === 'XRP' ? 6 : 0;
        if (c === 'stellar') return 7;
        if (c === 'hedera') return asset === '0.0.0' ? 8 : 6;
        if (c === 'solana') return asset === 'SOL' ? 9 : 6;
        return 6;
    }

    function isXRPLIOU(net, asset) {
        return networkChain(net) === 'xrpl' && String(asset || '').trim().toUpperCase() !== 'XRP';
    }

    const NETWORK_OPTIONS = [
        ['xrpl:0', 'XRPL Mainnet (xrpl:0)'],
        ['xrpl:1', 'XRPL Testnet (xrpl:1)'],
        ['stellar:pubnet', 'Stellar Mainnet (stellar:pubnet)'],
        ['stellar:testnet', 'Stellar Testnet (stellar:testnet)'],
        ['solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'Solana Mainnet'],
        ['solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', 'Solana Devnet'],
        ['hedera:mainnet', 'Hedera Mainnet (hedera:mainnet)'],
        ['hedera:testnet', 'Hedera Testnet (hedera:testnet)'],
    ];

    const ASSET_TYPE_OPTIONS = [
        ['native', 'Native coin (XRP / XLM / SOL / HBAR)'],
        ['iou', 'XRPL IOU / Trustline (e.g. RLUSD)'],
        ['stellar_asset', 'Stellar Classic Asset (CODE:ISSUER)'],
        ['soroban_sac', 'Stellar Soroban SAC (C...)'],
        ['spl', 'Solana SPL Token'],
        ['token2022', 'Solana Token-2022'],
        ['hts', 'Hedera HTS Fungible Token (0.0.N)'],
    ];

    let state = {
        loaded: false,
        canEdit: false,
        destinationsLocked: false,
        hardened: false,
        config: null,
    };

    function showFeedback(kind, text) {
        const box = $('fastlane-save-feedback');
        if (!box) return;
        if (!text) {
            box.className = 'alert d-none';
            box.textContent = '';
            return;
        }
        box.className = 'alert alert-' + kind;
        box.textContent = text;
    }

    function updatePolicyInputs() {
        const mode = $('fl-policy-mode')?.value || 'none';
        const urlWrap = $('fl-policy-url-wrap');
        const fileWrap = $('fl-policy-file-wrap');
        const unWrap = $('fl-unscreened-wrap');
        if (urlWrap) urlWrap.classList.toggle('d-none', mode !== 'webhook');
        if (fileWrap) fileWrap.classList.toggle('d-none', mode !== 'blocklist');
        if (unWrap) unWrap.classList.toggle('d-none', mode !== 'none');
    }

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
                alertEl.textContent = `Critical: fast-lane receipt journal is at ${pct}% capacity (${used}/${max}). Click "Archive Live" below to compact expired receipts without downtime.`;
            } else if (pct >= 80) {
                alertEl.className = 'alert alert-warning';
                alertEl.textContent = `Warning: fast-lane receipt journal is at ${pct}% capacity (${used}/${max}). Use "Archive Live" to compact expired receipts.`;
            } else {
                alertEl.className = 'alert d-none';
                alertEl.textContent = '';
            }
        }
    }

    function renderSponsors(d) {
        const card = $('fastlane-sponsor-card');
        const rows = $('fastlane-sponsor-rows');
        if (!card || !rows) return;
        const list = d.sponsor_status && Array.isArray(d.sponsor_status.sponsors) ? d.sponsor_status.sponsors : [];
        rows.replaceChildren();
        if (list.length === 0) {
            card.classList.add('d-none');
            return;
        }
        card.classList.remove('d-none');
        for (const s of list) {
            const col = el('div', undefined, 'col-md-6');
            const box = el('div', undefined, 'p-2 border rounded small ' + (s.low ? 'border-danger text-danger' : 'border-secondary-subtle'));
            box.append(
                el('div', `${s.network} · ${s.account || ''}`, 'fw-semibold font-monospace text-break'),
                el('div', `Balance: ${s.balance || 'unknown'} (min ${s.min_balance || '0'}) · Spend/min: ${s.spent_last_min || 0}/${s.max_per_min || 'unlimited'}`),
            );
            col.append(box);
            rows.append(col);
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
                    const out = await postJSON('/api/fastlane/reconcile', { fingerprint: r.fingerprint, stellar_hash: stellarHash });
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

    function makeSelect(options, selected, cls) {
        const sel = el('select', undefined, cls || 'form-select form-select-sm');
        let matched = false;
        for (const [val, label] of options) {
            const opt = el('option', label);
            opt.value = val;
            if (val === selected) {
                opt.selected = true;
                matched = true;
            }
            sel.append(opt);
        }
        if (selected && !matched) {
            const opt = el('option', selected);
            opt.value = selected;
            opt.selected = true;
            sel.append(opt);
        }
        return sel;
    }

    function makeField(labelText, inputEl, colCls) {
        const col = el('div', undefined, colCls || 'col-md-4');
        const lbl = el('label', labelText, 'form-label small mb-1');
        col.append(lbl, inputEl);
        return col;
    }

    function renderOffersEditor() {
        const host = $('fastlane-offers');
        if (!host || !state.config) return;
        host.replaceChildren();
        const offers = state.config.offers || [];
        if (offers.length === 0) {
            host.append(el('p', 'No paid fast-lane passes configured. Click a chain preset button above to add one.', 'small text-body-secondary mb-0'));
            return;
        }
        const colList = state.config.collections || [];
        const tokList = state.config.token_gates || [];

        offers.forEach((o, idx) => {
            const req = o.requirements || (o.requirements = { scheme: 'exact', network: 'xrpl:0', amount: '1000000', asset: 'XRP', payTo: '', maxTimeoutSeconds: 60 });
            const card = el('div', undefined, 'border rounded p-3 bg-body-tertiary');
            const hdr = el('div', undefined, 'd-flex justify-content-between align-items-center mb-2');
            hdr.append(el('strong', `Offer #${idx + 1}: ${o.label || o.asset_symbol || req.asset}`, 'small'));
            const rmBtn = el('button', 'Remove', 'btn btn-sm btn-outline-danger py-0');
            rmBtn.type = 'button';
            rmBtn.addEventListener('click', () => {
                state.config.offers.splice(idx, 1);
                renderOffersEditor();
            });
            hdr.append(rmBtn);
            card.append(hdr);

            const row = el('div', undefined, 'row g-2');

            const labelIn = el('input', undefined, 'form-control form-control-sm');
            labelIn.value = o.label || '';
            labelIn.addEventListener('input', () => { o.label = labelIn.value; });
            row.append(makeField('Label', labelIn, 'col-md-3'));

            const netSel = makeSelect(NETWORK_OPTIONS, req.network);
            netSel.addEventListener('change', () => {
                req.network = netSel.value;
                if (!o.asset_decimals) o.asset_decimals = defaultDecimals(req.network, req.asset);
            });
            row.append(makeField('Network', netSel, 'col-md-3'));

            const typeSel = makeSelect(ASSET_TYPE_OPTIONS, o.asset_type || (isXRPLIOU(req.network, req.asset) ? 'iou' : 'native'));
            typeSel.addEventListener('change', () => { o.asset_type = typeSel.value; });
            row.append(makeField('Asset type', typeSel, 'col-md-3'));

            const symIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            symIn.value = o.asset_symbol || '';
            symIn.placeholder = 'RLUSD / USDC / XRP';
            symIn.addEventListener('input', () => { o.asset_symbol = symIn.value.trim(); });
            row.append(makeField('Symbol', symIn, 'col-md-3'));

            const assetIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            assetIn.value = req.asset || '';
            assetIn.placeholder = 'XRP, RLUSD:r..., CODE:G..., SPL mint, 0.0.N';
            assetIn.addEventListener('input', () => { req.asset = assetIn.value.trim(); });
            row.append(makeField('Asset / Issuer / Mint', assetIn, 'col-md-5'));

            const dispIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            dispIn.value = o.display_amount || '';
            dispIn.placeholder = '0.99';
            const decIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            decIn.type = 'number';
            decIn.min = '0';
            decIn.max = '18';
            decIn.value = String(o.asset_decimals ?? defaultDecimals(req.network, req.asset));

            const syncAmount = () => {
                o.display_amount = dispIn.value.trim();
                o.asset_decimals = Number(decIn.value || 0);
                if (o.display_amount) {
                    req.amount = isXRPLIOU(req.network, req.asset)
                        ? o.display_amount
                        : decimalToAtomic(o.display_amount, o.asset_decimals);
                }
            };
            dispIn.addEventListener('input', syncAmount);
            decIn.addEventListener('input', syncAmount);
            row.append(makeField('Price (human)', dispIn, 'col-md-2'));
            row.append(makeField('Decimals', decIn, 'col-md-1'));

            const payToIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            payToIn.value = req.payTo || '';
            payToIn.placeholder = 'Merchant receiving wallet';
            if (state.destinationsLocked) {
                payToIn.disabled = true;
                payToIn.title = 'Locked by -fastlane-lock-destinations';
            }
            payToIn.addEventListener('input', () => { req.payTo = payToIn.value.trim(); });
            row.append(makeField('Receiving wallet (payTo)', payToIn, 'col-md-4'));

            // Optional fee sponsorship & purchase prerequisite gates
            const optsRow = el('div', undefined, 'col-12 d-flex flex-wrap align-items-center gap-3 pt-1 small');
            const c = networkChain(req.network);
            if (c === 'stellar' || c === 'hedera') {
                const sw = el('div', undefined, 'form-check form-switch mb-0');
                const chk = el('input', undefined, 'form-check-input');
                chk.type = 'checkbox';
                chk.checked = Boolean(req.extra && req.extra.areFeesSponsored === true);
                chk.addEventListener('change', () => {
                    req.extra = req.extra || {};
                    req.extra.areFeesSponsored = chk.checked;
                });
                sw.append(chk, el('label', 'Sponsor network fees (optional hot key)', 'form-check-label'));
                optsRow.append(sw);
            }

            if (colList.length > 0 || tokList.length > 0) {
                const gmWrap = el('div', undefined, 'd-flex align-items-center gap-1');
                gmWrap.append(el('span', 'Purchase prerequisites:', 'text-body-secondary'));
                const gmSel = makeSelect([['all', 'Require ALL'], ['any', 'Require ANY']], o.gate_mode || 'all', 'form-select form-select-sm w-auto');
                gmSel.addEventListener('change', () => { o.gate_mode = gmSel.value; });
                gmWrap.append(gmSel);
                optsRow.append(gmWrap);

                o.require_collections = Array.isArray(o.require_collections) ? o.require_collections : [];
                for (const col of colList) {
                    const lbl = el('label', undefined, 'form-check form-check-inline mb-0');
                    const cb = el('input', undefined, 'form-check-input');
                    cb.type = 'checkbox';
                    cb.checked = o.require_collections.includes(col.id);
                    cb.addEventListener('change', () => {
                        const s = new Set(o.require_collections || []);
                        if (cb.checked) s.add(col.id); else s.delete(col.id);
                        o.require_collections = Array.from(s);
                    });
                    lbl.append(cb, el('span', `NFT: ${col.label || col.id}`, 'form-check-label'));
                    optsRow.append(lbl);
                }
                o.require_token_gates = Array.isArray(o.require_token_gates) ? o.require_token_gates : [];
                for (const tg of tokList) {
                    const lbl = el('label', undefined, 'form-check form-check-inline mb-0');
                    const cb = el('input', undefined, 'form-check-input');
                    cb.type = 'checkbox';
                    cb.checked = o.require_token_gates.includes(tg.id);
                    cb.addEventListener('change', () => {
                        const s = new Set(o.require_token_gates || []);
                        if (cb.checked) s.add(tg.id); else s.delete(tg.id);
                        o.require_token_gates = Array.from(s);
                    });
                    lbl.append(cb, el('span', `Token: ${tg.label || tg.id}`, 'form-check-label'));
                    optsRow.append(lbl);
                }
            }
            if (optsRow.childNodes.length > 0) row.append(optsRow);

            card.append(row);
            host.append(card);
        });
    }

    function renderCollectionsEditor() {
        const host = $('fastlane-collections');
        if (!host || !state.config) return;
        host.replaceChildren();
        const list = state.config.collections || [];
        if (list.length === 0) {
            host.append(el('p', 'No NFT collection rules configured.', 'small text-body-secondary mb-0'));
            return;
        }
        list.forEach((c, idx) => {
            const card = el('div', undefined, 'border rounded p-2 bg-body-tertiary');
            const hdr = el('div', undefined, 'd-flex justify-content-between align-items-center mb-2');
            hdr.append(el('strong', `NFT Rule #${idx + 1}: ${c.label || c.id}`, 'small'));
            const rm = el('button', 'Remove', 'btn btn-sm btn-outline-danger py-0');
            rm.type = 'button';
            rm.addEventListener('click', () => {
                state.config.collections.splice(idx, 1);
                renderCollectionsEditor();
                renderOffersEditor();
            });
            hdr.append(rm);
            card.append(hdr);

            const row = el('div', undefined, 'row g-2');
            const idIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            idIn.value = c.id || '';
            idIn.addEventListener('input', () => { c.id = idIn.value.trim(); });
            row.append(makeField('Rule ID', idIn, 'col-md-4'));

            const lblIn = el('input', undefined, 'form-control form-control-sm');
            lblIn.value = c.label || '';
            lblIn.addEventListener('input', () => { c.label = lblIn.value; });
            row.append(makeField('Display label', lblIn, 'col-md-4'));

            const useSel = makeSelect([
                ['entry', 'Hold to Enter (free pass)'],
                ['purchase_gate', 'Hold to Buy (offer prerequisite)'],
                ['both', 'Both (enter free or buy)'],
            ], c.usage || 'entry');
            useSel.addEventListener('change', () => { c.usage = useSel.value; });
            row.append(makeField('Usage mode', useSel, 'col-md-4'));

            const netSel = makeSelect(NETWORK_OPTIONS, c.network || 'xrpl:0');
            netSel.addEventListener('change', () => { c.network = netSel.value; });
            row.append(makeField('Network', netSel, 'col-md-5'));

            const colIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            colIn.value = c.collection || '';
            colIn.placeholder = 'issuer:taxon | issuer:* | C... | 0.0.N | Metaplex mint';
            colIn.addEventListener('input', () => { c.collection = colIn.value.trim(); });
            row.append(makeField('Collection ID', colIn, 'col-md-7'));

            const issIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            issIn.value = c.issuer || '';
            issIn.placeholder = 'Optional issuing / treasury address check';
            issIn.addEventListener('input', () => { c.issuer = issIn.value.trim(); });
            row.append(makeField('Issuing address (optional)', issIn, 'col-12'));

            card.append(row);
            host.append(card);
        });
    }

    function renderTokenGatesEditor() {
        const host = $('fastlane-token-gates');
        if (!host || !state.config) return;
        host.replaceChildren();
        const list = state.config.token_gates || [];
        if (list.length === 0) {
            host.append(el('p', 'No token / trustline balance rules configured.', 'small text-body-secondary mb-0'));
            return;
        }
        list.forEach((tg, idx) => {
            const card = el('div', undefined, 'border rounded p-2 bg-body-tertiary');
            const hdr = el('div', undefined, 'd-flex justify-content-between align-items-center mb-2');
            hdr.append(el('strong', `Token Rule #${idx + 1}: ${tg.label || tg.id}`, 'small'));
            const rm = el('button', 'Remove', 'btn btn-sm btn-outline-danger py-0');
            rm.type = 'button';
            rm.addEventListener('click', () => {
                state.config.token_gates.splice(idx, 1);
                renderTokenGatesEditor();
                renderOffersEditor();
            });
            hdr.append(rm);
            card.append(hdr);

            const row = el('div', undefined, 'row g-2');
            const idIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            idIn.value = tg.id || '';
            idIn.addEventListener('input', () => { tg.id = idIn.value.trim(); });
            row.append(makeField('Rule ID', idIn, 'col-md-4'));

            const lblIn = el('input', undefined, 'form-control form-control-sm');
            lblIn.value = tg.label || '';
            lblIn.addEventListener('input', () => { tg.label = lblIn.value; });
            row.append(makeField('Display label', lblIn, 'col-md-4'));

            const useSel = makeSelect([
                ['both', 'Both (enter or buy)'],
                ['entry', 'Hold to Enter (free pass)'],
                ['purchase_gate', 'Hold to Buy (offer prerequisite)'],
            ], tg.usage || 'both');
            useSel.addEventListener('change', () => { tg.usage = useSel.value; });
            row.append(makeField('Usage mode', useSel, 'col-md-4'));

            const netSel = makeSelect(NETWORK_OPTIONS, tg.network || 'xrpl:0');
            netSel.addEventListener('change', () => { tg.network = netSel.value; });
            row.append(makeField('Network', netSel, 'col-md-5'));

            const assetIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            assetIn.value = tg.asset || '';
            assetIn.placeholder = 'RLUSD:r..., CODE:G..., SPL mint, 0.0.N';
            assetIn.addEventListener('input', () => { tg.asset = assetIn.value.trim(); });
            row.append(makeField('Token / Trustline Asset', assetIn, 'col-md-7'));

            const symIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            symIn.value = tg.asset_symbol || '';
            symIn.placeholder = 'RLUSD';
            symIn.addEventListener('input', () => { tg.asset_symbol = symIn.value.trim(); });
            row.append(makeField('Symbol', symIn, 'col-md-4'));

            const minIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            minIn.value = tg.display_min_amount || tg.min_amount || '';
            minIn.placeholder = '10';
            const decIn = el('input', undefined, 'form-control form-control-sm font-monospace');
            decIn.type = 'number';
            decIn.min = '0';
            decIn.max = '18';
            decIn.value = String(tg.asset_decimals ?? defaultDecimals(tg.network, tg.asset));
            const syncMin = () => {
                tg.display_min_amount = minIn.value.trim();
                tg.asset_decimals = Number(decIn.value || 0);
                tg.min_amount = isXRPLIOU(tg.network, tg.asset)
                    ? tg.display_min_amount
                    : decimalToAtomic(tg.display_min_amount, tg.asset_decimals);
            };
            minIn.addEventListener('input', syncMin);
            decIn.addEventListener('input', syncMin);
            row.append(makeField('Min balance (human)', minIn, 'col-md-5'));
            row.append(makeField('Decimals', decIn, 'col-md-3'));

            card.append(row);
            host.append(card);
        });
    }

    function addPresetOffer(key) {
        if (!state.config) return;
        const test = Boolean($('fl-test-mode')?.checked);
        const presets = {
            'xrpl-rlusd': {
                label: 'RLUSD Fast Pass',
                asset_symbol: 'RLUSD',
                asset_type: 'iou',
                asset_decimals: 0,
                display_amount: '0.99',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'xrpl:1' : 'xrpl:0',
                    asset: test ? 'RLUSD:rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV' : 'RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De',
                    amount: '0.99',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                    extra: { areFeesSponsored: false },
                },
            },
            'xrpl-xrp': {
                label: 'XRP Fast Pass',
                asset_symbol: 'XRP',
                asset_type: 'native',
                asset_decimals: 6,
                display_amount: '1',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'xrpl:1' : 'xrpl:0',
                    asset: 'XRP',
                    amount: '1000000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                    extra: { areFeesSponsored: false },
                },
            },
            'stellar-usdc': {
                label: 'Stellar USDC Pass',
                asset_symbol: 'USDC',
                asset_type: 'stellar_asset',
                asset_decimals: 7,
                display_amount: '0.99',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'stellar:testnet' : 'stellar:pubnet',
                    asset: test ? 'USDC:GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5' : 'USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
                    amount: '9900000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                    extra: { areFeesSponsored: false },
                },
            },
            'stellar-xlm': {
                label: 'XLM Fast Pass',
                asset_symbol: 'XLM',
                asset_type: 'native',
                asset_decimals: 7,
                display_amount: '5',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'stellar:testnet' : 'stellar:pubnet',
                    asset: 'XLM',
                    amount: '50000000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                    extra: { areFeesSponsored: false },
                },
            },
            'solana-usdc': {
                label: 'Solana USDC Pass',
                asset_symbol: 'USDC',
                asset_type: 'spl',
                asset_decimals: 6,
                display_amount: '0.99',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1' : 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
                    asset: test ? '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU' : 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
                    amount: '990000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                },
            },
            'solana-sol': {
                label: 'SOL Fast Pass',
                asset_symbol: 'SOL',
                asset_type: 'native',
                asset_decimals: 9,
                display_amount: '0.01',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1' : 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
                    asset: 'SOL',
                    amount: '10000000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                },
            },
            'hedera-usdc': {
                label: 'Hedera USDC Pass',
                asset_symbol: 'USDC',
                asset_type: 'hts',
                asset_decimals: 6,
                display_amount: '0.99',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'hedera:testnet' : 'hedera:mainnet',
                    asset: test ? '0.0.429274' : '0.0.456858',
                    amount: '990000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                    extra: { areFeesSponsored: false },
                },
            },
            'hedera-hbar': {
                label: 'HBAR Fast Pass',
                asset_symbol: 'HBAR',
                asset_type: 'native',
                asset_decimals: 8,
                display_amount: '10',
                requirements: {
                    scheme: 'exact',
                    network: test ? 'hedera:testnet' : 'hedera:mainnet',
                    asset: '0.0.0',
                    amount: '1000000000',
                    payTo: '',
                    maxTimeoutSeconds: 60,
                    extra: { areFeesSponsored: false },
                },
            },
        };
        const p = presets[key];
        if (!p) return;
        state.config.offers = state.config.offers || [];
        state.config.offers.push(structuredClone(p));
        renderOffersEditor();
    }

    function populateEditor(d) {
        state.config = {
            enabled: Boolean(d.enabled),
            test_mode: Boolean(d.test_mode),
            origin: d.origin || '',
            merchant: d.merchant || '',
            terms_url: d.terms_url || '',
            privacy_url: d.privacy_url || '',
            refund_url: d.refund_url || '',
            policy_mode: d.policy_mode || 'none',
            policy_url: d.policy_url || '',
            policy_blocklist_file: d.policy_blocklist_file || '',
            allow_unscreened_mainnet: Boolean(d.allow_unscreened_mainnet),
            pass_seconds: Number(d.pass_seconds || 300),
            pass_idle_seconds: Number(d.pass_idle_seconds || d.pass_seconds || 180),
            pass_max_seconds: Number(d.pass_max_seconds || 1800),
            pass_sliding: d.pass_sliding !== false,
            nft_pass_seconds: Number(d.nft_pass_seconds || 300),
            direct_pay_enabled: d.direct_pay_enabled !== false,
            direct_challenge_seconds: Number(d.direct_challenge_seconds || 600),
            max_records: Number(d.max_records || d.capacity || 100000),
            verify_addresses: Object.assign({}, d.verify_addresses || {}),
            offers: Array.isArray(d.offers) ? structuredClone(d.offers) : [],
            collections: Array.isArray(d.collections) ? structuredClone(d.collections) : [],
            token_gates: Array.isArray(d.token_gates) ? structuredClone(d.token_gates) : [],
        };

        $('fl-enabled').checked = state.config.enabled;
        $('fl-test-mode').checked = state.config.test_mode;
        $('fl-merchant').value = state.config.merchant;
        $('fl-origin').value = state.config.origin;
        $('fl-terms-url').value = state.config.terms_url;
        $('fl-privacy-url').value = state.config.privacy_url;
        $('fl-refund-url').value = state.config.refund_url;
        $('fl-policy-mode').value = state.config.policy_mode;
        $('fl-policy-url').value = state.config.policy_url;
        $('fl-policy-file').value = state.config.policy_blocklist_file;
        $('fl-allow-unscreened').checked = state.config.allow_unscreened_mainnet;
        $('fl-pass-secs').value = String(state.config.pass_seconds);
        $('fl-pass-idle').value = String(state.config.pass_idle_seconds);
        $('fl-pass-max').value = String(state.config.pass_max_seconds);
        $('fl-nft-secs').value = String(state.config.nft_pass_seconds);
        $('fl-pass-sliding').checked = state.config.pass_sliding;
        $('fl-direct-pay').checked = state.config.direct_pay_enabled;

        const va = state.config.verify_addresses || {};
        for (const [k, id] of [['xrpl', 'fl-verify-xrpl'], ['stellar', 'fl-verify-stellar'], ['solana', 'fl-verify-solana'], ['hedera', 'fl-verify-hedera']]) {
            const inp = $(id);
            if (!inp) continue;
            inp.value = va[k] || '';
            inp.disabled = state.destinationsLocked;
        }
        if ($('fl-mfa-wrap')) $('fl-mfa-wrap').classList.toggle('d-none', !state.hardened || state.destinationsLocked);

        updatePolicyInputs();
        renderOffersEditor();
        renderCollectionsEditor();
        renderTokenGatesEditor();
    }

    function collectEditorConfig() {
        const cfg = structuredClone(state.config);
        cfg.enabled = $('fl-enabled').checked;
        cfg.test_mode = $('fl-test-mode').checked;
        cfg.merchant = $('fl-merchant').value.trim();
        cfg.origin = $('fl-origin').value.trim();
        cfg.terms_url = $('fl-terms-url').value.trim();
        cfg.privacy_url = $('fl-privacy-url').value.trim();
        cfg.refund_url = $('fl-refund-url').value.trim();
        cfg.policy_mode = $('fl-policy-mode').value;
        cfg.policy_url = $('fl-policy-url').value.trim();
        cfg.policy_blocklist_file = $('fl-policy-file').value.trim();
        cfg.allow_unscreened_mainnet = $('fl-allow-unscreened').checked;
        cfg.pass_seconds = Number($('fl-pass-secs').value || 300);
        cfg.pass_idle_seconds = Number($('fl-pass-idle').value || 180);
        cfg.pass_max_seconds = Number($('fl-pass-max').value || 1800);
        cfg.nft_pass_seconds = Number($('fl-nft-secs').value || 300);
        cfg.pass_sliding = $('fl-pass-sliding').checked;
        cfg.direct_pay_enabled = $('fl-direct-pay').checked;

        const va = {};
        for (const [k, id] of [['xrpl', 'fl-verify-xrpl'], ['stellar', 'fl-verify-stellar'], ['solana', 'fl-verify-solana'], ['hedera', 'fl-verify-hedera']]) {
            const v = ($(id)?.value || '').trim();
            if (v) va[k] = v;
        }
        cfg.verify_addresses = Object.keys(va).length > 0 ? va : undefined;
        return cfg;
    }

    async function saveConfig() {
        if (!state.config) return;
        const btns = [$('fastlane-save-top'), $('fastlane-save-bottom')].filter(Boolean);
        btns.forEach((b) => { b.disabled = true; });
        showFeedback('info', 'Validating and applying fast-lane configuration live…');
        try {
            const cfg = collectEditorConfig();
            const mfa = ($('fl-mfa-code')?.value || '').trim();
            const out = await postJSON('/api/fastlane/config', { config: cfg, mfa_code: mfa });
            showFeedback('success', 'Saved and applied live with zero downtime.' + (out.destinations_changed ? ' Receiving wallets changed — Critical alert dispatched and audited.' : ''));
            if ($('fl-mfa-code')) $('fl-mfa-code').value = '';
            await load();
        } catch (err) {
            showFeedback('danger', 'Save failed: ' + err.message);
        } finally {
            btns.forEach((b) => { b.disabled = false; });
        }
    }

    async function runArchive(dryRun) {
        const st = $('fastlane-archive-status');
        const older = $('fastlane-archive-age')?.value || '720h';
        if (st) {
            st.className = 'small mt-2 text-body-secondary';
            st.textContent = (dryRun ? 'Previewing' : 'Archiving') + ` expired receipts older than ${older}…`;
        }
        try {
            const out = await postJSON('/api/fastlane/archive', { older_than: older, dry_run: dryRun });
            const rep = out.report || {};
            if (st) {
                st.className = 'small mt-2 text-success';
                st.textContent = dryRun
                    ? `Dry run: ${rep.archived || 0} receipt(s) would be archived, ${rep.kept || 0} kept.`
                    : `Archived ${rep.archived || 0} expired receipt(s) live (${rep.kept || 0} kept)` + (rep.archive_file ? ` → ${rep.archive_file}` : '.');
            }
            if (!dryRun) await load();
        } catch (err) {
            if (st) {
                st.className = 'small mt-2 text-danger';
                st.textContent = 'Archive failed: ' + err.message;
            }
        }
    }

    async function runRevoke() {
        const input = $('fastlane-revoke-target');
        const st = $('fastlane-revoke-status');
        const target = (input?.value || '').trim();
        if (!target) {
            if (st) {
                st.className = 'small mt-2 text-danger';
                st.textContent = 'Enter a session ID or pass ID first.';
            }
            return;
        }
        try {
            const out = await postJSON('/api/fastlane/revoke', { target });
            if (st) {
                st.className = 'small mt-2 text-success';
                st.textContent = `Revoked "${out.target}" immediately (propagated to cluster edges if Redis is configured).`;
            }
            if (input) input.value = '';
        } catch (err) {
            if (st) {
                st.className = 'small mt-2 text-danger';
                st.textContent = 'Revoke failed: ' + err.message;
            }
        }
    }

    async function load() {
        try {
            const r = await fetch(withSite('/api/fastlane'), { credentials: 'same-origin', signal: AbortSignal.timeout(8000) });
            if (!r.ok) throw Error('Sign in again to view fast-lane configuration.');
            const d = await r.json();
            state.canEdit = Boolean(d.can_edit);
            state.destinationsLocked = Boolean(d.destinations_locked);
            state.hardened = Boolean(d.hardened);

            $('fastlane-stats').replaceChildren();
            if ($('fastlane-lock-badge')) $('fastlane-lock-badge').classList.toggle('d-none', !state.destinationsLocked);

            if (!d.can_edit && !d.enabled) {
                $('fastlane-state').className = 'alert alert-info';
                $('fastlane-state').textContent = 'Wallet fast-lane is off for this site. Configure -fastlane-config (or fastlane_config in Concertfile) to enable live editing.';
                for (const id of ['fastlane-editor', 'fastlane-headroom-card', 'fastlane-unresolved-card', 'fastlane-sponsor-card', 'fastlane-revoke-card', 'fastlane-save-top', 'fastlane-mode-badge', 'fastlane-policy-badge']) {
                    if ($(id)) $(id).classList.add('d-none');
                }
                if ($('fastlane-capacity-alert')) $('fastlane-capacity-alert').className = 'alert d-none';
                return;
            }

            if ($('fastlane-mode-badge')) {
                const mb = $('fastlane-mode-badge');
                mb.classList.remove('d-none', 'text-bg-warning', 'text-bg-success');
                mb.classList.add(d.test_mode ? 'text-bg-warning' : 'text-bg-success');
                mb.textContent = d.test_mode ? 'TESTNET ONLY' : 'LIVE MAINNET';
            }
            if ($('fastlane-policy-badge')) {
                const pb = $('fastlane-policy-badge');
                pb.classList.remove('d-none', 'text-bg-info', 'text-bg-secondary', 'text-bg-danger');
                const pm = d.policy_mode || 'none';
                pb.classList.add(pm === 'none' && !d.test_mode ? 'text-bg-danger' : 'text-bg-info');
                pb.textContent = 'Policy: ' + pm.toUpperCase();
            }

            $('fastlane-state').className = d.healthy ? 'alert alert-info' : 'alert alert-danger';
            $('fastlane-state').textContent = (d.test_mode ? 'TEST MODE · Test networks only. ' : 'MAINNET LIVE · ') +
                (d.healthy ? 'Receipt journal healthy.' : 'Receipt journal needs attention; admission suspended.') +
                (d.merchant ? ' Merchant: ' + d.merchant : '');

            const st = d.states || { settled: 0, pending: 0, unknown: 0 };
            for (const [name, value] of [
                ['Settled sessions', st.settled || 0],
                ['Needs reconciliation', (st.pending || 0) + (st.unknown || 0)],
                ['Paid pass (idle / max)', d.pass_sliding ? `${d.pass_idle_seconds || d.pass_seconds}s / ${d.pass_max_seconds || d.pass_seconds}s` : `${d.pass_seconds || 0}s fixed`],
                ['NFT / token lease', (d.nft_pass_seconds || 0) + 's'],
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
            renderSponsors(d);
            renderUnresolved(d);
            populateEditor(d);

            if ($('fastlane-editor')) $('fastlane-editor').classList.remove('d-none');
            if ($('fastlane-save-top')) $('fastlane-save-top').classList.remove('d-none');
            if ($('fastlane-revoke-card')) $('fastlane-revoke-card').classList.remove('d-none');
        } catch (e) {
            $('fastlane-state').className = 'alert alert-warning';
            $('fastlane-state').textContent = e.message;
        }
    }

    $('fastlane-refresh')?.addEventListener('click', load);
    $('tab-fastlane-btn')?.addEventListener('shown.bs.tab', load);
    $('site-selector')?.addEventListener('change', load);
    $('fl-policy-mode')?.addEventListener('change', updatePolicyInputs);
    $('fastlane-save-top')?.addEventListener('click', saveConfig);
    $('fastlane-save-bottom')?.addEventListener('click', saveConfig);
    $('fastlane-archive-dry')?.addEventListener('click', () => runArchive(true));
    $('fastlane-archive-run')?.addEventListener('click', () => runArchive(false));
    $('fastlane-revoke-btn')?.addEventListener('click', runRevoke);

    $('fl-offer-presets')?.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-preset]');
        if (btn) addPresetOffer(btn.getAttribute('data-preset'));
    });

    $('fl-add-collection')?.addEventListener('click', () => {
        if (!state.config) return;
        const test = Boolean($('fl-test-mode')?.checked);
        const n = (state.config.collections || []).length + 1;
        state.config.collections = state.config.collections || [];
        state.config.collections.push({
            id: 'nft-' + n,
            label: 'NFT Collection #' + n,
            network: test ? 'xrpl:1' : 'xrpl:0',
            collection: '',
            issuer: '',
            usage: 'entry',
        });
        renderCollectionsEditor();
        renderOffersEditor();
    });

    $('fl-add-token-gate')?.addEventListener('click', () => {
        if (!state.config) return;
        const test = Boolean($('fl-test-mode')?.checked);
        const n = (state.config.token_gates || []).length + 1;
        state.config.token_gates = state.config.token_gates || [];
        state.config.token_gates.push({
            id: 'token-' + n,
            label: 'Token Holders #' + n,
            network: test ? 'xrpl:1' : 'xrpl:0',
            asset: test ? 'RLUSD:rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV' : 'RLUSD:rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De',
            asset_symbol: 'RLUSD',
            asset_decimals: 0,
            min_amount: '10',
            display_min_amount: '10',
            usage: 'both',
        });
        renderTokenGatesEditor();
        renderOffersEditor();
    });

    load();
})();
