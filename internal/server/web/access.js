'use strict';
(() => {
    const $ = (id) => document.getElementById(id);
    let config, csrf = '', session = '', nonce = '', busy = false, pending = null, hasAccess = false;
    let holdRules = [];
    let directPollTimer = null;
    let activeDirect = { payment: null, proof: null };

    // Resolve the return target the way the browser will and keep it only on this origin.
    const back = (() => {
        try {
            const u = new URL(new URLSearchParams(location.search).get('return') || '/', location.origin);
            return u.origin === location.origin && !u.pathname.startsWith('/_concert') ? u.pathname + u.search + u.hash : '/';
        } catch {
            return '/';
        }
    })();
    $('return').href = back;
    $('enter').href = back;

    const say = (m) => { $('message').hidden = false; $('message').textContent = m; };

    async function call(path, body, headers = {}) {
        const r = await fetch('/_concert' + path, {
            method: body === undefined ? 'GET' : 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json', 'X-Concert-CSRF': csrf, ...headers },
            body: body === undefined ? undefined : JSON.stringify(body),
            signal: AbortSignal.timeout(path === '/payment' ? 420000 : 50000),
        });
        const data = await r.json().catch(() => ({}));
        return { r, data };
    }

    const nonceOf = (token) => String(token || '').split('.')[0];
    async function renew() {
        const s = await post('/session', {});
        csrf = s.csrf;
        session = s.session;
    }
    async function send(path, body, headers) {
        let x = await call(path, body, headers);
        if (x.r.status === 409 && x.data.error === 'session_renewal_required') {
            await renew();
            x = await call(path, body, headers);
        }
        return x;
    }
    async function post(path, body, headers = {}) {
        const { r, data } = await send(path, body, headers);
        if (!r.ok) throw Error(data.error || 'Request could not be completed');
        return data;
    }
    async function run(fn) {
        if (busy) return;
        busy = true;
        for (const b of document.querySelectorAll('button')) b.disabled = true;
        try {
            await fn();
        } catch (e) {
            say(String(e.message || e).replaceAll('_', ' '));
        } finally {
            busy = false;
            for (const b of document.querySelectorAll('button')) b.disabled = false;
            availability();
        }
    }

    // ── Pure-JS ISO/IEC 18004 QR Code SVG Generator (Versions 1–10, EC Level L) ──
    // Zero external dependencies; renders a single crisp inline <svg> path (strict CSP safe).
    const makeQRSvg = (() => {
        const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
        let x = 1;
        for (let i = 0; i < 255; i++) {
            EXP[i] = x;
            LOG[x] = i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
        for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
        const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

        // [g1Blocks, g1Data, g2Blocks, g2Data, ecPerBlock, alignCoords]
        const VER = [
            null,
            [1, 19, 0, 0, 7, []],
            [1, 34, 0, 0, 10, [6, 18]],
            [1, 55, 0, 0, 15, [6, 22]],
            [1, 80, 0, 0, 20, [6, 26]],
            [1, 108, 0, 0, 26, [6, 30]],
            [2, 68, 0, 0, 18, [6, 34]],
            [2, 78, 0, 0, 20, [6, 22, 38]],
            [2, 97, 0, 0, 24, [6, 24, 42]],
            [2, 116, 0, 0, 30, [6, 26, 46]],
            [2, 68, 2, 69, 18, [6, 28, 50]],
        ];

        function rsGen(deg) {
            let p = [1];
            for (let i = 0; i < deg; i++) {
                const next = new Array(p.length + 1).fill(0);
                for (let j = 0; j < p.length; j++) {
                    next[j] ^= p[j];
                    next[j + 1] ^= mul(p[j], EXP[i]);
                }
                p = next;
            }
            return p;
        }

        function rsEC(data, ecLen) {
            const gen = rsGen(ecLen);
            const rem = new Uint8Array(ecLen);
            for (const b of data) {
                const f = b ^ rem[0];
                rem.copyWithin(0, 1);
                rem[ecLen - 1] = 0;
                for (let j = 0; j < ecLen; j++) rem[j] ^= mul(gen[j + 1], f);
            }
            return rem;
        }

        function bch(val, poly, dataBits, totalBits) {
            const shift = totalBits - dataBits;
            let r = val << shift;
            for (let i = totalBits - 1; i >= shift; i--) {
                if ((r >> i) & 1) r ^= poly << (i - shift);
            }
            return (val << shift) | r;
        }

        function encode(text) {
            const bytes = new TextEncoder().encode(text);
            let v = 0;
            for (let cand = 1; cand < VER.length; cand++) {
                const [g1b, g1d, g2b, g2d] = VER[cand];
                const capBytes = g1b * g1d + g2b * g2d;
                const hdrBits = 4 + (cand >= 10 ? 16 : 8);
                if (hdrBits + bytes.length * 8 <= capBytes * 8) {
                    v = cand;
                    break;
                }
            }
            if (!v) return null;
            const [g1b, g1d, g2b, g2d, ecLen, aligns] = VER[v];
            const totalData = g1b * g1d + g2b * g2d;

            // Pack bit stream: mode 0100 (Byte) + count + bytes + terminator + pad bytes.
            const bits = [];
            const push = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >> i) & 1); };
            push(0b0100, 4);
            push(bytes.length, v >= 10 ? 16 : 8);
            for (const b of bytes) push(b, 8);
            push(0, Math.min(4, totalData * 8 - bits.length));
            while (bits.length % 8) bits.push(0);
            const cw = [];
            for (let i = 0; i < bits.length; i += 8) {
                let b = 0;
                for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
                cw.push(b);
            }
            for (let p = 0; cw.length < totalData; p++) cw.push(p % 2 === 0 ? 0xec : 0x11);

            // Split into RS blocks & interleave.
            const dataBlocks = [], ecBlocks = [];
            let off = 0;
            for (let i = 0; i < g1b; i++) {
                const blk = cw.slice(off, off + g1d);
                off += g1d;
                dataBlocks.push(blk);
                ecBlocks.push(rsEC(blk, ecLen));
            }
            for (let i = 0; i < g2b; i++) {
                const blk = cw.slice(off, off + g2d);
                off += g2d;
                dataBlocks.push(blk);
                ecBlocks.push(rsEC(blk, ecLen));
            }
            const stream = [];
            const maxD = Math.max(g1d, g2d);
            for (let i = 0; i < maxD; i++) {
                for (const b of dataBlocks) if (i < b.length) stream.push(b[i]);
            }
            for (let i = 0; i < ecLen; i++) {
                for (const b of ecBlocks) stream.push(b[i]);
            }

            const N = 17 + 4 * v;
            const mod = Array.from({ length: N }, () => new Uint8Array(N));
            const fn = Array.from({ length: N }, () => new Uint8Array(N));
            const setFn = (r, c, val) => {
                if (r >= 0 && r < N && c >= 0 && c < N) {
                    mod[r][c] = val ? 1 : 0;
                    fn[r][c] = 1;
                }
            };

            // Finder patterns + separators
            for (const [fr, fc] of [[0, 0], [0, N - 7], [N - 7, 0]]) {
                for (let dr = -1; dr <= 7; dr++) {
                    for (let dc = -1; dc <= 7; dc++) {
                        const inside = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
                        const dark = inside && (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
                        setFn(fr + dr, fc + dc, dark);
                    }
                }
            }
            // Alignment patterns
            for (const ar of aligns) {
                for (const ac of aligns) {
                    if (fn[ar][ac]) continue;
                    for (let dr = -2; dr <= 2; dr++) {
                        for (let dc = -2; dc <= 2; dc++) {
                            const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
                            setFn(ar + dr, ac + dc, dark);
                        }
                    }
                }
            }
            // Timing patterns & dark module
            for (let i = 8; i < N - 8; i++) {
                setFn(6, i, i % 2 === 0);
                setFn(i, 6, i % 2 === 0);
            }
            setFn(4 * v + 9, 8, 1);

            // Reserve format info modules
            for (let i = 0; i < 9; i++) {
                if (i !== 6) { setFn(8, i, 0); setFn(i, 8, 0); }
            }
            for (let i = 0; i < 8; i++) { setFn(8, N - 1 - i, 0); setFn(N - 1 - i, 8, 0); }
            setFn(4 * v + 9, 8, 1);

            // Version info (v >= 7)
            if (v >= 7) {
                const vbits = bch(v, 0x1f25, 6, 18);
                for (let i = 0; i < 18; i++) {
                    const bit = (vbits >> i) & 1;
                    const a = Math.floor(i / 3), b = N - 11 + (i % 3);
                    setFn(a, b, bit);
                    setFn(b, a, bit);
                }
            }

            // Place data bits in zig-zag columns
            let bitIdx = 0;
            const totalBits = stream.length * 8;
            for (let col = N - 1; col > 0; col -= 2) {
                if (col === 6) col--;
                const up = (((N - 1 - col) >> 1) & 1) === 0;
                for (let step = 0; step < N; step++) {
                    const r = up ? N - 1 - step : step;
                    for (let dx = 0; dx < 2; dx++) {
                        const c = col - dx;
                        if (fn[r][c]) continue;
                        let bit = 0;
                        if (bitIdx < totalBits) {
                            bit = (stream[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
                            bitIdx++;
                        }
                        mod[r][c] = bit;
                    }
                }
            }

            const masks = [
                (r, c) => (r + c) % 2 === 0,
                (r) => r % 2 === 0,
                (_, c) => c % 3 === 0,
                (r, c) => (r + c) % 3 === 0,
                (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
                (r, c) => ((r * c) % 2 + (r * c) % 3) === 0,
                (r, c) => (((r * c) % 2 + (r * c) % 3) % 2) === 0,
                (r, c) => (((r + c) % 2 + (r * c) % 3) % 2) === 0,
            ];

            function applyFormat(grid, m) {
                const fmt = bch((0b01 << 3) | m, 0x537, 5, 15) ^ 0x5412;
                const coords1 = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
                const coords2 = [[N - 1, 8], [N - 2, 8], [N - 3, 8], [N - 4, 8], [N - 5, 8], [N - 6, 8], [N - 7, 8], [8, N - 8], [8, N - 7], [8, N - 6], [8, N - 5], [8, N - 4], [8, N - 3], [8, N - 2], [8, N - 1]];
                for (let i = 0; i < 15; i++) {
                    const bit = (fmt >> (14 - i)) & 1;
                    grid[coords1[i][0]][coords1[i][1]] = bit;
                    grid[coords2[i][0]][coords2[i][1]] = bit;
                }
            }

            function score(g) {
                let p = 0, dark = 0;
                for (let r = 0; r < N; r++) {
                    let runR = 1, runC = 1;
                    for (let c = 0; c < N; c++) {
                        dark += g[r][c];
                        if (c > 0) {
                            if (g[r][c] === g[r][c - 1]) { runR++; if (runR === 5) p += 3; else if (runR > 5) p++; } else runR = 1;
                            if (g[c][r] === g[c - 1][r]) { runC++; if (runC === 5) p += 3; else if (runC > 5) p++; } else runC = 1;
                        }
                        if (r < N - 1 && c < N - 1) {
                            const s = g[r][c] + g[r][c + 1] + g[r + 1][c] + g[r + 1][c + 1];
                            if (s === 0 || s === 4) p += 3;
                        }
                    }
                }
                const pct = Math.abs(Math.round((dark * 100) / (N * N)) - 50);
                p += Math.floor(pct / 5) * 10;
                return p;
            }

            let bestGrid = null, bestScore = Infinity;
            for (let m = 0; m < 8; m++) {
                const g = mod.map((row, r) => row.map((v0, c) => (fn[r][c] ? v0 : v0 ^ (masks[m](r, c) ? 1 : 0))));
                applyFormat(g, m);
                const sc = score(g);
                if (sc < bestScore) { bestScore = sc; bestGrid = g; }
            }
            return { N, grid: bestGrid };
        }

        return function renderSVG(text) {
            const res = encode(text);
            if (!res) return null;
            const { N, grid } = res;
            const quiet = 4, size = N + quiet * 2;
            let d = '';
            for (let r = 0; r < N; r++) {
                for (let c = 0; c < N; c++) {
                    if (grid[r][c]) d += `M${c + quiet},${r + quiet}h1v1h-1z`;
                }
            }
            const ns = 'http://www.w3.org/2000/svg';
            const svg = document.createElementNS(ns, 'svg');
            svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
            svg.setAttribute('shape-rendering', 'crispEdges');
            svg.setAttribute('role', 'img');
            const bg = document.createElementNS(ns, 'rect');
            bg.setAttribute('width', String(size));
            bg.setAttribute('height', String(size));
            bg.setAttribute('fill', '#ffffff');
            const path = document.createElementNS(ns, 'path');
            path.setAttribute('d', d);
            path.setAttribute('fill', '#110d21');
            svg.append(bg, path);
            return svg;
        };
    })();

    function stopDirectPolling() {
        if (directPollTimer) {
            clearInterval(directPollTimer);
            directPollTimer = null;
        }
    }

    function availability() {
        if (!config) return;
        const hasOffers = (config.offers || []).length > 0;
        const consent = $('consent').checked;
        $('pay').disabled = !consent || !hasOffers || !!pending || hasAccess;
        $('pay-direct').disabled = !consent || !hasOffers || hasAccess;
        $('submit-payment').disabled = !consent || !hasOffers || hasAccess;
        $('retry-payment').disabled = !consent || !pending;

        const chosenHold = holdRules[Number($('collection').value)];
        const hasHold = !!chosenHold;
        const isNFT = chosenHold?.kind === 'nft';
        $('prove-direct').disabled = !hasHold || hasAccess;
        $('prove').disabled = !isNFT || hasAccess;
        $('challenge').disabled = !isNFT || hasAccess;
        $('token-id-wrap').hidden = !isNFT;
    }

    function forgetPending() {
        sessionStorage.removeItem('concert.pending-payment');
        pending = null;
        $('retry-payment').hidden = true;
    }

    function ruleLabelByID(id, list) {
        const hit = (list || []).find((x) => x.id === id);
        return hit ? hit.label : id;
    }

    function formatOfferPrice(o) {
        if (!o) return 'Not offered';
        if (o.display_amount && o.asset_symbol) return `${o.display_amount} ${o.asset_symbol}`;
        const r = o.requirements;
        const chain = r.network.split(':')[0];
        if (chain === 'xrpl' && r.asset !== 'XRP') {
            return `${r.amount} ${o.asset_symbol || r.asset.split(':')[0]}`;
        }
        const d = o.asset_decimals || ({ xrpl: 6, stellar: 7, hedera: 8, solana: 9 }[chain] || 6);
        const sym = o.asset_symbol || ({ xrpl: 'XRP', stellar: 'XLM', hedera: 'HBAR', solana: 'SOL' }[chain] || r.asset);
        const s = String(r.amount).padStart(d + 1, '0');
        return s.slice(0, -d) + '.' + s.slice(-d).replace(/0+$/, '').padEnd(1, '0') + ' ' + sym;
    }

    function price() {
        const o = (config.offers || [])[Number($('offer').value)];
        if (!o) {
            $('price').textContent = 'Not offered';
            $('recipient').textContent = '';
            $('offer-prereq').hidden = true;
            $('pay-wallet-wrap').hidden = true;
            return;
        }
        const r = o.requirements;
        $('price').textContent = formatOfferPrice(o);
        const sponsored = Boolean(r.extra && r.extra.areFeesSponsored === true);
        $('price-sublabel').textContent = sponsored
            ? 'Fast-lane admission charge · network fee sponsored by merchant'
            : 'Fast-lane admission charge · network fee paid by your wallet';
        $('recipient').textContent = 'Pay to ' + r.payTo + (r.asset !== o.asset_symbol ? ` · Asset: ${r.asset}` : '');

        const reqCols = (o.require_collections || []).map((id) => 'NFT: ' + ruleLabelByID(id, config.all_collections));
        const reqToks = (o.require_token_gates || []).map((id) => 'Token: ' + ruleLabelByID(id, config.all_token_gates));
        const allReq = [...reqCols, ...reqToks];
        if (allReq.length > 0) {
            const joiner = o.gate_mode === 'any' ? ' OR ' : ' AND ';
            $('offer-prereq').textContent = 'Purchase prerequisite — paying wallet must hold: ' + allReq.join(joiner);
            $('offer-prereq').hidden = false;
            $('pay-wallet-wrap').hidden = false;
        } else {
            $('offer-prereq').hidden = true;
            $('pay-wallet-wrap').hidden = true;
        }
    }

    async function status() {
        const { data } = await call('/status');
        hasAccess = !!data.eligible;
        if (data.eligible) {
            stopDirectPolling();
            if (data.kind === 'payment') forgetPending();
            const expText = new Date(data.expires).toLocaleTimeString();
            const hardText = data.hard_expires ? ` (sliding up to ${new Date(data.hard_expires).toLocaleTimeString()})` : '';
            say('Access is ready! Your fast-lane pass is valid until ' + expText + hardText + '.');
            $('enter').hidden = false;
        } else if (['pending', 'unknown'].includes(data.state)) {
            say('Payment is awaiting reconciliation. Do not make another payment. Retry the identical signed payload or contact the merchant.');
            $('enter').hidden = true;
        } else {
            say(pending
                ? 'A signed payment is saved in this tab. Review the terms, then retry that payment. Do not authorize a second payment.'
                : 'No active fast-lane pass yet. Pay with any wallet, prove an NFT/token holding, or continue in the standard queue.');
            $('enter').hidden = true;
        }
    }

    async function settle(header) {
        let signed;
        try {
            signed = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header), (x) => x.charCodeAt(0))));
        } catch {
            throw Error('The payment header is not valid base64 JSON.');
        }
        const chosen = config.offers[Number($('offer').value)]?.requirements;
        if (!chosen || ['scheme', 'network', 'asset', 'amount', 'payTo'].some((k) => signed.accepted?.[k] !== chosen[k])) {
            throw Error('Signed payment does not match the selected network, asset, amount, or recipient.');
        }
        if (!$('consent').checked) throw Error('Review the price and accept the terms first.');
        if (pending && (pending.header !== header || nonceOf(pending.session) !== nonceOf(session))) {
            throw Error('A previous payment must be reconciled first. Retry its identical signed payload or contact the merchant.');
        }
        pending = { header, session };
        sessionStorage.setItem('concert.pending-payment', JSON.stringify(pending));
        $('payment-payload').value = header;
        $('retry-payment').hidden = false;
        say('Verifying your payment and waiting for on-ledger finality…');
        const d = await post('/payment', {}, { 'PAYMENT-SIGNATURE': header });
        forgetPending();
        if (!d.eligible) throw Error('This payment’s access period has expired.');
        await status();
    }

    // ── Direct On-Ledger QR + Destination Tag / Memo Flow ────────────────────
    function makeCopyRow(label, value) {
        const row = document.createElement('div');
        row.className = 'direct-row';
        const sm = document.createElement('small');
        sm.textContent = label;
        const valWrap = document.createElement('div');
        valWrap.className = 'direct-row-val';
        const code = document.createElement('code');
        code.textContent = String(value);
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';
        btn.addEventListener('click', () => {
            navigator.clipboard?.writeText(String(value)).then(() => {
                btn.textContent = 'Copied';
                setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
            }).catch(() => {});
        });
        valWrap.append(code, btn);
        row.append(sm, valWrap);
        return row;
    }

    function renderDirectChallenge(slot, ch) {
        activeDirect[slot] = ch;
        const prefix = slot === 'payment' ? 'pay' : 'prove';
        const box = $(prefix + '-direct-box');
        const qrHost = $(prefix + '-qr');
        const fields = $(prefix + '-direct-fields');
        const uriLink = $(prefix + '-direct-uri');
        const st = $(prefix + '-direct-status');

        qrHost.replaceChildren();
        const svg = makeQRSvg(ch.wallet_uri || ch.pay_to);
        if (svg) qrHost.append(svg);

        fields.replaceChildren();
        fields.append(makeCopyRow('Send exactly', `${ch.display_amount} ${ch.asset_symbol}`));
        fields.append(makeCopyRow('Destination wallet', ch.pay_to));
        if (ch.destination_tag) {
            fields.append(makeCopyRow('Destination Tag (required on XRPL)', String(ch.destination_tag)));
        }
        if (ch.memo) {
            fields.append(makeCopyRow('Memo (include in transaction)', ch.memo));
        }
        if (ch.asset && ch.asset !== ch.asset_symbol && ch.asset !== '0.0.0') {
            fields.append(makeCopyRow('Token / Issuer / Mint', ch.asset));
        }

        uriLink.href = ch.wallet_uri || '#';
        st.textContent = 'Waiting for on-ledger confirmation… checking automatically every 3.5 seconds (expires ' + new Date(ch.expires).toLocaleTimeString() + ').';
        box.hidden = false;

        stopDirectPolling();
        directPollTimer = setInterval(() => { verifyDirect(slot, true); }, 3500);
    }

    async function verifyDirect(slot, silent) {
        const ch = activeDirect[slot];
        if (!ch || hasAccess) return;
        const prefix = slot === 'payment' ? 'pay' : 'prove';
        const st = $(prefix + '-direct-status');
        try {
            const { r, data } = await send('/direct/verify', { challenge_id: ch.challenge_id });
            if (r.ok && data.eligible) {
                stopDirectPolling();
                st.textContent = 'Confirmed on-ledger! Tx: ' + (data.transaction || 'verified');
                await status();
                return;
            }
            if (data.pending || r.status === 202 || data.error === 'transaction_not_found_yet') {
                if (!silent) st.textContent = 'Not seen on-ledger yet — wait a few seconds after sending and we will confirm automatically.';
                return;
            }
            if (!silent) st.textContent = String(data.error || 'Could not confirm yet').replaceAll('_', ' ');
            if (data.error === 'challenge_expired_or_unknown') stopDirectPolling();
        } catch (err) {
            if (!silent) st.textContent = String(err.message || err).replaceAll('_', ' ');
        }
    }

    // ── Solana Wallet Standard (Phantom, Solflare, Backpack) ─────────────────
    // Supports ComputeBudget priority-fee instructions, native SOL transfers,
    // and SPL / Token-2022 Transfer & TransferChecked (+ idempotent ATA creation).
    const standard = [];
    {
        const api = { register: (...w) => { standard.push(...w); return () => {}; } };
        window.addEventListener('wallet-standard:register-wallet', (e) => { try { e.detail(api); } catch {} });
        try { window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: api })); } catch {}
    }
    const solanaChains = {
        '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp': 'solana:mainnet',
        EtWTRABZaYq6iMfeYKouRu166VU2xqa1: 'solana:devnet',
        '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z': 'solana:testnet',
    };
    function solanaWallet(network, feature) {
        const chain = solanaChains[network.split(':')[1]];
        const w = standard.find((x) => x.chains?.includes(chain) && x.features?.['standard:connect'] && x.features[feature]);
        return w ? { w, chain } : null;
    }
    async function connectAccount({ w, chain }) {
        const { accounts } = await w.features['standard:connect'].connect();
        const account = accounts.find((x) => !x.chains || x.chains.includes(chain));
        if (!account) throw Error('The wallet shared no account for this network.');
        return account;
    }
    const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const b58 = (bytes) => {
        let n = 0n;
        for (const b of bytes) n = n * 256n + BigInt(b);
        let s = '';
        while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
        for (const b of bytes) { if (b) break; s = '1' + s; }
        return s;
    };
    const b64 = (bytes) => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };
    const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

    const SYS_PROG = '11111111111111111111111111111111';
    const COMPUTE_PROG = 'ComputeBudget111111111111111111111111111111';
    const MEMO_PROG = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
    const TOKEN_PROG = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    const TOKEN2022_PROG = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
    const ATA_PROG = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';

    function inspectSolanaTx(tx, requirements, expectedPayer) {
        let i = 0;
        const bad = (msg) => { throw Error(msg || 'Unexpected Solana transaction instructions.'); };
        const u8 = () => (i < tx.length ? tx[i++] : bad());
        const take = (n) => (i + n <= tx.length ? tx.subarray(i, (i += n)) : bad());
        const shortLen = () => {
            let n = 0;
            for (let s = 0; s < 21; s += 7) {
                const b = u8();
                n |= (b & 127) << s;
                if (!(b & 128)) return n;
            }
            return bad();
        };
        const sigs = shortLen();
        if (sigs !== 1) bad('Expected single-signer Solana transaction.');
        take(64 * sigs);
        const numReqSigs = u8();
        u8(); u8(); // roSigned, roUnsigned
        if (numReqSigs !== 1) bad();
        const keyCount = shortLen();
        const keys = [];
        for (let k = 0; k < keyCount; k++) keys.push(b58(take(32)));
        take(32); // blockhash
        if (keys[0] !== expectedPayer) bad('Transaction fee payer does not match connected wallet.');

        const ixCount = shortLen();
        const isNative = requirements.asset === 'SOL';
        let paymentSeen = 0;
        let dest = '';
        let amount = '';

        for (let n = 0; n < ixCount; n++) {
            const prog = keys[u8()];
            const acctCount = shortLen();
            const accts = [];
            for (let a = 0; a < acctCount; a++) accts.push(keys[u8()]);
            const dataLen = shortLen();
            const data = take(dataLen);
            const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

            if (prog === COMPUTE_PROG || prog === MEMO_PROG) continue;
            if (isNative) {
                if (prog !== SYS_PROG || dataLen !== 12 || view.getUint32(0, true) !== 2 || accts.length !== 2) {
                    bad('Unexpected non-transfer instruction in SOL payment.');
                }
                if (accts[0] !== expectedPayer || accts[1] !== requirements.payTo) bad('SOL transfer accounts mismatch.');
                amount = view.getBigUint64(4, true).toString();
                if (amount !== String(requirements.amount)) bad('SOL transfer amount does not match displayed price.');
                dest = accts[1];
                paymentSeen++;
            } else {
                if (prog === ATA_PROG) {
                    // CreateAssociatedTokenAccountIdempotent (opcode 1, optional when recipient ATA doesn't exist yet)
                    if (dataLen === 1 && data[0] === 1) continue;
                    bad('Unexpected Associated Token Account instruction.');
                }
                if (prog !== TOKEN_PROG && prog !== TOKEN2022_PROG) bad('Unexpected program in SPL token payment.');
                if (dataLen === 9 && data[0] === 3 && accts.length >= 3) {
                    // SPL Transfer(amount)
                    if (accts[2] !== expectedPayer) bad('SPL transfer owner mismatch.');
                    amount = view.getBigUint64(1, true).toString();
                    dest = accts[1];
                } else if (dataLen === 10 && data[0] === 12 && accts.length >= 4) {
                    // SPL TransferChecked(amount, decimals): [src, mint, dst, owner]
                    if (accts[1] !== requirements.asset) bad('SPL token mint mismatch.');
                    if (accts[3] !== expectedPayer) bad('SPL transfer authority mismatch.');
                    amount = view.getBigUint64(1, true).toString();
                    dest = accts[2];
                } else {
                    bad('Unsupported SPL token instruction.');
                }
                if (amount !== String(requirements.amount)) bad('Token transfer amount does not match displayed price.');
                paymentSeen++;
            }
        }
        if (i !== tx.length || paymentSeen !== 1) bad('Transaction must contain exactly one verified payment instruction.');
        return { from: expectedPayer, to: dest, amount };
    }

    const adapter = (network) => window.concertWallets?.[network] || window.concertWallets?.[network.split(':')[0]];

    async function createNFTChallenge() {
        const chosen = holdRules[Number($('collection').value)];
        if (!chosen || chosen.kind !== 'nft') throw Error('Select an NFT collection rule to sign a message.');
        const c = chosen.rule;
        const d = await post('/nft/challenge', {
            rule: c.id,
            address: $('wallet-address').value.trim(),
            token_id: $('token-id').value.trim(),
        });
        nonce = d.nonce;
        $('challenge-message').value = d.message;
        return { d, c };
    }

    $('offer').addEventListener('change', () => {
        $('pay-direct-box').hidden = true;
        price();
        availability();
    });
    $('collection').addEventListener('change', () => {
        $('prove-direct-box').hidden = true;
        availability();
    });
    $('consent').addEventListener('change', availability);
    $('refresh').addEventListener('click', () => run(status));
    $('submit-payment').addEventListener('click', () => run(() => settle($('payment-payload').value.trim())));
    $('retry-payment').addEventListener('click', () => run(() => settle(pending.header)));

    // 1. Browser Extension x402 Payment
    $('pay').addEventListener('click', () => run(async () => {
        const o = config.offers[Number($('offer').value)];
        let a = adapter(o.requirements.network);
        if (!a && o.requirements.network.startsWith('solana:')) {
            const s = solanaWallet(o.requirements.network, 'solana:signTransaction');
            if (s) {
                a = {
                    createPaymentPayload: async ({ paymentRequired, requirements }) => {
                        const account = await connectAccount(s);
                        const prep = await post('/solana/prepare', {
                            network: requirements.network,
                            address: account.address,
                            asset: requirements.asset,
                        });
                        const prepared = unb64(prep.transaction);
                        const orig = inspectSolanaTx(prepared, requirements, account.address);
                        const [out] = await s.w.features['solana:signTransaction'].signTransaction({
                            account,
                            transaction: prepared,
                            chain: s.chain,
                        });
                        const signed = new Uint8Array(out.signedTransaction);
                        const after = inspectSolanaTx(signed, requirements, account.address);
                        if (after.to !== orig.to || after.amount !== orig.amount) {
                            throw Error('The wallet altered the payment destination or amount.');
                        }
                        return { x402Version: 2, resource: paymentRequired.resource, accepted: requirements, payload: { transaction: b64(signed) } };
                    },
                };
            }
        }
        if (!a?.createPaymentPayload) {
            throw Error('No browser wallet extension detected for this chain. Click "Pay from any wallet (QR + Destination Tag / Memo)" right below instead.');
        }
        const { r, data } = await send('/payment', {});
        if (r.ok) { await status(); return; }
        if (r.status !== 402) throw Error(data.error);
        const p = await a.createPaymentPayload({ paymentRequired: data, requirements: o.requirements, session });
        await settle(btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(p)))));
    }));

    // 2. Universal Direct QR + Destination Tag / Memo Paid Pass
    $('pay-direct').addEventListener('click', () => run(async () => {
        if (!$('consent').checked) throw Error('Review the price and accept the terms first.');
        const idx = Number($('offer').value);
        const addr = $('pay-wallet-address').value.trim();
        const ch = await post('/direct/challenge', {
            kind: 'payment',
            offer_index: idx,
            address: addr,
        });
        renderDirectChallenge('payment', ch);
        say('Payment request ready! Scan the QR code or send the exact amount with the displayed Destination Tag / Memo.');
    }));
    $('pay-direct-check').addEventListener('click', () => run(() => verifyDirect('payment', false)));

    // 3. Universal Direct 1-Drop / Memo Ownership Proof (NFTs & Token/Trustline Balances)
    $('prove-direct').addEventListener('click', () => run(async () => {
        const chosen = holdRules[Number($('collection').value)];
        if (!chosen) throw Error('No NFT or token holding rule is configured.');
        const addr = $('wallet-address').value.trim();
        if (!addr) throw Error('Enter your public wallet address first.');
        say('Checking your on-chain holdings before generating the 1-drop proof…');
        const ch = await post('/direct/challenge', {
            kind: 'proof',
            rule_kind: chosen.kind,
            rule_id: chosen.rule.id,
            address: addr,
            token_id: $('token-id').value.trim(),
        });
        renderDirectChallenge('proof', ch);
        say('Holdings verified on-chain! Send the 1-drop / Memo verification transaction from your wallet to unlock your fast-lane pass.');
    }));
    $('prove-direct-check').addEventListener('click', () => run(() => verifyDirect('proof', false)));

    // 4. Browser Extension NFT Signed-Message Proof
    $('challenge').addEventListener('click', () => run(async () => {
        await createNFTChallenge();
        say('Sign the displayed message with your wallet, then submit its signature.');
    }));
    $('submit-proof').addEventListener('click', () => run(async () => {
        await post('/nft/verify', {
            nonce,
            signature: $('signature').value.trim(),
            public_key: $('public-key').value.trim(),
        });
        await status();
    }));
    $('prove').addEventListener('click', () => run(async () => {
        const chosen = holdRules[Number($('collection').value)];
        if (!chosen || chosen.kind !== 'nft') throw Error('Use the "Prove via 1-drop / Memo transaction" button for token balance rules.');
        const c = chosen.rule;
        let a = adapter(c.network);
        if (!a && c.network.startsWith('solana:')) {
            const s = solanaWallet(c.network, 'solana:signMessage');
            let account;
            if (s) {
                a = {
                    connect: async () => (account = await connectAccount(s)).address,
                    signMessage: async (message) => {
                        const [x] = await s.w.features['solana:signMessage'].signMessage({
                            account,
                            message: new TextEncoder().encode(message),
                        });
                        return { signature: b64(new Uint8Array(x.signature)) };
                    },
                };
            }
        }
        if (!a?.signMessage) {
            throw Error('No signing wallet extension detected. Use "Prove via 1-drop / Memo transaction (Any Wallet)" right above instead.');
        }
        if (a.connect) $('wallet-address').value = await a.connect();
        const { d } = await createNFTChallenge();
        const proof = await a.signMessage(d.message, c.network);
        await post('/nft/verify', { nonce: d.nonce, signature: proof.signature, public_key: proof.public_key || '' });
        await status();
    }));

    // Keep the existing FIFO ticket alive while reviewing wallet options.
    const heartbeat = setInterval(() => {
        if (document.cookie.split(';').some((x) => x.trim().startsWith('room_probe='))) {
            fetch('/queue/status', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(5000) })
                .then((r) => (r.ok ? r.json() : null))
                .then((d) => {
                    if (d?.ready === true && !busy && !hasAccess) {
                        $('return').classList.add('button-primary');
                        $('return').textContent = 'Your turn in the standard queue · continue ↗';
                    }
                })
                .catch(() => {});
        }
    }, 5000);
    window.addEventListener('pagehide', () => { clearInterval(heartbeat); stopDirectPolling(); });

    run(async () => {
        const { data } = await call('/config');
        if (!data.enabled) throw Error('Wallet access is not enabled. The standard queue remains available.');
        config = data;
        const s = await post('/session', {});
        csrf = s.csrf;
        session = s.session;
        $('access-options').hidden = false;
        $('mode-label').textContent = data.test_mode ? 'TEST NETWORKS · NO MAINNET PAYMENTS' : 'WALLET ACCESS';
        if (data.test_mode) $('mode-label').classList.add('badge-test');
        $('merchant').textContent = 'Operated by ' + data.merchant;

        const slidingDesc = data.pass_sliding
            ? `Refreshes automatically while you browse (${data.pass_idle_seconds || data.pass_seconds}s idle timeout, up to ${Math.round((data.pass_max_seconds || data.pass_seconds) / 60)} min max) and never interrupts an active checkout.`
            : `${data.pass_seconds} seconds of priority eligibility after settlement.`;
        $('pass-description').textContent = slidingDesc + ' Priority access is subject to waiting-room capacity.';
        $('nft-description').textContent = `Verify an NFT or minimum token/trustline balance on-chain. Pass lasts ${data.nft_pass_seconds}s` + (data.pass_sliding ? ' (refreshes while active).' : '.');

        if (data.direct_pay_enabled !== false) {
            $('pay-direct').hidden = false;
            $('prove-direct').hidden = false;
        }

        for (const [id, url] of [['terms-link', data.terms_url], ['refund-link', data.refund_url], ['privacy-link', data.privacy_url], ['policy-link', data.refund_url]]) {
            $(id).href = url || '#';
        }

        (data.offers || []).forEach((x, i) => {
            const opt = document.createElement('option');
            opt.value = String(i);
            opt.textContent = `${x.label} · ${formatOfferPrice(x)}`;
            $('offer').append(opt);
        });

        holdRules = [];
        for (const c of (data.collections || [])) {
            holdRules.push({ kind: 'nft', rule: c });
        }
        for (const tg of (data.token_gates || [])) {
            holdRules.push({ kind: 'token', rule: tg });
        }
        holdRules.forEach((h, i) => {
            const opt = document.createElement('option');
            opt.value = String(i);
            const prefix = h.kind === 'nft' ? 'NFT · ' : 'Token Balance · ';
            opt.textContent = prefix + h.rule.label + (h.kind === 'token' && h.rule.display_min_amount ? ` (${h.rule.display_min_amount}+ ${h.rule.asset_symbol || ''})` : '');
            $('collection').append(opt);
        });

        const saved = sessionStorage.getItem('concert.pending-payment');
        if (saved) {
            try {
                pending = JSON.parse(saved);
                $('payment-payload').value = pending.header;
                $('retry-payment').hidden = false;
                const p = JSON.parse(atob(pending.header));
                const index = (config.offers || []).findIndex((o) => o.requirements.network === p.accepted?.network && o.requirements.asset === p.accepted?.asset);
                if (index >= 0) $('offer').value = String(index);
            } catch {
                forgetPending();
            }
        }
        price();
        availability();
        await status();
    });
})();
