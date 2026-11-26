'use strict';
(() => {
    const $ = id => document.getElementById(id);
    const start = Date.now();
    let stopped = false;
    let failures = 0;
    let timer;
    let skipURL = '';

    // Parse optional inert server-rendered state JSON (<script type="application/json">).
    let wrState = {};
    const stateEl = $('concert-wr-state');
    if (stateEl && stateEl.textContent) {
        try {
            wrState = JSON.parse(stateEl.textContent) || {};
        } catch {
            wrState = {};
        }
    }

    const i18nMap = (wrState && typeof wrState.i18n === 'object' && wrState.i18n) || {};
    function tr(key, fallback) {
        const val = i18nMap[key];
        return typeof val === 'string' && val.length > 0 ? val : fallback;
    }

    // Apply validated #RRGGBB accent color via CSS custom property (CSP style-src 'self' safe).
    const accentHex = (document.body && document.body.getAttribute('data-accent')) || wrState.accent_color || '';
    if (/^#[0-9A-Fa-f]{6}$/.test(accentHex)) {
        document.documentElement.style.setProperty('--accent', accentHex);
    }

    // Hydrate static [data-i18n] nodes when server state supplies a catalog.
    if (Object.keys(i18nMap).length > 0) {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (key && typeof i18nMap[key] === 'string' && i18nMap[key].length > 0) {
                el.textContent = i18nMap[key];
            }
        });
        document.querySelectorAll('[data-i18n-aria]').forEach(el => {
            const key = el.getAttribute('data-i18n-aria');
            if (key && typeof i18nMap[key] === 'string' && i18nMap[key].length > 0) {
                el.setAttribute('aria-label', i18nMap[key]);
            }
        });
    }

    // Language picker: sets concert_lang cookie and reloads with ?lang=<locale>.
    const langPicker = $('lang-picker');
    if (langPicker) {
        const activeLocale = wrState.locale || document.documentElement.getAttribute('lang') || 'en';
        if (Array.isArray(wrState.locales) && wrState.locales.length > 0 && langPicker.options.length === 0) {
            wrState.locales.forEach(loc => {
                if (!loc || typeof loc.code !== 'string') return;
                const opt = document.createElement('option');
                opt.value = loc.code;
                opt.textContent = loc.native_name || loc.name || loc.code;
                langPicker.appendChild(opt);
            });
        }
        if ([...langPicker.options].some(o => o.value === activeLocale)) {
            langPicker.value = activeLocale;
        }
        langPicker.addEventListener('change', () => {
            const chosen = langPicker.value;
            if (!/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,4})?$/.test(chosen)) return;
            const secure = location.protocol === 'https:' ? '; Secure' : '';
            document.cookie = 'concert_lang=' + encodeURIComponent(chosen) + '; Path=/; Max-Age=31536000; SameSite=Lax' + secure;
            const nextURL = new URL(location.href);
            nextURL.searchParams.set('lang', chosen);
            location.assign(nextURL.toString());
        });
    }

    // Format rolling ETA cleanly across locales.
    function formatETA(seconds) {
        if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0) {
            return tr('eta.calculating', 'Calculating…');
        }
        if (seconds < 60) {
            return tr('eta.under_minute', '< 1 min');
        }
        const mins = Math.max(1, Math.round(seconds / 60));
        if (mins >= 60) {
            const hours = Math.floor(mins / 60);
            const rem = mins % 60;
            return '~' + hours + 'h ' + (rem > 0 ? rem + ' ' + tr('eta.minutes', 'min') : '');
        }
        return '~' + mins + ' ' + tr('eta.minutes', 'min');
    }

    function updateETA(etaSeconds) {
        const etaEl = $('eta-value');
        if (!etaEl) return;
        etaEl.textContent = formatETA(etaSeconds);
    }

    if (wrState.eta && typeof wrState.eta.seconds === 'number') {
        updateETA(wrState.eta.seconds);
    }

    // Live operator broadcast banner helper (textContent only; never innerHTML).
    function updateBroadcast(broadcast) {
        const banner = $('broadcast-banner');
        const msgEl = $('broadcast-message');
        const timeEl = $('broadcast-time');
        if (!banner || !msgEl) return;
        const message = broadcast && typeof broadcast.message === 'string' ? broadcast.message.trim() : '';
        if (!message) {
            banner.hidden = true;
            msgEl.textContent = '';
            if (timeEl) {
                timeEl.textContent = '';
                timeEl.removeAttribute('datetime');
            }
            return;
        }
        msgEl.textContent = message;
        if (timeEl) {
            const updatedAt = typeof broadcast.updated_at === 'string' ? broadcast.updated_at : '';
            timeEl.textContent = updatedAt;
            if (updatedAt) timeEl.setAttribute('datetime', updatedAt);
        }
        banner.hidden = false;
    }

    if (wrState.broadcast && wrState.broadcast.message) {
        updateBroadcast(wrState.broadcast);
    }

    // Inline Crypto Fast-Lane / NFT VIP Bypass Drawer (keeps YouTube stream playing).
    const drawer = $('fastlane-drawer');
    const openDrawerBtn = $('open-fastlane-drawer');
    const closeDrawerBtn = $('close-fastlane-drawer');
    const tabPay = $('drawer-tab-pay');
    const tabNFT = $('drawer-tab-nft');
    const panelPay = $('drawer-panel-pay');
    const panelNFT = $('drawer-panel-nft');
    const offersList = $('drawer-offers-list');
    const nftList = $('drawer-nft-list');

    function setDrawerOpen(open) {
        if (!drawer) return;
        drawer.hidden = !open;
        if (openDrawerBtn) {
            openDrawerBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
        }
        if (open && closeDrawerBtn) {
            closeDrawerBtn.focus();
        }
    }

    function setDrawerTab(which) {
        const isPay = which !== 'nft';
        if (tabPay) {
            tabPay.classList.toggle('is-active', isPay);
            tabPay.setAttribute('aria-selected', isPay ? 'true' : 'false');
        }
        if (tabNFT) {
            tabNFT.classList.toggle('is-active', !isPay);
            tabNFT.setAttribute('aria-selected', !isPay ? 'true' : 'false');
        }
        if (panelPay) panelPay.hidden = !isPay;
        if (panelNFT) panelNFT.hidden = isPay;
    }

    if (openDrawerBtn) openDrawerBtn.addEventListener('click', () => setDrawerOpen(true));
    if (closeDrawerBtn) closeDrawerBtn.addEventListener('click', () => setDrawerOpen(false));
    if (tabPay) tabPay.addEventListener('click', () => setDrawerTab('pay'));
    if (tabNFT) tabNFT.addEventListener('click', () => setDrawerTab('nft'));
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && drawer && !drawer.hidden) {
            setDrawerOpen(false);
            if (openDrawerBtn) openDrawerBtn.focus();
        }
    });

    function appendDrawerRow(listEl, title, chainBadge, metaText) {
        if (!listEl) return;
        const li = document.createElement('li');
        li.className = 'drawer-item';

        const top = document.createElement('div');
        top.className = 'drawer-item-top';
        const titleSpan = document.createElement('span');
        titleSpan.textContent = title;
        top.appendChild(titleSpan);

        if (chainBadge) {
            const badge = document.createElement('span');
            badge.className = 'drawer-chain-badge';
            badge.textContent = chainBadge;
            top.appendChild(badge);
        }
        li.appendChild(top);

        if (metaText) {
            const meta = document.createElement('div');
            meta.className = 'drawer-item-meta';
            meta.textContent = metaText;
            li.appendChild(meta);
        }
        listEl.appendChild(li);
    }

    function populateFastlaneDrawer(cfg) {
        if (offersList) {
            offersList.textContent = '';
            const offers = Array.isArray(cfg.offers) ? cfg.offers : [];
            if (offers.length === 0) {
                appendDrawerRow(offersList, tr('fastlane.tab_pay', 'Crypto Fast-Lane'), 'CRYPTO', 'XRPL · Stellar · Hedera · Solana');
            } else {
                offers.forEach(o => {
                    const priceLabel = [o.amount, o.currency || o.asset].filter(Boolean).join(' ') || tr('fastlane.tab_pay', 'Crypto Fast-Lane');
                    const chain = o.chain || o.network || 'CRYPTO';
                    const meta = o.description || o.label || '';
                    appendDrawerRow(offersList, priceLabel, String(chain), meta);
                });
            }
        }
        if (nftList) {
            nftList.textContent = '';
            const collections = Array.isArray(cfg.collections) ? cfg.collections : [];
            if (collections.length === 0) {
                appendDrawerRow(nftList, tr('fastlane.tab_nft', 'NFT VIP Bypass'), 'NFT / TOKEN', 'XRPL · Stellar · Hedera · Solana');
            } else {
                collections.forEach(col => {
                    const name = col.name || col.label || col.issuer || tr('fastlane.tab_nft', 'NFT VIP Bypass');
                    const chain = col.chain || col.network || 'NFT';
                    const meta = col.min_balance ? ('Min balance: ' + col.min_balance) : (col.issuer || '');
                    appendDrawerRow(nftList, String(name), String(chain), String(meta));
                });
            }
        }
    }

    // Core queue status loop (100% backward compatible with existing hooks).
    function fatal(message) {
        stopped = true;
        clearTimeout(timer);
        if ($('queue-error')) {
            $('queue-error').hidden = false;
            $('queue-error').textContent = message;
        }
        if ($('queue-state')) $('queue-state').textContent = tr('status.action_needed', 'Action needed');
        if ($('session-state')) $('session-state').textContent = tr('session.paused', 'Paused');
    }

    const elapsed = setInterval(() => {
        const el = $('elapsed');
        if (!el) return;
        const n = Math.floor((Date.now() - start) / 1000);
        el.textContent = String(Math.floor(n / 60)).padStart(2, '0') + ':' + String(n % 60).padStart(2, '0');
    }, 1000);

    if (!document.cookie.split(';').some(x => x.trim().startsWith('room_probe='))) {
        fatal(tr('error.cookies', 'Cookies are needed to save your place. Enable cookies for this site, then reload once.'));
        return;
    }
    if ($('session-state')) $('session-state').textContent = tr('session.protected', 'Protected');

    // The room substitutes {{.Position}}; show it at once in the ticket style.
    const posEl = $('position');
    if (posEl) {
        const initial = parseInt(posEl.textContent, 10);
        posEl.textContent = initial > 0 ? String(initial).padStart(3, '0') : '…';
    }

    fetch('/_concert/config', { credentials: 'same-origin', signal: AbortSignal.timeout(8000) })
        .then(r => r.json())
        .then(c => {
            if (!c || typeof c !== 'object') return;
            if (c.legacy_skip_url) {
                skipURL = c.legacy_skip_url;
                if ($('legacy-link')) $('legacy-link').href = c.legacy_skip_url;
            }
            if (c.broadcast && typeof c.broadcast.message === 'string') {
                updateBroadcast(c.broadcast);
            }
            if (c.enabled) {
                const accessHref = '/_concert/access?return=' + encodeURIComponent(location.pathname + location.search);
                if ($('fastlane-card')) $('fastlane-card').hidden = false;
                if ($('access-link')) $('access-link').href = accessHref;
                if ($('drawer-access-link')) {
                    $('drawer-access-link').href = accessHref;
                    // In YouTube cinema layout, open full checkout in a new tab so the live stream keeps playing.
                    if (document.documentElement.getAttribute('data-layout') === 'youtube') {
                        $('drawer-access-link').target = '_blank';
                        $('drawer-access-link').rel = 'noopener noreferrer';
                    }
                }
                populateFastlaneDrawer(c);
            }
        })
        .catch(() => {});

    // Same rule as room's built-in page: offer paid skipping only with a price,
    // a place to skip from, and no skip-the-line pass already held.
    function skipOffer(d) {
        const show = !!skipURL && !d.has_pass && typeof d.skip_cost === 'number' && Number.isFinite(d.skip_cost) && d.skip_cost > 0 && d.position > 1;
        if ($('legacy-card')) $('legacy-card').hidden = !show;
        if (show && $('legacy-price')) {
            $('legacy-price').textContent = 'Current skip price: $' + d.skip_cost.toFixed(2);
        }
    }

    async function poll() {
        if (stopped) return;
        try {
            const r = await fetch('/queue/status', {
                credentials: 'same-origin',
                cache: 'no-store',
                signal: AbortSignal.timeout(8000)
            });
            if (r.status === 403) {
                fatal(tr('error.unavailable', 'Access is currently unavailable. Contact the site operator for help.'));
                return;
            }
            // Polled too soon (e.g. the wallet page shares this ticket): the place is kept.
            if (r.status === 429) {
                timer = setTimeout(poll, 3000 + Math.random() * 500);
                return;
            }
            if (!r.ok) throw Error('Status unavailable');
            const d = await r.json();
            failures = 0;
            if (d.cookies_required) {
                fatal(tr('error.cookie_missing', 'Your queue cookie is missing. Enable cookies for this site, then reload once.'));
                return;
            }
            if (d.ready === true) {
                stopped = true;
                if ($('queue-state')) $('queue-state').textContent = tr('status.ready', 'Your turn. Taking you in…');
                location.reload();
                return;
            }
            if (typeof d.position === 'number' && d.position > 0 && posEl) {
                posEl.textContent = String(d.position).padStart(3, '0');
            }
            if (typeof d.eta_seconds === 'number') {
                updateETA(d.eta_seconds);
            } else if (d.eta && typeof d.eta.seconds === 'number') {
                updateETA(d.eta.seconds);
            }
            if (d.broadcast && typeof d.broadcast.message === 'string') {
                updateBroadcast(d.broadcast);
            }
            skipOffer(d);
            if ($('queue-state')) $('queue-state').textContent = tr('status.saved', 'Your place is saved');
            if ($('queue-note')) {
                $('queue-note').textContent = d.has_pass
                    ? tr('note.pass_active', 'Your skip-the-line pass is active. Keep this tab open.')
                    : tr('note.keep_open', 'Keep this tab open. We’ll take you in when it’s your turn.');
            }
        } catch {
            failures++;
            if ($('queue-state')) $('queue-state').textContent = tr('status.reconnecting', 'Reconnecting');
            if ($('queue-note')) $('queue-note').textContent = tr('note.reconnecting', 'The status connection was interrupted. We’re retrying automatically.');
        }
        timer = setTimeout(poll, Math.min(10000, 2000 * 2 ** Math.min(failures, 3)) + Math.random() * 300);
    }

    window.addEventListener('pagehide', () => {
        stopped = true;
        clearTimeout(timer);
        clearInterval(elapsed);
    });
    window.addEventListener('pageshow', e => {
        if (e.persisted) location.reload();
    });
    poll();
})();
