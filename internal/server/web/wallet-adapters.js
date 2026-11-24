'use strict';
// Built-in browser wallet adapters for XRPL (GemWallet / Crossmark),
// Stellar (Freighter), and Hedera (HashPack / injected provider), plus
// extensibility on window.concertWallets. Solana Wallet Standard (Phantom,
// Solflare, Backpack) is built directly into access.js.
// Private keys always remain strictly inside the user's wallet extension.
(() => {
    const reg = window.concertWallets || Object.create(null);
    window.concertWallets = reg;

    const toHex = (str) => Array.from(new TextEncoder().encode(str)).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const hexToB64 = (hex) => {
        const clean = String(hex || '').replace(/^0x/i, '');
        const bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
        let s = '';
        for (const b of bytes) s += String.fromCharCode(b);
        return btoa(s);
    };

    // ── XRPL: GemWallet & Crossmark ──────────────────────────────────────────
    if (!reg.xrpl) {
        const getGem = () => window.gemWallet || window.gemWalletApi || null;
        const getCrossmark = () => (window.xrpl && window.xrpl.crossmark) || window.crossmark || null;

        reg.xrpl = {
            name: 'XRPL (GemWallet / Crossmark)',
            async connect() {
                const gem = getGem();
                if (gem && typeof gem.getAddress === 'function') {
                    const res = await gem.getAddress();
                    const addr = res?.result?.address || res?.address;
                    if (addr) return addr;
                }
                const cm = getCrossmark();
                if (cm?.methods?.signInAndWait) {
                    const res = await cm.methods.signInAndWait();
                    const addr = res?.response?.data?.address;
                    if (addr) return addr;
                }
                throw Error('Install GemWallet or Crossmark, or use the "Any Wallet (QR + Destination Tag)" button below.');
            },
            async signMessage(message) {
                const gem = getGem();
                if (gem && typeof gem.signMessage === 'function') {
                    const pubRes = typeof gem.getPublicKey === 'function' ? await gem.getPublicKey() : null;
                    const res = await gem.signMessage(message);
                    const sigHex = res?.result?.signedMessage || res?.signedMessage;
                    const pubHex = pubRes?.result?.publicKey || pubRes?.publicKey || '';
                    if (sigHex) return { signature: hexToB64(sigHex), public_key: pubHex };
                }
                throw Error('Your XRPL extension did not return a signed message. Use the "1-Drop / Destination Tag Proof" option for universal wallet support (Xaman, Ledger, GemWallet, Crossmark).');
            },
            async createPaymentPayload({ paymentRequired, requirements }) {
                const isIOU = String(requirements.asset || '').toUpperCase() !== 'XRP';
                const txAmount = (() => {
                    if (!isIOU) return String(requirements.amount);
                    const [currency, issuer] = String(requirements.asset).split(':');
                    return { currency, issuer, value: String(requirements.amount) };
                })();

                const gem = getGem();
                if (gem && typeof gem.signTransaction === 'function') {
                    const tx = {
                        TransactionType: 'Payment',
                        Destination: requirements.payTo,
                        Amount: txAmount,
                    };
                    const res = await gem.signTransaction({ transaction: tx });
                    const blob = res?.result?.signature || res?.result?.tx_blob || res?.tx_blob;
                    if (blob) {
                        return { x402Version: 2, resource: paymentRequired.resource, accepted: requirements, payload: { signedTxBlob: blob } };
                    }
                }
                const cm = getCrossmark();
                if (cm?.methods?.signAndWait) {
                    const tx = {
                        TransactionType: 'Payment',
                        Destination: requirements.payTo,
                        Amount: txAmount,
                    };
                    const res = await cm.methods.signAndWait(tx);
                    const blob = res?.response?.data?.txBlob || res?.response?.data?.tx_blob;
                    if (blob) {
                        return { x402Version: 2, resource: paymentRequired.resource, accepted: requirements, payload: { signedTxBlob: blob } };
                    }
                }
                throw Error('No XRPL signing extension detected (GemWallet / Crossmark). Use "Pay from Any Wallet (QR + Destination Tag)" below to pay from Xaman, Ledger, or any XRPL wallet.');
            },
        };
    }

    // ── Stellar: Freighter ───────────────────────────────────────────────────
    if (!reg.stellar) {
        const getFreighter = () => window.freighterApi || window.freighter || null;
        reg.stellar = {
            name: 'Stellar (Freighter)',
            async connect() {
                const f = getFreighter();
                if (!f) throw Error('Install Freighter, or use the "Any Wallet (QR + Memo)" option below (Lobstr, Freighter, StellarX).');
                if (typeof f.requestAccess === 'function') {
                    const r = await f.requestAccess();
                    if (typeof r === 'string') return r;
                    if (r?.address) return r.address;
                }
                if (typeof f.getPublicKey === 'function') return await f.getPublicKey();
                if (typeof f.getAddress === 'function') {
                    const r = await f.getAddress();
                    return typeof r === 'string' ? r : r?.address || '';
                }
                throw Error('Could not read Stellar public address from Freighter.');
            },
            async signMessage(message) {
                const f = getFreighter();
                if (f && typeof f.signMessage === 'function') {
                    const res = await f.signMessage(message);
                    const sig = typeof res === 'string' ? res : res?.signedMessage || res?.signature;
                    if (sig) return { signature: sig };
                }
                throw Error('Freighter signMessage unavailable. Use the "1-Stroop / Memo Proof" option below for universal Stellar wallet support.');
            },
            async createPaymentPayload() {
                throw Error('Use "Pay from Any Wallet (QR + Memo)" below to pay directly from Freighter, Lobstr, or any Stellar wallet, or paste a signed x402 payload.');
            },
        };
    }

    // ── Hedera: HashPack / Injected Provider ─────────────────────────────────
    if (!reg.hedera) {
        const getHedera = () => window.hashpack || window.hedera || null;
        reg.hedera = {
            name: 'Hedera (HashPack)',
            async connect() {
                const h = getHedera();
                if (h && typeof h.connect === 'function') {
                    const res = await h.connect();
                    const acct = res?.accountIds?.[0] || res?.accountId;
                    if (acct) return acct;
                }
                throw Error('Use "Any Wallet (QR + Memo)" below to pay or prove ownership directly from HashPack, Blade, or Kabila.');
            },
            async signMessage(message) {
                const h = getHedera();
                if (h && typeof h.signMessage === 'function') {
                    const res = await h.signMessage(toHex(message));
                    if (res?.signature) return { signature: res.signature };
                }
                throw Error('Use "1-Tinybar / Memo Proof" below for universal Hedera wallet support.');
            },
            async createPaymentPayload() {
                throw Error('Use "Pay from Any Wallet (QR + Memo)" below to pay directly from HashPack, Blade, or any Hedera wallet, or paste a signed x402 payload.');
            },
        };
    }
})();
