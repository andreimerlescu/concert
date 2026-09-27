'use strict';
(()=>{
    const $=id=>document.getElementById(id);let config,csrf='',session='',nonce='',busy=false,pending=null,hasAccess=false;
    // Resolve the return target the way the browser will (it strips tabs and
    // newlines, so "/\t/evil.example" becomes "//evil.example") and keep it only
    // when it stays on this origin.
    const back=(()=>{try{const u=new URL(new URLSearchParams(location.search).get('return')||'/',location.origin);return u.origin===location.origin&&!u.pathname.startsWith('/_concert')?u.pathname+u.search+u.hash:'/';}catch{return '/';}})();
    $('return').href=back;$('enter').href=back;
    const say=m=>{$('message').hidden=false;$('message').textContent=m;};
    // Settlement can wait for chain finality; everything else answers quickly.
    async function call(path,body,headers={}){const r=await fetch('/_concert'+path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','X-Concert-CSRF':csrf,...headers},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(path==='/payment'?420000:50000)});const data=await r.json();return {r,data};}
    const nonceOf=token=>String(token||'').split('.')[0];
    async function renew(){const s=await post('/session',{});csrf=s.csrf;session=s.session;}
    // Renewal keeps the session ID, so repeating the request is always safe.
    async function send(path,body,headers){let x=await call(path,body,headers);if(x.r.status===409&&x.data.error==='session_renewal_required'){await renew();x=await call(path,body,headers);}return x;}
    async function post(path,body,headers={}){const {r,data}=await send(path,body,headers);if(!r.ok)throw Error(data.error||'Request could not be completed');return data;}
    async function run(fn){if(busy)return;busy=true;for(const b of document.querySelectorAll('button'))b.disabled=true;try{await fn();}catch(e){say(e.message.replaceAll('_',' '));}finally{busy=false;for(const b of document.querySelectorAll('button'))b.disabled=false;availability();}}
    function availability(){if(!config)return;$('pay').disabled=!$('consent').checked||!config.offers.length||!!pending||hasAccess;$('submit-payment').disabled=!$('consent').checked||!config.offers.length||hasAccess;$('retry-payment').disabled=!$('consent').checked||!pending;$('prove').disabled=!config.collections.length;$('challenge').disabled=!config.collections.length;}
    function forgetPending(){sessionStorage.removeItem('concert.pending-payment');pending=null;$('retry-payment').hidden=true;}
    function price(){const o=config.offers[Number($('offer').value)];if(!o){$('price').textContent='Not offered';return;}const r=o.requirements,d={xrpl:6,stellar:7,hedera:8,solana:9}[r.network.split(':')[0]],ticker={xrpl:'XRP',stellar:'XLM',hedera:'HBAR',solana:'SOL'}[r.network.split(':')[0]],s=r.amount.padStart(d+1,'0');$('price').textContent=s.slice(0,-d)+'.'+s.slice(-d).replace(/0+$/,'').padEnd(1,'0')+' '+ticker;$('recipient').textContent='Pay to '+r.payTo;}
    async function status(){const {data}=await call('/status');hasAccess=!!data.eligible;if(data.eligible){if(data.kind==='payment')forgetPending();say('Access is ready. Your pass is valid until '+new Date(data.expires).toLocaleTimeString()+'.');$('enter').hidden=false;}else if(['pending','unknown'].includes(data.state)){say('Payment is awaiting reconciliation. Do not make another payment. Retry the identical signed payload or contact the merchant.');$('enter').hidden=true;}else{say(pending?'A signed payment is saved in this tab. Review the terms, then retry that payment. Do not authorize a second payment.':'No active fast-lane pass. You can continue in the standard queue.');$('enter').hidden=true;}}
    async function settle(header){
        let signed;try{signed=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header),x=>x.charCodeAt(0))));}catch{throw Error('The payment header is not valid base64 JSON.');}
        const chosen=config.offers[Number($('offer').value)]?.requirements;
        if(!chosen||['scheme','network','asset','amount','payTo'].some(k=>signed.accepted?.[k]!==chosen[k]))throw Error('Signed payment does not match the selected network, amount or recipient.');
        if(!$('consent').checked)throw Error('Review the price and accept the terms first.');
        if(pending&&(pending.header!==header||nonceOf(pending.session)!==nonceOf(session)))throw Error('A previous payment must be reconciled first. Retry its identical signed payload or contact the merchant.');
        pending={header,session};sessionStorage.setItem('concert.pending-payment',JSON.stringify(pending));$('payment-payload').value=header;$('retry-payment').hidden=false;
        say('Verifying your payment and waiting for settlement…');const d=await post('/payment',{}, {'PAYMENT-SIGNATURE':header});forgetPending();if(!d.eligible)throw Error('This payment’s access period has expired.');await status();}
    const adapter=network=>window.concertWallets?.[network]||window.concertWallets?.[network.split(':')[0]];
    async function createChallenge(){const c=config.collections[Number($('collection').value)];if(!c)throw Error('No collection is enabled.');const d=await post('/nft/challenge',{rule:c.id,address:$('wallet-address').value.trim(),token_id:$('token-id').value.trim()});nonce=d.nonce;$('challenge-message').value=d.message;return {d,c};}
    $('offer').addEventListener('change',price);$('consent').addEventListener('change',availability);
    $('refresh').addEventListener('click',()=>run(status));
    $('submit-payment').addEventListener('click',()=>run(()=>settle($('payment-payload').value.trim())));
    $('retry-payment').addEventListener('click',()=>run(()=>settle(pending.header)));
    $('pay').addEventListener('click',()=>run(async()=>{const o=config.offers[Number($('offer').value)];let a=adapter(o.requirements.network);
        if(!a&&o.requirements.network.startsWith('solana:')){
            const provider=window.phantom?.solana||window.solflare||window.solana;
            if(provider?.connect&&provider?.signTransaction)a={createPaymentPayload:async({paymentRequired,requirements})=>{
                    await provider.connect();const address=provider.publicKey.toString();
                    const prepared=await post('/solana/prepare',{network:requirements.network,address});
                    const tx=solanaWeb3.Transaction.from(Uint8Array.from(atob(prepared.transaction),c=>c.charCodeAt(0)));
                    if(tx.instructions.length!==1)throw Error('Unexpected transaction instructions.');
                    const transfer=solanaWeb3.SystemInstruction.decodeTransfer(tx.instructions[0]);
                    if(transfer.fromPubkey.toString()!==address||transfer.toPubkey.toString()!==requirements.payTo||String(transfer.lamports)!==requirements.amount)throw Error('Prepared transaction does not match the displayed price.');
                    const signed=await provider.signTransaction(tx);
                    return {x402Version:2,resource:paymentRequired.resource,accepted:requirements,payload:{transaction:btoa(String.fromCharCode(...signed.serialize()))}};
                }};
        }
        if(!a?.createPaymentPayload)throw Error('No compatible browser wallet adapter is installed for this network. Use the Concert agent SDK or a signed x402 payment below.');const {r,data}=await send('/payment',{});if(r.ok){await status();return;}if(r.status!==402)throw Error(data.error);const p=await a.createPaymentPayload({paymentRequired:data,requirements:o.requirements,session});await settle(btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(p)))));}));
    $('challenge').addEventListener('click',()=>run(async()=>{await createChallenge();say('Sign the displayed message with your wallet, then submit its signature.');}));
    $('submit-proof').addEventListener('click',()=>run(async()=>{await post('/nft/verify',{nonce,signature:$('signature').value.trim(),public_key:$('public-key').value.trim()});await status();}));
    $('prove').addEventListener('click',()=>run(async()=>{
        const c=config.collections[Number($('collection').value)];if(!c)throw Error('No collection is enabled.');let a=adapter(c.network);
        if(!a&&c.network.startsWith('solana:')){const p=window.phantom?.solana||window.solflare||window.solana;if(p?.connect&&p?.signMessage)a={connect:async()=>{await p.connect();return p.publicKey.toString();},signMessage:async(message)=>{const x=await p.signMessage(new TextEncoder().encode(message),'utf8');return {signature:btoa(String.fromCharCode(...(x.signature||x)))};}};}
        if(!a?.signMessage)throw Error('Connect a compatible wallet adapter, or use the signed-message form below.');if(a.connect)$('wallet-address').value=await a.connect();const {d}=await createChallenge();const proof=await a.signMessage(d.message,c.network);await post('/nft/verify',{nonce:d.nonce,signature:proof.signature,public_key:proof.public_key||''});await status();
    }));
    // Keep the existing FIFO ticket alive while reviewing wallet options. Never
    // auto-redirect from this page during an approval or settlement operation.
    const heartbeat=setInterval(()=>{if(document.cookie.split(';').some(x=>x.trim().startsWith('room_probe=')))fetch('/queue/status',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(5000)}).then(r=>r.ok?r.json():null).then(d=>{if(d?.ready===true&&!busy&&!hasAccess){$('return').classList.add('button-primary');$('return').textContent='Your turn in the standard queue · continue ↗';}}).catch(()=>{});},5000);
    window.addEventListener('pagehide',()=>clearInterval(heartbeat));
    run(async()=>{const {data}=await call('/config');if(!data.enabled)throw Error('Wallet access is not enabled. The standard queue remains available.');config=data;const s=await post('/session',{});csrf=s.csrf;session=s.session;$('access-options').hidden=false;$('mode-label').textContent=data.test_mode?'TEST NETWORKS · NO MAINNET PAYMENTS':'WALLET ACCESS';if(data.test_mode)$('mode-label').classList.add('badge-test');$('merchant').textContent='Operated by '+data.merchant;$('pass-description').textContent=data.pass_seconds+' seconds of priority eligibility after settlement. This does not reserve a slot or guarantee service availability.';$('nft-description').textContent='Prove ownership with a signed message. No payment or NFT transfer. Access lasts '+data.nft_pass_seconds+' seconds.';for(const [id,url] of [['terms-link',data.terms_url],['refund-link',data.refund_url],['privacy-link',data.privacy_url],['policy-link',data.refund_url]])$(id).href=url;for(const [id,items] of [['offer',data.offers],['collection',data.collections]])items.forEach((x,i)=>{const el=document.createElement('option');el.value=i;el.textContent=x.label;$(id).append(el);});
        const saved=sessionStorage.getItem('concert.pending-payment');if(saved){pending=JSON.parse(saved);$('payment-payload').value=pending.header;$('retry-payment').hidden=false;const p=JSON.parse(atob(pending.header));const index=config.offers.findIndex(o=>o.requirements.network===p.accepted?.network);if(index>=0)$('offer').value=index;}
        price();await status();});
})();