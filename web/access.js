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
    function originRejected(){
        const here=location.origin,right=config?.origin;$('origin-help').hidden=false;
        $('origin-text').textContent=right&&right!==here?'This page was opened from '+here+', but wallet actions only work from '+right+'. Your browser sends that address with every wallet request and Concert refuses any other. You can still read the options below.':'Concert refused this wallet request because its origin did not match the configured one. Reload the page from the site’s public address. You can still read the options below.';
        if(right&&right!==here){$('origin-link').href=right+location.pathname+location.search;$('origin-link').hidden=false;}
    }
    async function post(path,body,headers={}){const {r,data}=await send(path,body,headers);if(!r.ok){if(data.error==='origin_rejected'){originRejected();throw Error('Wallet actions are unavailable from this address.');}throw Error(data.error||'Request could not be completed');}return data;}
    async function run(fn){if(busy)return;busy=true;for(const b of document.querySelectorAll('button'))b.disabled=true;try{await fn();}catch(e){say(e.message.replaceAll('_',' '));}finally{busy=false;for(const b of document.querySelectorAll('button'))b.disabled=false;availability();}}
    function availability(){if(!config)return;for(const t of document.querySelectorAll('.chain-tab'))t.disabled=!config.offers.some(o=>o.requirements.network.split(':')[0]===t.dataset.chain);$('pay').disabled=!$('consent').checked||!config.offers.length||!!pending||hasAccess;$('submit-payment').disabled=!$('consent').checked||!config.offers.length||hasAccess;$('retry-payment').disabled=!$('consent').checked||!pending;$('prove').disabled=!config.collections.length;$('challenge').disabled=!config.collections.length;}
    function forgetPending(){sessionStorage.removeItem('concert.pending-payment');pending=null;$('retry-payment').hidden=true;}
    const digits={xrpl:6,stellar:7,hedera:8,solana:9},tickers={xrpl:'XRP',stellar:'XLM',hedera:'HBAR',solana:'SOL'};
    function fmt(r){const f=r.network.split(':')[0],d=digits[f],s=r.amount.padStart(d+1,'0');return s.slice(0,-d)+'.'+s.slice(-d).replace(/0+$/,'').padEnd(1,'0')+' '+tickers[f];}
    function price(){const o=config.offers[Number($('offer').value)];if(!o){$('price').textContent='Not offered';return;}$('price').textContent=fmt(o.requirements);$('recipient').textContent='Pay to '+o.requirements.payTo;}
    const row=(title,lines)=>{const d=document.createElement('div');d.className='info-row';const t=document.createElement('strong');t.textContent=title;d.append(t);for(const [text,code] of lines){const x=document.createElement(code?'code':'span');x.textContent=text;d.append(x,document.createElement('br'));}return d;};
    // Read-only summary of what a visitor can do, shown even when wallet
    // requests are refused (for example when the page is opened from the wrong
    // address), so a waiting visitor can always see what to bring.
    function renderInfo(){
        const cols=$('info-collections'),offers=$('info-offers');cols.replaceChildren();offers.replaceChildren();
        if(!config.collections.length)cols.textContent='No NFT collections are configured.';
        for(const c of config.collections)cols.append(row(c.label,[[c.network+' · rule '+c.id],[c.collection,true]]));
        if(!config.offers.length)offers.textContent='No payment options are configured.';
        for(const o of config.offers){const r=o.requirements;offers.append(row(o.label,[['Price: '+fmt(r)],['Pay to',false],[r.payTo,true]]));}
        $('info-pass').textContent='A paid pass grants priority for '+config.pass_seconds+' seconds. An NFT proof grants it for '+config.nft_pass_seconds+' seconds. Neither reserves a slot.';
        $('access-info').hidden=false;
    }
    // Tagged deposits: the page shows a QR code for a payment to the merchant's
    // address carrying this session's destination tag, then watches for it.
    let depositTimer=null,deposit=null,chosen='';
    const chainOf=n=>n.split(':')[0];
    function stopWatching(){clearTimeout(depositTimer);depositTimer=null;}
    async function watchDeposit(){
        stopWatching();if(!deposit||hasAccess)return;
        try{const {r,data}=await send('/deposit/check',{network:deposit.network});
            if(r.ok&&data.eligible){$('deposit-status').textContent='Payment received. You are in.';await status();return;}
            if(!r.ok&&data.error==='origin_rejected'){originRejected();return;}
            $('deposit-status').textContent=r.ok?'Watching the network for your payment… this page updates by itself.':'Could not check the network just now ('+String(data.error||r.status).replaceAll('_',' ')+'). Retrying.';
        }catch{$('deposit-status').textContent='Connection interrupted. Retrying.';}
        depositTimer=setTimeout(watchDeposit,5000);
    }
    const copy=(id,btn)=>{navigator.clipboard?.writeText($(id).textContent).then(()=>{btn.textContent='Copied';setTimeout(()=>btn.textContent='Copy',1500);}).catch(()=>{});};
    $('copy-address').addEventListener('click',e=>copy('deposit-address',e.currentTarget));
    $('copy-ref').addEventListener('click',e=>copy('deposit-ref',e.currentTarget));
    $('copy-amount').addEventListener('click',e=>{navigator.clipboard?.writeText($('deposit-amount').dataset.plain).then(()=>{e.currentTarget.textContent='Copied';setTimeout(()=>{e.currentTarget.textContent='Copy';},1500);}).catch(()=>{});});
    // A tab picks the chain: its offer, its payment details and (when the
    // offer takes a signed x402 payment) the wallet card.
    function selectChain(f){
        chosen=f;stopWatching();deposit=null;$('deposit-details').hidden=true;
        for(const t of document.querySelectorAll('.chain-tab'))t.setAttribute('aria-selected',String(t.dataset.chain===f));
        const i=config.offers.findIndex(o=>chainOf(o.requirements.network)===f),o=config.offers[i];
        if(i>=0){$('offer').value=String(i);price();}
        const canDeposit=!!o&&(config.deposit_networks||[]).includes(o.requirements.network);
        $('deposit-start').hidden=!canDeposit;$('deposit-unavailable').hidden=canDeposit;
        $('deposit-title').textContent=o?'Send '+tickers[f]+', skip ahead':'Not offered';
        $('wallet-card').hidden=!o||!!o.deposit_only;
        availability();
    }
    for(const t of document.querySelectorAll('.chain-tab'))t.addEventListener('click',()=>selectChain(t.dataset.chain));
    $('deposit-start').addEventListener('click',()=>run(async()=>{
        const o=config.offers.find(x=>chainOf(x.requirements.network)===chosen);
        const d=await post('/deposit',{network:o.requirements.network});
        deposit=d;$('deposit-qr').src=d.qr;$('deposit-amount').textContent=d.amount_display+' '+tickers[chosen];$('deposit-amount').dataset.plain=d.amount_display;$('deposit-address').textContent=d.address;
        const xrp=chosen==='xrpl';$('deposit-ref-label').textContent=xrp?'Destination tag':'Memo';$('deposit-ref').textContent=xrp?String(d.tag):d.memo;
        $('deposit-warning').textContent='Send exactly '+d.amount_display+' '+tickers[chosen]+'. The last digits of the amount are how we know the payment is yours'+(xrp?', and the destination tag is required by some wallets and exchanges':', and the memo helps if your wallet supports one')+'. A different amount cannot be matched and is not refunded automatically.';
        $('deposit-details').hidden=false;$('deposit-status').textContent='Watching the network for your payment…';
        say('Send the exact amount to the address. Keep this page open until you are let in.');watchDeposit();
    }));
    window.addEventListener('pagehide',stopWatching);
    async function status(){const {data}=await call('/status');hasAccess=!!data.eligible;if(data.eligible){stopWatching();if(data.kind==='payment')forgetPending();say('Access is ready. Your pass is valid until '+new Date(data.expires).toLocaleTimeString()+'.');$('enter').hidden=false;}else if(['pending','unknown'].includes(data.state)){say('Payment is awaiting reconciliation. Do not make another payment. Retry the identical signed payload or contact the merchant.');$('enter').hidden=true;}else{say(pending?'A signed payment is saved in this tab. Review the terms, then retry that payment. Do not authorize a second payment.':'No active fast-lane pass. You can continue in the standard queue.');$('enter').hidden=true;}}
    async function settle(header){
        let signed;try{signed=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header),x=>x.charCodeAt(0))));}catch{throw Error('The payment header is not valid base64 JSON.');}
        const chosen=config.offers[Number($('offer').value)]?.requirements;
        if(!chosen||['scheme','network','asset','amount','payTo'].some(k=>signed.accepted?.[k]!==chosen[k]))throw Error('Signed payment does not match the selected network, amount or recipient.');
        if(!$('consent').checked)throw Error('Review the price and accept the terms first.');
        if(pending&&(pending.header!==header||nonceOf(pending.session)!==nonceOf(session)))throw Error('A previous payment must be reconciled first. Retry its identical signed payload or contact the merchant.');
        pending={header,session};sessionStorage.setItem('concert.pending-payment',JSON.stringify(pending));$('payment-payload').value=header;$('retry-payment').hidden=false;
        say('Verifying your payment and waiting for settlement…');const d=await post('/payment',{}, {'PAYMENT-SIGNATURE':header});forgetPending();if(!d.eligible)throw Error('This payment’s access period has expired.');await status();}
    // Solana wallets through the Wallet Standard (Phantom, Solflare, Backpack
    // and others): the app half of its registration handshake, plus a decoder
    // that checks the prepared transfer before and after the wallet signs it.
    // No Solana SDK is loaded.
    const standard=[];{const api={register:(...w)=>{standard.push(...w);return()=>{};}};window.addEventListener('wallet-standard:register-wallet',e=>{try{e.detail(api);}catch{}});try{window.dispatchEvent(new CustomEvent('wallet-standard:app-ready',{detail:api}));}catch{}}
    const solanaChains={'5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp':'solana:mainnet',EtWTRABZaYq6iMfeYKouRu166VU2xqa1:'solana:devnet','4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z':'solana:testnet'};
    function solanaWallet(network,feature){const chain=solanaChains[network.split(':')[1]];const w=standard.find(x=>x.chains?.includes(chain)&&x.features?.['standard:connect']&&x.features[feature]);return w?{w,chain}:null;}
    async function connectAccount({w,chain}){const {accounts}=await w.features['standard:connect'].connect();const account=accounts.find(x=>!x.chains||x.chains.includes(chain));if(!account)throw Error('The wallet shared no account for this network.');return account;}
    const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const b58=bytes=>{let n=0n;for(const b of bytes)n=n*256n+BigInt(b);let s='';while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;}for(const b of bytes){if(b)break;s='1'+s;}return s;};
    const b64=bytes=>{let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s);},unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
    // A legacy transaction with one signature slot whose message holds exactly
    // [payer, payee, System Program] and one System Program transfer.
    function transferOf(tx){
        let i=0;const bad=()=>{throw Error('Unexpected transaction instructions.');};
        const u8=()=>i<tx.length?tx[i++]:bad(),take=n=>i+n<=tx.length?tx.subarray(i,i+=n):bad();
        const len=()=>{let n=0;for(let s=0;s<21;s+=7){const b=u8();n|=(b&127)<<s;if(!(b&128))return n;}return bad();};
        const sigs=len();take(64*sigs);const message=tx.subarray(i);
        const header=[u8(),u8(),u8()].join(),keys=[];if(sigs!==1||header!=='1,0,1')bad();
        for(let k=len();k>0;k--)keys.push(take(32));take(32);
        if(keys.length!==3||keys[2].some(b=>b)||len()!==1||u8()!==2||len()!==2||u8()!==0||u8()!==1||len()!==12)bad();
        const data=take(12),view=new DataView(data.buffer,data.byteOffset,12);if(view.getUint32(0,true)!==2||i!==tx.length)bad();
        return {from:b58(keys[0]),to:b58(keys[1]),lamports:view.getBigUint64(4,true).toString(),message};
    }
    const adapter=network=>window.concertWallets?.[network]||window.concertWallets?.[network.split(':')[0]];
    async function createChallenge(){const c=config.collections[Number($('collection').value)];if(!c)throw Error('No collection is enabled.');const d=await post('/nft/challenge',{rule:c.id,address:$('wallet-address').value.trim(),token_id:$('token-id').value.trim()});nonce=d.nonce;$('challenge-message').value=d.message;return {d,c};}
    $('offer').addEventListener('change',price);$('consent').addEventListener('change',availability);
    $('refresh').addEventListener('click',()=>run(status));
    $('submit-payment').addEventListener('click',()=>run(()=>settle($('payment-payload').value.trim())));
    $('retry-payment').addEventListener('click',()=>run(()=>settle(pending.header)));
    $('pay').addEventListener('click',()=>run(async()=>{const o=config.offers[Number($('offer').value)];let a=adapter(o.requirements.network);
        if(!a&&o.requirements.network.startsWith('solana:')){const s=solanaWallet(o.requirements.network,'solana:signTransaction');if(s)a={createPaymentPayload:async({paymentRequired,requirements})=>{
                const account=await connectAccount(s);
                const prepared=unb64((await post('/solana/prepare',{network:requirements.network,address:account.address})).transaction),t=transferOf(prepared);
                if(t.from!==account.address||t.to!==requirements.payTo||t.lamports!==requirements.amount)throw Error('Prepared transaction does not match the displayed price.');
                const [out]=await s.w.features['solana:signTransaction'].signTransaction({account,transaction:prepared,chain:s.chain});
                const signed=new Uint8Array(out.signedTransaction);if(b64(transferOf(signed).message)!==b64(t.message))throw Error('The wallet changed the prepared transaction.');
                return {x402Version:2,resource:paymentRequired.resource,accepted:requirements,payload:{transaction:b64(signed)}};
            }};}
        if(!a?.createPaymentPayload)throw Error('No compatible browser wallet adapter is installed for this network. Use the Concert agent SDK or a signed x402 payment below.');const {r,data}=await send('/payment',{});if(r.ok){await status();return;}if(r.status!==402)throw Error(data.error);const p=await a.createPaymentPayload({paymentRequired:data,requirements:o.requirements,session});await settle(btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(p)))));}));
    $('challenge').addEventListener('click',()=>run(async()=>{await createChallenge();say('Sign the displayed message with your wallet, then submit its signature.');}));
    $('submit-proof').addEventListener('click',()=>run(async()=>{await post('/nft/verify',{nonce,signature:$('signature').value.trim(),public_key:$('public-key').value.trim()});await status();}));
    $('prove').addEventListener('click',()=>run(async()=>{
        const c=config.collections[Number($('collection').value)];if(!c)throw Error('No collection is enabled.');let a=adapter(c.network);
        if(!a&&c.network.startsWith('solana:')){const s=solanaWallet(c.network,'solana:signMessage');let account;if(s)a={connect:async()=>(account=await connectAccount(s)).address,signMessage:async message=>{const [x]=await s.w.features['solana:signMessage'].signMessage({account,message:new TextEncoder().encode(message)});return {signature:b64(new Uint8Array(x.signature))};}};}
        if(!a?.signMessage)throw Error('Connect a compatible wallet adapter, or use the signed-message form below.');if(a.connect)$('wallet-address').value=await a.connect();const {d}=await createChallenge();const proof=await a.signMessage(d.message,c.network);await post('/nft/verify',{nonce:d.nonce,signature:proof.signature,public_key:proof.public_key||''});await status();
    }));
    // Keep the existing FIFO ticket alive while reviewing wallet options. Never
    // auto-redirect from this page during an approval or settlement operation.
    const heartbeat=setInterval(()=>{if(document.cookie.split(';').some(x=>x.trim().startsWith('room_probe=')))fetch('/queue/status',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(5000)}).then(r=>r.ok?r.json():null).then(d=>{if(d?.ready===true&&!busy&&!hasAccess){$('return').classList.add('button-primary');$('return').textContent='Your turn in the standard queue · continue ↗';}}).catch(()=>{});},5000);
    window.addEventListener('pagehide',()=>clearInterval(heartbeat));
    run(async()=>{const {data}=await call('/config');if(!data.enabled)throw Error('Wallet access is not enabled. The standard queue remains available.');config=data;renderInfo();const s=await post('/session',{});csrf=s.csrf;session=s.session;$('access-options').hidden=false;for(const t of document.querySelectorAll('.chain-tab'))t.disabled=!data.offers.some(o=>chainOf(o.requirements.network)===t.dataset.chain);$('mode-label').textContent=data.test_mode?'TEST NETWORKS · NO MAINNET PAYMENTS':'WALLET ACCESS';if(data.test_mode)$('mode-label').classList.add('badge-test');$('merchant').textContent='Operated by '+data.merchant;$('pass-description').textContent=data.pass_seconds+' seconds of priority eligibility after settlement. This does not reserve a slot or guarantee service availability.';$('nft-description').textContent='Prove ownership with a signed message. No payment or NFT transfer. Access lasts '+data.nft_pass_seconds+' seconds.';for(const [id,url] of [['terms-link',data.terms_url],['refund-link',data.refund_url],['privacy-link',data.privacy_url],['policy-link',data.refund_url]])$(id).href=url;for(const [id,items] of [['offer',data.offers],['collection',data.collections]])items.forEach((x,i)=>{const el=document.createElement('option');el.value=i;el.textContent=x.label;$(id).append(el);});
        const saved=sessionStorage.getItem('concert.pending-payment');if(saved){pending=JSON.parse(saved);$('payment-payload').value=pending.header;$('retry-payment').hidden=false;const p=JSON.parse(atob(pending.header));const index=config.offers.findIndex(o=>o.requirements.network===p.accepted?.network);if(index>=0)$('offer').value=index;}
        const first=[...document.querySelectorAll('.chain-tab')].find(t=>!t.disabled);if(first)selectChain(first.dataset.chain);else $('access-options').hidden=false;await status();});
})();