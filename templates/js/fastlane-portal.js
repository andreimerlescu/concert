'use strict';
(()=>{
    const $=id=>document.getElementById(id);if(!$('fastlane-state'))return;
    const el=(tag,text,cls)=>{const x=document.createElement(tag);if(text!==undefined)x.textContent=text;if(cls)x.className=cls;return x;};
    async function load(){
        try{const r=await fetch('/api/fastlane',{credentials:'same-origin',signal:AbortSignal.timeout(8000)});if(!r.ok)throw Error('Sign in again to view fast-lane configuration.');const d=await r.json();$('fastlane-stats').replaceChildren();$('fastlane-offers').replaceChildren();$('fastlane-collections').replaceChildren();
            if(!d.enabled){$('fastlane-state').textContent='Wallet admission is off. Configure a fast-lane file to enable payments or NFT access.';return;}
            $('fastlane-state').textContent=(d.test_mode?'TEST MODE · Test networks only. ':'LIVE CONFIGURATION · ')+(d.healthy?'Receipt journal healthy.':'Receipt journal needs attention; admission suspended.')+' Merchant: '+d.merchant;
            for(const [name,value] of [['Settled sessions',d.states.settled],['Needs reconciliation',d.states.pending+d.states.unknown],['Paid pass',d.pass_seconds+'s'],['NFT lease',d.nft_pass_seconds+'s']]){const col=el('div',undefined,'col-sm-6 col-xl-3'),card=el('div',undefined,'card stat-card'),body=el('div',undefined,'card-body');body.append(el('div',name,'small text-body-secondary'),el('div',String(value),'stat-value'));card.append(body);col.append(card);$('fastlane-stats').append(col);}
            for(const o of d.offers){const c=el('article',undefined,'fastlane-rule');c.append(el('h4',o.label),el('small',o.requirements.network+' · '+o.requirements.scheme),el('code',o.requirements.amount+' atomic units · '+o.requirements.asset),el('small','Recipient'),el('code',o.requirements.payTo));$('fastlane-offers').append(c);}
            for(const o of d.collections){const c=el('article',undefined,'fastlane-rule');c.append(el('h4',o.label),el('small',o.network+' · rule '+o.id),el('code',o.collection));$('fastlane-collections').append(c);}
        }catch(e){$('fastlane-state').textContent=e.message;}
    }
    // Settings editor: the two JSON files, checked and applied without a restart.
    const csrf=(document.querySelector('meta[name="csrf-token"]')||{getAttribute:()=>''}).getAttribute('content');
    const msg=(t,ok)=>{const m=$('fastlane-editor-msg');m.textContent=t;m.className='small '+(ok===undefined?'':ok?'text-success':'text-danger');};
    async function loadEditor(){
        try{const r=await fetch('/api/fastlane/config',{credentials:'same-origin'});if(!r.ok)throw Error('Sign in again to edit settings.');const d=await r.json();
            $('fastlane-json').value=d.fastlane;$('networks-json').value=d.networks;
            $('fastlane-editor-badge').textContent=d.saved?(d.running?'running':'saved · wallet access off'):'not configured yet · showing the sample';
            $('fastlane-apply').disabled=!d.writable;if(!d.writable)msg('Set CONCERT_DATA_DIR so settings can be saved.',false);else msg('');
        }catch(e){msg(e.message,false);}
    }
    async function save(dry){
        msg(dry?'Checking…':'Applying…');
        try{const r=await fetch('/api/fastlane/config',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({fastlane:$('fastlane-json').value,networks:$('networks-json').value,dry_run:dry}),signal:AbortSignal.timeout(300000)});
            const d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');
            msg(dry?'These settings are valid.':'Applied. '+(d.running?'Wallet access is running with the new settings.':'Wallet access is off.'),true);
            if(!dry){await loadEditor();await load();}
        }catch(e){msg(e.message,false);}
    }
    $('fastlane-check').addEventListener('click',()=>save(true));$('fastlane-apply').addEventListener('click',()=>save(false));$('fastlane-reload-editor').addEventListener('click',loadEditor);
    $('fastlane-refresh').addEventListener('click',()=>{load();});$('tab-fastlane-btn').addEventListener('shown.bs.tab',()=>{load();loadEditor();});load();loadEditor();
})();