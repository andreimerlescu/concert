'use strict';
(()=>{
    const $=id=>document.getElementById(id),start=Date.now();let stopped=false,failures=0,timer;
    function fatal(message){stopped=true;clearTimeout(timer);$('queue-error').hidden=false;$('queue-error').textContent=message;$('queue-state').textContent='Action needed';$('session-state').textContent='Paused';}
    const elapsed=setInterval(()=>{const n=Math.floor((Date.now()-start)/1000);$('elapsed').textContent=String(Math.floor(n/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0');},1000);
    if(!document.cookie.split(';').some(x=>x.trim().startsWith('room_probe='))){fatal('Cookies are needed to save your place. Enable cookies for this site, then reload once.');return;}
    $('session-state').textContent='Protected';
    // The room substitutes {{.Position}}; show it at once in the ticket style.
    const initial=parseInt($('position').textContent,10);$('position').textContent=initial>0?String(initial).padStart(3,'0'):'…';
    let skipURL='';
    fetch('/_concert/config',{credentials:'same-origin',signal:AbortSignal.timeout(8000)}).then(r=>r.json()).then(c=>{if(c.legacy_skip_url){skipURL=c.legacy_skip_url;$('legacy-link').href=c.legacy_skip_url;}if(c.enabled){$('fastlane-card').hidden=false;$('access-link').href='/_concert/access?return='+encodeURIComponent(location.pathname+location.search);}}).catch(()=>{});
    // Same rule as room's built-in page: offer paid skipping only with a price,
    // a place to skip from, and no skip-the-line pass already held.
    function skipOffer(d){
        const show=!!skipURL&&!d.has_pass&&typeof d.skip_cost==='number'&&Number.isFinite(d.skip_cost)&&d.skip_cost>0&&d.position>1;
        $('legacy-card').hidden=!show;if(show)$('legacy-price').textContent='Current skip price: $'+d.skip_cost.toFixed(2);
    }
    async function poll(){
        if(stopped)return;
        try{
            const r=await fetch('/queue/status',{credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(8000)});
            if(r.status===403){fatal('Access is currently unavailable. Contact the site operator for help.');return;}
            // Polled too soon (e.g. the wallet page shares this ticket): the place is kept.
            if(r.status===429){timer=setTimeout(poll,3000+Math.random()*500);return;}
            if(!r.ok)throw Error('Status unavailable');
            const d=await r.json();failures=0;
            if(d.cookies_required){fatal('Your queue cookie is missing. Enable cookies for this site, then reload once.');return;}
            if(d.ready===true){stopped=true;$('queue-state').textContent='Your turn. Taking you in…';location.reload();return;}
            if(typeof d.position==='number'&&d.position>0)$('position').textContent=String(d.position).padStart(3,'0');
            skipOffer(d);
            $('queue-state').textContent='Your place is saved';$('queue-note').textContent=d.has_pass?'Your skip-the-line pass is active. Keep this tab open.':'Keep this tab open. We’ll take you in when it’s your turn.';
        }catch{failures++;$('queue-state').textContent='Reconnecting';$('queue-note').textContent='The status connection was interrupted. We’re retrying automatically.';}
        timer=setTimeout(poll,Math.min(10000,2000*2**Math.min(failures,3))+Math.random()*300);
    }
    window.addEventListener('pagehide',()=>{stopped=true;clearTimeout(timer);clearInterval(elapsed)});
    window.addEventListener('pageshow',e=>{if(e.persisted)location.reload();});
    poll();
})();