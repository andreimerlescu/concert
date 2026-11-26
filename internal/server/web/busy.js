'use strict';
(()=>{
    const $=id=>document.getElementById(id);
    const raw=parseInt(document.body&&document.body.dataset?document.body.dataset.retryAfter:'',10);
    const base=Number.isFinite(raw)&&raw>0?raw:5;
    // Apply 0-20% positive jitter so burst reconnects do not synchronize.
    const delayMs=Math.round(base*1000*(1+Math.random()*0.2));
    const target=Date.now()+delayMs;
    let stopped=false,tickId=0,reloadId=0;

    function render(remainingMs){
        const secs=Math.max(0,Math.ceil(remainingMs/1000));
        const label=secs+'s';
        const countdown=$('retry-countdown');
        if(countdown)countdown.textContent=label;
        const timer=$('retry-timer');
        if(timer)timer.textContent=label;
        const state=$('busy-state');
        if(state)state.textContent=secs>0?'Retrying automatically in '+secs+'s':'Retrying now…';
    }

    function retryNow(){
        if(stopped)return;
        stopped=true;
        clearInterval(tickId);
        clearTimeout(reloadId);
        const state=$('busy-state');
        if(state)state.textContent='Retrying now…';
        window.location.reload();
    }

    const btn=$('retry-now');
    if(btn){
        btn.addEventListener('click',e=>{
            e.preventDefault();
            retryNow();
        });
    }

    render(delayMs);
    tickId=setInterval(()=>{
        const left=target-Date.now();
        if(left<=0){
            retryNow();
            return;
        }
        render(left);
    },250);
    reloadId=setTimeout(retryNow,delayMs);

    window.addEventListener('pagehide',()=>{
        stopped=true;
        clearInterval(tickId);
        clearTimeout(reloadId);
    });
    window.addEventListener('pageshow',e=>{
        if(e.persisted)window.location.reload();
    });
})();
