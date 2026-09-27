import {createServer} from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {buildEngine,validatePayment,canonical} from './engine.mjs';
import {SettlementJournal} from './journal.mjs';
import {verifyNFT} from './nft.mjs';
import {Connection,PublicKey,Transaction,SystemProgram} from '@solana/web3.js';

const json=(res,status,body)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(body));};

// createGateway returns the HTTP server without listening, so tests can drive
// it with a mocked engine. The chain SDKs stay behind engine and verifyNFT.
export function createGateway({config,networks,token,engine,journal,nft=verifyNFT}) {
    let active=0;
    const server=createServer({maxHeaderSize:16384},async(req,res)=>{
        const got=Buffer.from(req.headers.authorization??''), expected=Buffer.from('Bearer '+token);
        if(got.length!==expected.length||!timingSafeEqual(got,expected)){json(res,401,{error:'unauthorized'});return;}
        if(req.method==='GET'&&req.url==='/supported'){json(res,200,engine.getSupported());return;}
        if(req.method!=='POST'||!['/verify','/settle','/nft/verify','/solana/prepare'].includes(req.url)){json(res,404,{error:'not_found'});return;}
        if(active>=32){json(res,503,{error:'busy'});return;}active++;
        try {
            let size=0,chunks=[];for await(const c of req){size+=c.length;if(size>65536)throw Error('Request too large');chunks.push(c);}
            const input=JSON.parse(Buffer.concat(chunks).toString());
            if(req.url==='/solana/prepare'){
                const reqs=config.offers.find(o=>o.requirements.network===input.network&&o.requirements.scheme==='concert-native-sol')?.requirements;
                if(!reqs)throw Error('Network not offered');
                const connection=new Connection(networks[input.network].rpc,'finalized');
                if(`solana:${(await connection.getGenesisHash()).slice(0,32)}`!==input.network)throw Error('Network mismatch');
                const from=new PublicKey(input.address),to=new PublicKey(reqs.payTo);
                if(from.equals(to))throw Error('Self-payment is not accepted');
                const {blockhash}=await connection.getLatestBlockhash('finalized');
                const tx=new Transaction({feePayer:from,recentBlockhash:blockhash}).add(SystemProgram.transfer({fromPubkey:from,toPubkey:to,lamports:BigInt(reqs.amount)}));
                json(res,200,{transaction:tx.serialize({requireAllSignatures:false,verifySignatures:false}).toString('base64')});return;
            }
            if(req.url==='/nft/verify'){
                if(!(config.collections??[]).some(c=>c.network===input.network&&c.collection===input.collection))throw Error('Unknown collection');
                const network=networks[input.network];if(!network)throw Error('Missing network configuration');
                json(res,200,await nft(input,network));return;
            }
            const {p,r}=validatePayment(input,config,networks);
            if(req.url==='/verify'){
                const cached=journal.get(journal.fingerprint(p,r));
                if(cached){
                    // Never re-run on-chain preflight on an already consumed authorization.
                    // Concert only verifies authorizations it has not recorded, so a
                    // settled one here is a replay (for example after a lost Concert
                    // journal) and must not become a new pass.
                    if(cached.terms!==canonical(r))throw Error('Terms mismatch');
                    if(cached.state==='settled'){json(res,200,{isValid:false,invalidReason:'payment_already_settled',payer:cached.payer});return;}
                    json(res,200,{isValid:true,payer:cached.payer});return;
                }
                json(res,200,await engine.verify(p,r));return;
            }
            json(res,200,await journal.settle(p,r,()=>engine.verify(p,r),()=>engine.settle(p,r)));
        } catch {
            // SDK error strings may include RPC URLs/credentials or signed payloads.
            json(res,400,{error:'verification_failed'});
        } finally {active--;}
    });
    server.requestTimeout=15000;server.headersTimeout=10000;server.keepAliveTimeout=5000;
    return server;
}

function main() {
    process.umask(0o077);
    const config=JSON.parse(readFileSync(process.env.CONCERT_FASTLANE_CONFIG??'../examples/fastlane.testnet.json','utf8'));
    const networks=JSON.parse(readFileSync(process.env.CONCERT_NETWORKS_CONFIG??'../examples/networks.testnet.json','utf8'));
    const token=process.env.CONCERT_GATEWAY_TOKEN??'';
    if(!config.enabled)throw Error('Enable and complete the fast lane configuration before starting the gateway');
    if(token.length<32)throw Error('CONCERT_GATEWAY_TOKEN must be at least 32 characters');
    // The authenticated gateway is an operator-controlled trust boundary. Never
    // expose it directly to wallets or deploy an unauthenticated public facilitator.
    for(const n of Object.values(networks))for(const k of ['rpc','ws','horizon','mirror'])if(n[k]){
        const u=new URL(n[k]);if(!['https:','wss:'].includes(u.protocol)||u.username||u.password)throw Error('Chain endpoints must use HTTPS/WSS');
    }
    const journal=new SettlementJournal(process.env.CONCERT_GATEWAY_DB??'./data/settlements.sqlite');
    const server=createGateway({config,networks,token,engine:buildEngine(config,networks),journal});
    server.listen(Number(process.env.CONCERT_GATEWAY_PORT??8402),'127.0.0.1',()=>console.log('Concert chain gateway listening on loopback'));
    for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>server.close(async()=>{await journal.idle();journal.close();process.exit(0);}));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main();