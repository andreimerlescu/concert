// Operator recovery after a gateway crash/timeout. This command never signs,
// broadcasts, refunds or moves funds. It checks final ledger state, then records
// a settlement result for an already verified and journaled authorization.
import {readFileSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {Client, hashes, decode} from 'xrpl';
import {Connection} from '@solana/web3.js';
import {rpc, TransactionBuilder, Networks} from '@stellar/stellar-sdk';
import {inspectHederaTransaction} from '@x402/hedera';
import {inspectNativeSOL} from './solana.mjs';
import {fetchJSON} from './nft.mjs';
import {canonical,assertXrplNetwork} from './engine.mjs';

async function main() {
    const id=process.argv[2], supplied=process.argv[3];
    if(!/^[0-9a-f]{64}$/.test(id??''))throw Error('Usage: node reconcile.mjs <gateway payment fingerprint> [Stellar transaction hash]');
    const networks=JSON.parse(readFileSync(process.env.CONCERT_NETWORKS_CONFIG??'../examples/networks.testnet.json','utf8'));
    const db=new DatabaseSync(process.env.CONCERT_GATEWAY_DB??'./data/settlements.sqlite');
    try {
        const record=db.prepare('SELECT * FROM payments WHERE id=?').get(id);if(!record)throw Error('Receipt not found');
        if(record.state==='settled'){console.log('Already settled; no changes.');return;}
        const p=JSON.parse(record.payload),r=JSON.parse(record.terms),n=networks[r.network];if(!n)throw Error('Network configuration is missing');
        let transaction;
        switch(r.network.split(':')[0]) {
            case 'xrpl': {
                transaction=hashes.hashSignedTx(p.payload.signedTxBlob);
                const tx=decode(p.payload.signedTxBlob);
                if(tx.TransactionType!=='Payment'||tx.Account!==record.payer||tx.Destination!==r.payTo||tx.Amount!==r.amount||(Number(tx.Flags??0)&0x00020000))throw Error('Payment terms mismatch');
                const client=new Client(n.ws);await client.connect();
                try{await assertXrplNetwork(client,r.network);const result=(await client.request({command:'tx',transaction,binary:false})).result;if(!result.validated||result.meta?.TransactionResult!=='tesSUCCESS'||result.meta.delivered_amount!==r.amount)throw Error('Exact payment not finalized');}finally{await client.disconnect();}
                break;
            }
            case 'solana': {
                const x=inspectNativeSOL(p.payload.transaction,r);transaction=x.signature;
                const c=new Connection(n.rpc,'finalized');
                if(`solana:${(await c.getGenesisHash()).slice(0,32)}`!==r.network)throw Error('Network mismatch');
                const result=(await c.getSignatureStatuses([transaction],{searchTransactionHistory:true})).value[0];
                if(result?.confirmationStatus!=='finalized'||result.err)throw Error('Payment not finalized');
                break;
            }
            case 'hedera': {
                const inspected=inspectHederaTransaction(p.payload.transaction);transaction=inspected.transactionId;
                const m=/^(\d+\.\d+\.\d+)@(\d+)\.(\d+)$/.exec(transaction);if(!m)throw Error('Unrecognized Hedera transaction ID');
                const mirrorID=`${m[1]}-${m[2]}-${m[3].padStart(9,'0')}`;
                const data=await fetchJSON(n.mirror.replace(/\/$/,'')+'/api/v1/transactions/'+mirrorID);
                const tx=data.transactions?.find(x=>x.result==='SUCCESS'&&x.nonce===0&&!x.scheduled&&x.name==='CRYPTOTRANSFER');
                if(!tx||tx.token_transfers?.length)throw Error('Native HBAR payment not finalized');
                // JSON numbers outside the safe integer range cannot be reconciled
                // exactly. Refuse them rather than round a ledger amount.
                if(!(tx.transfers??[]).every(x=>Number.isSafeInteger(x.amount)))throw Error('Mirror amounts exceed exact JSON integer range');
                const net=address=>(tx.transfers??[]).filter(x=>x.account===address).reduce((sum,x)=>sum+BigInt(x.amount),0n);
                if(net(record.payer)!==-BigInt(r.amount)||net(r.payTo)!==BigInt(r.amount))throw Error('Ledger transfer does not match exact payment');
                break;
            }
            case 'stellar': {
                // The sponsor creates a fresh transaction envelope. Supply its hash
                // from the sponsor's ledger history, then compare the signed auth
                // entries and invocation, not just a matching amount/recipient.
                if(!/^[0-9a-fA-F]{64}$/.test(supplied??''))throw Error('Stellar recovery requires the sponsor transaction hash');transaction=supplied.toLowerCase();
                const pass=r.network==='stellar:pubnet'?Networks.PUBLIC:Networks.TESTNET;
                const result=await new rpc.Server(n.rpc).getTransaction(transaction);if(result.status!=='SUCCESS')throw Error('Payment not finalized');
                const envelope=TransactionBuilder.fromXDR(result.envelopeXdr,pass);
                if(envelope.hash().toString('hex')!==transaction)throw Error('Transaction hash mismatch');
                const settled=envelope.innerTransaction??envelope,original=TransactionBuilder.fromXDR(p.payload.transaction,pass);
                const op=settled.operations[0],expected=original.operations[0];
                if(settled.operations.length!==1||op.type!=='invokeHostFunction'||expected.type!=='invokeHostFunction'||op.func.toXDR('base64')!==expected.func.toXDR('base64')||canonical(op.auth.map(x=>x.toXDR('base64')))!==canonical(expected.auth.map(x=>x.toXDR('base64'))))throw Error('Ledger transaction does not contain this signed authorization');
                break;
            }
            default:throw Error('Unsupported network');
        }
        const result={success:true,network:r.network,transaction,payer:record.payer};
        // Stop the gateway while running this utility. The compare-and-update also
        // refuses to overwrite a result that another process completed meanwhile.
        const changed=db.prepare("UPDATE payments SET state='settled',response=? WHERE id=? AND state IN ('pending','unknown')").run(JSON.stringify(result),id);
        console.log(changed.changes===1?'Final settlement verified and recorded. Retry the IDENTICAL payment at Concert.':'Receipt changed concurrently; inspect it before retrying.');
    } finally {db.close();}
}
main().catch(e=>{console.error(e.message);process.exitCode=1;});