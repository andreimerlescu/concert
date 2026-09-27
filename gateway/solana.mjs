import {Connection, PublicKey, Transaction, VersionedTransaction, SystemProgram} from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export function inspectNativeSOL(encoded, requirements) {
    const raw = Buffer.from(encoded, 'base64');
    if (raw.length > 1232 || raw.length < 100 || raw.toString('base64') !== encoded) throw Error('Invalid transaction encoding');
    const tx = Transaction.from(raw);
    // One byte sequence per transaction: trailing or non-canonical bytes would
    // give the same signature a second payload fingerprint.
    if (!tx.serialize({requireAllSignatures:false,verifySignatures:false}).equals(raw)) throw Error('Non-canonical transaction encoding');
    if (tx.instructions.length !== 1 || tx.signatures.length !== 1) throw Error('Exactly one transfer and one payer are required');
    const ix = tx.instructions[0];
    if (!ix.programId.equals(SystemProgram.programId) || ix.keys.length !== 2 || ix.data.length !== 12 || ix.data.readUInt32LE(0) !== 2) throw Error('Only a native SystemProgram transfer is accepted');
    const payer = ix.keys[0].pubkey.toBase58();
    if (!ix.keys[0].isSigner || !ix.keys[0].isWritable || !ix.keys[1].isWritable || ix.keys[1].isSigner || !tx.feePayer?.equals(ix.keys[0].pubkey)) throw Error('Invalid transfer authority');
    if (payer === requirements.payTo || ix.keys[1].pubkey.toBase58() !== requirements.payTo || ix.data.readBigUInt64LE(4).toString() !== requirements.amount) throw Error('Payment terms mismatch');
    if (!tx.signature || !nacl.sign.detached.verify(tx.serializeMessage(), tx.signature, tx.feePayer.toBytes())) throw Error('Invalid payer signature');
    return {tx, raw, payer, signature: bs58.encode(tx.signature)};
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// This named extension deliberately does not impersonate x402's SPL exact
// scheme. It accepts one fully signed, payer-funded native SOL transfer.
export class NativeSOLScheme {
    scheme = 'concert-native-sol';
    caipFamily = 'solana:*';
    constructor(url, network, {connection = new Connection(url, 'finalized'), pollMs = 2000, confirmSeconds = 120} = {}) {
        this.connection = connection; this.network = network; this.pollMs = pollMs; this.confirmSeconds = confirmSeconds;
    }
    getExtra() { return {areFeesSponsored: false, paymentFlow: 'upfront'}; }
    getSigners() { return []; }
    async checkNetwork(req) {
        if (req.scheme !== this.scheme || req.asset !== 'SOL' || req.network !== this.network) throw Error('Wrong network or scheme');
        if (`solana:${(await this.connection.getGenesisHash()).slice(0,32)}` !== req.network) throw Error('RPC network mismatch');
    }
    async status(signature) { return (await this.connection.getSignatureStatuses([signature], {searchTransactionHistory:true})).value[0]; }
    async preflight(x) {
        if (!(await this.connection.isBlockhashValid(x.tx.recentBlockhash, 'finalized')).value) throw Error('Blockhash expired');
        const sim = await this.connection.simulateTransaction(VersionedTransaction.deserialize(x.raw), {sigVerify:true,commitment:'finalized'});
        if (sim.value.err) throw Error('Simulation failed');
    }
    // A signed transfer is public once it reaches the network. Only a
    // transaction this gateway has not yet seen on-chain can become new payment
    // evidence; otherwise anyone who observed it could claim the payer's pass.
    async verify(payload, req) {
        try {
            if (payload.x402Version !== 2) throw Error('Wrong x402 version');
            await this.checkNetwork(req);
            const x = inspectNativeSOL(payload.payload.transaction, req);
            if (await this.status(x.signature)) throw Error('Transaction was already submitted');
            await this.preflight(x);
            return {isValid:true,payer:x.payer};
        } catch { return {isValid:false,invalidReason:'invalid_native_sol_payment',payer:''}; }
    }
    // Called only after the gateway journaled this authorization as pending, so
    // a transfer already on-chain here is this payment landing, not a replay.
    async settle(payload, req) {
        await this.checkNetwork(req);
        const x = inspectNativeSOL(payload.payload.transaction, req);
        if (!(await this.status(x.signature))) {
            await this.preflight(x);
            const signature = await this.connection.sendRawTransaction(x.raw,{skipPreflight:false,maxRetries:3,preflightCommitment:'finalized'});
            if (signature !== x.signature) throw Error('RPC signature mismatch');
        }
        // Poll rather than rely on a WebSocket subscription. A timeout throws, so
        // the journal records the outcome as unknown rather than failed.
        const deadline = Date.now() + this.confirmSeconds*1000;
        for (;;) {
            const status = await this.status(x.signature);
            if (status?.err) throw Error('Transfer failed');
            if (status?.confirmationStatus === 'finalized') return {success:true,transaction:x.signature,network:req.network,payer:x.payer};
            if (Date.now() >= deadline) throw Error('Finality not observed');
            await sleep(this.pollMs);
        }
    }
}

const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const METADATA = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');

// Decode only the fields needed from the canonical Token Metadata account.
// Reject truncation and unverified metadata rather than trusting a name/URI.
export function readCollection(data, mint) {
    let i = 0;
    const take = n => { if (n < 0 || i+n > data.length) throw Error('Truncated metadata'); const b=data.subarray(i,i+n);i+=n;return b; };
    const byte = () => take(1)[0];
    const string = () => { const n=take(4).readUInt32LE();if(n>4096)throw Error('Invalid metadata string');take(n); };
    const option = f => { const tag=byte();if(tag===1)return f();if(tag!==0)throw Error('Invalid option');return null; };
    if(byte()!==4)throw Error('Not a MetadataV1 account');take(32);
    if(new PublicKey(take(32)).toBase58()!==mint)throw Error('Wrong metadata mint');
    string();string();string();take(2);
    option(()=>{const n=take(4).readUInt32LE();if(n>5)throw Error('Invalid creators');take(n*34);});
    take(2);option(byte);const standard=option(byte);
    if (standard!==null && ![0,3,4,5].includes(standard)) throw Error('Not a nonfungible token');
    return option(()=>({verified:byte()===1,key:new PublicKey(take(32)).toBase58()}));
}

export async function ownsSolanaNFT(url, address, collection, mint, network) {
    if (!mint) throw Error('NFT mint is required');
    const rpc = new Connection(url,'finalized');
    if(`solana:${(await rpc.getGenesisHash()).slice(0,32)}`!==network)throw Error('RPC network mismatch');
    const mintKey = new PublicKey(mint);
    const mintInfo = await rpc.getAccountInfo(mintKey,'finalized');
    if (!mintInfo || !mintInfo.owner.equals(TOKEN) || mintInfo.data.length!==82 || mintInfo.data.readBigUInt64LE(36)!==1n || mintInfo.data[44]!==0 || mintInfo.data[45]!==1) throw Error('Not a one-supply SPL NFT');
    const owned = await rpc.getParsedTokenAccountsByOwner(new PublicKey(address),{mint:mintKey},'finalized');
    if (!owned.value.some(a=>a.account.owner.equals(TOKEN) && a.account.data.parsed.info.owner===address && a.account.data.parsed.info.tokenAmount.amount==='1')) throw Error('Wallet does not own this mint');
    const [pda] = PublicKey.findProgramAddressSync([Buffer.from('metadata'),METADATA.toBuffer(),mintKey.toBuffer()],METADATA);
    const metadata = await rpc.getAccountInfo(pda,'finalized');
    if (!metadata || !metadata.owner.equals(METADATA)) throw Error('Metadata not owned by Metaplex');
    const c = readCollection(metadata.data,mint);
    if (!c?.verified || c.key!==collection) throw Error('Collection is not verified');
    return mint;
}