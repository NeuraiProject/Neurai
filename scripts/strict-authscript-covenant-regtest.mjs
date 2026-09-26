// Regtest covenant example for NIP-041 (AuthScript destination introspection).
// Builds the contract scripts with @neuraiproject/neurai-scripts, spends them with a
// NoAuth (authType 0x00) witness, and submits through the node RPC.
// Run by scripts/strict-authscript-covenant-regtest.sh inside a Node container that
// shares the network namespace of the regtest node.
import { createHash } from 'node:crypto';

const LIB = process.env.NEURAI_SCRIPTS || '/libs/neurai-scripts/dist/index.js';
const { ScriptBuilder, buildAuthScriptWitnessNoAuth, encodeAuthScriptScriptPubKey } = await import(LIB);

const RPC = process.env.RPC_URL || 'http://127.0.0.1:18521';
const AUTH = 'Basic ' + Buffer.from('u:p').toString('base64');
const OP_EQUAL = 0x87, OP_DROP = 0x75, OP_SPLIT = 0xb7, OP_TXFIELD = 0xb6, OP_TRUE = 0x51;
const OP_OUTPUTAUTHDEST = 0xc2;      // NIP-041, not yet known to the library: emitted as a raw opcode
const AUTHDEST_SELECTOR = 4;

let pass = 0, fail = 0;
const ok = (m) => { pass++; console.log('PASS: ' + m); };
const bad = (m) => { fail++; console.log('FAIL: ' + m); };
const check = (cond, m) => (cond ? ok(m) : bad(m));

async function rpc(method, ...params) {
  const res = await fetch(RPC, { method: 'POST', headers: { Authorization: AUTH, 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'c', method, params }) });
  const body = await res.json();
  if (body.error) { const e = new Error(body.error.message); e.code = body.error.code; throw e; }
  return body.result;
}
const hex = (u8) => Buffer.from(u8).toString('hex');
const unhex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const sha256 = (b) => createHash('sha256').update(b).digest();
const cat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));

// Node: TaggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
function taggedHash(tag, msg) { const t = sha256(Buffer.from(tag)); return sha256(cat(t, t, msg)); }
// Generic AuthScript v1, NoAuth: TaggedHash("NeuraiAuthScript", 0x01 || 0x00 || SHA256(witnessScript))
const noAuthCommitment = (ws) => taggedHash('NeuraiAuthScript', cat([0x01], [0x00], sha256(ws)));

// bech32m (witness v1 address of the contract, HRP tnq on regtest)
const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(v) { const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1;
  for (const x of v) { const b = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) c ^= G[i]; } return c >>> 0; }
function bech32m(hrp, version, program) {
  let acc = 0, bits = 0; const data = [version];
  for (const byte of program) { acc = (acc << 8) | byte; bits += 8; while (bits >= 5) { bits -= 5; data.push((acc >>> bits) & 31); } }
  if (bits) data.push((acc << (5 - bits)) & 31);
  const exp = [...hrp].map((c) => c.charCodeAt(0) >>> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
  const pm = polymod(exp.concat(data, [0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3;
  const chk = [0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(chk).map((d) => CH[d]).join('');
}

// Minimal witness transaction serializer (1 input, n outputs).
const le = (n, bytes) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b.subarray(0, bytes); };
const varint = (n) => (n < 0xfd ? Buffer.from([n]) : Buffer.concat([Buffer.from([0xfd]), le(n, 2)]));
function serializeTx({ txid, vout, outputs, witness }) {
  const parts = [le(2, 4), Buffer.from([0x00, 0x01]), varint(1), Buffer.from(txid, 'hex').reverse(), le(vout, 4), varint(0), le(0xffffffff, 4), varint(outputs.length)];
  for (const o of outputs) parts.push(le(o.sats, 8), varint(o.script.length), Buffer.from(o.script));
  parts.push(varint(witness.length));
  for (const item of witness) parts.push(varint(item.length), Buffer.from(item));
  parts.push(le(0, 4));
  return Buffer.concat(parts).toString('hex');
}

async function mine(n, addr) { await rpc('generatetoaddress', n, addr); }
async function fundContract(address, amount, mineTo) {
  const txid = await rpc('sendtoaddress', address, amount); await mine(1, mineTo);
  const tx = await rpc('getrawtransaction', txid, true);
  const out = tx.vout.find((o) => o.scriptPubKey.addresses && o.scriptPubKey.addresses[0] === address);
  return { txid, vout: out.n, sats: Math.round(out.value * 1e8) };
}
async function trySpend(utxo, witnessScript, outputScript) {
  const witness = buildAuthScriptWitnessNoAuth({ witnessScript });
  const raw = serializeTx({ txid: utxo.txid, vout: utxo.vout, witness, outputs: [{ sats: utxo.sats - 5_000_000, script: outputScript }] });
  try { return { txid: await rpc('sendrawtransaction', raw) }; } catch (e) { return { error: e.message }; }
}

// ---------------------------------------------------------------------------------
const minerAddr = await rpc('getnewaddress');
await mine(110, minerAddr);

const destAddr = await rpc('getnewaddress', '', 'ecdsa');                       // strict ECDSA, witness v3
const destSpk = unhex((await rpc('validateaddress', destAddr)).scriptPubKey);   // 53 20 <32 bytes>
check(destSpk.length === 34 && destSpk[0] === 0x53 && destSpk[1] === 0x20, 'strict ECDSA destination script is OP_3 <32 bytes>');
const program = destSpk.slice(2);
const dest33 = cat([0x03], program);

console.log('== contract 1: "output 0 must pay the strict destination X" (OP_OUTPUTAUTHDEST)');
const contract1 = new ScriptBuilder().pushInt(0).op(OP_OUTPUTAUTHDEST).pushBytes(dest33).op(OP_EQUAL).build();
console.log('   witnessScript: ' + hex(contract1));
const commitment1 = noAuthCommitment(contract1);
const spk1 = encodeAuthScriptScriptPubKey(Uint8Array.from(commitment1));
const addr1 = bech32m('tnq', 1, commitment1);
const v1 = await rpc('validateaddress', addr1);
check(v1.isvalid && v1.scriptPubKey === hex(spk1), 'library scriptPubKey and node address agree for the contract');

const u1 = await fundContract(addr1, 10, minerAddr);
const u2 = await fundContract(addr1, 10, minerAddr);

let r = await trySpend(u2, contract1, cat([0x52, 0x20], program));
check(!!r.error, 'rejected: same 32 bytes under witness v2 (' + (r.error || 'ACCEPTED') + ')');
r = await trySpend(u2, contract1, cat([0x51, 0x20], program));
check(!!r.error, 'rejected: same 32 bytes under witness v1 (' + (r.error || 'ACCEPTED') + ')');
r = await trySpend(u2, contract1, cat(destSpk, [OP_TRUE]));
check(!!r.error, 'rejected: destination prefix followed by an extra opcode (' + (r.error || 'ACCEPTED') + ')');
r = await trySpend(u2, contract1, unhex((await rpc('validateaddress', minerAddr)).scriptPubKey));
check(!!r.error, 'rejected: payment to a different address (' + (r.error || 'ACCEPTED') + ')');

r = await trySpend(u1, contract1, destSpk);
check(!!r.txid, 'accepted: payment to the exact strict destination X' + (r.error ? ' (' + r.error + ')' : ''));
if (r.txid) {
  await mine(1, minerAddr);
  const conf = (await rpc('getrawtransaction', r.txid, true)).confirmations;
  check(conf === 1, 'contract spend confirmed in a block');
  const mineCoins = await rpc('listunspent', 1, 9999, [destAddr]);
  check(mineCoins.length === 1 && Math.abs(mineCoins[0].amount - 9.95) < 1e-8, 'wallet received the funds at its strict ECDSA address');
}
r = await trySpend(u2, contract1, destSpk);
check(!!r.txid, 'second contract coin still spendable the right way');
await mine(1, minerAddr);

console.log('== contract 2: "the coin being spent is itself a generic v1 destination" (OP_TXFIELD selector 0x04)');
const contract2 = new ScriptBuilder().pushInt(AUTHDEST_SELECTOR).op(OP_TXFIELD).pushInt(1).op(OP_SPLIT, OP_DROP).pushInt(1).op(OP_EQUAL).build();
console.log('   witnessScript: ' + hex(contract2));
const addr2 = bech32m('tnq', 1, noAuthCommitment(contract2));
const u3 = await fundContract(addr2, 10, minerAddr);
r = await trySpend(u3, contract2, destSpk);
check(!!r.txid, 'accepted: spent-input destination reports version 01' + (r.error ? ' (' + r.error + ')' : ''));
await mine(1, minerAddr);

console.log(`RESULT: PASS=${pass} FAIL=${fail}`);
process.exit(fail ? 1 : 0);
