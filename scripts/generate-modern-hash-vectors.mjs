#!/usr/bin/env node
// Independent oracle: @noble/hashes (JavaScript), no node C++ crypto or RPC.
// Usage: node scripts/generate-modern-hash-vectors.mjs /path/to/node_modules/@noble/hashes
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
const root = process.argv[2];
if (!root) throw new Error('Pass the directory containing @noble/hashes');
const load = file => import(pathToFileURL(resolve(root, file)).href);
const { keccak_256, sha3_256 } = await load('sha3.js');
const { blake3 } = await load('blake3.js');
const { blake2b } = await load('blake2.js');
const { sha512 } = await load('sha2.js');
for (const size of [0,32,33,63,64,65,127,128,129,135,136,137,1023,1024,1025,1313,2420,3072]) {
 const data = Uint8Array.from({length:size}, (_,i)=>i%256);
 for (const [opcode,hash] of [
  ['KECCAK256',keccak_256],['BLAKE2B',x=>blake2b(x,{dkLen:32})],
  ['BLAKE3',blake3],['SHA3_256',sha3_256],['SHA512',sha512]
 ]) console.log(`        {${size}, OP_${opcode}, "${Buffer.from(hash(data)).toString('hex')}"},`);
}
