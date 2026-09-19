#!/usr/bin/env node
// Independent NIP-031 roots, using @noble/hashes rather than node C++ code.
// Usage: node scripts/generate-merkle-review-vectors.mjs /path/to/@noble/hashes
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const load=f=>import(pathToFileURL(resolve(process.argv[2],f)).href);
const {sha256}=await load('sha2.js');
const {keccak_256}=await load('sha3.js');
const {blake2b}=await load('blake2.js');
for(const scheme of [1,2,3,4]) for(const depth of [0,1,7,8,9,16,31,32]) for(const version of [1,2,3]) {
 const destination=Uint8Array.from([version,...Array.from({length:32},(_,i)=>i)]);
 const hash=[null,x=>sha256(sha256(x)),sha256,keccak_256,x=>blake2b(x,{dkLen:32})][scheme];
 // Scheme 1 receives a prehashed leaf, here SHA256(destination).
 let running=scheme===1?sha256(destination):hash(destination);
 for(let level=0;level<depth;level++) {
  const sibling=Uint8Array.from({length:32},(_,j)=>(37*level+j)%256);
  const right=(0xa5>>(level%8))&1;
  running=hash(Uint8Array.from(right?[...sibling,...running]:[...running,...sibling]));
 }
 console.log(`        {${scheme}, ${depth}, ${version}, "${Buffer.from(running).toString('hex')}"},`);
}
