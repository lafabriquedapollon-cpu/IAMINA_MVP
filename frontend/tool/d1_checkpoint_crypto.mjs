// D1-I5D.1: internal checkpoint codec only. No storage or admission authority.
// Callers must supply independently authenticated owner scope and enforce fencing.
import {sealArchive, openArchive} from './d1_archive_candidate.mjs';
const tag=new TextEncoder().encode('IAMINA-D1-KEY-V1');
const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
const equal=(a,b)=>a instanceof Uint8Array && b instanceof Uint8Array &&
  a.length===b.length && a.every((x,i)=>x===b[i]);
const require=(ok,message)=>{if(!ok)throw new Error(message);};
export function validRecord(r) {
  require(r&&Number.isSafeInteger(r.revision)&&r.revision>=1&&r.revision<=0xffffffff&&
    r.envelope instanceof Uint8Array&&r.archive instanceof Uint8Array,'Vault unavailable');
}
export function sameRecord(a,b) {
  return a&&b&&a.revision===b.revision&&equal(a.envelope,b.envelope)&&equal(a.archive,b.archive);
}
export async function wrapKey(seed,phrase,ownerScope) {
  const payload=new Uint8Array(tag.length+seed.length);
  payload.set(tag);payload.set(seed,tag.length);
  try{return await sealArchive(payload,phrase,ownerScope);}
  finally{payload.fill(0);}
}
export async function unwrapKey(envelope,phrase,ownerScope) {
  const payload=await openArchive(envelope,phrase,ownerScope);
  try{
    require(payload.length===tag.length+32&&tag.every((x,i)=>x===payload[i]),'Key envelope rejected');
    return hex(payload.subarray(tag.length));
  }finally{payload.fill(0);}
}
export async function encrypt(bytes,key,ownerScope,revision) {
  require(bytes instanceof Uint8Array&&bytes.length>=100&&bytes.length<=32*1024*1024-4,'Invalid snapshot');
  const payload=new Uint8Array(bytes.length+4);
  new DataView(payload.buffer).setUint32(0,revision);payload.set(bytes,4);
  try{return await sealArchive(payload,key,ownerScope);}
  finally{payload.fill(0);}
}
export async function decrypt(record,key,ownerScope) {
  validRecord(record);
  const payload=await openArchive(record.archive,key,ownerScope);
  try{
    require(payload.length>=104&&new DataView(payload.buffer,payload.byteOffset,4).getUint32(0)===record.revision,
      'Checkpoint revision rejected');
    return payload.slice(4);
  }finally{payload.fill(0);}
}
