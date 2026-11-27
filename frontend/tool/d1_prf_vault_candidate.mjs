// B2b.2 isolated read-only evidence vault. No real enrollment/migration.
// Synthetic owners only, fixed namespace, no raw-key or generic DB port.
// Trusted same-origin composition; no resistance to compromised origin JS
// or rollback of an entire browser profile.
import {createAdmissionStore} from './d1_admission_store.mjs';

const DB='iamina-d1-admission-prf-vault-candidate-v1';
const owners=new Set([900001,900002]);
const uuidPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const uuid='ac123456-1234-4abc-8def-000000000001';
const enc=new TextEncoder(), dec=new TextDecoder('utf-8',{fatal:true});
const fail=()=>new Error('D1_PRF_VAULT_REFUSED');
const require=ok=>{if(!ok)throw fail();};
const positive=x=>Number.isSafeInteger(x)&&x>0;
const uint=x=>Number.isSafeInteger(x)&&x>=0;
const bytes=(x,n)=>x instanceof Uint8Array&&x.length===n;
const sameBytes=(a,b)=>a instanceof Uint8Array&&b instanceof Uint8Array&&
  a.length===b.length&&a.every((v,i)=>v===b[i]);
const sameKeys=(x,keys)=>x&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const aad=(owner,binding,revision)=>enc.encode(JSON.stringify(['IAMINA-D1-PRF-VAULT-V1',owner,binding,revision]));
const validIdentity=i=>sameKeys(i,['owner','epoch','generation','acquisitionId'])&&
  owners.has(i.owner)&&uint(i.epoch)&&positive(i.generation)&&
  typeof i.acquisitionId==='string'&&/^[0-9a-f]{64}$/.test(i.acquisitionId);
const validFence=f=>f===null||(sameKeys(f,['owner','epoch','generation','acquisitionId','serial','active','binding','revision'])&&
  validIdentity({owner:f.owner,epoch:f.epoch,generation:f.generation,acquisitionId:f.acquisitionId})&&
  positive(f.serial)&&typeof f.active==='boolean'&&typeof f.binding==='string'&&f.revision===1);
const sameFence=(a,b)=>a&&b&&Object.keys(b).every(k=>a[k]===b[k])&&Object.keys(a).length===Object.keys(b).length;
const validRecord=(r,owner,binding)=>sameKeys(r,['owner','binding','revision','wrapped','iv','cipher'])&&
  r.owner===owner&&r.binding===binding&&r.revision===1&&bytes(r.wrapped,40)&&
  bytes(r.iv,12)&&r.cipher instanceof Uint8Array&&r.cipher.length>=17&&r.cipher.length<=4096;
const sameRecord=(a,b)=>validRecord(a,b.owner,b.binding)&&a.revision===b.revision&&
  sameBytes(a.wrapped,b.wrapped)&&sameBytes(a.iv,b.iv)&&sameBytes(a.cipher,b.cipher);
const validEvidence=e=>sameKeys(e,['uuid','originalValue','unit','provenance'])&&
  uuidPattern.test(e.uuid)&&typeof e.originalValue==='number'&&Number.isFinite(e.originalValue)&&
  e.originalValue>0&&['mg/dL','mmol/L'].includes(e.unit)&&
  e.provenance==='userEntered'&&Number.isFinite(e.originalValue*(e.unit==='mmol/L'?18.01559:1));

export function createPrfVault({lookup,fixtureProvision=false}) {
  const store=createAdmissionStore(DB);
  const leases=new WeakMap();
  const getEntry=token=>{const e=lookup(token);require(e&&e.key&&owners.has(e.owner));return e;};
  const local=(l,sessionOnly=false)=>{
    require(!l.retired&&lookup(l.possession)===l.entry);
    require(sessionOnly?l.session()===true:(l.pending()===true||l.session()===true));
  };
  const checkPending=l=>{require(!l.retired&&lookup(l.possession)===l.entry&&l.pending()===true);};
  async function unwrap(record,entry) {
    return crypto.subtle.unwrapKey('raw',record.wrapped,entry.key,'AES-KW',
      {name:'AES-GCM',length:256},false,['decrypt']);
  }
  async function decode(record,key) {
    let plain;
    try {
      plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:record.iv,
        additionalData:aad(record.owner,record.binding,record.revision),tagLength:128},key,record.cipher));
      const data=JSON.parse(dec.decode(plain));
      require(validEvidence(data));
      return data;
    } finally {plain?.fill(0);}
  }
  // Explicit synthetic setup, never present in the normal installed port.
  async function provisionFixture(token,isPending) {
    try {
      require(fixtureProvision&&typeof isPending==='function'&&isPending()===true);
      const entry=getEntry(token);
      require(!entry.used&&entry.acquisitionId==null);entry.used=true;
      const check=()=>require(lookup(token)===entry&&isPending()===true);
      const binding=entry.binding,owner=entry.owner,revision=1;
      let temporary=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
      check();
      const wrapped=new Uint8Array(await crypto.subtle.wrapKey('raw',temporary,entry.key,'AES-KW'));
      temporary=null;
      check();
      const key=await crypto.subtle.unwrapKey('raw',wrapped,entry.key,'AES-KW',
        {name:'AES-GCM',length:256},false,['encrypt']);
      check();
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const plain=enc.encode(JSON.stringify({uuid,originalValue:owner===900001?7.83:142,
        unit:owner===900001?'mmol/L':'mg/dL',provenance:'userEntered'}));
      let cipher;
      try {cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,
        additionalData:aad(owner,binding,revision),tagLength:128},key,plain));}
      finally {plain.fill(0);}
      check();
      await store.transaction(owner,true,(record,fence,db)=>{
        check();require(record===null&&fence===null);
        db.add({owner,binding,revision,wrapped,iv,cipher},'owner:'+owner);
      });
      check();
      return true;
    } catch (_) {throw fail();}
  }
  async function retireInternal(l) {
    l.retired=true;
    l.key=null;
    l.entry.key=null;
    if(!l.fence)return;
    await store.transaction(l.identity.owner,true,(_r,f,db)=>{
      require(validFence(f));
      if(sameFence(f,l.fence))db.put({...f,active:false},'fence');
    });
  }
  async function openLease(token,identityJson,pending,session) {
    let l;
    try {
      const entry=getEntry(token),identity=Object.freeze(JSON.parse(identityJson));
      require(validIdentity(identity)&&identity.owner===entry.owner&&
        identity.acquisitionId===entry.acquisitionId&&!entry.used&&
        typeof pending==='function'&&typeof session==='function'&&pending()===true&&session()===false);
      entry.used=true;
      l={possession:token,entry,identity,pending,session,retired:false,key:null,fence:null,record:null};
      entry.lease=l;
      const check=()=>checkPending(l);
      const record=await store.transaction(identity.owner,false,(r,f)=>{
        check();require(validFence(f)&&validRecord(r,identity.owner,entry.binding));return r;
      });
      check();
      l.key=await unwrap(record,entry);
      check();
      await decode(record,l.key); // authenticate before publishing durable authority
      check();
      l.record=record;
      await store.transaction(identity.owner,true,(r,f,db)=>{
        check();require(validFence(f)&&sameRecord(r,record));
        require(f===null||f.acquisitionId!==identity.acquisitionId);
        const serial=(f?.serial??0)+1;require(positive(serial));
        const next={...identity,serial,active:true,binding:entry.binding,revision:record.revision};
        l.fence=next;
        db.put(next,'fence');
      });
      check();
      const lease=Object.freeze(Object.create(null));
      leases.set(lease,l);
      return lease;
    } catch (_) {
      if(l)try{await retireInternal(l);}catch(_cleanup){/* fail closed; successor CAS can replace fence */}
      throw fail();
    }
  }
  async function current(l,sessionOnly=false) {
    local(l,sessionOnly);
    const record=await store.transaction(l.identity.owner,false,(r,f)=>{
      local(l,sessionOnly);
      require(validFence(f)&&sameFence(f,l.fence)&&sameRecord(r,l.record));return r;
    });
    local(l,sessionOnly);return record;
  }
  async function verifyLease(token) {
    try {const l=leases.get(token);require(l);await current(l);return true;}
    catch (_) {return false;}
  }
  async function readEvidence(token,id) {
    const l=leases.get(token);
    try {
      require(l&&typeof id==='string'&&uuidPattern.test(id));
      const record=await current(l,true);
      const key=l.key;require(key);
      const data=await decode(record,key);
      await current(l,true);
      local(l,true);
      return JSON.stringify(data.uuid===id?data:null);
    } catch (_) {
      if(l)try{await retireInternal(l);}catch(_cleanup){}
      throw fail();
    }
  }
  async function retireLease(token) {
    try {const l=leases.get(token);require(l);await retireInternal(l);return true;}
    catch (_) {throw fail();}
  }
  return Object.freeze({openLease,verifyLease,readEvidence,retireLease,
    ...(fixtureProvision?{provisionFixture}:{})});
}
