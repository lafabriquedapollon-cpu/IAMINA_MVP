// B2b.2 isolated read-only evidence vault. No real enrollment/migration.
// Synthetic owners only, fixed namespace, no raw-key or generic DB port.
// Trusted same-origin composition; no resistance to compromised origin JS
// or rollback of an entire browser profile.
import {createAdmissionStore} from './d1_admission_store.mjs';
import {assertFresh,createLifecycle,assertExisting} from './d1_prf_lifecycle_candidate.mjs';

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
const aad=(owner,binding,revision,operationId)=>enc.encode(JSON.stringify(
  operationId===undefined?['IAMINA-D1-PRF-VAULT-V1',owner,binding,revision]:
    ['IAMINA-D1-PRF-VAULT-PROVISION-V1',owner,binding,revision,operationId]));
const validIdentity=i=>sameKeys(i,['owner','epoch','generation','acquisitionId'])&&
  owners.has(i.owner)&&uint(i.epoch)&&positive(i.generation)&&
  typeof i.acquisitionId==='string'&&/^[0-9a-f]{64}$/.test(i.acquisitionId);
const validFence=f=>f===null||(sameKeys(f,['owner','epoch','generation','acquisitionId','serial','active','binding','revision'])&&
  validIdentity({owner:f.owner,epoch:f.epoch,generation:f.generation,acquisitionId:f.acquisitionId})&&
  positive(f.serial)&&typeof f.active==='boolean'&&typeof f.binding==='string'&&f.revision===1);
const sameFence=(a,b)=>a&&b&&Object.keys(b).every(k=>a[k]===b[k])&&Object.keys(a).length===Object.keys(b).length;
const validRecord=(r,owner,binding)=>(sameKeys(r,['owner','binding','revision','wrapped','iv','cipher'])||
  (sameKeys(r,['owner','binding','revision','wrapped','iv','cipher','operationId'])&&typeof r.operationId==='string'&&/^[0-9a-f]{64}$/.test(r.operationId)))&&
  r.owner===owner&&r.binding===binding&&r.revision===1&&bytes(r.wrapped,40)&&
  bytes(r.iv,12)&&r.cipher instanceof Uint8Array&&r.cipher.length>=17&&r.cipher.length<=4096;
const sameRecord=(a,b)=>validRecord(a,b.owner,b.binding)&&a.revision===b.revision&&a.operationId===b.operationId&&
  sameBytes(a.wrapped,b.wrapped)&&sameBytes(a.iv,b.iv)&&sameBytes(a.cipher,b.cipher);
const validEvidence=e=>sameKeys(e,['uuid','originalValue','unit','provenance'])&&
  uuidPattern.test(e.uuid)&&typeof e.originalValue==='number'&&Number.isFinite(e.originalValue)&&
  e.originalValue>0&&['mg/dL','mmol/L'].includes(e.unit)&&
  e.provenance==='userEntered'&&Number.isFinite(e.originalValue*(e.unit==='mmol/L'?18.01559:1));

export function createPrfVault({lookup,fixtureAuthority=null,signedAuthority=null}) {
  const store=createAdmissionStore(DB);
  const leases=new WeakMap();
  // Browser timers bound observable waits while JS is scheduled. A suspended
  // browser cannot execute cleanup until resumed; pending checks still fence
  // every continuation. Never interpret timeout as a durable ACK.
  const bounded=(work,onTimeout,ms=5000)=>new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{try{onTimeout();}finally{reject(fail());}},ms);
    Promise.resolve(work).then(value=>{clearTimeout(timer);resolve(value);},
      error=>{clearTimeout(timer);reject(error);});
  });
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
        additionalData:aad(record.owner,record.binding,record.revision,record.operationId),tagLength:128},key,record.cipher));
      const data=JSON.parse(dec.decode(plain));
      require(validEvidence(data));
      return data;
    } finally {plain?.fill(0);}
  }
  // Explicit synthetic setup, never present in the normal installed port.
  async function provisionWork(token,isPending,grant,signed) {
    try {
      require(typeof isPending==='function'&&isPending()===true);
      const entry=getEntry(token);
      require(!entry.used&&entry.acquisitionId==null);
      const authorization=signed
        ? (typeof signedAuthority==='function'?signedAuthority(grant,entry.owner,entry.binding):null)
        : (typeof fixtureAuthority==='function'&&fixtureAuthority(grant,entry.owner,entry.binding)===true
          ? {operationId:null,check:()=>true}:null);
      require(authorization&&typeof authorization.check==='function'&&authorization.check()===true);
      entry.used=true;
      const check=()=>require(lookup(token)===entry&&isPending()===true&&authorization.check()===true);
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
        additionalData:aad(owner,binding,revision,authorization.operationId??undefined),tagLength:128},key,plain));}
      finally {plain.fill(0);}
      check();
      await store.transactionWithLifecycle(owner,true,(record,fence,db,lifecycle)=>{
        check();assertFresh(owner,binding,record,lifecycle,fence);
        // Either both durable writes commit or neither does. No reset/delete
        // path, including cancellation after commit.
        db.add({owner,binding,revision,wrapped,iv,cipher,
          ...(authorization.operationId===null?{}:{operationId:authorization.operationId})},'owner:'+owner);
        db.add(createLifecycle(owner,binding,authorization.operationId),'lifecycle:'+owner);
      });
      check();
      return true;
    } catch (_) {throw fail();}
  }
  function provisionFixture(token,isPending,grant) {
    return provisionWork(token,isPending,grant,false);
  }
  async function provisionAuthorized(token,isPending,grant){
    let expired=false;
    return bounded(provisionWork(token,()=>!expired&&isPending()===true,grant,true),()=>{expired=true;});
  }
  // No reset/retry authority. Only original PRF possession can authenticate
  // a committed receipt, and only for the exact signed operation identifier.
  async function inspectProvisioning(token,operationId,isPending){
    try{
      require(typeof signedAuthority==='function'&&typeof operationId==='string'&&/^[0-9a-f]{64}$/.test(operationId)&&
        typeof isPending==='function'&&isPending()===true);
      const entry=getEntry(token);
      require(!entry.used&&entry.acquisitionId==null);
      entry.used=true;
      let expired=false;
      const check=()=>require(!expired&&lookup(token)===entry&&isPending()===true);
      const work=async()=>{
        const read=()=>store.transactionWithLifecycle(entry.owner,false,(r,_f,_db,m)=>{
          check();assertExisting(entry.owner,entry.binding,r,m);
          require(m.operationId===operationId&&validRecord(r,entry.owner,entry.binding));return r;
        });
        const r=await read();check();
        const key=await unwrap(r,entry);check();
        await decode(r,key);check();
        require(sameRecord(await read(),r));check();
        return true;
      };
      return await bounded(work(),()=>{expired=true;});
    }catch(_){throw fail();}
  }
  function retireInternal(l) {
    l.retired=true;
    l.key=null;
    l.entry.key=null;
    // An in-flight write sets l.fence in the transaction callback BEFORE
    // the commit ACK; a queued retirement follows that transaction.
    if(!l.fence)return Promise.resolve(true);
    if(!l.retirement){
      l.retirement=store.transaction(l.identity.owner,true,(_r,f,db)=>{
        require(validFence(f));
        if(sameFence(f,l.fence))db.put({...f,active:false},'fence');
        else require(!f||f.acquisitionId!==l.fence.acquisitionId||f.active===false);
        return true;
      }).catch(error=>{l.retirement=null;throw error;});
    }
    return l.retirement;
  }
  function startRetire(l){
    const work=retireInternal(l);
    work.catch(()=>{}); // caller may inspect/retry via waitRevocation
    return work;
  }
  function revokeEntry(entry){
    if(entry.lease)startRetire(entry.lease);
  }
  async function waitRevocation(entry){
    if(!entry.lease)return true;
    return bounded(retireInternal(entry.lease),()=>{});
  }
  async function openLeaseWork(token,identityJson,pending,session) {
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
      const record=await store.transactionWithLifecycle(identity.owner,false,(r,f,_db,lifecycle)=>{
        check();assertExisting(identity.owner,entry.binding,r,lifecycle);
        require(validFence(f===undefined?null:f)&&f!==null&&validRecord(r,identity.owner,entry.binding));return r;
      });
      check();
      const unwrapped=await unwrap(record,entry);
      check(); // do not republish a key after a late crypto result
      l.key=unwrapped;
      await decode(record,l.key); // authenticate before publishing durable authority
      check();
      l.record=record;
      await store.transactionWithLifecycle(identity.owner,true,(r,f,db,lifecycle)=>{
        check();assertExisting(identity.owner,entry.binding,r,lifecycle);
        require(f!==null&&validFence(f===undefined?null:f)&&sameRecord(r,record));
        require(f===undefined||f.acquisitionId!==identity.acquisitionId);
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
      if(l)startRetire(l);
      throw fail();
    }
  }
  async function openLease(token,identityJson,pending,session){
    const entry=lookup(token);
    // No cleanup of a preexisting lease when a duplicate request is refused.
    const old=entry?.lease;
    try{return await bounded(openLeaseWork(token,identityJson,pending,session),()=>{
      if(entry?.lease&&entry.lease!==old)startRetire(entry.lease);
    });}catch(_){
      if(entry?.lease&&entry.lease!==old){
        const l=entry.lease;
        try{await bounded(retireInternal(l),()=>{});}catch(_cleanup){}
      }
      throw fail();
    }
  }
  async function current(l,sessionOnly=false) {
    local(l,sessionOnly);
    const record=await store.transactionWithLifecycle(l.identity.owner,false,(r,f,_db,lifecycle)=>{
      local(l,sessionOnly);
      assertExisting(l.identity.owner,l.entry.binding,r,lifecycle);
      require(validFence(f)&&sameFence(f,l.fence)&&sameRecord(r,l.record));return r;
    });
    local(l,sessionOnly);return record;
  }
  async function verifyLease(token) {
    const l=leases.get(token);
    try {require(l);await bounded(current(l),()=>startRetire(l));return true;}
    catch (_) {if(l)startRetire(l);return false;}
  }
  async function readEvidenceWork(token,id) {
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
      if(l)startRetire(l);
      throw fail();
    }
  }
  async function readEvidence(token,id) {
    const l=leases.get(token);
    try {require(l);return await bounded(readEvidenceWork(token,id),()=>startRetire(l));}
    catch (_) {if(l)startRetire(l);throw fail();}
  }
  async function retireLease(token) {
    try {const l=leases.get(token);require(l);await bounded(retireInternal(l),()=>{});return true;}
    catch (_) {throw fail();}
  }
  return Object.freeze({openLease,verifyLease,readEvidence,retireLease,
    revokeEntry,waitRevocation,
    ...(typeof fixtureAuthority==='function'?{provisionFixture}:{}),
    ...(typeof signedAuthority==='function'?{provisionAuthorized,inspectProvisioning}:{})});
}
