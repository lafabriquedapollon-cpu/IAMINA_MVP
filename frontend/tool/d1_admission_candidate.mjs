// D1-I3: isolated synthetic proof of key custody and durable admission fencing.
// This is NOT a production auth authority or a migration of any patient vault.
import {sealArchive, openArchive} from './d1_archive_candidate.mjs';
import {requirePossessionSecret} from './d1_possession_candidate.mjs';

const DB='iamina-d1-admission-probe-v1', STORE='state';
const owners=new Set([900001,900002]);
const tag=new TextEncoder().encode('IAMINA-D1-KEY-V1');
const proofs=new WeakMap();
const scope=owner=>'amina_vault_v1_native_'+owner;
const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
const randomToken=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
const equal=(a,b)=>a instanceof Uint8Array && b instanceof Uint8Array &&
  a.length===b.length && a.every((x,i)=>x===b[i]);
const require=(ok,message)=>{if(!ok)throw new Error(message);};

// Test fixture ONLY. In a production adapter the proof must come from verified
// account/device identity and fresh app-lock proof, never caller booleans.
export function syntheticProof(owner, {identityVerified=false, unlocked=false, epoch=0}={}) {
  const ticket=Object.freeze({});
  proofs.set(ticket,{owner,identityVerified,unlocked,epoch,issued:performance.now()});
  return ticket;
}
function consume(ticket,owner,epoch) {
  const p=proofs.get(ticket);
  proofs.delete(ticket);
  require(owners.has(owner)&&Number.isSafeInteger(epoch)&&epoch>0&&p&&
    p.owner===owner&&p.epoch===epoch&&p.identityVerified===true&&p.unlocked===true&&
    performance.now()-p.issued<30000,'Admission proof rejected');
  return p.issued+30000;
}
function checkPhrase(phrase) {
  require(typeof phrase==='string'&&Array.from(phrase).length>=16&&phrase.length<=1024,
    'Possession secret required');
}
async function connect() {
  require(isSecureContext&&globalThis.indexedDB&&globalThis.crypto?.subtle,'Secure storage unavailable');
  return new Promise((resolve,reject)=>{
    const r=indexedDB.open(DB,1);
    r.onupgradeneeded=()=>r.result.createObjectStore(STORE);
    r.onsuccess=()=>{const db=r.result;db.onversionchange=()=>db.close();resolve(db);};
    r.onerror=()=>reject(new Error('Admission store unavailable'));
    r.onblocked=()=>reject(new Error('Admission store blocked'));
  });
}
// Read owner and global fence in one transaction. Callback must be synchronous.
// Writes and the fence check share one strict readwrite transaction.
async function transaction(owner,write,fn) {
  const db=await connect();
  try{
    return await new Promise((resolve,reject)=>{
      const tx=write?db.transaction(STORE,'readwrite',{durability:'strict'}):
        db.transaction(STORE,'readonly');
      let result, failure;
      tx.oncomplete=()=>resolve(result);
      tx.onabort=()=>reject(failure||new Error('Admission transaction failed'));
      if(write&&tx.durability!=='strict'){
        failure=new Error('Strict durability unavailable');tx.abort();return;
      }
      const store=tx.objectStore(STORE);
      const ownerReq=store.get('owner:'+owner), fenceReq=store.get('fence');
      let ready=0;
      const done=()=>{
        if(++ready!==2)return;
        try{
          result=fn(ownerReq.result??null,fenceReq.result??null,store);
        }catch(e){failure=e;tx.abort();}
      };
      ownerReq.onsuccess=done;fenceReq.onsuccess=done;
    });
  }finally{db.close();}
}
function validRecord(r) {
  require(r&&Number.isSafeInteger(r.revision)&&r.revision>=1&&r.revision<=0xffffffff&&
    r.envelope instanceof Uint8Array&&r.archive instanceof Uint8Array,'Vault unavailable');
}
function sameRecord(a,b) {
  return a&&b&&a.revision===b.revision&&equal(a.envelope,b.envelope)&&equal(a.archive,b.archive);
}
function fenceMatches(f,lease) {
  return f&&f.owner===lease.owner&&f.token===lease.token&&f.epoch===lease.epoch;
}
function validFence(f) {
  require(f&&typeof f.token==='string'&&/^[0-9a-f]{64}$/.test(f.token)&&
    ((f.owner===null&&f.epoch===null)||(owners.has(f.owner)&&Number.isSafeInteger(f.epoch)&&f.epoch>0)),
    'Admission fence unavailable');
}
function sameFence(a,b) {
  return a===null&&b===null || !!(a&&b&&a.owner===b.owner&&a.token===b.token&&a.epoch===b.epoch);
}
async function wrapKey(seed,phrase,owner) {
  const payload=new Uint8Array(tag.length+seed.length);
  payload.set(tag);payload.set(seed,tag.length);
  try{return await sealArchive(payload,phrase,scope(owner));}
  finally{payload.fill(0);}
}
async function unwrapKey(envelope,phrase,owner) {
  const payload=await openArchive(envelope,phrase,scope(owner));
  try{
    require(payload.length===tag.length+32&&tag.every((x,i)=>x===payload[i]),'Key envelope rejected');
    return hex(payload.subarray(tag.length));
  }finally{payload.fill(0);}
}
async function encrypt(bytes,key,owner,revision) {
  require(bytes instanceof Uint8Array&&bytes.length>=100&&bytes.length<=32*1024*1024-4,'Invalid snapshot');
  const payload=new Uint8Array(bytes.length+4);
  new DataView(payload.buffer).setUint32(0,revision);payload.set(bytes,4);
  try{return await sealArchive(payload,key,scope(owner));}
  finally{payload.fill(0);}
}
async function decrypt(record,key,owner) {
  validRecord(record);
  const payload=await openArchive(record.archive,key,scope(owner));
  try{
    require(payload.length>=104&&new DataView(payload.buffer,payload.byteOffset,4).getUint32(0)===record.revision,
      'Checkpoint revision rejected');
    return payload.slice(4);
  }finally{payload.fill(0);}
}
async function inspect(bytes,owner) {
  return JSON.parse(await window.d1Inspect(bytes,owner));
}
async function digest(bytes){
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
}
// Failed retirements survive loss of the admission handle within this
// document. Registry entries contain only fence coordinates, never keys,
// snapshots, possession phrases or session callbacks. No crash persistence.
const pendingRetirements=new Map();
function retireFence(lease){
  return transaction(lease.owner,true,(_r,f,store)=>{
    if(!fenceMatches(f,lease))return false;
    store.put({owner:null,token:randomToken(),epoch:null},'fence');return true;
  });
}
function retryRetirement(entry){
  if(entry.promise)return entry.promise;
  entry.status='pending';
  pendingRetirements.set(entry.lease.token,entry);
  entry.promise=retireFence(entry.lease).then(removed=>{
    entry.status=removed?'revoked':'superseded';
    pendingRetirements.delete(entry.lease.token);
    if(removed)notifyFenceChange();
    return removed;
  },()=>{
    entry.status='failed';
    entry.promise=null;
    throw new Error('Durable revocation unconfirmed');
  });
  return entry.promise;
}
// Synthetic recovery surface: no caller-supplied lease or authority.
// An obsolete lease can only CAS its own token, never the newer fence.
export async function retryPendingBoundRevocations(){
  const entries=[...pendingRetirements.values()];
  await Promise.allSettled(entries.map(retryRetirement));
  return {revoked:entries.filter(e=>e.status==='revoked').length,
    superseded:entries.filter(e=>e.status==='superseded').length,
    failed:entries.filter(e=>e.status==='failed').length};
}
export function pendingBoundRevocations(){
  return {pending:[...pendingRetirements.values()].filter(e=>e.status==='pending').length,
    failed:[...pendingRetirements.values()].filter(e=>e.status==='failed').length};
}
// Hints carry no owner, epoch, token or key. The committed fence is the
// only cross-document authority. Unsupported/dropped hints are harmless.
const FENCE_CHANNEL='iamina-d1-admission-probe-fence-v1';
function notifyFenceChange(){
  let channel;
  try{
    channel=new BroadcastChannel(FENCE_CHANNEL);
    channel.postMessage('fence-changed');
  }catch(_){/* optional optimization only */}
  finally{try{channel?.close();}catch(_){}}
}
async function readFence(){
  const db=await connect();
  try{
    return await new Promise((resolve,reject)=>{
      const tx=db.transaction(STORE,'readonly');
      const request=tx.objectStore(STORE).get('fence');
      tx.oncomplete=()=>resolve(request.result??null);
      tx.onabort=()=>reject(new Error('Admission fence unavailable'));
    });
  }finally{db.close();}
}
function monitorBoundFence(lease,authority,revoke){
  let stopped=false,busy=false,channel,timer;
  const check=async()=>{
    if(stopped||busy)return;
    busy=true;
    try{
      if(authority('session',lease.owner,lease.epoch,null)!==true)
        throw new Error('Bound authority retired');
      const actual=await readFence();
      if(stopped)return;
      if(!fenceMatches(actual,lease)||
         authority('session',lease.owner,lease.epoch,null)!==true)
        throw new Error('Admission fence retired');
    }catch(_){
      // Ambiguous IDB read also fails closed. Never resurrect on later reads.
      if(!stopped)void revoke().catch(()=>{});
    }finally{busy=false;}
  };
  const hint=event=>{if(event.data==='fence-changed')void check();};
  const wake=()=>{void check();};
  try{
    channel=new BroadcastChannel(FENCE_CHANNEL);
    channel.addEventListener('message',hint);
  }catch(_){try{channel?.close();}catch(__){}channel=null;}
  // Best effort only while a document executes JS; no timing guarantee
  // for suspended/backgrounded documents. Existing per-operation fence
  // validation remains mandatory and independent of this monitor.
  timer=setInterval(wake,2000);
  window.addEventListener('focus',wake);
  document.addEventListener('visibilitychange',wake);
  void check();
  return ()=>{
    if(stopped)return;
    stopped=true;
    clearInterval(timer);
    window.removeEventListener('focus',wake);
    document.removeEventListener('visibilitychange',wake);
    try{channel?.close();}catch(_){}
  };
}
const constructorPermit=Object.freeze({});
class AdmissionSession {
  #lease; #key; #retired=false; #busy=false; #guard;
  constructor(permit,lease,key,guard=null){
    require(permit===constructorPermit,'Admission required');
    this.#lease=lease;this.#key=key;this.#guard=guard;
  }
  #local(){
    require(!this.#retired,this.#guard?'Bound authority retired':'Session retired');
    if(this.#guard&&this.#guard('session',this.#lease.owner,this.#lease.epoch,null)!==true){
      this.#retired=true;this.#key=null;throw new Error('Bound authority retired');
    }
  }
  async #read(){
    this.#local();
    try{
      const r=await transaction(this.#lease.owner,false,(r,f)=>{
        require(fenceMatches(f,this.#lease),'Admission fence retired');validRecord(r);return r;
      });
      this.#local();return r;
    }catch(e){this.#retired=true;this.#key=null;throw e;}
  }
  async #verifyFence(){await this.#read();this.#local();}
  async inspect(){
    const r=await this.#read();
    let bytes;
    try{
      bytes=await decrypt(r,this.#key,this.#lease.owner);
      this.#local();
      const result=await inspect(bytes,this.#lease.owner);
      await this.#verifyFence();
      return {revision:r.revision,...result};
    }finally{bytes?.fill(0);}
  }
  async auditSnapshot(){
    // Synthetic test oracle: report exact bytes digest and full schema rows.
    // Do not expose the plaintext file to callers.
    const r=await this.#read();
    let bytes;
    try{
      bytes=await decrypt(r,this.#key,this.#lease.owner);this.#local();
      const sha256=await digest(bytes);this.#local();
      const tables=JSON.parse(await window.d1FullInspect(bytes,this.#lease.owner));
      await this.#verifyFence();
      return {sha256,revision:r.revision,tables};
    }finally{bytes?.fill(0);}
  }
  async readJournal(expectedRevision,start,end,limit,offset,{beforeReturn}={}){
    require(this.#guard,'Bound authority required');this.#local();
    require([expectedRevision,start,end,limit,offset].every(Number.isSafeInteger)&&
      expectedRevision>0&&start>0&&end>start&&end<=4102444800&&
      limit>=1&&limit<=50&&offset>=0&&offset<=10000,'Invalid journal range');
    const r=await this.#read();
    require(r.revision===expectedRevision,'Checkpoint conflict');
    let bytes;
    try{
      bytes=await decrypt(r,this.#key,this.#lease.owner);this.#local();
      const result=JSON.parse(await window.d1JournalPage(bytes,this.#lease.owner,start,end,limit,offset));
      this.#local();
      require(Array.isArray(result.rows)&&result.rows.length<=limit&&
        (result.nextOffset===null||(result.nextOffset===offset+limit&&result.nextOffset<=10000)),
        'Journal page invariant failed');
      if(beforeReturn)await beforeReturn();
      // A concurrent same-session mutation invalidates the page too, not only
      // a change of owner. No asynchronous work after the final local check.
      const current=await this.#read();this.#local();
      require(sameRecord(current,r),'Checkpoint conflict');
      return {revision:r.revision,rows:result.rows,nextOffset:result.nextOffset};
    }finally{bytes?.fill(0);}
  }
  async readGlucose(uuid){
    require(this.#guard,'Bound authority required');
    require(typeof uuid==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid),'Invalid measurement UUID');
    const r=await this.#read();
    let bytes;
    try{
      bytes=await decrypt(r,this.#key,this.#lease.owner);this.#local();
      const measurement=JSON.parse(await window.d1GlucoseRead(bytes,this.#lease.owner,uuid));
      await this.#verifyFence();this.#local();
      return {revision:r.revision,measurement};
    }finally{bytes?.fill(0);}
  }
  async insertGlucose(expectedRevision,uuid,mgDl,unit,seconds,{beforeCommit,beforeAck}={}){
    require(this.#guard,'Bound authority required');this.#local();
    require(Number.isSafeInteger(expectedRevision)&&expectedRevision>0&&
      typeof uuid==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)&&
      unit==='mg/dL'&&Number.isFinite(mgDl)&&mgDl>0&&Number.isSafeInteger(seconds)&&
      seconds>0&&seconds<=4102444800,'Invalid measurement');
    require(!this.#busy,'Mutation already pending');this.#busy=true;
    let bytes,next;
    const owner=this.#lease.owner,key=this.#key;
    const matches=m=>m&&m.uuid===uuid&&m.mgDl===mgDl&&m.loggedAtSeconds===seconds&&
      m.source==='manual'&&m.syncStatus==='pending';
    try{
      const r=await this.#read();
      bytes=await decrypt(r,key,owner);this.#local();
      const existing=JSON.parse(await window.d1GlucoseRead(bytes,owner,uuid));this.#local();
      if(existing!==null){
        require(matches(existing),'Measurement UUID conflict');
        await this.#verifyFence();this.#local();
        return {revision:r.revision,replay:true,measurement:existing};
      }
      require(r.revision===expectedRevision,'Checkpoint conflict');
      next=await window.d1GlucoseInsert(bytes,owner,uuid,mgDl,seconds);this.#local();
      const measurement=JSON.parse(await window.d1GlucoseRead(next,owner,uuid));this.#local();
      require(matches(measurement),'Measurement invariant failed');
      require(r.revision<0xffffffff,'Revision exhausted');
      const revision=r.revision+1;
      const archive=await encrypt(next,key,owner,revision);this.#local();
      if(beforeCommit)await beforeCommit();
      this.#local();
      await transaction(owner,true,(current,f,store)=>{
        this.#local();
        require(fenceMatches(f,this.#lease),'Admission fence retired');
        require(sameRecord(current,r),'Checkpoint conflict');
        store.put({revision,envelope:r.envelope,archive},'owner:'+owner);
      });
      if(beforeAck)await beforeAck();
      await this.#verifyFence();this.#local();
      return {revision,replay:false,measurement};
    }finally{bytes?.fill(0);next?.fill(0);this.#busy=false;}
  }
  async readTreatment(){
    require(this.#guard,'Bound authority required');
    const r=await this.#read();
    let bytes;
    try{
      bytes=await decrypt(r,this.#key,this.#lease.owner);this.#local();
      const declaration=JSON.parse(await window.d1TreatmentRead(bytes,this.#lease.owner));
      await this.#verifyFence();
      return {revision:r.revision,declaration};
    }finally{bytes?.fill(0);}
  }
  async writeTreatment(expectedRevision,state,codes,{beforeCommit,beforeAck}={}){
    require(this.#guard,'Bound authority required');
    this.#local();
    require(Number.isSafeInteger(expectedRevision)&&expectedRevision>0&&
      ['not_answered','unsure','declared','none_declared'].includes(state)&&
      Array.isArray(codes)&&codes.length<=4&&new Set(codes).size===codes.length&&
      codes.every(x=>['insulin','oral_meds','lifestyle','other'].includes(x))&&
      ((state==='declared')===(codes.length>0)),'Invalid declaration');
    const codesJson=JSON.stringify(codes);
    require(!this.#busy,'Mutation already pending');
    this.#busy=true;
    let bytes,next;
    const owner=this.#lease.owner,key=this.#key;
    try{
      const r=await this.#read();
      require(r.revision===expectedRevision,'Checkpoint conflict');
      bytes=await decrypt(r,key,owner);this.#local();
      next=await window.d1TreatmentChange(bytes,owner,state,codesJson);this.#local();
      const declaration=JSON.parse(await window.d1TreatmentRead(next,owner));this.#local();
      require(declaration&&declaration.owner===owner&&declaration.state===state&&
        JSON.stringify(declaration.codes)===codesJson&&declaration.syncStatus==='pending',
        'Declaration invariant failed');
      require(r.revision<0xffffffff,'Revision exhausted');
      const revision=r.revision+1;
      const archive=await encrypt(next,key,owner,revision);this.#local();
      if(beforeCommit)await beforeCommit();
      this.#local();
      await transaction(owner,true,(current,f,store)=>{
        this.#local();
        require(fenceMatches(f,this.#lease),'Admission fence retired');
        require(sameRecord(current,r),'Checkpoint conflict');
        store.put({revision,envelope:r.envelope,archive},'owner:'+owner);
      });
      if(beforeAck)await beforeAck();
      await this.#verifyFence();
      return {revision,declaration};
    }finally{bytes?.fill(0);next?.fill(0);this.#busy=false;}
  }
  retireLocal(){
    this.#retired=true;this.#key=null;
  }
  async retire(){
    // Immediately hide local state. A stale tab cannot revoke a newer lease.
    this.retireLocal();
    return retireFence(this.#lease);
  }
  async mutate(operation,{beforeCommit,beforeAck}={}){
    this.#local();
    require(typeof operation==='string'&&/^[a-z0-9-]{8,64}$/.test(operation),'Invalid operation');
    require(!this.#busy,'Mutation already pending');
    this.#busy=true;
    let bytes,next;
    const owner=this.#lease.owner,key=this.#key;
    try{
      const r=await this.#read();
      bytes=await decrypt(r,key,owner);this.#local();
      const before=await inspect(bytes,owner);this.#local();
      const id='d1-i1-'+owner+'-op-'+operation;
      if(before.ids.includes(id)){
        await this.#verifyFence();
        return {revision:r.revision,replay:true,operation};
      }
      next=await window.d1Mutate(bytes,owner,operation);this.#local();
      const after=await inspect(next,owner);this.#local();
      require(after.rows===before.rows+1&&after.ids.includes(id)&&
        before.ids.every(x=>after.ids.includes(x)),'Mutation invariant failed');
      require(r.revision<0xffffffff,'Revision exhausted');
      const revision=r.revision+1;
      const archive=await encrypt(next,key,owner,revision);this.#local();
      if(beforeCommit)await beforeCommit();
      this.#local();
      await transaction(owner,true,(current,f,store)=>{
        this.#local();
        require(fenceMatches(f,this.#lease),'Admission fence retired');
        require(sameRecord(current,r),'Checkpoint conflict');
        store.put({revision,envelope:r.envelope,archive},'owner:'+owner);
      });
      if(beforeAck)await beforeAck();
      await this.#verifyFence();
      return {revision,replay:false,operation};
    }catch(e){
      if(String(e).includes('Admission fence retired')){this.#retired=true;this.#key=null;}
      throw e;
    }finally{bytes?.fill(0);next?.fill(0);this.#busy=false;}
  }
}

// Explicit initial creation only; missing material is never silently repaired.
export async function enroll(owner,epoch,proof,phrase){
  const deadline=consume(proof,owner,epoch);checkPhrase(phrase);
  const baseline=await transaction(owner,false,(r,f)=>{require(r===null,'Existing vault cannot be overwritten');return f;});
  const seed=crypto.getRandomValues(new Uint8Array(32));
  const key=hex(seed);
  let bytes;
  try{
    const envelope=await wrapKey(seed,phrase,owner);
    bytes=await window.d1Snapshot(null,owner);
    await inspect(bytes,owner);
    const archive=await encrypt(bytes,key,owner,1);
    const lease={owner,epoch,token:randomToken()};
    await transaction(owner,true,(existing,f,store)=>{
      require(existing===null,'Existing vault cannot be overwritten');
      require(performance.now()<deadline,'Admission proof expired');
      require(sameFence(f,baseline),'Admission fence changed');
      store.put({revision:1,envelope,archive},'owner:'+owner);
      store.put(lease,'fence');
    });
    return new AdmissionSession(constructorPermit,lease,key);
  }finally{seed.fill(0);bytes?.fill(0);}
}

export async function admit(owner,epoch,proof,phrase,{beforeActivate}={}){
  const deadline=consume(proof,owner,epoch);checkPhrase(phrase);
  const {record,baseline}=await transaction(owner,false,(r,f)=>{validRecord(r);validFence(f);return {record:r,baseline:f};});
  const key=await unwrapKey(record.envelope,phrase,owner);
  let bytes;
  try{
    bytes=await decrypt(record,key,owner);
    await inspect(bytes,owner);
    const lease={owner,epoch,token:randomToken()};
    if(beforeActivate)await beforeActivate();
    await transaction(owner,true,(current,f,store)=>{
      require(performance.now()<deadline,'Admission proof expired');
      require(sameRecord(current,record),'Vault changed during admission');
      require(sameFence(f,baseline),'Admission fence changed');
      store.put(lease,'fence');
    });
    return new AdmissionSession(constructorPermit,lease,key);
  }finally{bytes?.fill(0);}
}

 // I4: explicit copy-only import of an independently attributed scoped v12
 // snapshot. The synthetic authority must NOT be used to adopt mixed legacy
 // data. Source file is neither changed nor deleted by this adapter.
export async function importScopedArchive(owner,epoch,proof,phrase,manifest,transfer,transferPhrase,{beforeActivate}={}){
  const deadline=consume(proof,owner,epoch);checkPhrase(phrase);checkPhrase(transferPhrase);
  require(manifest&&manifest.kind==='scoped-v12'&&manifest.owner===owner&&
    typeof manifest.sha256==='string'&&/^[0-9a-f]{64}$/.test(manifest.sha256),
    'Explicit scoped source provenance required');
  const expectedDigest=manifest.sha256;
  const baseline=await transaction(owner,false,(r,f)=>{
    require(r===null,'Existing vault cannot be overwritten');return f;
  });
  const seed=crypto.getRandomValues(new Uint8Array(32));
  const key=hex(seed);
  let bytes,verified;
  try{
    bytes=await openArchive(transfer,transferPhrase,scope(owner));
    require(await digest(bytes)===expectedDigest,'Source digest mismatch');
    await inspect(bytes,owner);
    await window.d1FullInspect(bytes,owner);
    const envelope=await wrapKey(seed,phrase,owner);
    const archive=await encrypt(bytes,key,owner,1);
    // Verify the ciphertext copy before publication, including all source bytes.
    verified=await decrypt({revision:1,envelope,archive},key,owner);
    require(equal(bytes,verified),'Imported snapshot mismatch');
    await window.d1FullInspect(verified,owner);
    const lease={owner,epoch,token:randomToken()};
    if(beforeActivate)await beforeActivate();
    await transaction(owner,true,(existing,f,store)=>{
      require(existing===null,'Existing vault cannot be overwritten');
      require(performance.now()<deadline,'Admission proof expired');
      require(sameFence(f,baseline),'Admission fence changed');
      store.put({revision:1,envelope,archive},'owner:'+owner);
      store.put(lease,'fence');
    });
    return new AdmissionSession(constructorPermit,lease,key);
  }finally{seed.fill(0);bytes?.fill(0);verified?.fill(0);}
}


// I5B test-only bridge. The authority callback is produced by the isolated
// Dart probe from a real consumed AppLockService ticket, not syntheticProof.
// JS within a compromised origin could forge callbacks: this is NOT a
// production security boundary. Only existing synthetic checkpoints qualify.
export async function admitBound(owner,epoch,authority,phrase,{beforeLease,afterLease}={}){
  require(owners.has(owner)&&Number.isSafeInteger(epoch)&&epoch>0&&
    typeof authority==='function','Bound authority required');
  const check=phase=>require(authority(phase,owner,epoch,null)===true,'Bound authority retired');
  check('claim');
  requirePossessionSecret(phrase);
  let bytes,session,retirement,stopMonitor,retired=false;
  const revoke=()=>{
    retired=true;
    stopMonitor?.();
    session?.retireLocal();
    if(!retirement)return Promise.resolve(false);
    return retryRetirement(retirement);
  };
  require(authority('watch',owner,epoch,()=>{void revoke().catch(()=>{});})===true,
    'Bound authority retired');
  try{
    check('pending');
    const {record,baseline}=await transaction(owner,false,(r,f)=>{
      check('pending');validRecord(r);validFence(f);return {record:r,baseline:f};
    });
    check('pending');
    const key=await unwrapKey(record.envelope,phrase,owner);
    check('pending');
    bytes=await decrypt(record,key,owner);
    check('pending');
    const lease={owner,epoch,token:randomToken()};
    if(beforeLease)await beforeLease();
    check('pending');
    await transaction(owner,true,(current,f,store)=>{
      check('pending');
      require(sameRecord(current,record),'Vault changed during admission');
      require(sameFence(f,baseline),'Admission fence changed');
      store.put(lease,'fence');
    });
    notifyFenceChange();
    retirement={lease,status:'active',promise:null};
    session=new AdmissionSession(constructorPermit,lease,key,authority);
    if(retired){await revoke();throw new Error('Bound authority retired');}
    if(afterLease)await afterLease();
    check('pending');
    // Durable lease exists BEFORE any Drift/SQLite opening in this path.
    await transaction(owner,false,(r,f)=>{
      check('pending');
      require(fenceMatches(f,lease)&&sameRecord(r,record),'Admission fence retired');
    });
    check('pending');
    await inspect(bytes,owner);
    check('pending');
    await transaction(owner,false,(r,f)=>{
      check('pending');
      require(fenceMatches(f,lease)&&sameRecord(r,record),'Admission fence retired');
    });
    check('activate');
    stopMonitor=monitorBoundFence(lease,authority,revoke);
    if(retired){stopMonitor();await revoke();throw new Error('Bound authority retired');}
    // Verify the now-active guard and fence before exposing any operation.
    await session.inspect();
    const perform=async fn=>{
      try{return await fn();}
      catch(e){await revoke();throw e;}
    };
    return Object.freeze({
      inspect:()=>perform(()=>session.inspect()),
      auditSnapshot:()=>perform(()=>session.auditSnapshot()),
      readJournal:(revision,start,end,limit,offset,hooks)=>perform(()=>session.readJournal(revision,start,end,limit,offset,hooks)),
      readGlucose:uuid=>perform(()=>session.readGlucose(uuid)),
      insertGlucose:(revision,uuid,mgDl,unit,seconds,hooks)=>perform(()=>session.insertGlucose(revision,uuid,mgDl,unit,seconds,hooks)),
      readTreatment:()=>perform(()=>session.readTreatment()),
      writeTreatment:(revision,state,codes,hooks)=>perform(()=>session.writeTreatment(revision,state,codes,hooks)),
      mutate:(operation,hooks)=>perform(()=>session.mutate(operation,hooks)),
      retire:()=>revoke(),
      revocationStatus:()=>retirement.status,
    });
  }catch(e){
    if(session)await revoke();
    throw e;
  }finally{bytes?.fill(0);}
}
