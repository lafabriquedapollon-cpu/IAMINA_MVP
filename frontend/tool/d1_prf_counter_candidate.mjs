// CONV-03B2a.3a — isolated credential-counter CAS, never loaded by main.
// No patient enrollment/recovery path: explicit registration is reserved for
// the trusted provisioning boundary and synthetic probe. Missing records fail
// closed in admission. This cannot resist whole-origin storage rollback.
import {derivePrfWrappingKey} from './d1_prf_possession_candidate.mjs';

const DB='iamina-d1-prf-counter-candidate-v1';
const STORE='credentials';
const fields=['version','credentialId','publicKeySpki','rpId','origin','signCount'];
const require=(ok)=>{if(!ok)throw new Error('D1_PRF_COUNTER_REFUSED');};
const pending=fn=>require(typeof fn==='function'&&fn()===true);
const uint32=x=>Number.isSafeInteger(x)&&x>=0&&x<=0xffffffff;
function canonical(value) {
  require(typeof value==='string'&&value.length>0&&value.length<=8192&&/^[A-Za-z0-9_-]+$/.test(value));
  const binary=atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4));
  require(btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'')===value);
}
function validated(c) {
  require(c&&c.version===1&&c.origin===location.origin&&c.rpId===location.hostname&&uint32(c.signCount));
  canonical(c.credentialId);canonical(c.publicKeySpki);
  return Object.freeze(Object.fromEntries(fields.map(k=>[k,c[k]])));
}
function sameCredential(a,b) {
  return !!a&&!!b&&fields.slice(0,-1).every(k=>a[k]===b[k]);
}
function record(value,credential) {
  require(value&&Object.keys(value).length===fields.length+1&&
    Number.isSafeInteger(value.revision)&&value.revision>=1);
  const clean=validated(value);
  require(sameCredential(clean,credential));
  return Object.freeze({...clean,revision:value.revision});
}
async function connect() {
  require(globalThis.isSecureContext===true&&globalThis.indexedDB&&globalThis.crypto?.subtle);
  return new Promise((resolve,reject)=>{
    const r=indexedDB.open(DB,1);
    let blocked=false;
    r.onupgradeneeded=()=>r.result.createObjectStore(STORE);
    r.onblocked=()=>{blocked=true;reject(new Error('D1_PRF_COUNTER_REFUSED'));};
    r.onerror=()=>reject(new Error('D1_PRF_COUNTER_REFUSED'));
    r.onsuccess=()=>{
      const db=r.result;
      if(blocked){db.close();return;}
      db.onversionchange=()=>db.close();
      resolve(db);
    };
  });
}
async function transact(credential,write,isPending,fn) {
  pending(isPending);
  const db=await connect();
  try {
    pending(isPending);
    const result=await new Promise((resolve,reject)=>{
      const tx=write?db.transaction(STORE,'readwrite',{durability:'strict'}):db.transaction(STORE,'readonly');
      let result;
      tx.oncomplete=()=>resolve(result);
      tx.onabort=()=>reject(new Error('D1_PRF_COUNTER_REFUSED'));
      if(write&&tx.durability!=='strict'){tx.abort();return;}
      const store=tx.objectStore(STORE);
      const get=store.get(credential.credentialId);
      get.onsuccess=()=>{
        try{pending(isPending);result=fn(get.result,store);}
        catch(_){tx.abort();}
      };
    });
    // Commit can survive a late cancellation, but no authority/result does.
    pending(isPending);
    return result;
  } finally {db.close();}
}

// Only a separately verified provisioning operation may call this.
// Never call on admission failure, recovery or missing storage.
export async function registerPrfCounter(credential,isPending) {
  const c=validated(credential);
  return transact(c,true,isPending,(existing,store)=>{
    require(existing===undefined);
    store.add({...c,revision:1},c.credentialId);
    return true;
  });
}
export async function readPrfCounter(credential,isPending) {
  const c=validated(credential);
  return transact(c,false,isPending,value=>{
    const current=record(value,c);
    require(current.signCount>=c.signCount);
    return current;
  });
}
export async function advancePrfCounter(snapshot,nextCount,isPending) {
  const c=validated(snapshot),expected=record(snapshot,c);
  require(uint32(nextCount)&&((c.signCount===0&&nextCount===0)||nextCount>c.signCount));
  require(expected.revision<Number.MAX_SAFE_INTEGER);
  return transact(c,true,isPending,(value,store)=>{
    const current=record(value,c);
    require(current.revision===expected.revision&&current.signCount===expected.signCount);
    store.put({...c,signCount:nextCount,revision:expected.revision+1},c.credentialId);
    return true;
  });
}

// One pending acquisition, one credential-global revision. No key is
// returned until the same credential/revision CAS completes. Counterless
// authenticators still advance the revision; no clone-detection claim.
export async function derivePrfWithDurableCounter({credential,owner,isPending}) {
  try {
    const snapshot=await readPrfCounter(credential,isPending);
    pending(isPending);
    const current=Object.freeze(Object.fromEntries(fields.map(k=>[k,snapshot[k]])));
    return await derivePrfWrappingKey({
      credential:current,owner,isPending,
      commitCounter:(stored,next)=>{
        require(sameCredential(stored,current)&&stored.signCount===current.signCount);
        return advancePrfCounter(snapshot,next,isPending);
      },
    });
  } catch (_) {throw new Error('D1_PRF_POSSESSION_REFUSED');}
}
