// Harness only. Synthetic signed assertions with fixed PRF output; no physical
// authenticator. The actual candidate modules perform every crypto/storage step.
import {createProvisionTransport} from './d1_prf_transport_candidate.mjs';
import {createSignedProvisioningAuthority} from './d1_prf_provision_authority_candidate.mjs';
import {createPrfBridge} from './d1_prf_guard_bridge_candidate.mjs';
import {registerPrfCounter,readPrfCounter} from './d1_prf_counter_candidate.mjs';
import {createAdmissionStore} from './d1_admission_store.mjs';
const enc=new TextEncoder();
const raw=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hex=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
const sha=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
const refused=async f=>{try{await f();return false;}catch(_){return true;}};
const uuid='ac123456-1234-4abc-8def-000000000001';
const store=createAdmissionStore('iamina-d1-admission-prf-vault-candidate-v1');
const snapshot=()=>store.transactionWithLifecycle(900001,false,(r,f,_db,m)=>({r,f,m}));
const exactRow=x=>x&&x.uuid===uuid&&x.originalValue===7.83&&x.unit==='mmol/L'&&x.provenance==='userEntered';
function der(raw){
  const integer=b=>{const x=Array.from(b);while(x.length>1&&x[0]===0)x.shift();if(x[0]&128)x.unshift(0);return [2,x.length,...x];};
  const r=integer(raw.slice(0,32)),s=integer(raw.slice(32));return Uint8Array.of(48,r.length+s.length,...r,...s);
}
async function setup(p){
  const credential=p.credential,owner=p.expected.owner;
  let pending=true,mode='original';
  const proofKey=await crypto.subtle.importKey('pkcs8',raw(p.proof),{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const issuer=await crypto.subtle.importKey('spki',raw(p.issuer),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const signer=await crypto.subtle.importKey('pkcs8',raw(p.authenticator),{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  class FixtureCredential{
    constructor(response,prf){this.rawId=Uint8Array.of(13,14,15,16);this.response=response;this.prf=prf;}
    getClientExtensionResults(){return {prf:this.prf};}
  }
  Object.defineProperty(window,'PublicKeyCredential',{value:FixtureCredential,configurable:true});
  Object.defineProperty(navigator,'credentials',{configurable:true,value:{get:async({publicKey:q})=>{
    if(q.userVerification!=='required'||q.rpId!==credential.rpId||b64(q.allowCredentials[0].id)!==credential.credentialId||
      q.extensions?.prf?.eval?.first?.length!==32)throw Error('fixture assertion contract');
    const counter=(await readPrfCounter(credential,()=>true)).signCount+1;
    const client=enc.encode(JSON.stringify({type:'webauthn.get',origin:location.origin,challenge:b64(q.challenge),crossOrigin:false}));
    const a=new Uint8Array(37);a.set(await sha(enc.encode(location.hostname)));a[32]=5;new DataView(a.buffer).setUint32(33,counter);
    const signed=new Uint8Array(69);signed.set(a);signed.set(await sha(client),37);
    const sig=der(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signer,signed)));
    return new FixtureCredential({clientDataJSON:client,authenticatorData:a,signature:sig},
      {enabled:true,results:{first:new Uint8Array(32).fill(mode==='changed'?38:37).buffer}});
  }}});
  const transport=createProvisionTransport({sessionId:p.sid,proofKey,isPending:()=>pending});
  const redemption=createProvisionTransport({sessionId:p.sid,proofKey,isPending:()=>pending,timeoutMs:p.scenario==='lost_ack'?500:5000});
  const authority=createSignedProvisioningAuthority({verificationKey:issuer,redeem:async(t,s)=>{
    const accepted=await redemption.redeem(t,s);
    if(p.scenario==='cancel_after_redeem')pending=false;
    return accepted;
  }});
  const bridge=createPrfBridge({signedAuthority:authority.consume});
  const acquire=(id=null)=>bridge.acquire(JSON.stringify(credential),owner,()=>pending,id);
  return {credential,owner,transport,authority,bridge,acquire,pending:()=>pending,resetPending:()=>{pending=true;},changed:()=>{mode='changed';},original:()=>{mode='original';}};
}
async function readLease(x){
  const id=hex(),identity={owner:x.owner,epoch:1,generation:1,acquisitionId:id};
  let active=false;
  const token=await x.acquire(id);
  try{
    const l=await x.bridge.openLease(token,JSON.stringify(identity),()=>!active&&x.pending(),()=>active&&x.pending());
    active=true;
    const verified=await x.bridge.verifyLease(l);
    const evidence=JSON.parse(await x.bridge.readEvidence(l,uuid));
    const retired=await x.bridge.retireLease(l);
    active=false;
    const denied=await refused(()=>x.bridge.readEvidence(l,uuid));
    return {verified,exact:exactRow(evidence),retired,denied};
  }finally{x.bridge.revoke(token);await x.bridge.waitRevocation(token);}
}
export async function initial(p){
  const x=await setup(p),checks={};
  checks.counterRegistered=await registerPrfCounter(x.credential,x.pending);
  const e=await x.transport.reserve(),operationId=e.ticket.operationId;
  checks.reserved=await x.transport.status(operationId)==='reserved';
  const token=await x.acquire();
  if(p.scenario==='normal'){
    const grant=await x.authority.authorize(e,p.expected,x.pending);
    checks.provisioned=await x.bridge.provisionAuthorized(token,x.pending,grant);
    checks.noGrantReplay=await refused(()=>x.bridge.provisionAuthorized(token,x.pending,grant));
    x.bridge.revoke(token);
    const s=await snapshot();
    checks.atomicReceipt=s.r?.operationId===operationId&&s.m?.operationId===operationId;
    checks.encrypted=s.r?.wrapped?.length===40&&s.r?.iv?.length===12&&s.r?.cipher?.length>16&&
      !Object.hasOwn(s.r,'originalValue')&&!Object.hasOwn(s.r,'key');
    const t=await x.acquire();
    checks.receiptAuthenticated=await x.bridge.inspectProvisioning(t,operationId,x.pending);
    x.bridge.revoke(t);
    checks.redeemed=await x.transport.status(operationId)==='redeemed';
    checks.noReissue=await refused(()=>x.transport.reserve());
  }else{
    checks.noGrant=await refused(()=>x.authority.authorize(e,p.expected,x.pending));
    x.resetPending();
    checks.noProvision=await refused(()=>x.bridge.provisionAuthorized(token,x.pending,{}));
    x.bridge.revoke(token);
    const s=await snapshot();
    checks.noLocalVault=s.r===undefined&&s.m===undefined&&s.f===undefined;
    checks.redeemed=await x.transport.status(operationId)==='redeemed';
    checks.noReissue=await refused(()=>x.transport.reserve());
  }
  return {operationId,checks};
}
export async function restart(p){
  const x=await setup(p),checks={};
  const s=await snapshot();
  checks.counterPersists=(await readPrfCounter(x.credential,x.pending)).signCount>0;
  checks.redeemed=await x.transport.status(p.operationId)==='redeemed';
  checks.noReissue=await refused(()=>x.transport.reserve());
  if(p.scenario==='normal'){
    const t=await x.acquire();
    checks.receiptAuthenticated=await x.bridge.inspectProvisioning(t,p.operationId,x.pending);
    x.bridge.revoke(t);
    x.changed();
    const bad=await x.acquire();
    checks.changedPrfRefused=await refused(()=>x.bridge.inspectProvisioning(bad,p.operationId,x.pending));
    x.bridge.revoke(bad);x.original();
    const r=await readLease(x);
    checks.readExact=r.verified&&r.exact;
    checks.retired=r.retired&&r.denied;
    const end=await snapshot();
    checks.durableFence=end.f?.active===false;
    checks.cipherPreserved=JSON.stringify(s.r)===JSON.stringify(end.r)&&JSON.stringify(s.m)===JSON.stringify(end.m);
  }else{
    const t=await x.acquire();
    checks.noReceipt=await refused(()=>x.bridge.inspectProvisioning(t,p.operationId,x.pending));
    x.bridge.revoke(t);
    const end=await snapshot();
    checks.noLocalVault=end.r===undefined&&end.m===undefined&&end.f===undefined;
  }
  return checks;
}
