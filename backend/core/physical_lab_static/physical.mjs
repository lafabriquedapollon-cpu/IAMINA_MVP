// Native browser WebAuthn only. No synthetic authenticator or raw PRF egress.
import {createPrfBridge} from './d1_prf_guard_bridge_candidate.mjs';
import {registerPrfCounter,readPrfCounter} from './d1_prf_counter_candidate.mjs';
import {createAdmissionStore} from './d1_admission_store.mjs';
import {createSignedProvisioningAuthority} from './d1_prf_provision_authority_candidate.mjs';
import {createProvisionTransport} from './physical_transport.mjs';
const enc=new TextEncoder(), hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const random=n=>crypto.getRandomValues(new Uint8Array(n));
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
const raw=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const require=ok=>{if(!ok)throw Error('refused');};
const owner=900001, uuid='ac123456-1234-4abc-8def-000000000001';
const credentialKey='iamina-physical-lab-credential-v1';
const report=document.getElementById('report'), stage=document.getElementById('stage');
const store=createAdmissionStore('iamina-d1-admission-prf-vault-candidate-v1');
let busy=false, live=null, generation=0;
const safe=()=>require(isSecureContext&&location.protocol==='https:'&&window.top===window&&navigator.credentials&&crypto.subtle);
const setStage=s=>stage.textContent=s;
const refused=async f=>{try{await f();return false;}catch(_){return true;}};
function capability(){
  const token=document.getElementById('operator').value;
  require(/^[0-9a-f]{64}$/.test(token));return token;
}
async function post(action,data,operator){
  const response=await fetch('/physical/'+action,{method:'POST',credentials:'same-origin',redirect:'error',
    cache:'no-store',headers:{'Content-Type':'application/json','X-D1-Operator':operator},
    body:JSON.stringify(data),signal:AbortSignal.timeout(12000)});
  require(response.status===200&&response.url===location.origin+'/physical/'+action&&
    response.headers.get('content-type')?.startsWith('application/json'));
  const text=await response.text();require(text.length<=32768);return JSON.parse(text);
}
const assertion=async(challenge,credential)=> {
  const a=await navigator.credentials.get({publicKey:{challenge:raw(challenge),rpId:location.hostname,
    allowCredentials:[{type:'public-key',id:raw(credential.credentialId),transports:['internal']}],
    userVerification:'required',timeout:30000}});
  require(a instanceof PublicKeyCredential&&b64(a.rawId)===credential.credentialId);
  return a;
};
function stored(){
  const c=JSON.parse(localStorage.getItem(credentialKey));
  require(c?.version===1&&c.origin===location.origin&&c.rpId===location.hostname);
  return c;
}
async function enroll(operator,pending){
  safe();require(localStorage.getItem(credentialKey)===null);
  setStage('Inscription serveur');
  const q=await post('enroll-begin',{},operator);require(pending());
  setStage('Créer la passkey sur cet appareil');
  const c=await navigator.credentials.create({publicKey:{
    challenge:raw(q.create),rp:{id:location.hostname,name:'IAMINA qualification'},
    user:{id:enc.encode('synthetic-owner-900001'),name:'synthetic-900001',displayName:'Qualification IAMINA'},
    pubKeyCredParams:[{type:'public-key',alg:-7}],attestation:'none',
    authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'required',userVerification:'required'},
    timeout:30000,extensions:{prf:{}}}});
  require(c instanceof PublicKeyCredential&&c.response.getPublicKeyAlgorithm()===-7&&
    c.getClientExtensionResults()?.prf?.enabled===true&&pending());
  const credential={version:1,credentialId:b64(c.rawId),publicKeySpki:b64(c.response.getPublicKey()),
    rpId:location.hostname,origin:location.origin,signCount:0};
  setStage('Prouver la possession au serveur');
  const a=await assertion(q.prove,credential);require(pending());
  const r=await post('enroll-finish',{challenge:q.create,credentialId:credential.credentialId,
    publicKeySpki:credential.publicKeySpki,creationClient:b64(c.response.clientDataJSON),
    creationAuth:b64(c.response.getAuthenticatorData()),assertionClient:b64(a.response.clientDataJSON),
    assertionAuth:b64(a.response.authenticatorData),signature:b64(a.response.signature)},operator);
  require(r.enrolled===true&&Number.isInteger(r.signCount)&&pending());
  credential.signCount=r.signCount;
  require(await registerPrfCounter(credential,pending));
  require(pending());localStorage.setItem(credentialKey,JSON.stringify(credential));
  return {enrolled:true,prfAdvertised:true,serverAssertion:true,counterRegistered:true,attestationVerified:false};
}
async function authenticate(operator,credential,pending){
  const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  require(!keys.privateKey.extractable&&pending());
  const spki=b64(await crypto.subtle.exportKey('spki',keys.publicKey));
  const begin=await post('begin',{proofSpki:spki},operator);
  const binding=JSON.stringify([credential.credentialId,credential.publicKeySpki,credential.rpId,credential.origin]);
  require(begin.context.owner===owner&&begin.context.binding===binding&&pending());
  setStage('Authentifier auprès de Django');
  const a=await assertion(begin.challenge,credential);require(pending());
  const finish=await post('finish',{challenge:begin.challenge,credentialId:credential.credentialId,
    clientData:b64(a.response.clientDataJSON),authData:b64(a.response.authenticatorData),
    signature:b64(a.response.signature)},operator);
  require(JSON.stringify(finish.context)===JSON.stringify(begin.context)&&pending());
  const transport=createProvisionTransport({sessionId:finish.sessionId,proofKey:keys.privateKey,
    operator,isPending:pending});
  const verificationKey=await crypto.subtle.importKey('spki',raw(begin.issuerSpki),
    {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const authority=createSignedProvisioningAuthority({verificationKey,redeem:transport.redeem});
  return {transport,authority,context:finish.context,bridge:createPrfBridge({signedAuthority:authority.consume})};
}
async function snapshot(){
  return store.transactionWithLifecycle(owner,false,(r,f,_db,m)=>({r,f,m}));
}
async function seal(operator,pending){
  safe();const credential=stored(), x=await authenticate(operator,credential,pending);
  setStage('Dériver la clé PRF locale');
  const token=await x.bridge.acquire(JSON.stringify(credential),owner,pending);
  try{
    const before=await snapshot();require(before.r===undefined&&before.m===undefined&&before.f===undefined&&pending());
    const e=await x.transport.reserve();require(await x.transport.status(e.ticket.operationId)==='reserved');
    const grant=await x.authority.authorize(e,x.context,pending);
    require(await x.bridge.provisionAuthorized(token,pending,grant));
    const replay=await refused(()=>x.bridge.provisionAuthorized(token,pending,grant));
    const end=await snapshot();
    require(end.r?.operationId===e.ticket.operationId&&end.m?.operationId===e.ticket.operationId&&
      end.r.wrapped.length===40&&end.r.iv.length===12&&end.r.cipher.length>16);
    const terminal=await x.transport.status(e.ticket.operationId)==='redeemed';
    const noReissue=await refused(()=>x.transport.reserve());
    require(replay&&terminal&&noReissue&&pending());
    return {serverAssertion:true,realPrf:true,encryptedVault:true,atomicReceipt:true,serverRedeemed:true,noGrantReplay:replay,noReissue};
  }finally{x.bridge.revoke(token);await x.bridge.waitRevocation(token);}
}
async function read(operator,pending){
  safe();const credential=stored(),x=await authenticate(operator,credential,pending);
  const before=await snapshot(),op=before.r?.operationId;
  require(typeof op==='string'&&before.m?.operationId===op&&await x.transport.status(op)==='redeemed'&&pending());
  setStage('Déverrouiller le coffre avec PRF');
  const acquisitionId=hex(random(32)),identity={owner,epoch:x.context.epoch,generation:x.context.generation,acquisitionId};
  let active=false;
  const token=await x.bridge.acquire(JSON.stringify(credential),owner,pending,acquisitionId);
  try{
    const lease=await x.bridge.openLease(token,JSON.stringify(identity),()=>!active&&pending(),()=>active&&pending());
    active=true;require(await x.bridge.verifyLease(lease)&&pending());
    const data=JSON.parse(await x.bridge.readEvidence(lease,uuid));
    require(data.uuid===uuid&&data.originalValue===7.83&&data.unit==='mmol/L'&&data.provenance==='userEntered');
    const counter=await readPrfCounter(credential,pending);
    live={bridge:x.bridge,token,lease,stop:()=>{active=false;}};
    return {serverAssertion:true,realPrf:true,readExact:true,serverRedeemed:true,counterRevision:counter.revision};
  }catch(e){active=false;x.bridge.revoke(token);await x.bridge.waitRevocation(token);throw e;}
}
async function lock(){
  require(live);const current=live;live=null;current.stop();
  const retired=await current.bridge.retireLease(current.lease);
  const denied=await refused(()=>current.bridge.readEvidence(current.lease,uuid));
  current.bridge.revoke(current.token);await current.bridge.waitRevocation(current.token);
  const end=await snapshot();require(retired&&denied&&end.f?.active===false);
  return {retired:true,readRefused:true,durableFence:true};
}
function buttons(disabled){for(const b of document.querySelectorAll('button'))b.disabled=disabled;}
function bind(id,action){
  document.getElementById(id).addEventListener('click',async()=>{
    if(busy||((id!=='lock')&&live))return;
    busy=true;buttons(true);const g=++generation;
    const pending=()=>g===generation&&!document.hidden;
    try{
      const result=await action(id==='lock'?null:capability(),pending);
      require(pending());setStage('PASS · '+id);report.textContent=JSON.stringify(result,null,2);
    }catch(_){setStage('REFUS · '+id);report.textContent='Aucune réinitialisation automatique.';}
    finally{busy=false;buttons(false);}
  });
}
bind('enroll',enroll);bind('seal',seal);bind('read',read);bind('lock',lock);
document.addEventListener('visibilitychange',()=>{
  if(document.hidden){generation++;if(live){const x=live;live=null;x.stop();x.bridge.revoke(x.token);x.bridge.waitRevocation(x.token).catch(()=>{});}}
});
window.addEventListener('pagehide',()=>{generation++;if(live){live.stop();live.bridge.revoke(live.token);live=null;}});
