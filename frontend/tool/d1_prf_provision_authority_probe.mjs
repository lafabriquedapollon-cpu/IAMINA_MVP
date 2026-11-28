// Synthetic independent inventory and signing key. In-memory issuer model,
// not a production server; no network, real account or patient data.
import {createSignedProvisioningAuthority,ticketBytes} from './d1_prf_provision_authority_candidate.mjs';
import {createPrfBridge} from './d1_prf_guard_bridge_candidate.mjs';
const hex=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
const refused=async fn=>{try{await fn();return false;}catch(e){return ['D1_PRF_AUTHORIZATION_REFUSED','D1_PRF_VAULT_REFUSED','fixture inventory refused'].includes(e.message);}};
export async function exerciseSignedProvisioning(credential){
  const binding=JSON.stringify([credential.credentialId,credential.publicKeySpki,credential.rpId,credential.origin]);
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  let now=Date.now(),live=true,offline=false;
  const pending=()=>live;
  const inventory=new Map([[900001,{state:'fresh'}],[900002,{state:'legacy'}]]);
  const sign=async(t,key=pair.privateKey)=>({ticket:t,signature:new Uint8Array(await crypto.subtle.sign(
    {name:'ECDSA',hash:'SHA-256'},key,ticketBytes(t)))});
  const context=owner=>({owner,binding,epoch:1,generation:1,nonce:hex()});
  const issue=async c=>{
    const previous=inventory.get(c.owner);
    if(previous?.state!=='fresh')throw new Error('fixture inventory refused');
    const t={version:1,purpose:'IAMINA-D1-FRESH-PROVISION-V1',...c,operationId:hex(),issuedAt:now,expiresAt:now+60000};
    inventory.set(c.owner,{state:'reserved',ticket:t});
    return sign(t);
  };
  const redeem=async t=>{
    if(offline)return false;
    const item=inventory.get(t.owner);
    if(item?.state!=='reserved'||JSON.stringify(item.ticket)!==JSON.stringify(t)||now>=t.expiresAt)return false;
    inventory.set(t.owner,{state:'redeemed',ticket:item.ticket});return true;
  };
  const verifier=()=>createSignedProvisioningAuthority({verificationKey:pair.publicKey,redeem,now:()=>now});
  const auth=verifier(),bridge=createPrfBridge({signedAuthority:auth.consume});
  const token=owner=>bridge.acquire(JSON.stringify(credential),owner,pending);
  const c=context(900001),b=context(900002);
  const checks={};
  checks.legacyInventoryRefused=await refused(()=>issue(b));
  inventory.set(900002,{state:'unknown'});
  checks.unknownInventoryRefused=await refused(()=>issue(b));
  inventory.set(900002,{state:'existing'});
  checks.existingInventoryRefused=await refused(()=>issue(b));
  const env=await issue(c);
  checks.reservationBlocksSecondIssue=await refused(()=>issue(c));
  checks.wrongSignature=await refused(async()=>auth.authorize(await sign(env.ticket,other.privateKey),c,pending));
  checks.tamper=await refused(()=>auth.authorize({...env,ticket:{...env.ticket,operationId:hex()}},c,pending));
  checks.wrongNonce=await refused(()=>auth.authorize(env,{...c,nonce:hex()},pending));
  checks.wrongEpoch=await refused(()=>auth.authorize(env,{...c,epoch:2},pending));
  checks.wrongGeneration=await refused(()=>auth.authorize(env,{...c,generation:2},pending));
  checks.wrongOwner=await refused(()=>auth.authorize(env,{...c,owner:900002},pending));
  checks.wrongBinding=await refused(()=>auth.authorize(env,{...c,binding:JSON.stringify(['AQIDBA',credential.publicKeySpki,credential.rpId,credential.origin])},pending));
  now=env.ticket.expiresAt;
  checks.expired=await refused(()=>auth.authorize(env,c,pending));
  now=env.ticket.issuedAt;
  offline=true;
  checks.offlineRefuses=await refused(()=>auth.authorize(env,c,pending));
  offline=false;live=false;
  checks.cancelledAuthorization=await refused(()=>auth.authorize(env,c,pending));
  live=true;
  const grant=await auth.authorize(env,c,pending);
  checks.oneRedemptionAcrossVerifiers=await refused(()=>verifier().authorize(env,c,pending));
  const t=await token(900001);
  checks.forgedGrantRefuses=await refused(()=>bridge.provisionAuthorized(t,pending,{}));
  let calls=0;
  checks.lostCommitAck=await refused(()=>bridge.provisionAuthorized(t,()=>++calls<7,grant))&&calls===7;
  bridge.revoke(t);
  const readWrite=async(name,change)=>new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-admission-prf-vault-candidate-v1',1);
    req.onerror=()=>reject(req.error);
    req.onsuccess=()=>{const db=req.result,tx=db.transaction('state',change?'readwrite':'readonly'),
      st=tx.objectStore('state'),q=st.get(name);let value;
      q.onsuccess=()=>{value=q.result;if(change)st.put(change(value),name);};
      tx.oncomplete=()=>{db.close();resolve(value);};tx.onabort=()=>{db.close();reject(tx.error);};};
  });
  const record=await readWrite('owner:900001'),marker=await readWrite('lifecycle:900001');
  checks.atomicSignedReceipt=record?.operationId===env.ticket.operationId&&marker?.operationId===record.operationId;
  const inspect=async op=>{const p=await token(900001);try{return await bridge.inspectProvisioning(p,op,pending);}finally{bridge.revoke(p);}};
  checks.uncertainCommitAuthenticated=await inspect(env.ticket.operationId);
  checks.wrongReceiptRefused=await refused(()=>inspect(hex()));
  const fake=hex();
  await readWrite('owner:900001',r=>({...r,operationId:fake}));
  await readWrite('lifecycle:900001',r=>({...r,operationId:fake}));
  checks.receiptTamperRefused=await refused(()=>inspect(fake));
  await readWrite('owner:900001',()=>record);
  await readWrite('lifecycle:900001',()=>marker);
  const replay=await token(900001);
  checks.consumedGrantRefused=await refused(()=>bridge.provisionAuthorized(replay,pending,grant));
  bridge.revoke(replay);
  checks.uncertainDoesNotReissue=await refused(()=>issue(c));
  // Fixture changes inventory explicitly to model a different newly verified
  // account; no application reset or implicit inventory fallback.
  inventory.set(900002,{state:'fresh'});
  const envB=await issue(b),grantB=await auth.authorize(envB,b,pending),tB=await token(900002);
  calls=0;
  checks.precommitCancelled=await refused(()=>bridge.provisionAuthorized(tB,()=>++calls<6,grantB))&&calls===6;
  bridge.revoke(tB);
  checks.precommitNoPartial=await readWrite('owner:900002')===undefined&&await readWrite('lifecycle:900002')===undefined;
  checks.precommitNoAutoReissue=await refused(()=>issue(b));
  return checks;
}
