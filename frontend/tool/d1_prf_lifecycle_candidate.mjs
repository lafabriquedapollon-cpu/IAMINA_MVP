// B2c.1: isolated lifecycle contract. No real issuer, enrollment, migration,
// backup secret, or recovery of a lost key. No account bearer can mint a grant.
// A production fresh-account issuer must independently establish no prior
// vault (including server inventory and legacy clients); local absence alone
// cannot distinguish first use from whole-origin loss.
const owners=new Set([900001,900002]);
const fail=()=>new Error('D1_PRF_LIFECYCLE_REFUSED');
const require=ok=>{if(!ok)throw fail();};
const keys=(x,k)=>x&&Object.keys(x).length===k.length&&k.every(v=>Object.hasOwn(x,v));
const validBinding=b=>{
  try{
    const a=JSON.parse(b);
    return typeof b==='string'&&Array.isArray(a)&&a.length===4&&a.every(x=>typeof x==='string'&&x.length>0)&&
      a[2]===location.hostname&&a[3]===location.origin&&JSON.stringify(a)===b;
  }catch(_){return false;}
};
export function assertFresh(owner,binding,record,lifecycle,fence){
  require(owners.has(owner)&&validBinding(binding)&&record===undefined&&lifecycle===undefined&&fence===undefined);
}
const validOperation=id=>typeof id==='string'&&/^[0-9a-f]{64}$/.test(id);
export function createLifecycle(owner,binding,operationId=null){
  require(owners.has(owner)&&validBinding(binding)&&(operationId===null||validOperation(operationId)));
  return Object.freeze({version:1,owner,binding,state:'sealed',...(operationId===null?{}:{operationId})});
}
export function assertExisting(owner,binding,record,lifecycle){
  require(owners.has(owner)&&validBinding(binding)&&(keys(lifecycle,['version','owner','binding','state'])||
    (keys(lifecycle,['version','owner','binding','state','operationId'])&&validOperation(lifecycle.operationId)))&&
    lifecycle.version===1&&lifecycle.owner===owner&&lifecycle.binding===binding&&lifecycle.state==='sealed'&&
    record&&record.owner===owner&&record.binding===binding);
}
// Synthetic issuer only. The closure is deliberately not installed globally,
// and can issue only for the two fixture owners. Caller of consume cannot
// fabricate a grant from JSON, an access token, or another issuer's handle.
export function createFixtureFreshAuthority(){
  const grants=new WeakMap();
  const issue=(owner,credential)=>{
    const binding=JSON.stringify([credential.credentialId,credential.publicKeySpki,credential.rpId,credential.origin]);
    require(owners.has(owner)&&validBinding(binding));
    const grant=Object.freeze(Object.create(null));
    grants.set(grant,{owner,binding});
    return grant;
  };
  const consume=(grant,owner,binding)=>{
    const item=grants.get(grant);
    if(!item||item.owner!==owner||item.binding!==binding)return false;
    grants.delete(grant);
    return true;
  };
  return Object.freeze({issue,consume});
}
