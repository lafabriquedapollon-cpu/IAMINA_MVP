// B2c.2 isolated client verifier. Trust root and atomic redemption transport
// are supplied by a trusted composition, never a UI or a bearer token.
// No production issuer or HTTP endpoint is installed here.
const fail=()=>new Error('D1_PRF_AUTHORIZATION_REFUSED');
const require=x=>{if(!x)throw fail();};
const keys=(x,k)=>x&&Object.keys(x).length===k.length&&k.every(v=>Object.hasOwn(x,v));
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const uint=x=>Number.isSafeInteger(x)&&x>=0;
const fields=['owner','binding','epoch','generation','nonce'];
const ticketFields=['version','purpose',...fields,'operationId','issuedAt','expiresAt'];
const enc=new TextEncoder();
const owners=new Set([900001,900002]);
function contextValid(x){
  return keys(x,fields)&&owners.has(x.owner)&&uint(x.epoch)&&uint(x.generation)&&x.generation>0&&hex(x.nonce)&&
    typeof x.binding==='string'&&x.binding.length<=16384&&(()=>{
      try{const b=JSON.parse(x.binding);return Array.isArray(b)&&b.length===4&&b.every(v=>typeof v==='string'&&v.length>0)&&
        b[2]===location.hostname&&b[3]===location.origin&&JSON.stringify(b)===x.binding;}catch(_){return false;}
    })();
}
export const ticketBytes=t=>enc.encode(JSON.stringify(ticketFields.map(k=>t[k])));
export function createSignedProvisioningAuthority({verificationKey,redeem,now=()=>Date.now()}){
  require(verificationKey instanceof CryptoKey&&verificationKey.type==='public'&&
    verificationKey.algorithm.name==='ECDSA'&&verificationKey.algorithm.namedCurve==='P-256'&&
    verificationKey.usages.includes('verify')&&typeof redeem==='function'&&typeof now==='function');
  const grants=new WeakMap();
  async function authorize(envelope,expected,isPending){
    try{
      require(keys(envelope,['ticket','signature'])&&contextValid(expected)&&typeof isPending==='function');
      const context=Object.freeze({...expected}),t=Object.freeze({...envelope.ticket});
      const sig=envelope.signature;
      require(keys(t,ticketFields)&&t.version===1&&t.purpose==='IAMINA-D1-FRESH-PROVISION-V1'&&
        fields.every(k=>t[k]===context[k])&&hex(t.operationId)&&uint(t.issuedAt)&&uint(t.expiresAt)&&
        t.expiresAt>t.issuedAt&&t.expiresAt-t.issuedAt<=60000&&sig instanceof Uint8Array&&sig.length===64);
      const signature=new Uint8Array(sig);
      const start=now(),mono=performance.now();
      require(uint(start)&&start>=t.issuedAt&&start<t.expiresAt);
      const live=()=>{const current=now();return isPending()===true&&uint(current)&&current>=start&&
        current<t.expiresAt&&performance.now()-mono<t.expiresAt-start;};
      require(live());
      require(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verificationKey,signature,ticketBytes(t)));
      require(live());
      // The trusted issuer must atomically redeem against its independent
      // inventory. A valid signature alone never authorizes creation.
      require(await redeem(t,signature)===true);
      require(live());
      const grant=Object.freeze(Object.create(null));
      grants.set(grant,{owner:t.owner,binding:t.binding,operationId:t.operationId,live});
      return grant;
    }catch(_){throw fail();}
  }
  function consume(grant,owner,binding){
    const g=grants.get(grant);
    if(!g||g.owner!==owner||g.binding!==binding)return null;
    grants.delete(grant);
    if(!g.live())return null;
    return Object.freeze({operationId:g.operationId,check:g.live});
  }
  return Object.freeze({authorize,consume});
}
