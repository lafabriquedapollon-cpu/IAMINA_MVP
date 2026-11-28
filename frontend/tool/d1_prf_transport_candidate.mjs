// Loopback-only candidate, not a production HTTP/auth integration.
const fail=()=>new Error('D1_PRF_TRANSPORT_REFUSED');
const require=x=>{if(!x)throw fail();};
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const validHex=(s,n)=>typeof s==='string'&&s.length===n&&/^[0-9a-f]+$/.test(s);
const bytes=s=>Uint8Array.from(s.match(/../g),x=>parseInt(x,16));
const exact=(x,k)=>x&&Object.keys(x).length===k.length&&k.every(v=>Object.hasOwn(x,v));
const enc=new TextEncoder();
export function createProvisionTransport({sessionId,proofKey,isPending,timeoutMs=5000}){
  require(location.protocol==='http:'&&location.hostname==='127.0.0.1'&&location.port&&
    validHex(sessionId,64)&&proofKey instanceof CryptoKey&&proofKey.type==='private'&&!proofKey.extractable&&
    proofKey.algorithm.name==='ECDSA'&&proofKey.algorithm.namedCurve==='P-256'&&proofKey.usages.includes('sign')&&
    typeof isPending==='function'&&Number.isSafeInteger(timeoutMs)&&timeoutMs>=50&&timeoutMs<=5000);
  async function call(action,payload){
    const abort=new AbortController();
    let expired=false;
    const start=performance.now();
    const check=()=>require(!expired&&isPending()===true&&performance.now()-start<timeoutMs);
    let timer;
    const work=async()=>{
      check();
      const body=JSON.stringify({action,requestId:hex(crypto.getRandomValues(new Uint8Array(32))),payload});
      require(enc.encode(body).length<=32768);
      const signature=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},proofKey,
        enc.encode('IAMINA-D1-SESSION-PROOF-V1\n'+sessionId+'\n'+body)));
      check();
      const response=await fetch('/d1-provision-candidate',{method:'POST',credentials:'omit',redirect:'error',
        cache:'no-store',signal:abort.signal,headers:{'Content-Type':'application/json',
          'X-D1-Session':sessionId,'X-D1-Proof':hex(signature)},body});
      check();
      require(response.status===200&&response.url===location.origin+'/d1-provision-candidate'&&
        response.headers.get('content-type')?.split(';')[0]==='application/json'&&response.body);
      const reader=response.body.getReader(),chunks=[];let size=0;
      try{
        while(true){
          const {done,value}=await reader.read();check();
          if(done)break;
          size+=value.length;require(size<=32768);chunks.push(value);
        }
      }finally{reader.releaseLock();}
      const data=new Uint8Array(size);let offset=0;
      for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length;}
      check();return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));
    };
    try{
      return await Promise.race([work(),new Promise((_,reject)=>{
        timer=setTimeout(()=>{expired=true;abort.abort();reject(fail());},timeoutMs);
      })]);
    }catch(_){throw fail();}
    finally{expired=true;clearTimeout(timer);abort.abort();}
  }
  return Object.freeze({
    reserve:async()=>{const e=await call('reserve',{});require(exact(e,['ticket','signature'])&&validHex(e.signature,128));
      return {ticket:e.ticket,signature:bytes(e.signature)};},
    redeem:async(ticket,signature)=>{require(signature instanceof Uint8Array&&signature.length===64);
      const r=await call('redeem',{ticket,signature:hex(signature)});require(exact(r,['redeemed'])&&r.redeemed===true);return true;},
    status:async operationId=>{require(validHex(operationId,64));const r=await call('status',{operationId});
      require(exact(r,['state'])&&['reserved','redeemed'].includes(r.state));return r.state;},
  });
}
