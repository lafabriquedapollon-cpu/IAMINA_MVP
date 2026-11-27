"""Real IndexedDB counter CAS on isolated loopback; synthetic credentials only."""
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright
from urllib.parse import urlsplit
from h4_egress_guard import NoServiceWorkerScripts, static_request_allowed, attach_direct_transport_guard, service_worker_script_request
from h4_websocket_guard import attach_websocket_guard

ROOT=Path(__file__).parent
MODULES={name:(ROOT/name).read_bytes() for name in (
    "d1_prf_counter_candidate.mjs","d1_prf_possession_candidate.mjs",
    "d1_prf_guard_bridge_candidate.mjs","d1_prf_vault_candidate.mjs",
    "d1_admission_store.mjs","d1_prf_lifecycle_candidate.mjs")}
INTEROP=os.environ.get("D1_PRF_INTEROP_JS")
if INTEROP:
    MODULES["d1-prf-interop.js"]=Path(INTEROP).read_bytes()

class Handler(NoServiceWorkerScripts,http.server.SimpleHTTPRequestHandler):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,directory=str(Path(INTEROP).resolve().parent if INTEROP else ROOT),**kwargs)

    def end_headers(self):
        self.send_header("Cache-Control","no-store")
        super().end_headers()

    def do_GET(self):
        path=urlsplit(self.path).path
        if service_worker_script_request(self.path,self.headers):
            self.send_error(403)
            return
        if path=="/prf-synthetic.html" or path[1:] in MODULES:
            data,kind=(b"<!doctype html><meta charset=utf-8><title>PRF counter synthetic</title>","text/html") if path=="/prf-synthetic.html" else (MODULES[path[1:]],"text/javascript")
            self.send_response(200)
            self.send_header("Content-Type",kind)
            self.send_header("Content-Length",str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if not INTEROP:
            self.send_error(404)
            return
        # Same index/bootstrap/static serving as the proven D1 Flutter probe.
        super().do_GET()

    def log_message(self,*_):
        pass

INIT="""async () => {
    window.prfCounter=await import('/d1_prf_counter_candidate.mjs');
    window.current=true;
    window.c={version:1,credentialId:'AQIDBA',publicKeySpki:'BQYHCA',
      rpId:location.hostname,origin:location.origin,signCount:4};
    window.zero={...c,credentialId:'CQoLDA',signCount:0};
    window.pending=()=>window.current;
    window.refuse=async fn=>{try{await fn();return false;}catch(e){
      return e.message==='D1_PRF_COUNTER_REFUSED';}};
}"""

# Real WebCrypto signature/derivation with explicitly simulated WebAuthn PRF.
# The counter store is real IndexedDB; no physical authenticator claim.
SIGNED_PRF="""async()=>{
    const pubDescriptor=Object.getOwnPropertyDescriptor(window,'PublicKeyCredential');
    const credDescriptor=Object.getOwnPropertyDescriptor(navigator,'credentials');
    const enc=new TextEncoder();
    const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)))
      .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
    const sha=async bytes=>new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
    const der=raw=>{
        const integer=bytes=>{
            const x=Array.from(bytes);
            while(x.length>1&&x[0]===0)x.shift();
            if(x[0]&128)x.unshift(0);
            return [2,x.length,...x];
        };
        const r=integer(raw.slice(0,32)),s=integer(raw.slice(32));
        return Uint8Array.of(48,r.length+s.length,...r,...s);
    };
    class FixtureCredential{
        constructor(rawId,response,prf){Object.assign(this,{rawId,response,prf});}
        getClientExtensionResults(){return {prf:this.prf};}
    }
    const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
    const id=Uint8Array.of(13,14,15,16);
    const credential={version:1,credentialId:b64(id),
      publicKeySpki:b64(await crypto.subtle.exportKey('spki',pair.publicKey)),
      rpId:location.hostname,origin:location.origin,signCount:0};
    let counter=1,output,requests=0,delay=null,omitPrf=false;
    try{
        Object.defineProperty(window,'PublicKeyCredential',{value:FixtureCredential,configurable:true});
        Object.defineProperty(navigator,'credentials',{configurable:true,value:{get:async({publicKey:p})=>{
            requests++;
            if(p.userVerification!=='required'||p.rpId!==location.hostname||
              b64(p.allowCredentials[0].id)!==credential.credentialId||
              p.extensions.prf.eval.first.length!==32)throw new Error('fixture contract');
            const client=enc.encode(JSON.stringify({type:'webauthn.get',origin:location.origin,
                challenge:b64(p.challenge),crossOrigin:false}));
            const auth=new Uint8Array(37);
            auth.set(await sha(enc.encode(location.hostname)));
            auth[32]=5;
            new DataView(auth.buffer).setUint32(33,counter);
            const signed=new Uint8Array(69);signed.set(auth);signed.set(await sha(client),37);
            const signature=der(new Uint8Array(await crypto.subtle.sign(
              {name:'ECDSA',hash:'SHA-256'},pair.privateKey,signed)));
            output=new Uint8Array(32).fill(37);
            if(delay) await delay;
            return new FixtureCredential(id,{clientDataJSON:client,authenticatorData:auth,signature},
              omitPrf?undefined:{enabled:true,results:{first:output.buffer}});
        }}});
        await prfCounter.registerPrfCounter(credential,pending);
        const derive=()=>prfCounter.derivePrfWithDurableCounter({credential,owner:900001,isPending:pending});
        const first=await derive();
        const stored=await prfCounter.readPrfCounter(credential,pending);
        if(first.extractable||first.algorithm.name!=='AES-KW'||stored.signCount!==1||
           stored.revision!==2||!output.every(x=>x===0))return false;
        const data=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
        const wrapped=await crypto.subtle.wrapKey('raw',data,first,'AES-KW');
        counter=2;
        const second=await derive();
        const unwrapped=await crypto.subtle.unwrapKey('raw',wrapped,second,'AES-KW',
          {name:'AES-GCM'},false,['encrypt','decrypt']);
        if(unwrapped.extractable)return false;
        // Replay of the same signed counter must not release a key or advance IDB.
        try{await derive();return false;}catch(e){if(e.message!=='D1_PRF_POSSESSION_REFUSED')return false;}
        const after=await prfCounter.readPrfCounter(credential,pending);
        if(!(requests===3&&after.signCount===2&&after.revision===3&&output.every(x=>x===0)))return false;
        const {createPrfBridge}=await import('/d1_prf_guard_bridge_candidate.mjs');
        const bridge=createPrfBridge(), foreign=createPrfBridge();
        const refused=async fn=>{try{await fn();return false;}catch(e){return e.message==='D1_PRF_POSSESSION_REFUSED';}};
        const acquire=()=>bridge.acquire(JSON.stringify(credential),900001,pending);
        const tests={};
        counter=3;
        const token=await acquire();
        tests.opaque=bridge.isLive(token)&&Object.isFrozen(token)&&Object.keys(token).length===0&&JSON.stringify(token)==='{}';
        tests.forgery=!bridge.isLive({})&&!foreign.isLive(token);
        bridge.revoke(token);bridge.revoke(token);
        tests.revocation=!bridge.isLive(token);
        counter=4;
        const successor=await acquire();
        bridge.revoke(token);
        tests.successor=bridge.isLive(successor);
        tests.replay=await refused(acquire);
        counter=5;omitPrf=true;
        tests.absent=await refused(acquire);
        omitPrf=false;
        current=false;
        tests.cancelledBefore=await refused(acquire);
        current=true;
        let release;
        delay=new Promise(resolve=>{release=resolve;});
        let entered;
        const oldCount=requests;
        const request=acquire();
        const handled=refused(()=>request);
        // Wait for real fixture authenticator invocation, then retire.
        for(let i=0;i<100&&requests===oldCount;i++)await new Promise(r=>setTimeout(r,5));
        entered=requests===oldCount+1;
        current=false;release();
        tests.cancelledDuring=entered&&await handled;
        current=true;delay=null;
        const final=await prfCounter.readPrfCounter(credential,pending);
        tests.noCounterOnRefusal=final.signCount===4&&final.revision===5;
        bridge.revoke(successor);
        tests.closed=!bridge.isLive(successor);
        if(!Object.values(tests).every(x=>x===true))throw new Error('guard bridge '+JSON.stringify(tests));
        window.guardBridgeChecks=tests;
        const {createFixtureFreshAuthority}=await import('/d1_prf_lifecycle_candidate.mjs');
        const fresh=createFixtureFreshAuthority();
        let provisionDart;
        if(typeof window.d1PrfInteropRun==='function'){
            const {installPrfBridge}=await import('/d1_prf_guard_bridge_candidate.mjs');
            provisionDart=installPrfBridge({fixtureAuthority:fresh.consume});
            window.d1PrfInteropPending=()=>current;
            const runDart=()=>window.d1PrfInteropRun(JSON.stringify(credential),900001);
            const dartChecks={};
            counter=5;
            dartChecks.realInteropHandle=await runDart()==='PASS';
            counter=6;omitPrf=true;
            dartChecks.realInteropAbsent=await runDart()==='REFUSED';
            omitPrf=false;
            current=false;
            dartChecks.realInteropRetired=await runDart()==='REFUSED';
            current=true;
            const dartAfter=await prfCounter.readPrfCounter(credential,pending);
            dartChecks.realInteropDurableAck=dartAfter.signCount===5&&dartAfter.revision===6;
            if(!Object.values(dartChecks).every(x=>x===true))throw new Error('Dart bridge '+JSON.stringify(dartChecks));
            window.dartBridgeChecks=dartChecks;
        }
        // Dedicated immutable floor: every reopening goes to the same
        // credential-global register, never a legacy counter write.
        const authority={};
        const baseline=await prfCounter.readPrfCounter(credential,pending);
        const initialFloor=credential.signCount;
        const reopen=async(owner=900001)=>bridge.acquire(JSON.stringify(credential),owner,pending);
        counter=baseline.signCount+1;
        const reopenA=await reopen();
        bridge.revoke(reopenA);
        authority.lockRevoked=!bridge.isLive(reopenA);
        counter++;
        const reopenB=await reopen(900002);
        bridge.revoke(reopenB);
        authority.sharedCredentialCounter=(await prfCounter.readPrfCounter(credential,pending)).signCount===counter;
        authority.replayRefused=await refused(()=>reopen());
        const beforeAhead=requests;
        authority.aheadFloorRefused=await refused(()=>bridge.acquire(
          JSON.stringify({...credential,signCount:counter+1}),900001,pending))&&requests===beforeAhead;
        counter++;
        let unlockBoth;
        delay=new Promise(resolve=>{unlockBoth=resolve;});
        const started=requests;
        const attempts=[reopen(),reopen(900002)].map(p=>p.then(t=>({t}),()=>({t:null})));
        for(let i=0;i<200&&requests<started+2;i++)await new Promise(r=>setTimeout(r,5));
        const bothEntered=requests===started+2;
        unlockBoth();
        const outcomes=await Promise.all(attempts);
        delay=null;
        const winners=outcomes.filter(x=>x.t&&bridge.isLive(x.t));
        authority.signedRaceOneWinner=bothEntered&&winners.length===1;
        winners.forEach(x=>bridge.revoke(x.t));
        const afterAuthority=await prfCounter.readPrfCounter(credential,pending);
        authority.singleDurableRevision=afterAuthority.signCount===counter&&
          afterAuthority.revision===baseline.revision+3;
        authority.immutableFloor=credential.signCount===initialFloor;
        if(!Object.values(authority).every(x=>x===true))throw new Error('counter authority '+JSON.stringify(authority));
        window.authorityChecks=authority;
        const vaultChecks={};
        const vault=typeof provisionDart==='function'?window.iaminaD1PrfBridge:
          createPrfBridge({fixtureAuthority:fresh.consume});
        const provision=provisionDart??vault.provisionFixture;
        const getToken=async(owner,n=null)=>{counter++;return vault.acquire(JSON.stringify(credential),owner,pending,
          n===null?null:n.toString(16).padStart(64,'0'));};
        const identity=(owner,n)=>JSON.stringify({owner,epoch:1,generation:1,acquisitionId:n.toString(16).padStart(64,'0')});
        const evidenceId='ac123456-1234-4abc-8def-000000000001';
        const no=async fn=>{try{await fn();return false;}catch(e){return e.message==='D1_PRF_VAULT_REFUSED';}};
        let active=false,waiting=true;
        const phase=()=>waiting,session=()=>active;
        const missing=await getToken(900001,1);
        vaultChecks.missingRefused=await no(()=>vault.openLease(missing,identity(900001,1),phase,session));
        vault.revoke(missing);
        const pA=await getToken(900001),pB=await getToken(900002);
        const lifecycleChecks={};
        lifecycleChecks.noGrant=await no(()=>provision(pA,pending));
        lifecycleChecks.bearerNotGrant=await no(()=>provision(pA,pending,'synthetic-bearer'));
        lifecycleChecks.forgedGrant=await no(()=>provision(pA,pending,{}));
        const grantA=fresh.issue(900001,credential),grantB=fresh.issue(900002,credential);
        lifecycleChecks.foreignOwnerGrant=await no(()=>provision(pA,pending,grantB));
        const wrong=fresh.issue(900001,{...credential,credentialId:'AQIDBA'});
        lifecycleChecks.foreignCredentialGrant=await no(()=>provision(pA,pending,wrong));
        const foreign=createFixtureFreshAuthority();
        lifecycleChecks.foreignIssuerGrant=await no(()=>provision(pA,pending,foreign.issue(900001,credential)));
        // A cancelled request does not consume an untouched grant.
        const cancelled=await getToken(900001);
        lifecycleChecks.cancelledFresh=await no(()=>provision(cancelled,()=>false,fresh.issue(900001,credential)));
        vault.revoke(cancelled);
        // Concurrent, separately authorized first-create requests share the
        // same durable owner slot. Exactly one atomic record+marker commit.
        const pA2=await getToken(900001),grantA2=fresh.issue(900001,credential);
        const outcomesA=await Promise.allSettled([provision(pA,pending,grantA),provision(pA2,pending,grantA2)]);
        lifecycleChecks.oneFreshWinner=outcomesA.filter(x=>x.status==='fulfilled'&&x.value===true).length===1&&
          outcomesA.filter(x=>x.status==='rejected'&&x.reason.message==='D1_PRF_VAULT_REFUSED').length===1;
        vaultChecks.explicitProvision=lifecycleChecks.oneFreshWinner&&await provision(pB,pending,grantB);
        vault.revoke(pA);vault.revoke(pA2);vault.revoke(pB);
        const dup=await getToken(900001);
        lifecycleChecks.consumedGrant=await no(()=>provision(dup,pending,grantA));
        vaultChecks.noReprovision=await no(()=>provision(dup,pending,fresh.issue(900001,credential)));vault.revoke(dup);
        lifecycleChecks.normalPortNoProvision=!Object.hasOwn(createPrfBridge(),'provisionFixture');
        const normal=typeof provisionDart==='function'?window.iaminaD1PrfBridge:createPrfBridge();
        lifecycleChecks.installedNoProvision=!Object.hasOwn(normal,'provisionFixture');
        const a=await getToken(900001,2);
        vaultChecks.wrongOwner=await no(()=>vault.openLease(a,identity(900002,2),phase,session));
        vaultChecks.wrongAcquisition=await no(()=>vault.openLease(a,identity(900001,3),phase,session));
        const lA=await vault.openLease(a,identity(900001,2),phase,session);
        vaultChecks.opaqueLease=Object.isFrozen(lA)&&Object.keys(lA).length===0&&!await vault.verifyLease({});
        vaultChecks.pendingVerify=await vault.verifyLease(lA);
        vaultChecks.oneShot=await no(()=>vault.openLease(a,identity(900001,2),phase,session));
        // Pending read retires the lease: admission is not a read authority.
        vaultChecks.pendingReadRefused=await no(()=>vault.readEvidence(lA,evidenceId));
        vault.revoke(a);
        const a2=await getToken(900001,4);
        const lA2=await vault.openLease(a2,identity(900001,4),phase,session);
        waiting=false;active=true;
        const aValue=JSON.parse(await vault.readEvidence(lA2,evidenceId));
        vaultChecks.aEvidence=aValue.originalValue===7.83&&aValue.unit==='mmol/L';
        vaultChecks.missingRow=await vault.readEvidence(lA2,'ac123456-1234-4abc-8def-000000000002')==='null';
        waiting=true;active=false;
        const b=await getToken(900002,5),lB=await vault.openLease(b,identity(900002,5),phase,session);
        waiting=false;active=true;
        vaultChecks.oldFence=!await vault.verifyLease(lA2)&&await no(()=>vault.readEvidence(lA2,evidenceId));
        await vault.retireLease(lA2);
        vaultChecks.successor=await vault.verifyLease(lB);
        const bValue=JSON.parse(await vault.readEvidence(lB,evidenceId));
        vaultChecks.bEvidence=bValue.originalValue===142&&bValue.unit==='mg/dL';
        vault.revoke(b);
        vaultChecks.directDurableRevocation=await vault.waitRevocation(b);
        vaultChecks.revoked=!await vault.verifyLease(lB)&&await no(()=>vault.readEvidence(lB,evidenceId));
        await vault.retireLease(lB);
        waiting=true;active=false;
        const a3=await getToken(900001,6),lA3=await vault.openLease(a3,identity(900001,6),phase,session);
        waiting=false;active=true;
        vaultChecks.reopenA=JSON.parse(await vault.readEvidence(lA3,evidenceId)).originalValue===7.83;
        await vault.retireLease(lA3);vault.revoke(a3);
        vaultChecks.retired=!await vault.verifyLease(lA3);
        // Direct storage inspection: ciphertext only, no plaintext/DEK.
        const storedRows=await new Promise((resolve,reject)=>{
          const r=indexedDB.open('iamina-d1-admission-prf-vault-candidate-v1',1);
          r.onerror=()=>reject(r.error);
          r.onsuccess=()=>{const db=r.result,tx=db.transaction('state','readonly');
            const q=tx.objectStore('state').getAll();
            tx.oncomplete=()=>{db.close();resolve(q.result);};
            tx.onabort=()=>{db.close();reject(tx.error);};};
        });
        const rows=storedRows.filter(r=>r.cipher);
        const markers=storedRows.filter(r=>r.state==='sealed');
        lifecycleChecks.atomicMarkers=markers.length===2&&rows.every(r=>markers.some(m=>m.owner===r.owner&&m.binding===r.binding&&m.version===1));
        if(!Object.values(lifecycleChecks).every(x=>x===true))throw new Error('lifecycle '+JSON.stringify(lifecycleChecks));
        window.lifecycleChecks=lifecycleChecks;
        vaultChecks.encryptedAtRest=rows.length===2&&rows.every(r=>r.wrapped.length===40&&
          r.iv.length===12&&r.cipher.length>16&&!Object.hasOwn(r,'originalValue')&&!Object.hasOwn(r,'key')&&
          !new TextDecoder().decode(r.cipher).includes('originalValue'));
        if(!Object.values(vaultChecks).every(x=>x===true))throw new Error('vault '+JSON.stringify(vaultChecks));
        window.vaultChecks=vaultChecks;
        if(typeof provisionDart==='function'){
            counter++;
            window.d1PrfInteropPending=()=>current;
            const outcome=await window.d1PrfVaultInteropRun(JSON.stringify(credential),900001);
            if(outcome!=='PASS')throw new Error('Dart vault '+outcome);
            window.vaultDartPass=true;
        }
        // Synthetic signing key only, held by test harness across browser
        // restart. Neither the PRF wrapping key nor the data key is exported.
        window.vaultRestartFixture={credential,counter,signer:await crypto.subtle.exportKey('jwk',pair.privateKey)};
        return true;
    }finally{
        if(pubDescriptor)Object.defineProperty(window,'PublicKeyCredential',pubDescriptor);
        else delete window.PublicKeyCredential;
        if(credDescriptor)Object.defineProperty(navigator,'credentials',credDescriptor);
        else delete navigator.credentials;
    }
}"""

VAULT_RESTART="""async(fixture)=>{
    const {credential,signer}=fixture;
    let counter=fixture.counter,prfMode='original';
    const enc=new TextEncoder();
    const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)))
      .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
    const id=Uint8Array.of(13,14,15,16);
    const sha=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
    const key=await crypto.subtle.importKey('jwk',signer,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
    const der=raw=>{
        const integer=bytes=>{
            const x=Array.from(bytes);
            while(x.length>1&&x[0]===0)x.shift();
            if(x[0]&128)x.unshift(0);
            return [2,x.length,...x];
        };
        const r=integer(raw.slice(0,32)),s=integer(raw.slice(32));
        return Uint8Array.of(48,r.length+s.length,...r,...s);
    };
    class FixtureCredential{
        constructor(rawId,response,prf){Object.assign(this,{rawId,response,prf});}
        getClientExtensionResults(){return {prf:this.prf};}
    }
    Object.defineProperty(window,'PublicKeyCredential',{value:FixtureCredential,configurable:true});
    Object.defineProperty(navigator,'credentials',{configurable:true,value:{get:async({publicKey:p})=>{
        if(p.userVerification!=='required'||b64(p.allowCredentials[0].id)!==credential.credentialId)
          throw new Error('fixture contract');
        if(fixture.onlyInstall){
          const r=await prfCounter.readPrfCounter(credential,()=>true);
          counter=r.signCount+1;
        }
        const client=enc.encode(JSON.stringify({type:'webauthn.get',origin:location.origin,
          challenge:b64(p.challenge),crossOrigin:false}));
        const auth=new Uint8Array(37);auth.set(await sha(enc.encode(location.hostname)));
        auth[32]=5;new DataView(auth.buffer).setUint32(33,counter);
        const signed=new Uint8Array(69);signed.set(auth);signed.set(await sha(client),37);
        const signature=der(new Uint8Array(await crypto.subtle.sign(
          {name:'ECDSA',hash:'SHA-256'},key,signed)));
        if(prfMode==='lost')throw new DOMException('synthetic authenticator unavailable','NotAllowedError');
        return new FixtureCredential(id,{clientDataJSON:client,authenticatorData:auth,signature},
          prfMode==='absent'?{enabled:false}:{enabled:true,results:{first:new Uint8Array(32).fill(prfMode==='changed'?38:37).buffer}});
    }}});
    const {createPrfBridge,installPrfBridge}=await import('/d1_prf_guard_bridge_candidate.mjs');
    if(fixture.onlyInstall){
      installPrfBridge();
      return true;
    }
    const bridge=createPrfBridge();
    const checks={};
    const uuid='ac123456-1234-4abc-8def-000000000001';
    const idFor=n=>n.toString(16).padStart(64,'0');
    const identity=(owner,n)=>JSON.stringify({owner,epoch:2,generation:3,acquisitionId:idFor(n)});
    const acquire=async(owner,n)=>{counter++;return bridge.acquire(JSON.stringify(credential),owner,()=>true,idFor(n));};
    const refused=async fn=>{try{await fn();return false;}catch(e){return e.message==='D1_PRF_VAULT_REFUSED';}};
    const readWrite=async(owner,change)=>new Promise((resolve,reject)=>{
        const r=indexedDB.open('iamina-d1-admission-prf-vault-candidate-v1',1);
        r.onerror=()=>reject(r.error);
        r.onsuccess=()=>{const db=r.result,tx=db.transaction('state',change?'readwrite':'readonly');
          const st=tx.objectStore('state'),q=st.get(owner);
          let result;
          q.onsuccess=()=>{result=q.result;if(change){const next=change(result);if(next===undefined)st.delete(owner);else st.put(next,owner);}};
          tx.oncomplete=()=>{db.close();resolve(result);};
          tx.onabort=()=>{db.close();reject(tx.error);};};
    });
    const before=await readWrite('fence');
    checks.restartRetiredFence=before.active===false;
    let waiting=true,active=false;
    const p=()=>waiting,s=()=>active;
    const token=await acquire(900001,80),lease=await bridge.openLease(token,identity(900001,80),p,s);
    waiting=false;active=true;
    const row=JSON.parse(await bridge.readEvidence(lease,uuid));
    checks.restartA=row.originalValue===7.83&&row.unit==='mmol/L';
    await bridge.retireLease(lease);
    waiting=true;active=false;
    const tokenB=await acquire(900002,81),leaseB=await bridge.openLease(tokenB,identity(900002,81),p,s);
    waiting=false;active=true;
    checks.restartB=JSON.parse(await bridge.readEvidence(leaseB,uuid)).originalValue===142;
    await bridge.retireLease(leaseB);
    // The pending callback becomes false exactly after the durable ACK.
    const late=await acquire(900001,82);
    let calls=0;
    checks.lateAckRefused=await refused(()=>bridge.openLease(late,identity(900001,82),()=>++calls<7,()=>false));
    const lateFence=await readWrite('fence');
    checks.lateAckRetired=calls===7&&lateFence.acquisitionId===idFor(82)&&lateFence.active===false;
    // Tamper a single ciphertext byte, then restore the synthetic original.
    const original=await readWrite('owner:900001',r=>({...r,cipher:r.cipher.map((b,i)=>i===0?b^1:b)}));
    const tampered=await acquire(900001,83);
    checks.tamperRefused=await refused(()=>bridge.openLease(tampered,identity(900001,83),()=>true,()=>false));
    await readWrite('owner:900001',()=>original);
    const restored=await acquire(900001,84),restoredLease=await bridge.openLease(restored,identity(900001,84),()=>true,()=>false);
    checks.restoredAfterTamper=await bridge.verifyLease(restoredLease);
    await bridge.retireLease(restoredLease);
    if(!Object.values(checks).every(x=>x===true))throw new Error('restart '+JSON.stringify(checks));
    const recovery={};
    const {createFixtureFreshAuthority}=await import('/d1_prf_lifecycle_candidate.mjs');
    const fresh=createFixtureFreshAuthority(),provisioner=createPrfBridge({fixtureAuthority:fresh.consume});
    const mark=await readWrite('lifecycle:900001');
    const encrypted=await readWrite('owner:900001');
    const frozenFence=await readWrite('fence');
    const snapshot=async()=>JSON.stringify([await readWrite('lifecycle:900001'),
      await readWrite('owner:900001'),await readWrite('fence')]);
    const intact=await snapshot();
    const denied=async fn=>{try{await fn();return false;}catch(e){return e.message==='D1_PRF_POSSESSION_REFUSED';}};
    prfMode='lost';
    recovery.lostAuthenticator=await denied(()=>acquire(900001,100));
    prfMode='absent';
    recovery.absentPrf=await denied(()=>acquire(900001,101));
    prfMode='changed';
    const changed=await acquire(900001,102);
    recovery.changedPrf=await refused(()=>bridge.openLease(changed,identity(900001,102),()=>true,()=>false));
    bridge.revoke(changed);
    prfMode='original';
    recovery.failuresPreserveCipher=await snapshot()===intact;
    // Existing owner with missing metadata must not become a fresh owner.
    await readWrite('lifecycle:900001',()=>undefined);
    const noMarker=await acquire(900001,103);
    recovery.missingMarkerRefuses=await refused(()=>bridge.openLease(noMarker,identity(900001,103),()=>true,()=>false));
    counter++;
    const noMarkerFresh=await provisioner.acquire(JSON.stringify(credential),900001,()=>true);
    recovery.noResetWithoutMarker=await refused(()=>provisioner.provisionFixture(noMarkerFresh,()=>true,fresh.issue(900001,credential)));
    provisioner.revoke(noMarkerFresh);
    recovery.missingMarkerCipherPreserved=JSON.stringify(await readWrite('owner:900001'))===JSON.stringify(encrypted);
    await readWrite('lifecycle:900001',()=>mark);
    // Existing marker without ciphertext is loss, never fresh provisioning.
    await readWrite('owner:900001',()=>undefined);
    const noCipher=await acquire(900001,104);
    recovery.missingCipherRefuses=await refused(()=>bridge.openLease(noCipher,identity(900001,104),()=>true,()=>false));
    counter++;
    const noCipherFresh=await provisioner.acquire(JSON.stringify(credential),900001,()=>true);
    recovery.noResetWithoutCipher=await refused(()=>provisioner.provisionFixture(noCipherFresh,()=>true,fresh.issue(900001,credential)));
    provisioner.revoke(noCipherFresh);
    recovery.markerPreserved=JSON.stringify(await readWrite('lifecycle:900001'))===JSON.stringify(mark);
    await readWrite('owner:900001',()=>encrypted);
    // Reject metadata copied from another owner and replaced credential.
    const markB=await readWrite('lifecycle:900002');
    await readWrite('lifecycle:900001',()=>markB);
    const wrongOwner=await acquire(900001,105);
    recovery.foreignMarkerRefuses=await refused(()=>bridge.openLease(wrongOwner,identity(900001,105),()=>true,()=>false));
    await readWrite('lifecycle:900001',()=>({...mark,binding:JSON.stringify(['AQIDBA',credential.publicKeySpki,credential.rpId,credential.origin])}));
    const wrongCredential=await acquire(900001,106);
    recovery.replacedCredentialRefuses=await refused(()=>bridge.openLease(wrongCredential,identity(900001,106),()=>true,()=>false));
    await readWrite('lifecycle:900001',()=>null);
    const malformed=await acquire(900001,107);
    recovery.nullMarkerRefuses=await refused(()=>bridge.openLease(malformed,identity(900001,107),()=>true,()=>false));
    await readWrite('lifecycle:900001',()=>mark);
    recovery.fenceAndCipherUnchanged=await snapshot()===intact;
    // Exact original credential and PRF restore the read path without a
    // destructive reset. This is reopening, not recovery of a lost key.
    const originalToken=await acquire(900001,108);
    let reopening=true,opened=false;
    const originalLease=await bridge.openLease(originalToken,identity(900001,108),()=>reopening,()=>opened);
    reopening=false;opened=true;
    recovery.originalCredentialReopens=JSON.parse(await bridge.readEvidence(originalLease,uuid)).originalValue===7.83;
    await bridge.retireLease(originalLease);
    recovery.originalCipherPreserved=JSON.stringify(await readWrite('owner:900001'))===JSON.stringify(encrypted);
    // Missing both local keys still cannot be re-created when a prior
    // durable fence exists. Whole-profile loss needs independent inventory.
    await readWrite('owner:900001',()=>undefined);
    await readWrite('lifecycle:900001',()=>undefined);
    counter++;
    const both=await provisioner.acquire(JSON.stringify(credential),900001,()=>true);
    recovery.priorFenceBlocksReset=await refused(()=>provisioner.provisionFixture(both,()=>true,fresh.issue(900001,credential)));
    provisioner.revoke(both);
    await readWrite('owner:900001',()=>encrypted);
    await readWrite('lifecycle:900001',()=>mark);
    recovery.restoredExact=JSON.stringify(await readWrite('owner:900001'))===JSON.stringify(encrypted)&&
      JSON.stringify(await readWrite('lifecycle:900001'))===JSON.stringify(mark);
    if(!Object.values(recovery).every(x=>x===true))throw new Error('recovery '+JSON.stringify(recovery));
    return {restart:checks,recovery};

}"""

# Same compiled Flutter runtime artifact as existing D1 browser probes;
# independent tabs share the real PRF counter and encrypted vault namespace.
def flutter_runtime_checks(ctx,origin,fixture):
    pages=[ctx.new_page(),ctx.new_page()]
    checks={}
    for p in pages:
        diagnostics=[]
        p.on("pageerror",lambda e:diagnostics.append(("pageerror",str(e)[:500])))
        p.on("console",lambda m:diagnostics.append(("console",m.type,m.text[:500])) if m.type in ("error","warning") else None)
        p.on("requestfailed",lambda q:diagnostics.append(("requestfailed",urlsplit(q.url).path,q.failure)))
        p.on("response",lambda response:diagnostics.append(("http",response.status,urlsplit(response.url).path)) if response.status>=400 else None)
        try:
            response=p.goto(origin+"/",wait_until="domcontentloaded")
            assert response and response.status==200
            p.wait_for_function("typeof window.d1PrfRuntimeRun==='function' && typeof window.d1Snapshot==='function'",timeout=60000)
        except Exception:
            actual_locale=p.evaluate("()=>({language:navigator.language,languages:Array.from(navigator.languages)})")
            print("D1_PRF_FLUTTER_BOOT_FAILURE "+json.dumps({"locale":actual_locale,"diagnostics":diagnostics[-30:]}),flush=True)
            raise
        print("D1_PRF_FLUTTER_BOOT_READY",flush=True)
        p.evaluate(INIT)
        assert p.evaluate(VAULT_RESTART,{**fixture,"onlyInstall":True}) is True
        assert p.evaluate("(c)=>d1PrfRuntimeRun('init',JSON.stringify(c))",fixture["credential"])=="PASS"
    a,b=pages
    def call(p,op,arg=""):
        return p.evaluate("([op,arg])=>d1PrfRuntimeRun(op,arg)",[op,arg])
    def record(p,owner):
        return call(p,"login",str(owner))=="PASS" and call(p,"admit")=="PASS"
    def read(p):
        return json.loads(call(p,"read"))
    def fence(p):
        return p.evaluate("""async()=>{
          const {createAdmissionStore}=await import('/d1_admission_store.mjs');
          return createAdmissionStore('iamina-d1-admission-prf-vault-candidate-v1').readFence();
        }""")
    checks["flutterA"]=record(a,900001) and read(a)=={"value":7.83,"unit":"mmol/L","provenance":"userEntered"}
    old_fence=fence(a)
    # Hold an actual decrypt promise open in tab A; tab B replaces its fence.
    a.evaluate("""()=>{
      const original=crypto.subtle.decrypt.bind(crypto.subtle);
      window.prfDecryptEntered=false;
      Object.defineProperty(crypto.subtle,'decrypt',{configurable:true,value:async(...args)=>{
        const value=await original(...args);
        await new Promise(resolve=>{window.prfDecryptRelease=resolve;window.prfDecryptEntered=true;});
        return value;
      }});
      window.prfReadSettled=false;
      window.prfRead=d1PrfRuntimeRun('read','').then(v=>{window.prfReadSettled=true;return v;});
    }""")
    a.wait_for_function("window.prfDecryptEntered===true")
    checks["flutterB"]=record(b,900002) and read(b)=={"value":142,"unit":"mg/dL","provenance":"userEntered"}
    new_fence=fence(b)
    checks["crossTabFenceReplaced"]=old_fence["acquisitionId"]!=new_fence["acquisitionId"] and new_fence["owner"]==900002 and new_fence["active"]
    still_pending=a.evaluate("()=>!window.prfReadSettled")
    a.evaluate("()=>{delete crypto.subtle.decrypt;window.prfDecryptRelease();}")
    checks["crossTabLateRead"]=still_pending and a.evaluate("()=>window.prfRead")=="REFUSED"
    checks["staleRetirePreservesB"]=call(a,"retire")=="PASS" and read(b)["value"]==142
    checks["lockRevokesB"]=call(b,"lock")=="PASS" and call(b,"read")=="REFUSED" and call(b,"retire")=="PASS"
    checks["lockDurableFence"]=fence(b)["acquisitionId"]==new_fence["acquisitionId"] and not fence(b)["active"]
    checks["flutterReopenA"]=record(a,900001) and read(a)["value"]==7.83
    # Hang WebCrypto after decrypt, without ever returning its result before
    # deadline. The operation must refuse and retire independently.
    a.evaluate("""()=>{
      const original=crypto.subtle.decrypt.bind(crypto.subtle);
      window.prfDecryptEntered=false;
      Object.defineProperty(crypto.subtle,'decrypt',{configurable:true,value:async(...args)=>{
        const value=await original(...args);
        await new Promise(resolve=>{window.prfDecryptRelease=resolve;window.prfDecryptEntered=true;});
        return value;
      }});
      window.prfReadSettled=false;
      window.prfRead=d1PrfRuntimeRun('read','').then(v=>{window.prfReadSettled=true;return v;});
    }""")
    a.wait_for_function("window.prfDecryptEntered===true")
    timeout_fence=fence(a)
    checks["boundedRead"]=a.evaluate("()=>window.prfRead")=="REFUSED"
    retired=fence(a)
    checks["timeoutRetired"]=retired["acquisitionId"]==timeout_fence["acquisitionId"] and not retired["active"] and json.loads(call(a,"status"))["active"] is False
    checks["timeoutRetireRetry"]=call(a,"retire")=="PASS"
    a.evaluate("()=>{delete crypto.subtle.decrypt;window.prfDecryptRelease();}")
    # Stall the unwrap during admission itself. No lease/fence may be
    # published by a late return, and the next admission must still work.
    a.evaluate("""()=>{
      const original=crypto.subtle.unwrapKey.bind(crypto.subtle);
      window.prfUnwrapEntered=false;
      Object.defineProperty(crypto.subtle,'unwrapKey',{configurable:true,value:async(...args)=>{
        const value=await original(...args);
        await new Promise(resolve=>{window.prfUnwrapRelease=resolve;window.prfUnwrapEntered=true;});
        return value;
      }});
      window.prfAdmission=d1PrfRuntimeRun('admit','');
    }""")
    a.wait_for_function("window.prfUnwrapEntered===true")
    checks["boundedAdmission"]=a.evaluate("()=>window.prfAdmission")=="REFUSED"
    checks["timeoutNoNewFence"]=fence(a)==retired
    a.evaluate("()=>{delete crypto.subtle.unwrapKey;window.prfUnwrapRelease();}")
    checks["successorAfterTimeout"]=record(b,900002) and read(b)["value"]==142
    checks["identitySwitchRetires"]=call(b,"login","900001")=="PASS" and call(b,"read")=="REFUSED"
    checks["sameTabSwitchA"]=call(b,"admit")=="PASS" and read(b)["value"]==7.83
    checks["noLegacyCalls"]=all(json.loads(call(p,"status"))["legacyCalls"]==0 for p in pages)
    checks["finalRetirement"]=call(b,"retire")=="PASS"
    # Issue two real PRF tokens in different documents, then overlap their
    # lease acquisition by holding both unwrap operations at a barrier.
    for p,owner,n in ((a,900001,901),(b,900002,902)):
        p.evaluate("""async([c,owner,n])=>{
          const id=n.toString(16).padStart(64,'0');
          window.raceIdentity=JSON.stringify({owner,epoch:9,generation:9,acquisitionId:id});
          window.raceToken=await iaminaD1PrfBridge.acquire(JSON.stringify(c),owner,()=>true,id);
          const original=crypto.subtle.unwrapKey.bind(crypto.subtle);
          window.raceEntered=false;
          Object.defineProperty(crypto.subtle,'unwrapKey',{configurable:true,value:async(...args)=>{
            const value=await original(...args);
            await new Promise(resolve=>{window.raceRelease=resolve;window.raceEntered=true;});
            return value;
          }});
          window.racePending=true;window.raceActive=false;
          window.raceLeaseWork=iaminaD1PrfBridge.openLease(window.raceToken,window.raceIdentity,
            ()=>window.racePending,()=>window.raceActive).then(v=>{window.raceLease=v;return true;},()=>false);
        }""",[fixture["credential"],owner,n])
    for p in pages: p.wait_for_function("window.raceEntered===true")
    for p in pages: p.evaluate("()=>{delete crypto.subtle.unwrapKey;window.raceRelease();}")
    outcomes=[p.evaluate("()=>window.raceLeaseWork") for p in pages]
    checks["overlappingLeaseAcquisitions"]=all(outcomes)
    for p in pages: p.evaluate("()=>{window.racePending=false;window.raceActive=true;}")
    winners=[p.evaluate("()=>iaminaD1PrfBridge.verifyLease(window.raceLease)") for p in pages]
    checks["oneCurrentFence"]=sorted(winners)==[False,True]
    if checks["oneCurrentFence"]:
        winner=pages[winners.index(True)];loser=pages[winners.index(False)]
        loser.evaluate("()=>iaminaD1PrfBridge.retireLease(window.raceLease)")
        checks["raceLoserRetireSafe"]=winner.evaluate("()=>iaminaD1PrfBridge.verifyLease(window.raceLease)")
        winner.evaluate("()=>iaminaD1PrfBridge.retireLease(window.raceLease)")
    else: checks["raceLoserRetireSafe"]=False
    for p in pages: p.close()
    assert len(checks)==21 and all(checks.values()),checks
    return checks

def setup(ctx,origin):
    page=ctx.new_page()
    assert page.goto(origin+"/prf-synthetic.html").status==200
    # Check actual browser locale and Intl, not merely configured options.
    locale=page.evaluate("""()=>{
      const language=navigator.language,languages=Array.from(navigator.languages);
      return {language,languages,canonical:Intl.getCanonicalLocales(languages),
        dateLocale:new Intl.DateTimeFormat(language).resolvedOptions().locale,
        numberLocale:new Intl.NumberFormat(language).resolvedOptions().locale};
    }""")
    assert locale["language"]=="fr-FR" and locale["canonical"] and locale["dateLocale"].startswith("fr") and locale["numberLocale"].startswith("fr"),locale
    print("D1_PRF_BROWSER_LOCALE "+json.dumps(locale),flush=True)
    page.evaluate(INIT)
    return page

def run():
    name=os.environ["D1_PRF_ENGINE"]
    assert name in ("chromium","webkit")
    sha=os.environ["EXPECTED_SHA"]
    with tempfile.TemporaryDirectory(prefix="d1-prf-counter-") as tmp, http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler) as server:
        threading.Thread(target=server.serve_forever,daemon=True).start()
        origin=f"http://127.0.0.1:{server.server_port}"
        blocked=[]
        def route(r):
            if static_request_allowed(r.request,(origin,)): r.continue_()
            else: blocked.append(urlsplit(r.request.url).path);r.abort()
        with sync_playwright() as pw:
            engine=getattr(pw,name)
            def launch():
                # Match the proven D1 Flutter browser configuration instead of
                # inheriting a runner-dependent locale (e.g. POSIX/C).
                ctx=engine.launch_persistent_context(tmp,headless=True,locale="fr-FR",
                    viewport={"width":390,"height":844},service_workers="block")
                ctx.route("**/*",route)
                attach_websocket_guard(ctx,blocked)
                attach_direct_transport_guard(ctx,blocked)
                return ctx
            checks=[]
            def check(label,result):
                assert result is True,label
                checks.append(label)
            ctx=launch()
            try:
                a,b=setup(ctx,origin),setup(ctx,origin)
                check("missing_refuses",a.evaluate("()=>refuse(()=>prfCounter.readPrfCounter(c,pending))"))
                check("missing_no_assertion",a.evaluate("""async()=>{
                    try{await prfCounter.derivePrfWithDurableCounter({credential:c,owner:900001,isPending:pending});
                        return false;}catch(e){return e.message==='D1_PRF_POSSESSION_REFUSED';}
                }"""))
                check("explicit_register",a.evaluate("()=>prfCounter.registerPrfCounter(c,pending)"))
                check("duplicate_register_refuses",b.evaluate("()=>refuse(()=>prfCounter.registerPrfCounter(c,pending))"))
                for p in (a,b):
                    p.evaluate("async()=>{window.snap=await prfCounter.readPrfCounter(c,pending);}")
                check("same_baseline",a.evaluate("()=>snap.revision===1&&snap.signCount===4") and b.evaluate("()=>snap.revision===1&&snap.signCount===4"))
                # Both pages race the same committed snapshot. Only one CAS wins.
                for p in (a,b):
                    p.evaluate("""()=>{window.outcome=prfCounter.advancePrfCounter(snap,5,pending)
                      .then(()=>true,()=>false);}""")
                results=[p.evaluate("()=>outcome") for p in (a,b)]
                check("one_cross_document_winner",sorted(results)==[False,True])
                check("committed_counter",a.evaluate("async()=>{const r=await prfCounter.readPrfCounter(c,pending);return r.revision===2&&r.signCount===5;}"))
                check("stale_refuses",b.evaluate("()=>refuse(()=>prfCounter.advancePrfCounter(snap,6,pending))"))
                check("wrong_public_key_refuses",a.evaluate("()=>refuse(()=>prfCounter.readPrfCounter({...c,publicKeySpki:'AQIDBA'},pending))"))
                check("ahead_of_store_refuses",a.evaluate("()=>refuse(()=>prfCounter.readPrfCounter({...c,signCount:6},pending))"))
                a.evaluate("async()=>{window.snap=await prfCounter.readPrfCounter(c,pending);}")
                check("rollback_refuses",a.evaluate("()=>refuse(()=>prfCounter.advancePrfCounter(snap,4,pending))"))
                check("positive_to_zero_refuses",a.evaluate("()=>refuse(()=>prfCounter.advancePrfCounter(snap,0,pending))"))
                check("cancelled_refuses",a.evaluate("()=>{current=false;return refuse(()=>prfCounter.advancePrfCounter(snap,6,pending));}"))
                check("zero_register",b.evaluate("()=>prfCounter.registerPrfCounter(zero,pending)"))
                check("zero_advances_revision",b.evaluate("""async()=>{
                    const first=await prfCounter.readPrfCounter(zero,pending);
                    await prfCounter.advancePrfCounter(first,0,pending);
                    const next=await prfCounter.readPrfCounter(zero,pending);
                    return next.signCount===0&&next.revision===2&&await refuse(()=>prfCounter.advancePrfCounter(first,0,pending));
                }"""))
            finally: ctx.close()
            ctx=launch()
            try:
                a=setup(ctx,origin)
                check("restart_exact",a.evaluate("""async()=>{
                    const r=await prfCounter.readPrfCounter(c,pending);
                    const z=await prfCounter.readPrfCounter(zero,pending);
                    return r.revision===2&&r.signCount===5&&z.revision===2&&z.signCount===0;
                }"""))
                check("restart_stale_refuses",a.evaluate("()=>refuse(()=>prfCounter.advancePrfCounter({...c,revision:1},6,pending))"))
                check("restart_advance",a.evaluate("""async()=>{
                    const r=await prfCounter.readPrfCounter(c,pending);
                    await prfCounter.advancePrfCounter(r,6,pending);
                    const after=await prfCounter.readPrfCounter(c,pending);
                    return after.revision===3&&after.signCount===6;
                }"""))
                if INTEROP:
                    a.add_script_tag(url=origin+"/d1-prf-interop.js")
                    a.wait_for_function("typeof window.d1PrfInteropRun==='function'")
                check("signed_prf_durable_ack_and_replay",a.evaluate(SIGNED_PRF))
                guard=a.evaluate("window.guardBridgeChecks")
                assert len(guard)==10 and all(v is True for v in guard.values())
                print("D1_PRF_GUARD_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(guard),count=len(guard))),flush=True)
                authority=a.evaluate("window.authorityChecks")
                assert len(authority)==7 and all(v is True for v in authority.values())
                print("D1_PRF_SINGLE_AUTHORITY_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(authority),count=len(authority))),flush=True)
                lifecycle=a.evaluate("window.lifecycleChecks")
                assert len(lifecycle)==12 and all(v is True for v in lifecycle.values()),lifecycle
                print("D1_PRF_LIFECYCLE_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(lifecycle),count=len(lifecycle))),flush=True)
                vault=a.evaluate("window.vaultChecks")
                assert len(vault)==19 and all(v is True for v in vault.values())
                print("D1_PRF_VAULT_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(vault),count=len(vault))),flush=True)
                if INTEROP:
                    assert a.evaluate("window.vaultDartPass") is True
                    print("D1_PRF_VAULT_DART_PASS "+json.dumps(dict(source=sha,engine=name,count=1)),flush=True)
                    dart=a.evaluate("window.dartBridgeChecks")
                    assert len(dart)==4 and all(v is True for v in dart.values())
                    print("D1_PRF_DART_INTEROP_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(dart),count=len(dart))),flush=True)
                restart_fixture=a.evaluate("window.vaultRestartFixture")
            finally: ctx.close()
            ctx=launch()
            try:
                a=setup(ctx,origin)
                result=a.evaluate(VAULT_RESTART,restart_fixture)
                restart=result["restart"]
                assert len(restart)==7 and all(v is True for v in restart.values())
                print("D1_PRF_VAULT_RESTART_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(restart),count=len(restart))),flush=True)
                recovery=result["recovery"]
                assert len(recovery)==18 and all(v is True for v in recovery.values()),recovery
                print("D1_PRF_RECOVERY_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(recovery),count=len(recovery))),flush=True)
                if INTEROP:
                    runtime=flutter_runtime_checks(ctx,origin,restart_fixture)
                    print("D1_PRF_FLUTTER_RUNTIME_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(runtime),count=len(runtime))),flush=True)
                check("zero_external_requests",not blocked)
            finally: ctx.close()
        print("D1_PRF_COUNTER_PASS "+json.dumps(dict(source=sha,engine=name,checks=checks,count=len(checks))),flush=True)
        server.shutdown()

if __name__=="__main__":
    run()
