"""Real IndexedDB counter CAS on isolated loopback; synthetic credentials only."""
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).parent
MODULES={name:(ROOT/name).read_bytes() for name in (
    "d1_prf_counter_candidate.mjs","d1_prf_possession_candidate.mjs",
    "d1_prf_guard_bridge_candidate.mjs","d1_prf_vault_candidate.mjs",
    "d1_admission_store.mjs")}
INTEROP=os.environ.get("D1_PRF_INTEROP_JS")
if INTEROP:
    MODULES["d1-prf-interop.js"]=Path(INTEROP).read_bytes()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path=="/":
            data,kind=b"<!doctype html><title>PRF counter synthetic</title>","text/html"
        elif self.path[1:] in MODULES:
            data,kind=MODULES[self.path[1:]],"text/javascript"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type",kind)
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(data)
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
        let provisionDart;
        if(typeof window.d1PrfInteropRun==='function'){
            const {installPrfBridge}=await import('/d1_prf_guard_bridge_candidate.mjs');
            provisionDart=installPrfBridge({fixtureProvision:true});
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
          createPrfBridge({fixtureProvision:true});
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
        vaultChecks.explicitProvision=await provision(pA,pending)&&await provision(pB,pending);
        vault.revoke(pA);vault.revoke(pB);
        const dup=await getToken(900001);
        vaultChecks.noReprovision=await no(()=>provision(dup,pending));vault.revoke(dup);
        const a=await getToken(900001,2);
        vaultChecks.wrongOwner=await no(()=>vault.openLease(a,identity(900002,2),phase,session));
        vaultChecks.wrongAcquisition=await no(()=>vault.openLease(a,identity(900001,3),phase,session));
        const lA=await vault.openLease(a,identity(900001,2),phase,session);
        vaultChecks.opaqueLease=Object.isFrozen(lA)&&Object.keys(lA).length===0&&!await vault.verifyLease({});
        vaultChecks.pendingVerify=await vault.verifyLease(lA);
        vaultChecks.oneShot=await no(()=>vault.openLease(a,identity(900001,3),phase,session));
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
    let counter=fixture.counter;
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
        const client=enc.encode(JSON.stringify({type:'webauthn.get',origin:location.origin,
          challenge:b64(p.challenge),crossOrigin:false}));
        const auth=new Uint8Array(37);auth.set(await sha(enc.encode(location.hostname)));
        auth[32]=5;new DataView(auth.buffer).setUint32(33,counter);
        const signed=new Uint8Array(69);signed.set(auth);signed.set(await sha(client),37);
        const signature=der(new Uint8Array(await crypto.subtle.sign(
          {name:'ECDSA',hash:'SHA-256'},key,signed)));
        return new FixtureCredential(id,{clientDataJSON:client,authenticatorData:auth,signature},
          {enabled:true,results:{first:new Uint8Array(32).fill(37).buffer}});
    }}});
    const {createPrfBridge}=await import('/d1_prf_guard_bridge_candidate.mjs');
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
          q.onsuccess=()=>{result=q.result;if(change)st.put(change(result),owner);};
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
    return checks;
}"""

def setup(ctx,origin):
    page=ctx.new_page()
    assert page.goto(origin).status==200
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
            if r.request.url.startswith(origin+"/"): r.continue_()
            else: blocked.append(r.request.url);r.abort()
        with sync_playwright() as pw:
            engine=getattr(pw,name)
            def launch():
                ctx=engine.launch_persistent_context(tmp,headless=True,service_workers="block")
                ctx.route("**/*",route)
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
                vault=a.evaluate("window.vaultChecks")
                assert len(vault)==18 and all(v is True for v in vault.values())
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
                restart=a.evaluate(VAULT_RESTART,restart_fixture)
                assert len(restart)==7 and all(v is True for v in restart.values())
                print("D1_PRF_VAULT_RESTART_PASS "+json.dumps(dict(source=sha,engine=name,checks=list(restart),count=len(restart))),flush=True)
                check("zero_external_requests",not blocked)
            finally: ctx.close()
        print("D1_PRF_COUNTER_PASS "+json.dumps(dict(source=sha,engine=name,checks=checks,count=len(checks))),flush=True)
        server.shutdown()

if __name__=="__main__":
    run()
