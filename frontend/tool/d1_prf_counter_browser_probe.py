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
    "d1_prf_guard_bridge_candidate.mjs")}

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
        return true;
    }finally{
        if(pubDescriptor)Object.defineProperty(window,'PublicKeyCredential',pubDescriptor);
        else delete window.PublicKeyCredential;
        if(credDescriptor)Object.defineProperty(navigator,'credentials',credDescriptor);
        else delete navigator.credentials;
    }
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
                check("signed_prf_durable_ack_and_replay",a.evaluate(SIGNED_PRF))
                check("zero_external_requests",not blocked)
            finally: ctx.close()
        print("D1_PRF_COUNTER_PASS "+json.dumps(dict(source=sha,engine=name,checks=checks,count=len(checks))),flush=True)
        server.shutdown()

if __name__=="__main__":
    run()
