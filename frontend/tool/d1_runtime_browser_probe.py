"""D1-I1 actual schema v12, memory-only Drift, atomic encrypted IDB checkpoints.

Synthetic isolated origins/profiles only. No patient identities or real credentials.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright
from h4_websocket_guard import attach_websocket_guard
from h4_egress_guard import static_request_allowed, attach_direct_transport_guard

WEB = Path(os.environ["D1_RUNTIME_WEB"]).resolve()
ENGINE = os.environ["D1_RUNTIME_ENGINE"]
MARKER = "D1_I1_SYNTHETIC_NOT_PATIENT"


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def log_message(self, *_):
        pass


# Independent server-side observation for the UI qualification only.
# A completed GET of the exact packaged fallback asset is real evidence even
# if a WebKit/Playwright response callback is missed. Never trigger a fetch
# from the test to satisfy the spontaneous engine-request requirement.
_FONT_WITNESS_PATHS = {
    "/assets/engine-font-fallback/notosanssymbols/v43/rP2up3q65FkAtHfwd-eIS2brbDN6gxP34F9jRRCe4W3gfQ8gb_VFRkzrbQ.woff2": "notosanssymbols",
    "/assets/engine-font-fallback/notosansarabic/v28/nwpxtLGrOAZMl5nJ_wfgRg3DrWFZWsnVBJ_sS6tlqHHFlhQ5l3sQWIHPqzCfyGyvvnCBFQLaig.woff2": "notosansarabic",
}


class FontWitnessHandler(Handler):
    def send_response(self, code, message=None):
        self.response_status = code
        super().send_response(code, message)

    def end_headers(self):
        if self.path in _FONT_WITNESS_PATHS:
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        self.response_status = None
        family = _FONT_WITNESS_PATHS.get(self.path)
        super().do_GET()
        if family is not None and self.response_status == 200:
            # Only after the handler has completed streaming the response.
            self.server.font_witness.append(family)


def open_context(browser_type, profile, locale, origin, extra_origin=None, trace=None, timezone_id=None):
    context = browser_type.launch_persistent_context(
        str(profile), headless=True, locale=locale,
        viewport={"width":390,"height":844}, service_workers="block",
        **({"timezone_id":timezone_id} if timezone_id else {}),
    )
    blocked, errors = [], []
    def route(r):
        allowed = (origin,) if extra_origin is None else (origin, extra_origin)
        if static_request_allowed(r.request, allowed):
            r.continue_()
        else:
            blocked.append(r.request.url.split("?")[0])
            r.abort()
            if trace is not None:
                trace("blocked", r.request)
    context.route("**/*", route)
    attach_websocket_guard(context, blocked)
    attach_direct_transport_guard(context, blocked)
    page = context.pages[0] if context.pages else context.new_page()
    def page_error(error):
        errors.append(str(error)[:300])
        if trace is not None:
            trace("pageerror", error)
    page.on("pageerror", page_error)
    if trace is not None:
        page.on("console", lambda message: trace("console", message))
        page.on("response", lambda response: trace("response", response))
        page.on("requestfailed", lambda request: trace("requestfailed", request))
    page.goto(origin, wait_until="domcontentloaded")
    page.wait_for_function("typeof window.d1Snapshot === 'function' && typeof window.d1Inspect === 'function'", timeout=60000)
    return context, page, blocked, errors


FIRST = r"""async () => {
  const {readCheckpoint, commitCheckpoint} = await import('/d1_checkpoint_candidate.mjs');
  const {openArchive} = await import('/d1_archive_candidate.mjs');
  const A='amina_vault_v1_native_900001', B='amina_vault_v1_native_900002';
  const s='synthetic probe key A 2026', t='synthetic probe key B 2026';
  const check=(ok, msg)=>{if(!ok) throw new Error(msg);};
  const reject=async fn=>{try{await fn();}catch{return true;}return false;};
  const inspect=async (record, owner)=>JSON.parse(await window.d1Inspect(record.bytes,owner));
  check(await readCheckpoint(A,s)===null,'A unexpectedly exists');
  check(await readCheckpoint(B,t)===null,'B unexpectedly exists');
  const firstA=await window.d1Snapshot(null,900001);
  const firstB=await window.d1Snapshot(null,900002);
  check((await commitCheckpoint(A,s,null,firstA)).revision===1,'A first ACK');
  check((await commitCheckpoint(B,t,null,firstB)).revision===1,'B first ACK');
  check(await reject(()=>commitCheckpoint(A,s,null,firstA)),'Overwrite on missing expected token');
  const oldA=await readCheckpoint(A,s);
  check((await inspect(oldA,900001)).rows===1,'A initial read');
  check(await reject(()=>window.d1Inspect(oldA.bytes,900002)),'Wrong SQLite owner accepted');
  check(await reject(()=>readCheckpoint(A,t)),'Wrong key accepted');
  check(await reject(()=>openArchive(oldA.archive,s,B)),'Wrong archive scope accepted');
  const modified=oldA.archive.slice(); modified[modified.length-1]^=1;
  check(await reject(()=>commitCheckpoint(A,s,{revision:1,archive:modified},firstA)),'Tampered token accepted');
  check(await reject(()=>commitCheckpoint(A,s,{revision:2,archive:oldA.archive},firstA)),'Revision mismatch accepted');
  const next=await window.d1Snapshot(oldA.bytes,900001);
  const outcomes=await Promise.allSettled([
    commitCheckpoint(A,s,oldA,next), commitCheckpoint(A,s,oldA,next)
  ]);
  check(outcomes.filter(x=>x.status==='fulfilled').length===1 &&
        outcomes.filter(x=>x.status==='rejected' && String(x.reason).includes('Checkpoint conflict')).length===1,
        'CAS did not enforce one winner');
  check(await reject(()=>commitCheckpoint(A,s,oldA,next)),'Stale writer accepted');
  const finalA=await readCheckpoint(A,s), finalB=await readCheckpoint(B,t);
  check(finalA.revision===2 && finalB.revision===1,'Owner revision isolation');
  check((await inspect(finalA,900001)).rows===2 && (await inspect(finalB,900002)).rows===1,'Owner row isolation');
  return {ackA:finalA.revision,ackB:finalB.revision,casWinners:1,negativeCases:7};
}"""

RESTORE = r"""async () => {
  const {readCheckpoint} = await import('/d1_checkpoint_candidate.mjs');
  const A='amina_vault_v1_native_900001', B='amina_vault_v1_native_900002';
  const s='synthetic probe key A 2026', t='synthetic probe key B 2026';
  const check=(ok,msg)=>{if(!ok) throw new Error(msg);};
  const a=await readCheckpoint(A,s), b=await readCheckpoint(B,t);
  check(a.revision===2 && b.revision===1,'Persisted revisions lost');
  const ar=JSON.parse(await window.d1Inspect(a.bytes,900001));
  const br=JSON.parse(await window.d1Inspect(b.bytes,900002));
  const ar2=JSON.parse(await window.d1Inspect(a.bytes,900001));
  check(JSON.stringify(ar)===JSON.stringify(ar2),'A-B-A not stable');
  check(ar.rows===2 && br.rows===1 && ar.schema===12 && br.schema===12 &&
        ar.integrity==='ok' && br.integrity==='ok' &&
        JSON.stringify(ar.raw)==='[101.25,102.25]' && JSON.stringify(br.raw)==='[101.25]',
        'Restored data mismatch');
  check(JSON.stringify(ar.ids)==='["d1-i1-900001-1","d1-i1-900001-2"]' &&
        JSON.stringify(br.ids)==='["d1-i1-900002-1"]','UUID loss');
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-runtime-probe-v1',1);
    req.onsuccess=()=>resolve(req.result); req.onerror=()=>reject(req.error);
  });
  let records;
  try {
    records=await new Promise((resolve,reject)=>{
      const tx=db.transaction('checkpoints','readonly');
      const req=tx.objectStore('checkpoints').getAll();
      tx.oncomplete=()=>resolve(req.result); tx.onabort=()=>reject(tx.error);
    });
  }finally{db.close();}
  const marker=new TextEncoder().encode('D1_I1_SYNTHETIC_NOT_PATIENT');
  const header=new TextEncoder().encode('SQLite format 3');
  const contains=(haystack,needle)=>haystack.some((_,i)=>needle.every((v,j)=>haystack[i+j]===v));
  check(records.length===2 && records.every(r=>Object.keys(r).sort().join(',')==='archive,revision' &&
    r.archive instanceof Uint8Array && !contains(r.archive,marker) && !contains(r.archive,header)),
    'Unexpected durable plaintext or record');
  check(typeof indexedDB.databases==='function','Cannot enumerate durable browser databases');
  const databases=(await indexedDB.databases()).map(d=>d.name).sort();
  check(JSON.stringify(databases)==='["iamina-d1-runtime-probe-v1"]','Unexpected durable database');
  check(localStorage.length===0 && sessionStorage.length===0,'Unexpected browser storage');
  check((await caches.keys()).length===0,'Unexpected CacheStorage');
  if(navigator.storage && typeof navigator.storage.getDirectory==='function'){
    const root=await navigator.storage.getDirectory();
    for await(const entry of root.values()) throw new Error('Unexpected OPFS file '+entry.name);
  }
  return {a:ar,b:br,aba:true,encryptedRecords:records.length,
          durableDatabases:databases,opfsChecked:typeof navigator.storage?.getDirectory==='function'};
}"""


# I2 uses real separate documents sharing a persistent browser profile.
# All gates are deterministic: no timing race or automatic conflict retry.
I2_START = r"""async ({operation, gate, owner=900001}) => {
  const {SyntheticMutationSession}=await import('/d1_durable_mutation_candidate.mjs');
  const secret=owner===900001?'synthetic probe key A 2026':'synthetic probe key B 2026';
  const session=new SyntheticMutationSession(owner,secret);
  window.i2Session=session;
  const state=window.i2State={stage:'starting',outcome:null,release:null,staged:false};
  const hold=stage=>new Promise(resolve=>{state.stage=stage;state.release=resolve;});
  const hooks={
    afterPrepare:()=>gate==='prepare'?hold('prepared'):undefined,
    onStaged:()=>{state.staged=true;if(gate==='abort-staged')session.retire();},
    beforeAck:()=>gate==='ack'?hold('committed'):undefined,
  };
  // Return control to Playwright; the promise stays in this actual tab.
  session.mutate(operation,hooks).then(
    result=>{state.outcome={ok:true,...result};},
    error=>{state.outcome={ok:false,error:String(error)};}
  );
  return true;
}"""

I2_READ = r"""async () => {
  const {readCheckpoint}=await import('/d1_checkpoint_candidate.mjs');
  const a=await readCheckpoint('amina_vault_v1_native_900001','synthetic probe key A 2026');
  const b=await readCheckpoint('amina_vault_v1_native_900002','synthetic probe key B 2026');
  const ar=JSON.parse(await window.d1Inspect(a.bytes,900001));
  const br=JSON.parse(await window.d1Inspect(b.bytes,900002));
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-runtime-probe-v1',1);
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
  let records;
  try{
    records=await new Promise((resolve,reject)=>{
      const tx=db.transaction('checkpoints','readonly');
      const req=tx.objectStore('checkpoints').getAll();
      tx.oncomplete=()=>resolve(req.result);tx.onabort=()=>reject(tx.error);
    });
  }finally{db.close();}
  const marker=new TextEncoder().encode('D1_I1_SYNTHETIC_NOT_PATIENT');
  const header=new TextEncoder().encode('SQLite format 3');
  const contains=(haystack,needle)=>haystack.some((_,i)=>needle.every((v,j)=>haystack[i+j]===v));
  if(records.length!==2 || !records.every(r=>Object.keys(r).sort().join(',')==='archive,revision' &&
      r.archive instanceof Uint8Array && !contains(r.archive,marker) && !contains(r.archive,header)))
    throw new Error('Unexpected durable plaintext or record');
  if(JSON.stringify((await indexedDB.databases()).map(x=>x.name).sort())!=='["iamina-d1-runtime-probe-v1"]' ||
      localStorage.length || sessionStorage.length || (await caches.keys()).length)
    throw new Error('Unexpected durable storage');
  if(navigator.storage?.getDirectory){
    const root=await navigator.storage.getDirectory();
    for await(const entry of root.values())throw new Error('Unexpected OPFS file');
  }
  a.bytes.fill(0);b.bytes.fill(0);
  return {a:ar,b:br,revA:a.revision,revB:b.revision,encryptedRecords:records.length};
}"""


def new_ready_page(ctx, origin, errors):
    page = ctx.new_page()
    page.on("pageerror", lambda error: errors.append(str(error)[:300]))
    page.goto(origin, wait_until="domcontentloaded")
    page.wait_for_function("typeof window.d1Mutate === 'function' && typeof window.d1Inspect === 'function'", timeout=60000)
    return page


def start(page, operation, gate="none"):
    page.evaluate(I2_START, {"operation":operation,"gate":gate})


def stage(page, expected):
    page.wait_for_function("(s)=>window.i2State && window.i2State.stage===s", arg=expected, timeout=30000)


def outcome(page):
    page.wait_for_function("window.i2State && window.i2State.outcome!==null", timeout=30000)
    return page.evaluate("window.i2State.outcome")


def release(page):
    page.evaluate("window.i2State.release()")


def inspect_i2(page, revision, operations):
    observed = page.evaluate(I2_READ)
    expected = ["d1-i1-900001-1", "d1-i1-900001-2"] + ["d1-i1-900001-op-"+op for op in operations]
    assert observed["revA"] == revision and observed["revB"] == 1, observed
    assert observed["a"]["ids"] == sorted(expected), observed
    assert observed["a"]["rows"] == len(expected), observed
    assert observed["a"]["raw"] == [101.25+i for i in range(len(expected))], observed
    assert observed["b"]["ids"] == ["d1-i1-900002-1"] and observed["b"]["raw"] == [101.25], observed
    assert all(observed[owner]["schema"]==12 and observed[owner]["integrity"]=="ok" for owner in ("a","b")), observed
    return observed


def exercise_i2(ctx, page, origin, errors):
    # Two tabs both prepare revision 2, then race two different operations.
    second = new_ready_page(ctx, origin, errors)
    start(page, "tab-one-001", "prepare")
    start(second, "tab-two-001", "prepare")
    stage(page, "prepared")
    stage(second, "prepared")
    assert page.evaluate("""async()=>{try{await window.i2Session.mutate('busy-test-001');return false;}
        catch(e){return String(e).includes('Mutation already pending');}}""")
    release(page)
    release(second)
    a, b = outcome(page), outcome(second)
    assert sum(x["ok"] for x in (a,b))==1, (a,b)
    winner, loser = (a,b) if a["ok"] else (b,a)
    assert winner["revision"]==3 and not winner["replay"], winner
    assert "Checkpoint conflict" in loser["error"], loser
    winning_op = "tab-one-001" if a["ok"] else "tab-two-001"
    losing_op = "tab-two-001" if a["ok"] else "tab-one-001"
    inspect_i2(page,3,[winning_op])
    start(second,losing_op)
    assert outcome(second)=={"ok":True,"operation":losing_op,"revision":4,"replay":False}
    both = [winning_op,losing_op]
    inspect_i2(page,4,both)

    # Session retirement after the IDB put is staged must abort the transaction.
    start(second,"abort-staged-001","abort-staged")
    aborted = outcome(second)
    assert not aborted["ok"] and "Session retired" in aborted["error"], aborted
    assert second.evaluate("window.i2State.staged") is True
    assert second.evaluate("""async()=>{try{await window.i2Session.mutate('retired-001');return false;}
        catch(e){return String(e).includes('Session retired');}}""")
    inspect_i2(page,4,both)

    # Retire while mutation is prepared: late completion cannot persist or ACK.
    start(second,"retired-prepared-001","prepare")
    stage(second,"prepared")
    second.evaluate("window.i2Session.retire()")
    release(second)
    assert not outcome(second)["ok"]
    inspect_i2(page,4,both)

    # Close an actual document before dispatching its commit.
    start(second,"closed-before-001","prepare")
    stage(second,"prepared")
    second.close()
    inspect_i2(page,4,both)

    # Commit completed, but application ACK is intentionally held; close tab.
    second = new_ready_page(ctx,origin,errors)
    start(second,"lost-ack-001","ack")
    stage(second,"committed")
    assert second.evaluate("window.i2State.outcome===null")
    inspect_i2(page,5,both+["lost-ack-001"])
    second.close()
    second = new_ready_page(ctx,origin,errors)
    start(second,"lost-ack-001")
    assert outcome(second)=={"ok":True,"operation":"lost-ack-001","revision":5,"replay":True}
    inspect_i2(page,5,both+["lost-ack-001"])

    # A retired session cannot publish an already-durable late ACK.
    start(second,"retired-after-001","ack")
    stage(second,"committed")
    second.evaluate("window.i2Session.retire()")
    release(second)
    late = outcome(second)
    assert not late["ok"] and "Session retired" in late["error"], late
    final_ops = both+["lost-ack-001","retired-after-001"]
    final = inspect_i2(page,6,final_ops)
    start(page,"retired-after-001")
    assert outcome(page)=={"ok":True,"operation":"retired-after-001","revision":6,"replay":True}
    second.close()
    return {"raceWinner":winning_op,"raceLoser":losing_op,"casWinners":1,
            "stagedAbort":True,"closedBeforeCommit":True,"lostAckReplay":True,
            "retiredBeforeCommit":True,"retiredAfterCommitNoAck":True,
            "operations":final_ops,"final":final}



# I3 deliberately runs in a fresh profile, not on the I1/I2 storage.
# The test authority is synthetic, with no actual account or app-lock proof.
I3_INIT = r"""async () => {
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,pa='synthetic possession A 2026',pb='synthetic possession B 2026';
  const proof=(owner,epoch,options={})=>api.syntheticProof(owner,
    {identityVerified:true,unlocked:true,epoch,...options});
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,expected)=>{try{await fn();}catch(e){
    if(expected&&!String(e).includes(expected))throw e;return;
  }throw new Error('Expected rejection: '+expected);};
  window.i3={api,A,B,pa,pb,proof,check,reject};
  await reject(()=>api.admit(A,1,proof(A,1),pa),'Vault unavailable');
  await reject(()=>api.enroll(A,1,proof(A,1,{identityVerified:false}),pa),'Admission proof rejected');
  await reject(()=>api.enroll(A,1,proof(A,1,{unlocked:false}),pa),'Admission proof rejected');
  await reject(()=>api.enroll(A,1,proof(B,1),pa),'Admission proof rejected');
  await reject(()=>api.enroll(A,2,proof(A,1),pa),'Admission proof rejected');
  await reject(()=>api.enroll(A,1,proof(A,1),'short'),'Possession secret required');
  const once=proof(A,1);
  const a=await api.enroll(A,1,once,pa);
  check((await a.inspect()).revision===1,'First enrollment');
  await reject(()=>api.admit(A,1,once,pa),'Admission proof rejected');
  await reject(()=>api.enroll(A,1,proof(A,1),pa),'Existing vault cannot be overwritten');
  await reject(()=>api.admit(A,1,proof(A,1),pb),'Archive authentication failed');
  const b=await api.enroll(B,2,proof(B,2),pb);
  await reject(()=>a.inspect(),'Admission fence retired');
  check((await b.inspect()).owner===B,'B admission');
  check(await a.retire()===false,'Stale A retired newer B');
  check((await b.inspect()).revision===1,'B stale retire damage');
  check(await b.retire()===true,'B revoke');
  await reject(()=>b.inspect(),'Session retired');
  window.i3.session=await api.admit(A,3,proof(A,3),pa);
  check((await window.i3.session.inspect()).rows===1,'A re-admission');
  return {negativeCases:9,ownerSwitch:true,staleRetireRejected:true};
}"""

I3_SETUP = r"""async () => {
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,pa='synthetic possession A 2026',pb='synthetic possession B 2026';
  const proof=(owner,epoch)=>api.syntheticProof(owner,{identityVerified:true,unlocked:true,epoch});
  window.i3={api,A,B,pa,pb,proof};
}"""

I3_START = r"""({operation,gate,epoch})=>{
  const x=window.i3;
  const state=window.i3State={stage:'starting',outcome:null,release:null};
  const hold=stage=>new Promise(resolve=>{state.stage=stage;state.release=resolve;});
  const settle=p=>p.then(result=>{state.outcome={ok:true,result};},
    error=>{state.outcome={ok:false,error:String(error)};});
  if(gate==='admission'){
    settle(x.api.admit(x.A,epoch,x.proof(x.A,epoch),x.pa,
      {beforeActivate:()=>hold('verified')}));
  }else{
    settle(x.session.mutate(operation,{
      beforeCommit:()=>gate==='commit'?hold('prepared'):undefined,
      beforeAck:()=>gate==='ack'?hold('committed'):undefined,
    }));
  }
  return true;
}"""

I3_DISK = r"""async () => {
  const db=await new Promise((resolve,reject)=>{
    const r=indexedDB.open('iamina-d1-admission-probe-v1',1);
    r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
  });
  let records;
  try{
    records=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),store=tx.objectStore('state');
      const a=store.get('owner:900001'),b=store.get('owner:900002'),f=store.get('fence'),k=store.getAllKeys();
      tx.oncomplete=()=>resolve({a:a.result,b:b.result,f:f.result,keys:k.result});
      tx.onabort=()=>reject(tx.error);
    });
  }finally{db.close();}
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const needles=['SQLite format 3','D1_I1_SYNTHETIC_NOT_PATIENT',
    'synthetic possession A 2026','synthetic possession B 2026'].map(x=>new TextEncoder().encode(x));
  const contains=(h,n)=>h.some((_,i)=>n.every((v,j)=>h[i+j]===v));
  for(const r of [records.a,records.b]){
    check(Object.keys(r).sort().join(',')==='archive,envelope,revision','Unexpected owner record fields');
    for(const bytes of [r.archive,r.envelope]){
      check(bytes instanceof Uint8Array&&bytes.length>52&&!needles.some(n=>contains(bytes,n)),
        'Unexpected durable plaintext');
    }
  }
  check(!records.a.envelope.every((v,i)=>v===records.b.envelope[i]),'Owner envelope collision');
  check(JSON.stringify(records.keys.sort())==='["fence","owner:900001","owner:900002"]','Unexpected durable keys');
  check(JSON.stringify((await indexedDB.databases()).map(x=>x.name).sort())==='["iamina-d1-admission-probe-v1"]'&&
    !localStorage.length&&!sessionStorage.length&&!(await caches.keys()).length,'Unexpected durable storage');
  if(navigator.storage?.getDirectory){
    const root=await navigator.storage.getDirectory();
    for await(const _ of root.values())throw new Error('Unexpected OPFS file');
  }
  return {revisionA:records.a.revision,revisionB:records.b.revision,
    fenceOwner:records.f.owner,encryptedOwners:2};
}"""

I3_TAMPER = r"""async () => {
  const {api,A,B,pa,pb,proof}=window.i3;
  const db=await new Promise((resolve,reject)=>{
    const r=indexedDB.open('iamina-d1-admission-probe-v1',1);
    r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);
  });
  async function read(owner){
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),r=tx.objectStore('state').get('owner:'+owner);
      tx.oncomplete=()=>resolve(r.result);tx.onabort=()=>reject(tx.error);
    });
  }
  async function put(owner,value){
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readwrite',{durability:'strict'});
      tx.objectStore('state').put(value,'owner:'+owner);
      tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);
    });
  }
  const original=await read(A), other=await read(B);
  const rejected=async()=>{try{await api.admit(A,19,proof(A,19),pa);return false;}catch{return true;}};
  let count=0;
  try{
    const corrupt=original.envelope.slice();corrupt[corrupt.length-1]^=1;
    await put(A,{...original,envelope:corrupt});
    if(!await rejected())throw new Error('Tampered envelope admitted');count++;
    await put(A,{...original,envelope:other.envelope});
    if(!await rejected())throw new Error('Cross-owner envelope admitted');count++;
    await put(A,{revision:original.revision,archive:original.archive});
    if(!await rejected())throw new Error('Missing envelope admitted');count++;
    try{await api.enroll(A,19,proof(A,19),pa);throw new Error('Unexpected reset');}
    catch(e){if(!String(e).includes('Existing vault cannot be overwritten'))throw e;}count++;
    await put(A,{...original,revision:original.revision+1});
    if(!await rejected())throw new Error('Revision tamper admitted');count++;
  }finally{await put(A,original);db.close();}
  return count;
}"""


def i3_start(page,operation,gate,epoch=0):
    page.evaluate(I3_START,{"operation":operation,"gate":gate,"epoch":epoch})


def i3_stage(page,expected):
    page.wait_for_function("(s)=>window.i3State?.stage===s",arg=expected,timeout=30000)


def i3_outcome(page):
    page.wait_for_function("window.i3State?.outcome!=null",timeout=30000)
    return page.evaluate("window.i3State.outcome")


def i3_release(page):
    page.evaluate("window.i3State.release()")


def i3_admit(page,owner,epoch):
    return page.evaluate("""async ({owner,epoch})=>{
        const x=window.i3;
        x.session=await x.api.admit(owner,epoch,x.proof(owner,epoch),owner===x.A?x.pa:x.pb);
        return await x.session.inspect();
    }""",{"owner":owner,"epoch":epoch})


def exercise_i3(ctx,page,origin,errors):
    record=page.evaluate(I3_INIT)
    second=new_ready_page(ctx,origin,errors)
    second.evaluate(I3_SETUP)
    # An independently verified but delayed admission cannot outlive revocation.
    i3_start(second,"unused","admission",4)
    i3_stage(second,"verified")
    assert page.evaluate("window.i3.session.retire()") is True
    i3_release(second)
    late=i3_outcome(second)
    assert not late["ok"] and "Admission fence changed" in late["error"],late
    assert i3_admit(page,900001,5)["revision"]==1

    # Old tab already holds plaintext in memory and has sealed a next snapshot.
    # B admission changes the durable fence, with no notification dependency.
    i3_start(page,"stale-cross-owner-001","commit")
    i3_stage(page,"prepared")
    assert i3_admit(second,900002,6)["owner"]==900002
    i3_release(page)
    stale=i3_outcome(page)
    assert not stale["ok"] and "Admission fence retired" in stale["error"],stale
    assert page.evaluate("window.i3.session.retire()") is False
    assert second.evaluate("window.i3.session.inspect()")["revision"]==1
    a=i3_admit(page,900001,7)
    assert a["revision"]==1 and a["rows"]==1,a

    # Durable commit, then another tab admits the SAME owner before ACK.
    i3_start(page,"fenced-ack-001","ack")
    i3_stage(page,"committed")
    a=i3_admit(second,900001,8)
    assert a["revision"]==2 and a["rows"]==2,a
    i3_release(page)
    stale_ack=i3_outcome(page)
    assert not stale_ack["ok"] and "Admission fence retired" in stale_ack["error"],stale_ack
    i3_start(second,"fenced-ack-001","none")
    replay=i3_outcome(second)
    assert replay=={"ok":True,"result":{"revision":2,"replay":True,"operation":"fenced-ack-001"}},replay

    # Lock from the current tab invalidates all old leases; explicit re-admission.
    assert second.evaluate("window.i3.session.retire()") is True
    assert page.evaluate(I3_DISK)=={"revisionA":2,"revisionB":1,"fenceOwner":None,"encryptedOwners":2}
    assert page.evaluate(I3_TAMPER)==5
    assert i3_admit(page,900001,20)["ids"]==["d1-i1-900001-1","d1-i1-900001-op-fenced-ack-001"]
    assert page.evaluate("window.i3.session.retire()") is True
    second.close()
    record.update(delayedAdmissionRejected=True,crossOwnerStaleCommitRejected=True,
                  sameOwnerLateAckRejected=True,replay=True,tamperCases=5,
                  durable=page.evaluate(I3_DISK))
    return record


def restore_i3(page):
    page.evaluate(I3_SETUP)
    a=i3_admit(page,900001,21)
    assert a["revision"]==2 and a["raw"]==[101.25,102.25] and a["schema"]==12 and a["integrity"]=="ok",a
    b=i3_admit(page,900002,22)
    assert b["revision"]==1 and b["raw"]==[101.25] and b["schema"]==12 and b["integrity"]=="ok",b
    assert page.evaluate("window.i3.session.retire()") is True
    return {"a":a,"b":b,"durable":page.evaluate(I3_DISK)}



# I4: independent browser origins in one profile, explicit encrypted transfer.
# The legacy fixture is a synthetic raw snapshot, not a real Drift worker store.
I4_LEGACY = r"""async (action)=>{
  const {sealArchive}=await import('/d1_archive_candidate.mjs');
  const owner=900001,scope='amina_vault_v1_native_900001',secret='synthetic transfer secret 2026';
  const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
  const digest=async bytes=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
  // Same DB name and key as the new origin, intentionally different record.
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-admission-probe-v1',1);
    req.onupgradeneeded=()=>req.result.createObjectStore('state');
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
  async function read(){
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),store=tx.objectStore('state');
      const r=store.get('owner:900001'),f=store.get('fence');
      tx.oncomplete=()=>resolve({record:r.result??null,fence:f.result??null});
      tx.onabort=()=>reject(tx.error);
    });
  }
  async function put(bytes){
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readwrite',{durability:'strict'});
      tx.objectStore('state').put({legacyBytes:bytes},'owner:900001');
      tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error);
    });
  }
  try{
    let state=await read();
    if(action==='create'){
      if(state.record!==null)throw new Error('Unexpected existing source');
      await put(await window.d1LegacySnapshot(owner));
      state=await read();
    }
    if(state.fence!==null || !(state.record?.legacyBytes instanceof Uint8Array) ||
        Object.keys(state.record).join(',')!=='legacyBytes')
      throw new Error('Unexpected source state or crossed origin');
    if(action==='mutate'){
      await put(await window.d1Mutate(state.record.legacyBytes,owner,'old-client-001'));
      state=await read();
    }
    const bytes=state.record.legacyBytes;
    const sha256=await digest(bytes);
    const tables=JSON.parse(await window.d1FullInspect(bytes,owner));
    if(action==='create'){
      const archive=await sealArchive(bytes,secret,scope);
      const invalid=new Uint8Array(128);
      const invalidArchive=await sealArchive(invalid,secret,scope);
      return {manifest:{kind:'scoped-v12',owner,sha256},transfer:Array.from(archive),
        invalid:{sha256:await digest(invalid),transfer:Array.from(invalidArchive)},tables};
    }
    return {sha256,tables};
  }finally{db.close();}
}"""

I4_IMPORT = r"""async ({manifest,transfer,invalid,tables})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const owner=900001,phrase='synthetic migrated possession 2026',secret='synthetic transfer secret 2026';
  const proof=()=>api.syntheticProof(owner,{identityVerified:true,unlocked:true,epoch:1});
  const archive=new Uint8Array(transfer);
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,expected)=>{try{await fn();}catch(e){
    if(expected&&!String(e).includes(expected))throw e;return;
  }throw new Error('Expected rejection: '+expected);};
  const load=(m=manifest,a=archive,s=secret,hooks={})=>
    api.importScopedArchive(owner,1,proof(),phrase,m,a,s,hooks);
  await reject(()=>load({...manifest,kind:'unscoped-mixed'}),'Explicit scoped source provenance required');
  await reject(()=>load({...manifest,owner:900002}),'Explicit scoped source provenance required');
  await reject(()=>load({...manifest,sha256:'0'.repeat(64)}),'Source digest mismatch');
  await reject(()=>load(manifest,archive,'synthetic wrong transfer secret'),'Archive authentication failed');
  const tampered=archive.slice();tampered[tampered.length-1]^=1;
  await reject(()=>load(manifest,tampered),'Archive authentication failed');
  await reject(()=>load({...manifest,sha256:invalid.sha256},new Uint8Array(invalid.transfer)),null);
  await reject(()=>load(manifest,archive,secret,{beforeActivate:()=>{throw new Error('Interrupted import');}}),'Interrupted import');
  await reject(()=>api.admit(owner,1,proof(),phrase),'Vault unavailable');
  const session=await load();
  window.i4Session=session;
  const observed=await session.auditSnapshot();
  check(observed.revision===1&&observed.sha256===manifest.sha256&&
    JSON.stringify(observed.tables)===JSON.stringify(tables),'Imported bytes/tables differ');
  await reject(()=>load(),'Existing vault cannot be overwritten');
  check((await session.auditSnapshot()).sha256===manifest.sha256,'Overwrite changed imported vault');
  return {observed,negativeCases:9};
}"""

I4_DEST = r"""async ({expected,restore})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const owner=900001,phrase='synthetic migrated possession 2026';
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  if(restore){
    const proof=api.syntheticProof(owner,{identityVerified:true,unlocked:true,epoch:2});
    window.i4Session=await api.admit(owner,2,proof,phrase);
  }
  const observed=await window.i4Session.auditSnapshot();
  check(observed.revision===1&&observed.sha256===expected,'Imported bytes changed');
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-admission-probe-v1',1);
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
  let stored;
  try{
    stored=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),store=tx.objectStore('state');
      const r=store.get('owner:900001'),keys=store.getAllKeys();
      tx.oncomplete=()=>resolve({record:r.result,keys:keys.result});tx.onabort=()=>reject(tx.error);
    });
  }finally{db.close();}
  check(Object.keys(stored.record).sort().join(',')==='archive,envelope,revision' &&
        JSON.stringify(stored.keys.sort())==='["fence","owner:900001"]','Unexpected destination state');
  const needles=['SQLite format 3','D1_I1_SYNTHETIC_NOT_PATIENT','synthetic migrated possession 2026',
    'synthetic transfer secret 2026'].map(x=>new TextEncoder().encode(x));
  const contains=(h,n)=>h.some((_,i)=>n.every((v,j)=>h[i+j]===v));
  for(const bytes of [stored.record.archive,stored.record.envelope])
    check(bytes instanceof Uint8Array&&!needles.some(n=>contains(bytes,n)),'Destination plaintext');
  check(JSON.stringify((await indexedDB.databases()).map(x=>x.name).sort())==='["iamina-d1-admission-probe-v1"]' &&
        !localStorage.length&&!sessionStorage.length&&!(await caches.keys()).length,'Unexpected destination storage');
  if(navigator.storage?.getDirectory){
    const root=await navigator.storage.getDirectory();
    for await(const _ of root.values())throw new Error('Unexpected destination OPFS file');
  }
  return observed;
}"""


def exercise_i4(ctx,page,legacy_origin,errors):
    source=new_ready_page(ctx,legacy_origin,errors)
    assert source.evaluate("location.origin") != page.evaluate("location.origin")
    exported=source.evaluate(I4_LEGACY,"create")
    tables=exported["tables"]
    assert len(tables)==6 and all(len(rows)==1 for rows in tables.values()),tables
    assert tables["log_entries"][0]["sync_status"]=="pending" and tables["log_entries"][0]["sync_attempts"]==2
    assert tables["patient_treatment_declarations_v1"][0]["sync_status"]=="pending"
    assert tables["patient_treatment_declarations_v1"][0]["local_generation"]==3
    assert tables["reminders"][0]["enabled"] in (0,False)
    imported=page.evaluate(I4_IMPORT,exported)
    assert imported["observed"]["tables"]==tables
    expected=exported["manifest"]["sha256"]
    unchanged=source.evaluate(I4_LEGACY,"read")
    assert unchanged=={"sha256":expected,"tables":tables},unchanged
    # An old document writes its own origin after cutover. It cannot update
    # the new origin's IDB even though both use the identical store and key.
    changed=source.evaluate(I4_LEGACY,"mutate")
    assert changed["sha256"]!=expected and len(changed["tables"]["log_entries"])==2,changed
    final=page.evaluate(I4_DEST,{"expected":expected,"restore":False})
    assert final==imported["observed"],final
    assert page.evaluate("window.i4Session.retire()") is True
    source.close()
    return {"sourceSha":expected,"oldClientChangedSha":changed["sha256"],
            "sourcePreservedBeforeOldWrite":True,"oldOriginWriteIsolated":True,
            "negativeCases":imported["negativeCases"],"imported":final}


def restore_i4(ctx,page,legacy_origin,errors,record):
    source=new_ready_page(ctx,legacy_origin,errors)
    old=source.evaluate(I4_LEGACY,"read")
    assert old["sha256"]==record["oldClientChangedSha"] and len(old["tables"]["log_entries"])==2,old
    source.close()
    new=page.evaluate(I4_DEST,{"expected":record["sourceSha"],"restore":True})
    assert new==record["imported"],new
    assert page.evaluate("window.i4Session.retire()") is True
    return {"sourceSha":old["sha256"],"destinationSha":new["sha256"],
            "sourceRows":len(old["tables"]["log_entries"]),"destinationRows":len(new["tables"]["log_entries"]),
            "exactTablesPreserved":True}




# I5B: random portable possession, independent of simulated identity proof.
# Only the Python harness retains the generated secrets between browser restarts.
# Never include secrets in JSON evidence, exception messages or screenshots.
I5_POSSESSION = r"""async ({secrets,restore})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const key=await import('/d1_possession_candidate.mjs');
  const A=900001,B=900002;
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,expected)=>{try{await fn();}catch(e){
    check(String(e).includes(expected),'Unexpected rejection reason');return;
  }throw new Error('Expected refusal');};
  const proof=(owner,epoch)=>api.syntheticProof(owner,{identityVerified:true,unlocked:true,epoch});
  const a=key.requirePossessionSecret(secrets[0]),b=key.requirePossessionSecret(secrets[1]);
  check(a!==b,'Random secret collision');
  let negatives=0;
  for(const invalid of ['',a.slice(1),a+'0',a.toUpperCase().replace(/^./,'G'),a+'\n',null]){
    await reject(()=>key.requirePossessionSecret(invalid),'Invalid possession secret');negatives++;
  }
  const epoch=restore?32:31;
  if(!restore){
    const sa=await api.enroll(A,epoch,proof(A,epoch),a);
    await sa.mutate('possession-001');
    await sa.retire();
    const sb=await api.enroll(B,epoch,proof(B,epoch),b);
    await sb.retire();
  }
  await reject(()=>api.admit(A,epoch,proof(A,epoch),b),'Archive authentication failed');negatives++;
  await reject(()=>api.admit(B,epoch,proof(B,epoch),a),'Archive authentication failed');negatives++;
  const bad=a.slice(0,63)+(a.endsWith('0')?'1':'0');
  await reject(()=>api.admit(A,epoch,proof(A,epoch),bad),'Archive authentication failed');negatives++;
  const ticket=proof(A,epoch);
  const sa=await api.admit(A,epoch,ticket,a);
  const ra=await sa.auditSnapshot();
  await reject(()=>api.admit(A,epoch,ticket,a),'Admission proof rejected');negatives++;
  check(await sa.retire(),'A retire failed');
  const sb=await api.admit(B,epoch,proof(B,epoch),b);
  const rb=await sb.auditSnapshot();
  check(await sb.retire(),'B retire failed');
  check(ra.revision===2&&rb.revision===1&&ra.sha256!==rb.sha256,'Owner/revision mismatch');
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-admission-probe-v1',1);
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(new Error('Store unavailable'));
  });
  try{
    const state=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),store=tx.objectStore('state');
      const a=store.get('owner:900001'),b=store.get('owner:900002'),keys=store.getAllKeys();
      tx.oncomplete=()=>resolve({a:a.result,b:b.result,keys:keys.result});
      tx.onabort=()=>reject(new Error('Store read failed'));
    });
    const encode=x=>new TextEncoder().encode(x);
    const raw=x=>Uint8Array.from(x.match(/../g),y=>parseInt(y,16));
    const needles=[encode(a),encode(b),raw(a),raw(b),encode('SQLite format 3'),
      encode('D1_I1_SYNTHETIC_NOT_PATIENT')];
    const contains=(h,n)=>h.some((_,i)=>n.every((v,j)=>h[i+j]===v));
    check(JSON.stringify(state.keys.sort())==='["fence","owner:900001","owner:900002"]','Unexpected durable keys');
    for(const rec of [state.a,state.b]){
      check(Object.keys(rec).sort().join(',')==='archive,envelope,revision','Unexpected record');
      for(const bytes of [rec.archive,rec.envelope])
        check(bytes instanceof Uint8Array&&!needles.some(n=>contains(bytes,n)),'Unexpected durable secret/plaintext');
    }
    check(!localStorage.length&&!sessionStorage.length&&!(await caches.keys()).length,'Unexpected storage');
    check(JSON.stringify((await indexedDB.databases()).map(x=>x.name).sort())==='["iamina-d1-admission-probe-v1"]','Unexpected database');
    if(navigator.storage?.getDirectory){
      const root=await navigator.storage.getDirectory();
      for await(const _ of root.values())throw new Error('Unexpected OPFS file');
    }
  }finally{db.close();}
  return {a:ra,b:rb,negativeCases:negatives,plaintextCheck:true};
}"""


def exercise_possession(browser_type,profile,locale,origin):
    secrets=None
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            secrets=page.evaluate("""async ()=>{
              const k=await import('/d1_possession_candidate.mjs');
              return [k.generatePossessionSecret(),k.generatePossessionSecret()];
            }""")
            assert len(secrets)==2 and all(len(s)==64 for s in secrets)
            first=page.evaluate(I5_POSSESSION,{"secrets":secrets,"restore":False})
            assert not blocked and not errors
        finally:
            ctx.close()
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            restored=page.evaluate(I5_POSSESSION,{"secrets":secrets,"restore":True})
            assert restored==first and first["negativeCases"]==10
            assert not blocked and not errors
        finally:
            ctx.close()
        return {"first":first,"restart":True}
    except Exception:
        # Never propagate Playwright arguments or arbitrary error strings.
        raise RuntimeError("D1 possession qualification failed") from None
    finally:
        secrets=None



# Actual Dart auth/app-lock services, simulated HTTP/authenticator/storage,
# connected to the real synthetic encrypted Drift/IndexedDB runtime.
I5_BOUND = r"""async ({a,b})=>{
  const stage=x=>{window.__d1BoundStage=x;};
  stage("bootstrap");
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002;
  const check=(v,m)=>{if(!v)throw new Error(m);};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason),'Unexpected bound refusal');return;
  }throw new Error('Expected bound refusal');};
  const proof=(o,e)=>api.syntheticProof(o,{identityVerified:true,unlocked:true,epoch:e});
  // Bootstrap only the isolated fixtures using the previously qualified path.
  const sa=await api.enroll(A,1,proof(A,1),a);
  await sa.retire();
  const sb=await api.enroll(B,1,proof(B,1),b);
  await sb.retire();
  const fence=async()=>{
    const db=await new Promise((resolve,reject)=>{
      const r=indexedDB.open('iamina-d1-admission-probe-v1',1);
      r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Store unavailable'));
    });
    try{return await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),r=tx.objectStore('state').get('fence');
      tx.oncomplete=()=>resolve(r.result.owner);tx.onabort=()=>reject(new Error('Store failed'));
    });}finally{db.close();}
  };
  stage("bound-admission");
  await window.d1BoundLogin(A);
  const epoch=()=>window.d1BoundEpoch();
  const ticket=()=>window.d1BoundProof(A);
  let negatives=0;
  let p=await ticket();
  await reject(()=>api.admitBound(A,epoch(),p,b),'Archive authentication failed');negatives++;
  await reject(()=>api.admitBound(A,epoch(),p,a),'Bound authority retired');negatives++;
  p=await ticket();
  await reject(()=>api.admitBound(B,epoch(),p,b),'Bound authority retired');negatives++;
  check(await fence()===null,'Invalid proof changed fence');
  p=await ticket();
  await reject(()=>api.admitBound(A,epoch(),p,a,{beforeLease:()=>window.d1BoundLock()}),
    'Bound authority retired');negatives++;
  check(await fence()===null,'Retired pending ticket changed fence');
  p=await ticket();
  await reject(()=>api.admitBound(A,epoch(),p,a,{afterLease:async()=>{
    check(await fence()===A,'Lease missing before SQLite open');
    window.d1BoundLock();
  }}),'Bound authority retired');negatives++;
  check(await fence()===null,'Retired activation left fence');
  p=await ticket();
  const s=await api.admitBound(A,epoch(),p,a,{afterLease:async()=>{
    check(await fence()===A,'Missing durable activation');
  }});
  check((await s.inspect()).revision===1,'Unexpected A revision');
  await reject(()=>api.admitBound(A,epoch(),p,a),'Bound authority retired');negatives++;
  await reject(()=>s.mutate('bound-before-001',{beforeCommit:()=>window.d1BoundLock()}),
    'Bound authority retired');negatives++;
  check(await fence()===null,'Retired mutation left lease');
  p=await ticket();
  const reopened=await api.admitBound(A,epoch(),p,a);
  check((await reopened.inspect()).revision===1,'Retired mutation committed');
  check((await reopened.mutate('bound-success-001')).revision===2,'Mutation missing');
  await window.d1BoundLogin(B);
  // Observe durable retirement before attempting any operation on the old session.
  for(let i=0;i<100&&await fence()!==null;i++)await new Promise(r=>setTimeout(r,20));
  check(await fence()===null,'Idle identity retirement did not clear fence');
  await reject(()=>reopened.inspect(),'Bound authority retired');negatives++;
  check(await fence()===null,'Retired identity left fence');
  const bp=await window.d1BoundProof(B);
  const bs=await api.admitBound(B,epoch(),bp,b);
  check((await bs.inspect()).revision===1,'B contaminated');
  await bs.retire();
  await window.d1BoundLogin(A);
  const ap=await ticket();
  const as=await api.admitBound(A,epoch(),ap,a);
  const report=await as.auditSnapshot();
  check(report.revision===2&&report.tables.log_entries.length===2,'A checkpoint mismatch');
  check(report.tables.log_entries.some(x=>x.client_uuid==='d1-i1-900001-op-bound-success-001'),'A row absent');
  window.d1BoundLock();
  for(let i=0;i<100&&await fence()!==null;i++)await new Promise(r=>setTimeout(r,20));
  check(await fence()===null,'Idle lock retirement did not clear fence');
  await reject(()=>as.inspect(),'Bound authority retired');
  check(await as.retire()===true,'Retirement acknowledgement missing');
  stage("legacy-clinical");
  const clinicalTicket=await ticket();
  const clinical=await api.admitBoundClinical(A,epoch(),clinicalTicket,a);
  const allowed=['readJournal','readGlucose','insertGlucose','editGlucose','deleteGlucose','readEvidence','readEvidenceJournal','insertEvidence','editEvidence','deleteEvidence','readTreatment','writeTreatment','retire'];
  check(Object.isFrozen(clinical)&&Object.getPrototypeOf(clinical)===null&&
    JSON.stringify(Object.keys(clinical))===JSON.stringify(allowed),'Unexpected clinical surface');
  const u='ac123456-1234-4abc-8def-000000000010',t=1795564800;
  const inserted=await clinical.insertGlucose(2,u,131.25,'mg/dL',t);
  check(inserted.revision===3&&inserted.measurement.uuid===u,'Clinical insert failed');
  const observed=await clinical.readGlucose(u);
  check(observed.revision===3&&observed.measurement.mgDl===131.25,'Clinical read failed');
  const late=clinical.readJournal(3,t-1,t+1,50,0);
  window.d1BoundLock();
  await reject(()=>late,'Bound authority retired');
  await window.d1BoundLogin(B);
  const clinicalB=await api.admitBoundClinical(B,epoch(),await window.d1BoundProof(B),b);
  const bReading=await clinicalB.readGlucose(u);
  check(bReading.revision===1&&bReading.measurement===null,'Clinical owner isolation failed');
  await reject(()=>clinical.readGlucose(u),'Bound authority retired');
  await clinicalB.retire();
  stage("evidence-admission");
  await window.d1BoundLogin(A);
  let e=await api.admitBoundClinical(A,epoch(),await ticket(),a);
  const v='ac123456-1234-4abc-8def-000000000011';
  stage("evidence-legacy");
  check((await e.readEvidence(u)).evidence===null,'Legacy unit inferred');
  stage("evidence-insert");
  const added=await e.insertEvidence(3,v,7.83,'mmol/L',t+1);
  stage("evidence-projection");
  const ev=added.evidence;
  check(added.revision===4&&ev.originalValue===7.83&&ev.originalUnit==='mmol/L'&&
    Math.abs(ev.mgDl-141.0620697)<1e-9&&ev.displayMgDl==='141'&&ev.displayMmolL==='7.8','D5 conversion mismatch');
  stage("evidence-reopen");
  await e.retire();
  e=await api.admitBoundClinical(A,epoch(),await ticket(),a);
  check(JSON.stringify((await e.readEvidence(v)).evidence)===JSON.stringify(ev),'Evidence reopen mismatch');
  stage("evidence-duplicate");
  await reject(()=>e.insertEvidence(4,v,8,'mmol/L',t+1),'Existing or deleted measurement identity');
  e=await api.admitBoundClinical(A,epoch(),await ticket(),a);
  check((await e.readEvidence(v)).revision===4,'Duplicate changed revision');
  stage("evidence-old-port");
  await reject(()=>e.deleteGlucose(4,v),'Explicit evidence requires dedicated port');
  e=await api.admitBoundClinical(A,epoch(),await ticket(),a);
  check((await e.readEvidence(v)).evidence.originalValue===7.83,'Old port changed evidence');
  stage("evidence-lock");
  const pending=e.readEvidence(v);
  const denied=reject(()=>pending,'Bound authority retired');
  window.d1BoundLock();
  await denied;
  await window.d1BoundLogin(B);
  stage("evidence-owner-isolation");
  const other=await api.admitBoundClinical(B,epoch(),await window.d1BoundProof(B),b);
  check((await other.readEvidence(v)).evidence===null,'Evidence owner leak');
  await other.retire();
  stage("evidence-mutations");
  await window.d1BoundLogin(A);
  const open=async()=>{const proof=await ticket();return api.admitBoundClinical(A,epoch(),proof,a);};
  e=await open();
  const replay=await e.insertEvidence(3,v,7.83,'mmol/L',t+1);
  check(replay.replay===true&&replay.revision===4,'Insert replay failed');
  const edit=await e.editEvidence(4,v,145,'mg/dL',t+2);
  check(edit.revision===5&&edit.replay===false&&edit.evidence.originalUnit==='mg/dL'&&
    edit.evidence.originalValue===145&&edit.evidence.displayMgDl==='145','Evidence edit failed');
  await e.retire();
  e=await open();
  check((await e.editEvidence(4,v,145,'mg/dL',t+2)).replay===true,'Edit replay failed');
  await reject(()=>e.editEvidence(4,v,146,'mg/dL',t+2),'Checkpoint conflict');
  e=await open();
  check((await e.readEvidence(v)).evidence.originalValue===145,'Stale edit changed row');
  const lostProof=await ticket();
  const raw=await api.admitBound(A,epoch(),lostProof,a);
  await reject(()=>raw.deleteEvidence(5,v,{beforeCommit:()=>window.d1BoundLock()}),'Bound authority retired');
  e=await open();
  check((await e.readEvidence(v)).revision===5,'Retired delete committed');
  const ackProof=await ticket();
  const ack=await api.admitBound(A,epoch(),ackProof,a);
  await reject(()=>ack.deleteEvidence(5,v,{beforeAck:()=>window.d1BoundLock()}),'Bound authority retired');
  e=await open();
  const gone=await e.readEvidence(v);
  check(gone.revision===6&&gone.evidence===null,'Lost acknowledgement deletion missing');
  check((await e.deleteEvidence(5,v)).replay===true,'Delete replay failed');
  await reject(()=>e.insertEvidence(6,v,145,'mg/dL',t+2),'Existing or deleted measurement identity');
  e=await open();
  await reject(()=>e.deleteGlucose(6,v),'Explicit evidence requires dedicated port');
  e=await open();
  check((await e.readEvidence(v)).revision===6,'Rejected mutation changed revision');
  await e.retire();
  await window.d1BoundLogin(B);
  const proofB=await window.d1BoundProof(B);
  const b2=await api.admitBoundClinical(B,epoch(),proofB,b);
  check((await b2.readEvidence(v)).revision===1,'B revision changed');
  await b2.retire();
  stage("complete");
  return {negativeCases:negatives+1,revisionA:2,revisionB:1,leaseBeforeOpen:true,retiredFenceCleared:true,idleRevocation:true,clinicalPort:true,clinicalRevisionA:3,explicitEvidence:true,evidenceRevision:4,evidenceMutationRevision:6};
}"""


I5_BOUND_RESTART = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,u='ac123456-1234-4abc-8def-000000000010',v='ac123456-1234-4abc-8def-000000000011';
  const check=(ok)=>{if(!ok)throw Error('Restart invariant failed');};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason));return;
  }throw Error('Expected restart refusal');};
  const open=async(owner,secret,raw=false)=>{
    const proof=await window.d1BoundProof(owner);
    return raw?api.admitBound(owner,window.d1BoundEpoch(),proof,secret):
      api.admitBoundClinical(owner,window.d1BoundEpoch(),proof,secret);
  };
  await window.d1BoundLogin(A);
  let s=await open(A,a,true);
  const audit=await s.auditSnapshot();
  const tables=audit.tables;
  check(audit.revision===6&&tables.log_entries.length===3&&
    !tables.log_entries.some(row=>row.client_uuid===v)&&
    tables.log_entries.some(row=>row.client_uuid===u&&row.blood_sugar===131.25)&&
    tables.d1_d5_fixture_evidence_v1.length===0);
  const tomb=tables.d1_d5_fixture_deleted_v1;
  const receipt=tables.d1_d5_fixture_receipt_v1;
  check(tomb.length===1&&Object.keys(tomb[0]).length===2&&tomb[0].client_uuid===v&&tomb[0].owner_id===A);
  check(receipt.length===1&&Object.keys(receipt[0]).length===5&&receipt[0].singleton===1&&
    receipt[0].owner_id===A&&receipt[0].client_uuid===v&&receipt[0].action==='delete'&&receipt[0].base_revision===5);
  await s.retire();
  s=await open(A,a);
  const gone=await s.readEvidence(v);
  check(gone.revision===6&&gone.evidence===null);
  const replay=await s.deleteEvidence(5,v);
  check(replay.revision===6&&replay.replay===true&&replay.evidence===null);
  await reject(()=>s.insertEvidence(6,v,145,'mg/dL',1795564802),'Existing or deleted measurement identity');
  s=await open(A,a);
  check((await s.readEvidence(v)).revision===6);
  await s.retire();
  await window.d1BoundLogin(B);
  s=await open(B,b,true);
  const other=await s.auditSnapshot();
  check(other.revision===1&&other.tables.log_entries.length===1&&
    !('d1_d5_fixture_deleted_v1' in other.tables)&&!('d1_d5_fixture_receipt_v1' in other.tables));
  await s.retire();
  return {revisionA:6,revisionB:1,tombstone:true,receipt:true,noResurrection:true,replay:true,legacyPreserved:true};
}"""


I5_EVIDENCE_JOURNAL = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,t=1795564800;
  const ids=[21,22,23,24].map(n=>'ac123456-1234-4abc-8def-'+String(n).padStart(12,'0'));
  const check=ok=>{if(!ok)throw Error('Evidence journal invariant failed');};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason));return;
  }throw Error('Expected journal refusal');};
  const open=async(owner,secret,raw=false)=>{
    const proof=await window.d1BoundProof(owner);
    return raw?api.admitBound(owner,window.d1BoundEpoch(),proof,secret):
      api.admitBoundClinical(owner,window.d1BoundEpoch(),proof,secret);
  };
  window.__d1EvidenceJournalStage='insert';
  await window.d1BoundLogin(A);
  let s=await open(A,a);
  for(let i=0;i<ids.length;i++){
    const result=await s.insertEvidence(6+i,ids[i],i===0?7.83:140+i,
      i===0?'mmol/L':'mg/dL',t+[0,1,1,2][i]);
    check(result.revision===7+i);
  }
  window.__d1EvidenceJournalStage='pagination';
  const first=await s.readEvidenceJournal(10,t,t+2,2,0);
  const second=await s.readEvidenceJournal(10,t,t+2,2,2);
  check(first.revision===10&&first.nextOffset===2&&first.rows.map(x=>x.uuid).join(',')===ids.slice(1,3).join(','));
  check(second.revision===10&&second.nextOffset===null&&second.rows.length===1&&
    second.rows[0].uuid===ids[0]&&second.rows[0].originalUnit==='mmol/L'&&
    second.rows[0].originalValue===7.83&&second.rows[0].displayMgDl==='141'&&second.rows[0].displayMmolL==='7.8');
  check((await s.readEvidenceJournal(10,t+2,t+3,50,0)).rows[0].uuid===ids[3]);
  check((await s.readEvidenceJournal(10,t+3,t+4,50,0)).rows.length===0);
  check((await s.readEvidenceJournal(10,t,t+2,50,0)).rows.length===3);
  check((await s.readEvidenceJournal(10,t,t+2,2,4)).rows.length===0);
  window.__d1EvidenceJournalStage='conflict';
  check((await s.editEvidence(10,ids[0],150,'mg/dL',t+3)).revision===11);
  await reject(()=>s.readEvidenceJournal(10,t,t+2,2,2),'Checkpoint conflict');
  s=await open(A,a);
  check((await s.readEvidenceJournal(11,t,t+2,50,0)).rows.length===2);
  await reject(()=>s.readEvidenceJournal(11,t,t+2,51,0),'Invalid evidence journal range');
  s=await open(A,a);
  await s.retire();
  window.__d1EvidenceJournalStage='revocation';
  s=await open(A,a,true);
  await reject(()=>s.readEvidenceJournal(11,t,t+4,50,0,{beforeReturn:()=>window.d1BoundLock()}),'Bound authority retired');
  await window.d1BoundLogin(B);
  s=await open(B,b);
  const empty=await s.readEvidenceJournal(1,t,t+4,50,0);
  check(empty.rows.length===0&&empty.nextOffset===null&&empty.revision===1);
  await s.retire();
  window.__d1EvidenceJournalStage='complete';
  return {halfOpen:true,pagination:true,tieOrder:true,legacyExcluded:true,sourceProjection:true,staleRejected:true,revoked:true,ownerIsolation:true,revisionA:11};
}"""


def exercise_bound(browser_type,profile,locale,origin):
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
    try:
        # Fresh random fixture secrets held only in this harness invocation.
        # Do not include them in result records or exception diagnostics.
        secrets=page.evaluate("""async ()=>{
          const k=await import('/d1_possession_candidate.mjs');
          return {a:k.generatePossessionSecret(),b:k.generatePossessionSecret()};
        }""")
        result=page.evaluate(I5_BOUND,secrets)
        assert result=={"negativeCases":9,"revisionA":2,"revisionB":1,
                       "leaseBeforeOpen":True,"retiredFenceCleared":True,"idleRevocation":True,
                       "clinicalPort":True,"clinicalRevisionA":3,"explicitEvidence":True,"evidenceRevision":4,"evidenceMutationRevision":6}
        assert not blocked and not errors
    except Exception:
        # Only fixed synthetic stage codes; never print exception contents,
        # evidence, credentials, keys or raw browser messages.
        stage = "unknown"
        try:
            candidate = page.evaluate("window.__d1BoundStage || 'unknown'")
            if candidate in {"bootstrap", "bound-admission", "legacy-clinical",
                             "evidence-admission", "evidence-legacy", "evidence-insert",
                             "evidence-projection", "evidence-reopen", "evidence-duplicate",
                             "evidence-old-port", "evidence-lock", "evidence-owner-isolation",
                             "evidence-mutations", "complete"}:
                stage = candidate
        except Exception:
            pass
        raise RuntimeError("D1 bound admission qualification failed stage=" + stage) from None
    finally:
        ctx.close()
    # Reopen the same on-disk profile with a fresh browser process, not merely
    # a new tab or a new session in the previous document.
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
    try:
        restart=page.evaluate(I5_BOUND_RESTART,secrets)
        assert restart=={"revisionA":6,"revisionB":1,"tombstone":True,"receipt":True,
                         "noResurrection":True,"replay":True,"legacyPreserved":True}
        assert not blocked and not errors
        result["restart"]=restart
        journal=page.evaluate(I5_EVIDENCE_JOURNAL,secrets)
        assert journal=={"halfOpen":True,"pagination":True,"tieOrder":True,"legacyExcluded":True,
                         "sourceProjection":True,"staleRejected":True,"revoked":True,
                         "ownerIsolation":True,"revisionA":11}
        assert not blocked and not errors
        result["evidenceJournal"]=journal
        return result
    except Exception:
        stage="restart"
        try:
            candidate=page.evaluate("window.__d1EvidenceJournalStage || 'restart'")
            if candidate in {"restart","insert","pagination","conflict","revocation","complete"}:
                stage=candidate
        except Exception:
            pass
        raise RuntimeError("D1 evidence restart/journal qualification failed stage="+stage) from None
    finally:
        secrets.clear()
        ctx.close()



# Independent documents share the strict IDB fence, not Dart auth state.
# Harness retains only synthetic possession secrets outside the browser.
I5_CROSS_BOOT = r"""async ()=>{
  const api=await import('/d1_admission_candidate.mjs');
  const keys=await import('/d1_possession_candidate.mjs');
  const secrets=[keys.generatePossessionSecret(),keys.generatePossessionSecret()];
  for(let i=0;i<2;i++){
    const owner=900001+i;
    const s=await api.enroll(owner,1,api.syntheticProof(owner,
      {identityVerified:true,unlocked:true,epoch:1}),secrets[i]);
    await s.retire();
  }
  return secrets;
}"""
I5_CROSS_OPEN = r"""async ({owner,secret})=>{
  const api=await import('/d1_admission_candidate.mjs');
  await window.d1BoundLogin(owner);
  const p=await window.d1BoundProof(owner);
  window.d1CrossSession=await api.admitBound(owner,window.d1BoundEpoch(),p,secret);
  return (await window.d1CrossSession.inspect()).revision;
}"""
I5_CROSS_FENCE = r"""async ()=>{
  const db=await new Promise((resolve,reject)=>{
    const r=indexedDB.open('iamina-d1-admission-probe-v1',1);
    r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Store unavailable'));
  });
  try{return await new Promise((resolve,reject)=>{
    const tx=db.transaction('state','readonly'),r=tx.objectStore('state').get('fence');
    tx.oncomplete=()=>resolve(r.result.owner);tx.onabort=()=>reject(new Error('Store failed'));
  });}finally{db.close();}
}"""


def exercise_cross_revocation(browser_type,profile,locale,origin):
    secrets=None
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            secrets=page.evaluate(I5_CROSS_BOOT)
            assert page.evaluate(I5_CROSS_OPEN,{"owner":900001,"secret":secrets[0]})==1
            second=ctx.new_page()
            second.on("pageerror",lambda error: errors.append(str(error)[:300]))
            second.goto(origin,wait_until="domcontentloaded")
            second.wait_for_function("typeof window.d1BoundProof === 'function'",timeout=60000)
            assert second.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secrets[1]})==1
            assert page.evaluate(I5_CROSS_FENCE)==900002
            page.evaluate("window.d1BoundLock()")
            # Await the stale tab's proactive CAS result; it must NOT erase B.
            assert page.evaluate("window.d1CrossSession.retire()") is False
            assert page.evaluate("""async()=>{try{await window.d1CrossSession.inspect();return false;}
              catch(e){return String(e).includes('Bound authority retired');}}""")
            assert second.evaluate(I5_CROSS_FENCE)==900002
            assert second.evaluate("window.d1CrossSession.mutate('cross-success-001')")["revision"]==2
            assert not blocked and not errors
            # Deliberately close without retire. An orphan fence is allowed;
            # it is not an authority, and no key is restored from it.
        finally:
            ctx.close()
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            assert page.evaluate(I5_CROSS_FENCE)==900002
            assert page.evaluate("typeof window.d1CrossSession")=="undefined"
            assert page.evaluate(I5_CROSS_OPEN,{"owner":900001,"secret":secrets[0]})==1
            assert page.evaluate(I5_CROSS_FENCE)==900001
            assert page.evaluate("window.d1CrossSession.retire()") is True
            assert page.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secrets[1]})==2
            assert page.evaluate("window.d1CrossSession.retire()") is True
            assert page.evaluate(I5_CROSS_FENCE) is None
            assert not blocked and not errors
        finally:
            ctx.close()
        return {"staleRetirePreservesB":True,"orphanReplacedAfterRestart":True,
                "revisionA":1,"revisionB":2}
    except Exception:
        raise RuntimeError("D1 cross-document revocation qualification failed") from None
    finally:
        secrets=None


# Fault injection at the native IDB boundary in an isolated browser profile.
# Abort AFTER staging the fence tombstone, not just before calling retire().
I5_REVOCATION_FAILURE = r"""async ()=>{
  const api=await import('/d1_admission_candidate.mjs');
  const key=await import('/d1_possession_candidate.mjs');
  const A=900001,B=900002,a=key.generatePossessionSecret(),b=key.generatePossessionSecret();
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason),'Unexpected failure reason');return;
  }throw new Error('Expected refusal');};
  const proof=(o)=>api.syntheticProof(o,{identityVerified:true,unlocked:true,epoch:1});
  for(const [owner,secret] of [[A,a],[B,b]]){
    const s=await api.enroll(owner,1,proof(owner),secret);await s.retire();
  }
  const read=async()=>{
    const db=await new Promise((resolve,reject)=>{
      const r=indexedDB.open('iamina-d1-admission-probe-v1',1);
      r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Store unavailable'));
    });
    try{return await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),s=tx.objectStore('state');
      const f=s.get('fence'),a=s.get('owner:900001'),b=s.get('owner:900002');
      tx.oncomplete=()=>resolve({f:f.result,a:a.result.revision,b:b.result.revision});
      tx.onabort=()=>reject(new Error('Store failed'));
    });}finally{db.close();}
  };
  const admit=async(owner,secret,hooks={})=>{
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    return api.admitBound(owner,window.d1BoundEpoch(),p,secret,hooks);
  };
  const nativeOpen=IDBFactory.prototype.open,nativePut=IDBObjectStore.prototype.put;
  let aborts=0,opens=0;
  const denyOpen=()=>{IDBFactory.prototype.open=function(...args){
    if(args[0]==='iamina-d1-admission-probe-v1'){opens++;throw new Error('Injected IDB open failure');}
    return nativeOpen.apply(this,args);
  };};
  const abortRetire=()=>{IDBObjectStore.prototype.put=function(value,k){
    const request=nativePut.call(this,value,k);
    if(k==='fence'&&value.owner===null){aborts++;this.transaction.abort();}
    return request;
  };};
  const restore=()=>{IDBFactory.prototype.open=nativeOpen;IDBObjectStore.prototype.put=nativePut;};
  const waitFailed=async s=>{
    for(let i=0;i<100&&s.revocationStatus()!=='failed';i++)await new Promise(r=>setTimeout(r,20));
    check(s.revocationStatus()==='failed','Failure was not recorded');
  };
  try{
    // Open failure: immediate refusal, durable fence unchanged, explicit retry.
    let s=await admit(A,a);
    const baseline=await s.auditSnapshot(),first=await read();
    denyOpen();window.d1BoundLock();await waitFailed(s);
    await reject(()=>s.retire(),'Durable revocation unconfirmed');
    await reject(()=>s.inspect(),'Durable revocation unconfirmed');
    check(opens>=3&&api.pendingBoundRevocations().failed===1,'Missing open failure evidence');
    restore();
    check(JSON.stringify(await read())===JSON.stringify(first),'Open failure changed durable state');
    const retry=await api.retryPendingBoundRevocations();
    check(retry.revoked===1&&retry.failed===0&&retry.superseded===0,'Retry did not clear original fence');
    check(s.revocationStatus()==='revoked'&&(await read()).f.owner===null,'False retry ACK');
    await reject(()=>s.inspect(),'Bound authority retired');
    // Real transaction abort after put: no tombstone or checkpoint change.
    s=await admit(A,a);
    const beforeAbort=await read();
    abortRetire();window.d1BoundLock();await waitFailed(s);restore();
    check(aborts===1&&JSON.stringify(await read())===JSON.stringify(beforeAbort),'Aborted put changed state');
    const newer=await admit(B,b);
    const bBefore=await read();
    const stale=await api.retryPendingBoundRevocations();
    check(stale.superseded===1&&stale.revoked===0&&stale.failed===0,'Stale retry result wrong');
    check(s.revocationStatus()==='superseded'&&JSON.stringify(await read())===JSON.stringify(bBefore),'Stale retry erased B');
    await reject(()=>s.mutate('failed-retire-001'),'Bound authority retired');
    check((await newer.inspect()).revision===1,'B corrupted');
    await newer.retire();
    // Activation fails after acquiring lease and no session handle is returned.
    await reject(()=>admit(A,a,{afterLease:()=>{
      abortRetire();window.d1BoundLock();
    }}),'Durable revocation unconfirmed');
    restore();
    check(api.pendingBoundRevocations().failed===1&&(await read()).f.owner===A,'Lost orphan cleanup handle');
    const orphan=await api.retryPendingBoundRevocations();
    check(orphan.revoked===1&&orphan.failed===0&&(await read()).f.owner===null,'Orphan retry failed');
    const fresh=await admit(A,a);
    const actual=await fresh.auditSnapshot();
    check(actual.sha256===baseline.sha256&&actual.revision===baseline.revision&&
      JSON.stringify(actual.tables)===JSON.stringify(baseline.tables),'A bytes changed during failure');
    await fresh.retire();
    check(api.pendingBoundRevocations().failed===0&&api.pendingBoundRevocations().pending===0,'Registry not drained');
    check((await read()).a===1&&(await read()).b===1&&(await read()).f.owner===null,'Final durable state wrong');
    return {openFailure:true,abortedStagedPut:true,oldSessionRejected:true,
      retryRevoked:true,staleRetryPreservesB:true,orphanRetry:true,exactSnapshot:true};
  }finally{restore();}
}"""


def exercise_revocation_failure(browser_type,profile,locale,origin):
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
    try:
        result=page.evaluate(I5_REVOCATION_FAILURE)
        assert result=={"openFailure":True,"abortedStagedPut":True,
                       "oldSessionRejected":True,"retryRevoked":True,
                       "staleRetryPreservesB":True,"orphanRetry":True,"exactSnapshot":True}
        assert not blocked and not errors
        return result
    except Exception:
        raise RuntimeError("D1 durable revocation fault qualification failed") from None
    finally:
        ctx.close()



# Broadcast hints are never admission authority. Independent documents
# verify the committed fence even when the transport is disabled.
I5_HINT_SEND = r"""async ()=>{
  const ch=new BroadcastChannel('iamina-d1-admission-probe-fence-v1');
  try{ch.postMessage({owner:900001,token:'forged',epoch:1});
      ch.postMessage('fence-changed');}
  finally{ch.close();}
}"""
I5_WAIT_SUPERSEDED = r"""async ()=>{
  for(let i=0;i<160;i++){
    const state=window.d1CrossSession.revocationStatus();
    if(state==='superseded')return true;
    if(state==='failed'||state==='revoked')return false;
    await new Promise(r=>setTimeout(r,25));
  }
  return false;
}"""
I5_OLD_REFUSAL = r"""async ()=>{
  try{await window.d1CrossSession.inspect();return false;}
  catch(e){return String(e).includes('Bound authority retired');}
}"""
I5_PROBE_HINTS = r"""()=>{
  window.d1Hints=[];
  window.d1HintObserver=new BroadcastChannel('iamina-d1-admission-probe-fence-v1');
  window.d1HintObserver.onmessage=e=>window.d1Hints.push(e.data);
}"""


def exercise_cross_hints(browser_type,profile,locale,origin):
    secrets=None
    stage="open-context"
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            stage="step-01"
            secrets=page.evaluate(I5_CROSS_BOOT)
            stage="step-02"
            assert page.evaluate(I5_CROSS_OPEN,{"owner":900001,"secret":secrets[0]})==1
            stage="step-03"
            second=ctx.new_page()
            second.on("pageerror",lambda error: errors.append(str(error)[:300]))
            stage="step-04"
            second.goto(origin,wait_until="domcontentloaded")
            stage="step-05"
            second.wait_for_function("typeof window.d1BoundProof === 'function'",timeout=60000)
            stage="step-06"
            page.evaluate(I5_PROBE_HINTS)
            # False hint must not authorize or revoke a current lease.
            stage="step-07"
            second.evaluate(I5_HINT_SEND)
            stage="step-08"
            page.wait_for_function("window.d1Hints.length===2",polling=50,timeout=5000)
            stage="step-09"
            assert page.evaluate("window.d1CrossSession.inspect()")["revision"]==1
            stage="step-10"
            assert page.evaluate("window.d1CrossSession.revocationStatus()")=="active"
            stage="step-11"
            page.evaluate("window.d1Hints.length=0")
            # Real A->B admission emits an anonymous hint only after commit.
            stage="step-12"
            assert second.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secrets[1]})==1
            stage="step-13"
            page.wait_for_function("window.d1Hints.length>=1",polling=50,timeout=5000)
            stage="step-14"
            assert page.evaluate("window.d1Hints.every(x=>x==='fence-changed')")
            stage="step-15"
            assert page.evaluate(I5_WAIT_SUPERSEDED)
            stage="step-16"
            assert page.evaluate(I5_OLD_REFUSAL)
            stage="step-17"
            assert page.evaluate(I5_CROSS_FENCE)==900002
            # Late/duplicate signal from old A cannot revoke or resurrect B.
            stage="step-18"
            page.evaluate(I5_HINT_SEND)
            stage="step-19"
            assert second.evaluate("window.d1CrossSession.inspect()")["revision"]==1
            stage="step-20"
            assert second.evaluate("window.d1CrossSession.revocationStatus()")=="active"
            # Same-owner replacement with sender transport disabled: the
            # receiver must retire without a new operation or delivered hint.
            stage="step-21"
            page.evaluate("""()=>{window.d1SavedPost=BroadcastChannel.prototype.postMessage;
              BroadcastChannel.prototype.postMessage=function(){throw new Error('Injected hint loss');};}""")
            admitted=False
            try:
                stage="step-22"
                assert page.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secrets[1]})==1
                admitted=True
            finally:
                # Return a serializable boolean, not an unbound native method.
                # Preserve step-22 if the admission itself failed.
                if admitted:
                    stage="step-23"
                assert page.evaluate("""()=>{
                  const saved=window.d1SavedPost;
                  if(typeof saved!=='function')return false;
                  BroadcastChannel.prototype.postMessage=saved;
                  return BroadcastChannel.prototype.postMessage===saved;
                }""")
            stage="step-24"
            assert second.evaluate(I5_WAIT_SUPERSEDED)
            stage="step-25"
            assert second.evaluate(I5_OLD_REFUSAL)
            stage="step-26"
            assert page.evaluate("window.d1CrossSession.inspect()")["revision"]==1
            stage="step-27"
            assert second.evaluate("window.d1CrossSession.retire()") is False
            # No BroadcastChannel at all in receiver: per-operation/fallback
            # durable fencing still works after another admission.
            stage="step-28"
            assert page.evaluate("window.d1CrossSession.retire()") is True
            stage="step-29"
            second.evaluate("window.BroadcastChannel=undefined")
            stage="step-30"
            assert second.evaluate(I5_CROSS_OPEN,{"owner":900001,"secret":secrets[0]})==1
            stage="step-31"
            assert page.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secrets[1]})==1
            stage="step-32"
            assert second.evaluate(I5_WAIT_SUPERSEDED)
            stage="step-33"
            assert second.evaluate(I5_OLD_REFUSAL)
            stage="step-34"
            assert page.evaluate("window.d1CrossSession.inspect()")["revision"]==1
            stage="step-35"
            assert page.evaluate("window.d1CrossSession.retire()") is True
            stage="step-36"
            assert page.evaluate(I5_CROSS_FENCE) is None
            stage="step-37"
            page.evaluate("window.d1HintObserver.close()")
            stage="step-38"
            assert not blocked and not errors
        finally:
            ctx.close()
        return {"anonymousCommitHint":True,"falseHintIgnored":True,
                "idleSuperseded":True,"lateHintSafe":True,
                "lostHintFallback":True,"noChannelFallback":True,
                "sameOwnerFenced":True,"noResurrection":True}
    except Exception:
        raise RuntimeError("D1 cross-document hint qualification failed at "+stage) from None
    finally:
        secrets=None



# First real clinical-store operation, isolated from application providers.
I5_CLINICAL = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002;
  const check=(v,m)=>{if(!v)throw new Error(m);};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason),'Unexpected refusal');return;
  }throw new Error('Expected refusal');};
  const open=async(owner,secret)=>{
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    return api.admitBound(owner,window.d1BoundEpoch(),p,secret);
  };
  const unchanged=(before,after)=>{
    for(const table of Object.keys(before.tables)){
      if(table!=='patient_treatment_declarations_v1')
        check(JSON.stringify(before.tables[table])===JSON.stringify(after.tables[table]),'Other table changed');
    }
  };
  let s=await open(A,a);
  const initial=await s.auditSnapshot();
  check(initial.revision===1&&(await s.readTreatment()).declaration===null,'Unexpected initial declaration');
  await reject(()=>s.writeTreatment(1,'declared',[]),'Invalid declaration');
  s=await open(A,a);
  await reject(()=>s.writeTreatment(2,'declared',['oral_meds']),'Checkpoint conflict');
  s=await open(A,a);
  await reject(()=>s.writeTreatment(1,'declared',['oral_meds'],{beforeCommit:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  const noWrite=await s.auditSnapshot();
  check(noWrite.sha256===initial.sha256&&noWrite.revision===1,'Precommit retirement changed bytes');
  const ack=await s.writeTreatment(1,'declared',['oral_meds','lifestyle']);
  check(ack.revision===2&&ack.declaration.owner===A&&ack.declaration.generation===1&&
    ack.declaration.syncStatus==='pending'&&ack.declaration.provenance==='patient_declared','Invalid first ACK');
  const first=await s.auditSnapshot();
  unchanged(initial,first);
  check(first.tables.patient_treatment_declarations_v1.length===1,'Declaration missing');
  await reject(()=>s.writeTreatment(2,'unsure',[],{beforeAck:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  const recovered=await s.readTreatment();
  check(recovered.revision===3&&recovered.declaration.generation===2&&
    recovered.declaration.state==='unsure'&&recovered.declaration.codes.length===0,'Lost ACK recovery mismatch');
  unchanged(initial,await s.auditSnapshot());
  await window.d1BoundLogin(B);
  await reject(()=>s.readTreatment(),'Bound authority retired');
  const bp=await window.d1BoundProof(B);
  const bs=await api.admitBound(B,window.d1BoundEpoch(),bp,b);
  check((await bs.readTreatment()).declaration===null,'Cross-owner declaration leak');
  const bAck=await bs.writeTreatment(1,'none_declared',[]);
  check(bAck.revision===2&&bAck.declaration.owner===B&&bAck.declaration.generation===1,'B ACK mismatch');
  await bs.retire();
  s=await open(A,a);
  check(JSON.stringify(await s.readTreatment())===JSON.stringify(recovered),'A recovery changed');
  await s.retire();
  return {invalidRefused:true,staleRefused:true,precommitUnchanged:true,
    durableAck:true,lostAckRecovered:true,otherTablesUnchanged:true,ownerIsolation:true};
}"""
I5_CLINICAL_RESTART = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const result=[];
  for(const [owner,secret] of [[900001,a],[900002,b]]){
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    const s=await api.admitBound(owner,window.d1BoundEpoch(),p,secret);
    result.push(await s.readTreatment());
    await s.retire();
  }
  return result.map(x=>({revision:x.revision,owner:x.declaration.owner,
    generation:x.declaration.generation,state:x.declaration.state}));
}"""



# Inspect the accessible origin's durable state independently of the admission
# wrapper. This is an API-visible inventory, not a disk/memory forensic audit.
I5_CLINICAL_STORAGE = r"""async ({a,b})=>{
  const {openArchive}=await import('/d1_archive_candidate.mjs');
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const encode=x=>new TextEncoder().encode(x);
  const raw=x=>Uint8Array.from(x.match(/../g),y=>parseInt(y,16));
  const hex=x=>Array.from(x,v=>v.toString(16).padStart(2,'0')).join('');
  const contains=(hay,needle)=>hay.some((_,i)=>needle.every((v,j)=>hay[i+j]===v));
  const names=(await indexedDB.databases()).map(x=>x.name).sort();
  check(JSON.stringify(names)==='["iamina-d1-admission-probe-v1"]','Unexpected durable DB');
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open(names[0],1);
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(new Error('Store unavailable'));
  });
  try{
    check(JSON.stringify(Array.from(db.objectStoreNames))==='["state"]','Unexpected store');
    const values=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),store=tx.objectStore('state');
      const keys=store.getAllKeys(),f=store.get('fence'),x=store.get('owner:900001'),y=store.get('owner:900002');
      tx.oncomplete=()=>resolve({keys:keys.result,f:f.result,x:x.result,y:y.result});
      tx.onabort=()=>reject(new Error('Store read failed'));
    });
    check(JSON.stringify(values.keys.sort())==='["fence","owner:900001","owner:900002"]','Unexpected durable keys');
    check(values.f&&Object.keys(values.f).sort().join(',')==='epoch,owner,token'&&
      values.f.owner===null&&values.f.epoch===null&&/^[0-9a-f]{64}$/.test(values.f.token),'Unexpected retired fence');
    const needles=[encode(a),encode(b),raw(a),raw(b),encode('SQLite format 3'),
      encode('D1_I1_SYNTHETIC_NOT_PATIENT'),encode('patient_treatment_declarations_v1'),
      encode('patient_declared'),encode('none_declared'),encode('oral_meds'),
      encode('iamina.fixture_900001'),encode('iamina.fixture_900002')];
    for(const [owner,rec,secret,wrongSecret,rev,expected] of [
      [900001,values.x,a,b,3,'unsure'],[900002,values.y,b,a,2,'none_declared']]){
      check(rec&&Object.keys(rec).sort().join(',')==='archive,envelope,revision'&&rec.revision===rev,'Unexpected record');
      for(const bytes of [rec.archive,rec.envelope]){
        check(bytes instanceof Uint8Array&&bytes.length>=53&&
          [73,65,77,73,78,65,1,0].every((v,i)=>bytes[i]===v),'Unexpected archive format');
        check(!needles.some(n=>contains(bytes,n)),'Durable plaintext or secret');
      }
      const scope='amina_vault_v1_native_'+owner;
      const wrongScope='amina_vault_v1_native_'+(owner===900001?900002:900001);
      for(const [s,p] of [[wrongSecret,scope],[secret,wrongScope]]){
        let denied=false;
        try{const invalid=await openArchive(rec.envelope,s,p);invalid.fill(0);}
        catch(e){denied=String(e).includes('Archive authentication failed');}
        check(denied,'Wrong scope or secret accepted');
      }
      const envelope=await openArchive(rec.envelope,secret,scope);
      let payload,sqlite;
      try{
        const tag=encode('IAMINA-D1-KEY-V1');
        check(envelope.length===tag.length+32&&tag.every((v,i)=>envelope[i]===v),'Envelope contents wrong');
        const key=envelope.subarray(tag.length);
        const keyHex=hex(key);
        for(const stored of [values.x,values.y])
          for(const bytes of [stored.archive,stored.envelope])
            check(!contains(bytes,key)&&!contains(bytes,encode(keyHex)),'Durable clear data key');
        payload=await openArchive(rec.archive,keyHex,scope);
        check(payload.length>=104&&new DataView(payload.buffer,payload.byteOffset,4).getUint32(0)===rev,'Encrypted revision mismatch');
        sqlite=payload.slice(4);
        const tables=JSON.parse(await window.d1FullInspect(sqlite,owner));
        const decl=tables.patient_treatment_declarations_v1;
        check(decl.length===1&&decl[0].user_id===owner&&decl[0].declaration_state===expected&&
          decl[0].local_generation===(owner===900001?2:1)&&decl[0].sync_status==='pending','Decrypted declaration mismatch');
      }finally{envelope.fill(0);payload?.fill(0);sqlite?.fill(0);}
    }
    check(!localStorage.length&&!sessionStorage.length&&!(await caches.keys()).length,'Unexpected browser storage');
    const opfsChecked=typeof navigator.storage?.getDirectory==='function';
    if(opfsChecked){
      const root=await navigator.storage.getDirectory();
      for await(const _ of root.values())throw new Error('Unexpected OPFS file');
    }
    return {inventoryExact:true,archiveFormat:true,noKnownPlaintext:true,
      wrongScopeSecretRefused:true,independentDecrypt:true,otherStoresEmpty:true,opfsChecked};
  }finally{db.close();}
}"""


def exercise_clinical_store(browser_type,profile,locale,origin):
    secrets=None
    stage="bootstrap"
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            secrets=page.evaluate(I5_CROSS_BOOT)
            stage="clinical-operations"
            result=page.evaluate(I5_CLINICAL,{"a":secrets[0],"b":secrets[1]})
            assert result=={"invalidRefused":True,"staleRefused":True,
                "precommitUnchanged":True,"durableAck":True,"lostAckRecovered":True,
                "otherTablesUnchanged":True,"ownerIsolation":True}
            stage="storage-before-restart"
            before_storage=page.evaluate(I5_CLINICAL_STORAGE,{"a":secrets[0],"b":secrets[1]})
            assert all(before_storage[k] is True for k in ("inventoryExact","archiveFormat","noKnownPlaintext","wrongScopeSecretRefused","independentDecrypt","otherStoresEmpty"))
            assert not blocked and not errors
        finally:
            ctx.close()
        stage="restart"
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            restored=page.evaluate(I5_CLINICAL_RESTART,{"a":secrets[0],"b":secrets[1]})
            assert restored==[{"revision":3,"owner":900001,"generation":2,"state":"unsure"},
                {"revision":2,"owner":900002,"generation":1,"state":"none_declared"}]
            stage="storage-after-restart"
            after_storage=page.evaluate(I5_CLINICAL_STORAGE,{"a":secrets[0],"b":secrets[1]})
            assert after_storage==before_storage
            assert not blocked and not errors
        finally:
            ctx.close()
        return {**result,"restart":True,"storageBefore":before_storage,"storageAfter":after_storage}
    except Exception:
        raise RuntimeError("D1 clinical store qualification failed at "+stage) from None
    finally:
        secrets=None



I5_GLUCOSE = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,t=1795564800;
  const u='ab123456-1234-4abc-8def-000000000001',v='ab123456-1234-4abc-8def-000000000002';
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason),'Unexpected refusal');return;
  }throw new Error('Expected refusal');};
  const open=async(owner,secret)=>{
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    return api.admitBound(owner,window.d1BoundEpoch(),p,secret);
  };
  let s=await open(A,a);
  const initial=await s.auditSnapshot();
  check((await s.readGlucose(u)).measurement===null,'Unexpected reading');
  await reject(()=>s.insertGlucose(1,u,123.25,'mmol/L',t),'Invalid measurement');
  s=await open(A,a);
  await reject(()=>s.insertGlucose(1,u,0,'mg/dL',t),'Invalid measurement');
  s=await open(A,a);
  await reject(()=>s.insertGlucose(2,u,123.25,'mg/dL',t),'Checkpoint conflict');
  s=await open(A,a);
  await reject(()=>s.insertGlucose(1,u,123.25,'mg/dL',t,{beforeCommit:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  const before=await s.auditSnapshot();
  check(before.sha256===initial.sha256&&before.revision===1,'Precommit changed snapshot');
  const ack=await s.insertGlucose(1,u,123.25,'mg/dL',t);
  check(ack.revision===2&&!ack.replay&&ack.measurement.mgDl===123.25&&
    ack.measurement.loggedAtSeconds===t&&ack.measurement.syncStatus==='pending','ACK mismatch');
  const first=await s.auditSnapshot();
  const replay=await s.insertGlucose(1,u,123.25,'mg/dL',t);
  check(replay.revision===2&&replay.replay&&(await s.auditSnapshot()).sha256===first.sha256,'Replay changed snapshot');
  await reject(()=>s.insertGlucose(2,u,124.25,'mg/dL',t),'Measurement UUID conflict');
  s=await open(A,a);
  await reject(()=>s.insertGlucose(2,u,123.25,'mg/dL',t+1),'Measurement UUID conflict');
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===first.sha256,'UUID conflict changed snapshot');
  await reject(()=>s.insertGlucose(2,v,137.5,'mg/dL',t+60,{beforeAck:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  const recovered=await s.insertGlucose(2,v,137.5,'mg/dL',t+60);
  check(recovered.revision===3&&recovered.replay,'Lost ACK not replayed');
  const end=await s.auditSnapshot();
  check(end.tables.log_entries.length===initial.tables.log_entries.length+2,'Wrong log count');
  for(const k of Object.keys(initial.tables)){
    if(k!=='log_entries')check(JSON.stringify(initial.tables[k])===JSON.stringify(end.tables[k]),'Other table changed');
  }
  check(initial.tables.log_entries.every(old=>end.tables.log_entries.some(row=>JSON.stringify(row)===JSON.stringify(old))),'Existing log changed');
  await window.d1BoundLogin(B);
  await reject(()=>s.readGlucose(u),'Bound authority retired');
  const bp=await window.d1BoundProof(B);
  const bs=await api.admitBound(B,window.d1BoundEpoch(),bp,b);
  check((await bs.readGlucose(u)).measurement===null,'Cross-owner reading leak');
  const other=await bs.insertGlucose(1,u,211.75,'mg/dL',t);
  check(other.revision===2&&other.measurement.mgDl===211.75,'B same UUID failure');
  await bs.retire();
  s=await open(A,a);
  check((await s.readGlucose(u)).measurement.mgDl===123.25&&
    (await s.auditSnapshot()).sha256===end.sha256,'A changed by B');
  await s.retire();
  return {explicitUnit:true,invalidRefused:true,staleRefused:true,precommitUnchanged:true,
    durableAck:true,exactReplay:true,uuidConflict:true,lostAckRecovered:true,
    otherTablesUnchanged:true,sameUuidOwnerIsolation:true};
}"""
I5_GLUCOSE_RESTART = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const u='ab123456-1234-4abc-8def-000000000001',v='ab123456-1234-4abc-8def-000000000002';
  const result=[];
  for(const [owner,secret] of [[900001,a],[900002,b]]){
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    const s=await api.admitBound(owner,window.d1BoundEpoch(),p,secret);
    const x=await s.readGlucose(u),y=await s.readGlucose(v);
    result.push({revision:x.revision,value:x.measurement.mgDl,second:y.measurement?.mgDl??null});
    await s.retire();
  }
  const check=(ok)=>{if(!ok)throw new Error('Unexpected durable storage');};
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-admission-probe-v1',1);
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(new Error('Store unavailable'));
  });
  try{
    const records=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),st=tx.objectStore('state');
      const x=st.get('owner:900001'),y=st.get('owner:900002'),keys=st.getAllKeys();
      tx.oncomplete=()=>resolve({x:x.result,y:y.result,keys:keys.result});tx.onabort=reject;
    });
    const enc=x=>new TextEncoder().encode(x);
    const raw=x=>Uint8Array.from(x.match(/../g),y=>parseInt(y,16));
    const needles=[enc(u),enc(v),enc('D1_I5C_SYNTHETIC_GLUCOSE'),enc('SQLite format 3'),enc(a),enc(b),raw(a),raw(b)];
    check(JSON.stringify(records.keys.sort())==='["fence","owner:900001","owner:900002"]');
    for(const rec of [records.x,records.y]){
      check(Object.keys(rec).sort().join(',')==='archive,envelope,revision');
      for(const bytes of [rec.archive,rec.envelope])
        check(bytes instanceof Uint8Array&&!needles.some(n=>bytes.some((_,i)=>n.every((x,j)=>bytes[i+j]===x))));
    }
    check(JSON.stringify((await indexedDB.databases()).map(x=>x.name).sort())==='["iamina-d1-admission-probe-v1"]');
    check(!localStorage.length&&!sessionStorage.length&&!(await caches.keys()).length);
    if(navigator.storage?.getDirectory){
      const root=await navigator.storage.getDirectory();
      for await(const _ of root.values())throw new Error('Unexpected OPFS file');
    }
  }finally{db.close();}
  return result;
}"""


def exercise_glucose_store(browser_type,profile,locale,origin):
    secrets=None
    stage="bootstrap"
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            secrets=page.evaluate(I5_CROSS_BOOT)
            stage="glucose-operations"
            result=page.evaluate(I5_GLUCOSE,{"a":secrets[0],"b":secrets[1]})
            assert result=={"explicitUnit":True,"invalidRefused":True,"staleRefused":True,
                "precommitUnchanged":True,"durableAck":True,"exactReplay":True,
                "uuidConflict":True,"lostAckRecovered":True,"otherTablesUnchanged":True,
                "sameUuidOwnerIsolation":True}
            assert not blocked and not errors
        finally:
            ctx.close()
        stage="restart-storage"
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            restored=page.evaluate(I5_GLUCOSE_RESTART,{"a":secrets[0],"b":secrets[1]})
            assert restored==[{"revision":3,"value":123.25,"second":137.5},
                {"revision":2,"value":211.75,"second":None}]
            assert not blocked and not errors
        finally:
            ctx.close()
        return {**result,"restart":True,"noKnownPlaintext":True}
    except Exception:
        raise RuntimeError("D1 glucose qualification failed at "+stage) from None
    finally:
        secrets=None


I5_JOURNAL = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,t=1795564800;
  const u='ac123456-1234-4abc-8def-000000000001',v='ac123456-1234-4abc-8def-000000000002';
  const w='ac123456-1234-4abc-8def-000000000003',z='ac123456-1234-4abc-8def-000000000004';
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason),'Unexpected refusal');return;
  }throw new Error('Expected refusal');};
  const open=async(owner,secret)=>{
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    return api.admitBound(owner,window.d1BoundEpoch(),p,secret);
  };
  let s=await open(A,a);
  const empty=await s.readJournal(1,t-1,t+100,2,0);
  check(empty.rows.length===0&&empty.nextOffset===null,'Legacy row disclosed');
  await s.insertGlucose(1,v,120.25,'mg/dL',t+30);
  await s.insertGlucose(2,u,121.25,'mg/dL',t+30);
  await s.insertGlucose(3,w,122.25,'mg/dL',t);
  await s.insertGlucose(4,z,123.25,'mg/dL',t+100);
  const before=await s.auditSnapshot();
  const first=await s.readJournal(5,t,t+100,2,0);
  const second=await s.readJournal(5,t,t+100,2,first.nextOffset);
  check(first.revision===5&&first.nextOffset===2&&first.rows.map(x=>x.uuid).join(',')===[u,v].join(',')&&
    first.rows[0].mgDl===121.25&&second.rows.length===1&&second.rows[0].uuid===w&&second.nextOffset===null,
    'Pagination, tie or bounds mismatch');
  const narrow=await s.readJournal(5,t+30,t+31,50,0);
  check(narrow.rows.length===2&&narrow.rows.every(x=>x.loggedAtSeconds===t+30),'Range mismatch');
  check((await s.readJournal(5,t,t+100,2,3)).rows.length===0,'Past end mismatch');
  check((await s.auditSnapshot()).sha256===before.sha256,'Read mutated snapshot');
  await reject(()=>s.readJournal(5,t,t+100,51,0),'Invalid journal range');
  s=await open(A,a);
  await reject(()=>s.readJournal(5,t,t,2,0),'Invalid journal range');
  s=await open(A,a);
  await reject(()=>s.readJournal(5,t,t+100,2,-1),'Invalid journal range');
  s=await open(A,a);
  await reject(()=>s.readJournal(4,t,t+100,2,0),'Checkpoint conflict');
  s=await open(A,a);
  await reject(()=>s.readJournal(5,t,t+100,2,0,{beforeReturn:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===before.sha256,'Lock changed snapshot');
  // A successful new insert within the same session changes the revision.
  // The old page must be withheld, even if the owner and fence still match.
  const q='ac123456-1234-4abc-8def-000000000005';
  await reject(()=>s.readJournal(5,t,t+100,2,0,{
    beforeReturn:()=>s.insertGlucose(5,q,125.25,'mg/dL',t+60)}),'Checkpoint conflict');
  s=await open(A,a);
  const after=await s.readJournal(6,t,t+100,50,0);
  check(after.rows.map(x=>x.uuid).join(',')===[q,u,v,w].join(','),'Concurrent update missing');
  const aSnapshot=await s.auditSnapshot();
  await window.d1BoundLogin(B);
  await reject(()=>s.readJournal(6,t,t+100,2,0),'Bound authority retired');
  const bp=await window.d1BoundProof(B);
  const bs=await api.admitBound(B,window.d1BoundEpoch(),bp,b);
  check((await bs.readJournal(1,t,t+100,50,0)).rows.length===0,'A rows visible in B');
  await bs.insertGlucose(1,u,211.25,'mg/dL',t+30);
  const bpage=await bs.readJournal(2,t,t+100,50,0);
  check(bpage.rows.length===1&&bpage.rows[0].uuid===u&&bpage.rows[0].mgDl===211.25,'B page mismatch');
  await bs.retire();
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===aSnapshot.sha256,'B changed A');
  check(JSON.stringify(await s.readJournal(6,t,t+100,50,0))===JSON.stringify(after),'A page mismatch');
  await s.retire();
  return {legacyExcluded:true,stablePagination:true,rangeBoundaries:true,invalidRefused:true,
    staleRefused:true,readOnly:true,lockDuringRead:true,concurrentRevisionRefused:true,ownerIsolation:true};
}"""
I5_JOURNAL_RESTART = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const results=[];
  for(const [owner,secret,revision] of [[900001,a,6],[900002,b,2]]){
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    const s=await api.admitBound(owner,window.d1BoundEpoch(),p,secret);
    const page=await s.readJournal(revision,1795564800,1795564900,50,0);
    results.push({revision:page.revision,values:page.rows.map(x=>x.mgDl),next:page.nextOffset});
    await s.retire();
  }
  return results;
}"""


def exercise_journal(browser_type,profile,locale,origin):
    secrets=None
    stage="bootstrap"
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            secrets=page.evaluate(I5_CROSS_BOOT)
            stage="journal-operations"
            result=page.evaluate(I5_JOURNAL,{"a":secrets[0],"b":secrets[1]})
            assert result=={"legacyExcluded":True,"stablePagination":True,"rangeBoundaries":True,
                "invalidRefused":True,"staleRefused":True,"readOnly":True,"lockDuringRead":True,
                "concurrentRevisionRefused":True,"ownerIsolation":True}
            assert not blocked and not errors
        finally:
            ctx.close()
        stage="restart"
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            restored=page.evaluate(I5_JOURNAL_RESTART,{"a":secrets[0],"b":secrets[1]})
            assert restored==[{"revision":6,"values":[125.25,121.25,120.25,122.25],"next":None},
                {"revision":2,"values":[211.25],"next":None}]
            assert not blocked and not errors
        finally:
            ctx.close()
        return {**result,"restart":True}
    except Exception:
        raise RuntimeError("D1 journal qualification failed at "+stage) from None
    finally:
        secrets=None


I5_JOURNAL_CHANGE = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs');
  const A=900001,B=900002,t=1795564800;
  const u='ad123456-1234-4abc-8def-000000000001',v='ad123456-1234-4abc-8def-000000000002';
  const check=(ok,msg)=>{if(!ok)throw new Error(msg);};
  const reject=async(fn,reason)=>{try{await fn();}catch(e){
    check(String(e).includes(reason),'Unexpected refusal');return;
  }throw new Error('Expected refusal');};
  const open=async(owner,secret)=>{
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    return api.admitBound(owner,window.d1BoundEpoch(),p,secret);
  };
  let s=await open(A,a);
  await s.insertGlucose(1,u,120.25,'mg/dL',t);
  await s.insertGlucose(2,v,130.25,'mg/dL',t+60);
  const initial=await s.auditSnapshot();
  await reject(()=>s.editGlucose(3,u,0,'mg/dL',t),'Invalid measurement change');
  s=await open(A,a);
  await reject(()=>s.editGlucose(2,u,121.25,'mg/dL',t),'Checkpoint conflict');
  s=await open(A,a);
  await reject(()=>s.editGlucose(3,u,121.25,'mg/dL',t,{beforeCommit:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===initial.sha256,'Edit precommit changed data');
  const ack=await s.editGlucose(3,u,121.25,'mg/dL',t+10);
  check(ack.revision===4&&!ack.replay&&!ack.deleted&&ack.measurement.mgDl===121.25&&
    ack.measurement.loggedAtSeconds===t+10,'Edit ACK mismatch');
  const edited=await s.auditSnapshot();
  const originalRow=initial.tables.log_entries.find(x=>x.client_uuid===u);
  const editedRow=edited.tables.log_entries.find(x=>x.client_uuid===u);
  check(originalRow&&editedRow&&Object.keys(originalRow).every(k=>
    ['blood_sugar','logged_at'].includes(k)||originalRow[k]===editedRow[k]),'Edit changed unrelated field');
  const noOp=await s.editGlucose(4,u,121.25,'mg/dL',t+10);
  check(noOp.revision===4&&noOp.replay&&(await s.auditSnapshot()).sha256===edited.sha256,'Edit no-op mutated data');
  await reject(()=>s.editGlucose(4,u,122.25,'mg/dL',t+20,{beforeAck:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  const recovered=await s.readGlucose(u);
  check(recovered.revision===5&&recovered.measurement.mgDl===122.25,'Edit recovery mismatch');
  await reject(()=>s.editGlucose(4,u,122.25,'mg/dL',t+20),'Checkpoint conflict');
  s=await open(A,a);
  const beforeDelete=await s.auditSnapshot();
  await reject(()=>s.deleteGlucose(4,u),'Checkpoint conflict');
  s=await open(A,a);
  await reject(()=>s.deleteGlucose(5,u,{beforeCommit:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===beforeDelete.sha256,'Delete precommit changed data');
  await reject(()=>s.deleteGlucose(5,u,{beforeAck:()=>window.d1BoundLock()}),'Bound authority retired');
  s=await open(A,a);
  const del=await s.deleteGlucose(5,u);
  check(del.revision===6&&del.replay&&del.deleted&&del.measurement===null,'Delete recovery mismatch');
  const deleted=await s.auditSnapshot();
  await reject(()=>s.deleteGlucose(7,u),'Checkpoint conflict');
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===deleted.sha256,'Future revision changed bytes');
  check(deleted.tables.d1_fixture_deleted_glucose.length===1&&
    deleted.tables.d1_fixture_deleted_glucose[0].uuid===u,'Missing tombstone');
  check((await s.readGlucose(u)).measurement===null,'Deleted measurement visible');
  const page=await s.readJournal(6,t,t+100,50,0);
  check(page.rows.length===1&&page.rows[0].uuid===v&&page.rows[0].mgDl===130.25,'Journal deletion mismatch');
  await reject(()=>s.insertGlucose(6,u,120.25,'mg/dL',t),'Measurement UUID deleted');
  s=await open(A,a);
  await reject(()=>s.editGlucose(6,u,125.25,'mg/dL',t),'Measurement unavailable');
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===deleted.sha256,'Rejected mutation changed data');
  // Ordinary acknowledged deletion is also exercised on a second row.
  const normal=await s.deleteGlucose(6,v);
  check(normal.revision===7&&normal.deleted&&!normal.replay,'Delete ACK mismatch');
  const end=await s.auditSnapshot();
  check(end.tables.d1_fixture_deleted_glucose.length===2&&end.tables.log_entries.length===initial.tables.log_entries.length-2,
    'Unexpected deletion count');
  for(const k of Object.keys(initial.tables)){
    if(k!=='log_entries')check(JSON.stringify(initial.tables[k])===JSON.stringify(end.tables[k]),'Other table changed');
  }
  check(initial.tables.log_entries.filter(x=>x.client_uuid!==u&&x.client_uuid!==v).every(old=>
    end.tables.log_entries.some(row=>JSON.stringify(row)===JSON.stringify(old))),'Unrelated log changed');
  await window.d1BoundLogin(B);
  await reject(()=>s.deleteGlucose(7,u),'Bound authority retired');
  const bp=await window.d1BoundProof(B);
  const bs=await api.admitBound(B,window.d1BoundEpoch(),bp,b);
  await reject(()=>bs.deleteGlucose(1,u),'Measurement unavailable');
  const b2=await open(B,b);
  const added=await b2.insertGlucose(1,u,211.25,'mg/dL',t);
  check(added.revision===2&&added.measurement.mgDl===211.25,'B UUID blocked by A tombstone');
  await b2.retire();
  s=await open(A,a);
  check((await s.auditSnapshot()).sha256===end.sha256,'B changed A');
  await s.retire();
  return {invalidRefused:true,staleRefused:true,editPrecommitUnchanged:true,editAck:true,
    editNoOp:true,editLostAck:true,deletePrecommitUnchanged:true,deleteLostAck:true,
    deleteAck:true,noResurrection:true,otherTablesUnchanged:true,ownerIsolation:true,
    futureRevisionRefused:true,editFieldsPreserved:true};
}"""
I5_JOURNAL_CHANGE_RESTART = r"""async ({a,b})=>{
  const api=await import('/d1_admission_candidate.mjs'),t=1795564800;
  const u='ad123456-1234-4abc-8def-000000000001',v='ad123456-1234-4abc-8def-000000000002';
  const result=[];
  for(const [owner,secret,revision] of [[900001,a,7],[900002,b,2]]){
    await window.d1BoundLogin(owner);
    const p=await window.d1BoundProof(owner);
    const s=await api.admitBound(owner,window.d1BoundEpoch(),p,secret);
    const page=await s.readJournal(revision,t,t+100,50,0);
    const audit=await s.auditSnapshot();
    if(owner===900001){
      const repeat=await s.deleteGlucose(5,u);
      if(!repeat.replay||!repeat.deleted||repeat.revision!==7)throw new Error('Deletion replay mismatch');
      let rejected=false;
      try{await s.insertGlucose(7,u,120.25,'mg/dL',t);}catch(e){rejected=String(e).includes('Measurement UUID deleted');}
      if(!rejected)throw new Error('Restart resurrection');
    }
    result.push({revision:page.revision,values:page.rows.map(x=>x.mgDl),
      tombstones:audit.tables.d1_fixture_deleted_glucose?.length??0});
    await s.retire();
  }
  const db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('iamina-d1-admission-probe-v1',1);
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(new Error('Store unavailable'));
  });
  try{
    const records=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly'),st=tx.objectStore('state');
      const x=st.get('owner:900001'),y=st.get('owner:900002'),keys=st.getAllKeys();
      tx.oncomplete=()=>resolve({x:x.result,y:y.result,keys:keys.result});tx.onabort=reject;
    });
    const check=ok=>{if(!ok)throw new Error('Unexpected durable storage');};
    const enc=x=>new TextEncoder().encode(x);
    const raw=x=>Uint8Array.from(x.match(/../g),y=>parseInt(y,16));
    const needles=[enc(u),enc(v),enc('d1_fixture_deleted_glucose'),enc('SQLite format 3'),enc(a),enc(b),raw(a),raw(b)];
    check(JSON.stringify(records.keys.sort())==='["fence","owner:900001","owner:900002"]');
    for(const rec of [records.x,records.y]){
      check(Object.keys(rec).sort().join(',')==='archive,envelope,revision');
      for(const bytes of [rec.archive,rec.envelope])
        check(bytes instanceof Uint8Array&&!needles.some(n=>bytes.some((_,i)=>n.every((x,j)=>bytes[i+j]===x))));
    }
    check(JSON.stringify((await indexedDB.databases()).map(x=>x.name).sort())==='["iamina-d1-admission-probe-v1"]');
    check(!localStorage.length&&!sessionStorage.length&&!(await caches.keys()).length);
    if(navigator.storage?.getDirectory){
      const root=await navigator.storage.getDirectory();
      for await(const _ of root.values())throw new Error('Unexpected OPFS file');
    }
  }finally{db.close();}
  return result;
}"""


def exercise_journal_change(browser_type,profile,locale,origin):
    secrets=None
    stage="bootstrap"
    try:
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            secrets=page.evaluate(I5_CROSS_BOOT)
            stage="journal-change"
            result=page.evaluate(I5_JOURNAL_CHANGE,{"a":secrets[0],"b":secrets[1]})
            assert result=={"invalidRefused":True,"staleRefused":True,"editPrecommitUnchanged":True,
                "editAck":True,"editNoOp":True,"editLostAck":True,"deletePrecommitUnchanged":True,
                "deleteLostAck":True,"deleteAck":True,"noResurrection":True,
                "otherTablesUnchanged":True,"ownerIsolation":True,
                "futureRevisionRefused":True,"editFieldsPreserved":True}
            assert not blocked and not errors
        finally:
            ctx.close()
        stage="restart-storage"
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
        try:
            restored=page.evaluate(I5_JOURNAL_CHANGE_RESTART,{"a":secrets[0],"b":secrets[1]})
            assert restored==[{"revision":7,"values":[],"tombstones":2},
                {"revision":2,"values":[211.25],"tombstones":0}]
            assert not blocked and not errors
        finally:
            ctx.close()
        return {**result,"restart":True,"noKnownPlaintext":True}
    except Exception:
        raise RuntimeError("D1 journal change qualification failed at "+stage) from None
    finally:
        secrets=None


UI_MOUNT = r"""async (arabic)=>{
  const api=await import('/d1_admission_candidate.mjs');
  const {generatePossessionSecret}=await import('/d1_possession_candidate.mjs');
  const secrets=new Map();
  for(const owner of [900001,900002]){
    const secret=generatePossessionSecret();secrets.set(owner,secret);
    const bootstrap=await api.enroll(owner,1,api.syntheticProof(owner,{identityVerified:true,unlocked:true,epoch:1}),secret);
    await bootstrap.retire();
  }
  let active=null, binding=null, generation=0, lastRequest=0, retired=()=>{};
  const start=1,end=4102444800,limit=10;
  let currentOffset=0,nextOffset=null,currentRevision=null;
  const sentinel='ac123456-1234-4abc-8def-000000000099';
  const sameBinding=(a,b)=>a&&b&&['owner','epoch','identityGeneration','session','vault'].every(k=>a[k]===b[k]);
  const clear=()=>{generation++;active=null;binding=null;currentOffset=0;nextOffset=null;currentRevision=null;retired();};
  const lock=()=>{clear();try{window.d1BoundLock();}catch(_){/* no fixture auth initialized yet */}};
  const check=(g)=>{if(g!==generation)throw Error('UI authority retired');};
  const call=async(action,json)=>{
    const args=JSON.parse(json);
    const g=generation;
    try{
      if(!Number.isSafeInteger(args.requestId)||args.requestId<=lastRequest||
         !Number.isSafeInteger(args.generation)||args.generation<0||
         !Number.isSafeInteger(args.session)||args.session<=0)throw Error('Invalid request correlation');
      lastRequest=args.requestId;
      if(args.start!==start||args.end!==end||args.limit!==limit||!Number.isSafeInteger(args.offset)||
         args.offset<0||args.offset>10000||args.offset%limit!==0||
         (action!=='page'&&args.offset!==0))throw Error('Invalid journal coordinates');
      if(action==='open'){
        if(active||args.binding!==null||args.session!==args.requestId||
           ![900001,900002].includes(args.owner))throw Error('Invalid fixture');
        const target=args.owner;
        await window.d1BoundLogin(target);check(g);
        const proof=await window.d1BoundProof(target);check(g);
        const epoch=window.d1BoundEpoch(), identityGeneration=window.d1BoundIdentityGeneration();
        if(!Number.isSafeInteger(identityGeneration)||identityGeneration<0)throw Error('Identity required');
        const session=await api.admitBoundClinical(target,epoch,proof,secrets.get(target),
          ()=>{if(g===generation)lock();});
        if(g!==generation){await session.retire();throw Error('UI authority retired');}
        active=session;
        binding=Object.freeze({owner:target,epoch,identityGeneration,session:args.session,
          vault:'amina_vault_v1_native_'+target});
      }else{
        if(!active||!binding||args.owner!==binding.owner||args.session!==binding.session||
           !sameBinding(args.binding,binding)||!Number.isSafeInteger(args.revision)||args.revision!==currentRevision)throw Error('UI authority required');
        if(action==='page'&&!(args.offset===nextOffset||currentOffset>0&&args.offset===currentOffset-limit))
          throw Error('Invalid page navigation');
      }
      const session=active, expected=binding;
      const live=()=>{
        check(g);
        if(active!==session||binding!==expected||window.d1BoundEpoch()!==expected.epoch||
           window.d1BoundIdentityGeneration()!==expected.identityGeneration)throw Error('UI binding retired');
      };
      live();
      let ack=null;
      if(action==='insert'||action==='edit'){
        if(!Number.isSafeInteger(args.loggedAtSeconds)||args.loggedAtSeconds<start||
           args.loggedAtSeconds>=end||args.loggedAtSeconds>Math.floor(Date.now()/1000))throw Error('Invalid measurement instant');
        if(action==='insert')ack=await session.insertEvidence(args.revision,crypto.randomUUID(),args.value,args.unit,args.loggedAtSeconds);
        else{
          const existing=await session.readEvidence(args.uuid);live();
          if(existing.revision!==args.revision||existing.evidence?.loggedAtSeconds!==args.loggedAtSeconds)
            throw Error('Measurement instant changed');
          ack=await session.editEvidence(args.revision,args.uuid,args.value,args.unit,args.loggedAtSeconds);
          if(ack.evidence.createdAtSeconds!==existing.evidence.createdAtSeconds)throw Error('Creation instant changed');
        }
      }else if(action==='delete')ack=await session.deleteEvidence(args.revision,args.uuid);
      else if(action!=='open'&&action!=='page')throw Error('Unsupported UI action');
      live();
      const revision=(await session.readEvidence(sentinel)).revision;live();
      if(action==='page'&&revision!==args.revision)throw Error('Checkpoint conflict');
      if(action!=='open'&&action!=='page'&&(ack?.revision!==args.revision+1||revision!==ack.revision))throw Error('Mutation ACK mismatch');
      const journal=await session.readEvidenceJournal(revision,start,end,limit,args.offset);live();
      if(journal.revision!==revision)throw Error('Fixture journal mismatch');
      currentRevision=revision;currentOffset=args.offset;nextOffset=journal.nextOffset;
      return JSON.stringify({binding:expected,generation:args.generation,requestId:args.requestId,revision,
        start,end,limit,offset:currentOffset,nextOffset,rows:journal.rows});
    }catch(_){
      if(g===generation)lock();
      throw Error('UI operation refused');
    }
  };
  window.d1MountEvidenceUi(call,lock,cb=>{retired=cb;},arabic);
}"""


def exercise_evidence_ui(browser_type, profile, locale, origin, width, height, font_witness):
    from PIL import Image
    from playwright.sync_api import expect
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    proof.mkdir(parents=True,exist_ok=True)
    import re
    from urllib.parse import urlsplit
    stage="before-navigation"
    frames=[]
    local_fonts=[]
    local_font_failures=[]
    def trace(kind, payload):
        record={"engine":ENGINE,"locale":locale,"width":width,"stage":stage,"event":kind}
        try:
            if kind=="blocked":
                u=urlsplit(payload.url)
                record["resourceType"]=payload.resource_type
                # Public, immutable font paths only; reject arbitrary URLs and queries.
                if (u.hostname=="fonts.gstatic.com" and not u.query and not u.fragment
                    and re.fullmatch(r"/s/[a-z0-9]{1,80}/v[0-9]{1,4}/[A-Za-z0-9_.-]{1,220}\.(?:woff2?|ttf|otf)",u.path)):
                    record["fontPath"]=u.path
                elif u.hostname in ("fonts.gstatic.com","fonts.googleapis.com"):
                    record["fontHost"]=u.hostname
                    record["pathDigest"]=hashlib.sha256(u.path.encode()).hexdigest()
                else:
                    record["category"]="other-blocked"
            elif kind in ("response","requestfailed"):
                u=urlsplit(payload.url)
                prefix="/assets/engine-font-fallback/"
                if not payload.url.startswith(origin+"/") or not u.path.startswith(prefix):
                    return
                relative=u.path[len(prefix):]
                known=relative in (
                    "notosanssymbols/v43/rP2up3q65FkAtHfwd-eIS2brbDN6gxP34F9jRRCe4W3gfQ8gb_VFRkzrbQ.woff2",
                    "notosansarabic/v28/nwpxtLGrOAZMl5nJ_wfgRg3DrWFZWsnVBJ_sS6tlqHHFlhQ5l3sQWIHPqzCfyGyvvnCBFQLaig.woff2",
                )
                ok=kind=="response" and payload.status==200 and known
                record["localFont"]=relative.split("/")[0] if known else "unknown"
                record["status"]=payload.status if kind=="response" else "requestfailed"
                (local_fonts if ok else local_font_failures).append(record["localFont"])
            elif kind=="pageerror":
                message=str(payload)
                stack=getattr(payload,"stack","") or ""
                record["messageDigest"]=hashlib.sha256(message.encode()).hexdigest()
                record["errorName"]=getattr(payload,"name","") if getattr(payload,"name","") in (
                    "Error","TypeError","ReferenceError","RangeError","SyntaxError","RuntimeError","AbortError",
                    "InvalidStateError","SecurityError","NotSupportedError") else "other"
                markers=("undefined is not an object","null is not an object","can't find variable",
                    "not a function","out of bounds","memory access","out of memory","stack overflow",
                    "wasm","webassembly","canvas","webgl","context lost","failed to fetch","networkerror",
                    "load failed","null check","disposed","unexpected null","resizeobserver",
                    "aborterror","invalidstateerror","securityerror","not supported")
                record["markers"]=[m for m in markers if m in message.lower()]
                record["frames"]=[{"file":a,"line":int(b),"column":int(c)}
                    for a,b,c in re.findall(r"(main\.dart\.js|flutter_bootstrap\.js|canvaskit\.js|skwasm\.js):(\d+):(\d+)",stack)[:8]]
            elif kind=="console":
                message=payload.text
                if not re.search(r"font|glyph",message,re.IGNORECASE):
                    return
                # Only numeric Unicode identifiers; no raw console text.
                record["codepoints"]=re.findall(r"\bU\+[0-9A-Fa-f]{4,6}\b",message)[:32]
                record["markers"]=[m for m in ("fallback","missing","glyph","failed","download")
                    if m in message.lower()]
                if not record["markers"] and not record["codepoints"]:
                    return
            print("D1_D5_UI_TRACE "+json.dumps(record,ensure_ascii=False),flush=True)
        except Exception:
            # Diagnostics must not change the qualification or network policy.
            pass
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin,trace=trace)
    stage="before"
    def shot(name):
        path=proof/f"conv-ui-{ENGINE}-{locale}-{width}-{name}.png"
        page.screenshot(path=str(path),animations="disabled",timeout=15000)
        with Image.open(path) as im:
            rgb=im.convert("RGB")
            assert rgb.size==(width,height)
            assert len(rgb.getcolors(width*height) or [])>50
        frames.append({"name":name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"file":path.name})
    def semantics():
        page.wait_for_selector("flutter-view, flt-glass-pane",timeout=60000)
        placeholder=page.locator("flt-semantics-placeholder")
        if placeholder.count():
            placeholder.evaluate("(el)=>el.click()")
    ar=locale=="ar-MA"
    def label(fr,arabic):
        return arabic if ar else fr
    def text(fr,arabic):
        return page.get_by_text(label(fr,arabic),exact=True).first
    def click(fr,arabic):
        target=text(fr,arabic)
        expect(target).to_be_visible(timeout=20000)
        target.click(timeout=20000)
    def control(identifier):
        target=page.locator(f'[flt-semantics-identifier="{identifier}"]')
        expect(target).to_have_count(1,timeout=15000)
        expect(target).to_be_visible(timeout=15000)
        return target
    def tap(identifier):
        target=control(identifier)
        target.scroll_into_view_if_needed(timeout=10000)
        rect=target.bounding_box(timeout=10000)
        assert rect and rect["width"]>0 and rect["height"]>0
        # Text entry was proven on R1; preserve its real pointer/focus path.
        if identifier == "evidence-value":
            page.mouse.click(rect["x"]+rect["width"]/2,rect["y"]+rect["height"]/2)
        else:
            # Use Playwright actionability/hit testing rather than an unchecked
            # pointer at the semantic wrapper's center. Never force or dispatch.
            target.click(timeout=10000)
    def diagnostic():
        result={}
        for identifier in ("evidence-value","evidence-save","evidence-mmoll","evidence-input-error"):
            node=page.locator(f'[flt-semantics-identifier="{identifier}"]')
            info={"count":node.count()}
            if info["count"] == 1:
                info.update({"visible":node.is_visible(),"bounds":node.bounding_box(timeout=1000)})
                info["semantics"]=node.evaluate("""el=>{
                    const r=el.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;
                    let hit=document.elementFromPoint(x,y);
                    while(hit?.shadowRoot?.elementFromPoint){
                        const inner=hit.shadowRoot.elementFromPoint(x,y);
                        if(!inner||inner===hit)break;
                        hit=inner;
                    }
                    return {role:el.getAttribute('role'),pointerEvents:getComputedStyle(el).pointerEvents,
                        hitTag:hit?.tagName??null,hitRole:hit?.getAttribute('role')??null,
                        hitIdentifier:hit?.getAttribute('flt-semantics-identifier')??null};
                }""")
            result[identifier]=info
        result["refusalTextCount"]=text("Saisie ou opération refusée.","تم رفض الإدخال أو العملية.").count()
        result["emptyJournalCount"]=text("Aucune mesure explicite","لا توجد قياسات صريحة").count()
        result["nativeFocusCount"]=page.locator("input:focus, textarea:focus").count()
        result["lockedCount"]=text("Coffre verrouillé","المخزن مقفل").count()
        result["blockedCount"]=len(blocked)
        result["pageErrorCount"]=len(errors)
        # Fixed allowlist categories only: no raw URL, query, error or identifier.
        from urllib.parse import urlsplit
        def blocked_kind(url):
            u=urlsplit(url)
            if u.hostname in ("fonts.gstatic.com","fonts.googleapis.com"):
                return "external-font"
            if u.hostname in ("127.0.0.1","localhost"):
                return "local-api" if "/api/" in u.path else "local-other"
            return "other-external"
        def error_kind(error):
            for needle, category in (
                ("ResizeObserver","resize-observer"),("Unexpected null","unexpected-null"),
                ("Null check operator","null-check"),("disposed","disposed"),
                ("StateError","state-error"),("TypeError","type-error"),
                ("Failed to fetch","fetch-failure"),("Script error","script-error")):
                if needle.lower() in error.lower():
                    return category
            return "unclassified"
        result["blockedKinds"]=sorted(set(blocked_kind(u) for u in blocked))
        result["pageErrorKinds"]=sorted(set(error_kind(e) for e in errors))
        return result
    def enter(value):
        nonlocal stage
        prefix=stage
        stage=prefix+"-focus"
        tap("evidence-value")
        # Flutter Web's native text editing element may be inside a shadow root.
        # Require exactly one focused editor before sending real keyboard events.
        native=page.locator("input:focus, textarea:focus")
        expect(native).to_have_count(1,timeout=10000)
        stage=prefix+"-replace"
        native.press("ControlOrMeta+a",timeout=10000)
        native.press_sequentially(value,delay=60,timeout=10000)
        stage=prefix+"-value"
        try:
            expect(native).to_have_count(1,timeout=10000)
            expect(native).to_have_value(value,timeout=10000)
        finally:
            # Synthetic-only, bounded metadata: never print actual input text.
            try:
                current=native.input_value(timeout=1000) if native.count()==1 else None
                print("D1_D5_INPUT_DIAG "+json.dumps({
                    "engine":ENGINE,"locale":locale,"width":width,"stage":stage,
                    "focusedCount":native.count(),"length":len(current) if current is not None else None,
                    "matchesExpected":current==value,
                }),flush=True)
            except Exception:
                pass
    try:
        page.set_viewport_size({"width":width,"height":height})
        semantics()
        expect(page.get_by_text("D1-I1 synthetic Drift checkpoint probe",exact=True)).to_be_visible(timeout=20000)
        page.wait_for_timeout(350)
        shot("before-probe")
        stage="mount"
        page.evaluate(UI_MOUNT,ar)
        semantics()
        expect(text("Coffre verrouillé","المخزن مقفل")).to_be_visible(timeout=20000)
        page.wait_for_timeout(350)
        shot("after-locked")
        stage="open"
        click("Ouvrir profil A","فتح الملف A")
        expect(text("Aucune mesure explicite","لا توجد قياسات صريحة")).to_be_visible(timeout=20000)
        stage="insert-native-input"
        enter("7.83")
        stage="insert-no-unit-click"
        print("D1_D5_UI_DIAG "+json.dumps({"engine":ENGINE,"locale":locale,"width":width,
            "stage":"before-no-unit-click","state":diagnostic()},ensure_ascii=False),flush=True)
        tap("evidence-save")
        stage="insert-no-unit-refusal-visible"
        expect(text("Saisie ou opération refusée.","تم رفض الإدخال أو العملية.")).to_be_visible(timeout=10000)
        stage="insert-no-unit-journal-empty"
        expect(text("Aucune mesure explicite","لا توجد قياسات صريحة")).to_be_visible()
        print("D1_D5_UI_DIAG "+json.dumps({"engine":ENGINE,"locale":locale,"width":width,
            "stage":"after-no-unit-refusal","state":diagnostic()},ensure_ascii=False),flush=True)
        stage="insert-unit"
        tap("evidence-mmoll")
        expect(text("Saisie ou opération refusée.","تم رفض الإدخال أو العملية.")).to_have_count(0,timeout=10000)
        stage="insert-commit"
        tap("evidence-save")
        expect(page.get_by_text("7.83 mmol/L",exact=True)).to_be_visible(timeout=20000)
        stage="insert-projection"
        expect(page.get_by_text("141 mg/dL · 7.8 mmol/L",exact=True)).to_be_visible(timeout=20000)
        page.wait_for_timeout(350)
        shot("after-form-journal")
        stage="edit-open"
        click("Modifier","تعديل")
        stage="edit-native-input"
        enter("8.2")
        stage="edit-commit"
        tap("evidence-save")
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible(timeout=20000)
        stage="lock"
        page.evaluate("window.d1BoundLock()")
        expect(text("Coffre verrouillé","المخزن مقفل")).to_be_visible(timeout=20000)
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_have_count(0)
        stage="other-owner"
        click("Ouvrir profil B","فتح الملف B")
        expect(text("Aucune mesure explicite","لا توجد قياسات صريحة")).to_be_visible(timeout=20000)
        click("Verrouiller","قفل")
        click("Ouvrir profil A","فتح الملف A")
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible(timeout=20000)
        stage="delete-open"
        click("Supprimer","حذف")
        expect(text("Confirmer la suppression","تأكيد الحذف")).to_be_visible()
        stage="delete-cancel"
        click("Conserver","احتفاظ")
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible()
        stage="delete-confirm"
        click("Supprimer","حذف")
        click("Confirmer la suppression","تأكيد الحذف")
        stage="delete-journal-empty"
        expect(text("Aucune mesure explicite","لا توجد قياسات صريحة")).to_be_visible(timeout=20000)
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_have_count(0)
        shot("after-delete")
        stage="final-lock"
        click("Verrouiller","قفل")
        expect(text("Coffre verrouillé","المخزن مقفل")).to_be_visible(timeout=20000)
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_have_count(0)
        stage="final-egress"
        assert not blocked
        stage="final-pageerror"
        assert not errors
        stage="final-local-font"
        expected_font = "notosansarabic" if ar else "notosanssymbols"
        # Bounded observation only; no retry, reload or synthetic font fetch.
        for _ in range(20):
            if expected_font in font_witness:
                break
            page.wait_for_timeout(100)
        print("D1_D5_FONT_WITNESS "+json.dumps({
            "engine":ENGINE,"locale":locale,"width":width,"expected":expected_font,
            "browserResponses":sorted(set(local_fonts)),
            "browserFailures":sorted(set(local_font_failures)),
            "serverCompletedGets":sorted(set(font_witness)),
        }),flush=True)
        assert not blocked and not errors
        assert not local_font_failures
        # A lazy engine fallback need not request a font in every viewport.
        # Require actual spontaneous family coverage across the full matrix below.
        # The separate H4 probe explicitly decodes and paints both WOFF2 assets.
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "viewport":[width,height],"frames":frames,"localFonts":sorted(set(font_witness)),
                "browserLocalFonts":sorted(set(local_fonts)),
                "expectedLocalFont":expected_font,
                "spontaneousFontGet":expected_font in font_witness,
                "blockedRequests":len(blocked),"pageErrors":len(errors),"result":"PASS"}
    except Exception as failure:
        # Diagnostic metadata is limited to the synthetic form's known controls;
        # never emit raw exception messages, arbitrary DOM text or secrets.
        try:
            print("D1_D5_UI_DIAG "+json.dumps({"engine":ENGINE,"locale":locale,"width":width,
                "stage":stage,"exceptionType":type(failure).__name__,"state":diagnostic()},
                ensure_ascii=False),flush=True)
        except Exception as diagnostic_failure:
            print("D1_D5_UI_DIAG "+json.dumps({"engine":ENGINE,"locale":locale,"width":width,
                "stage":stage,"exceptionType":type(failure).__name__,
                "diagnosticExceptionType":type(diagnostic_failure).__name__}),flush=True)
        # All data in this isolated profile is synthetic. Preserve an actual
        # failure frame without printing browser exceptions or secrets.
        try:
            page.screenshot(path=str(proof/f"conv-ui-{ENGINE}-{locale}-{width}-failure-{stage}.png"),
                            animations="disabled",timeout=10000)
        except Exception:
            pass
        raise RuntimeError("D1 D5 UI qualification failed stage="+stage+" viewport="+str(width)) from None
    finally:
        ctx.close()


def run():
    assert ENGINE in ("chromium", "webkit")
    assert (WEB / "main.dart.js").stat().st_size > 1000
    results = []
    with tempfile.TemporaryDirectory(prefix="d1-runtime-") as root:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server, \
             http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as legacy_server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            threading.Thread(target=legacy_server.serve_forever, daemon=True).start()
            origin = f"http://127.0.0.1:{server.server_port}"
            legacy_origin = f"http://127.0.0.1:{legacy_server.server_port}"
            try:
                with sync_playwright() as pw:
                    browser_type = getattr(pw, ENGINE)
                    for locale in ("fr-FR", "ar-MA"):
                        record = dict(source_sha=os.environ["EXPECTED_SHA"], engine=ENGINE, locale=locale,
                                      sqlite3_wasm_sha256=hashlib.sha256((WEB/"sqlite3.wasm").read_bytes()).hexdigest(),
                                      build_sha256=hashlib.sha256((WEB/"main.dart.js").read_bytes()).hexdigest())
                        profile = Path(root)/locale
                        try:
                            ctx, page, blocked, errors = open_context(browser_type, profile, locale, origin)
                            try:
                                record["first"] = page.evaluate(FIRST)
                                assert not blocked and not errors, (blocked,errors)
                                # Real page reload, no application teardown checkpoint.
                                page.reload(wait_until="domcontentloaded")
                                page.wait_for_function("typeof window.d1Inspect === 'function'", timeout=60000)
                                record["reload"] = page.evaluate(RESTORE)
                                assert not blocked and not errors, (blocked,errors)
                            finally:
                                ctx.close()
                            ctx, page, blocked, errors = open_context(browser_type, profile, locale, origin)
                            try:
                                record["restart"] = page.evaluate(RESTORE)
                                assert not blocked and not errors, (blocked,errors)
                                record["i2"] = exercise_i2(ctx,page,origin,errors)
                                assert not blocked and not errors, (blocked,errors)
                            finally:
                                ctx.close()
                            ctx,page,blocked,errors = open_context(browser_type,profile,locale,origin)
                            try:
                                record["i2_restart"] = inspect_i2(page,6,record["i2"]["operations"])
                                assert not blocked and not errors, (blocked,errors)
                            finally:
                                ctx.close()
                            i3_profile = Path(root)/(locale+"-admission")
                            ctx,page,blocked,errors = open_context(browser_type,i3_profile,locale,origin)
                            try:
                                record["i3"] = exercise_i3(ctx,page,origin,errors)
                                assert not blocked and not errors, (blocked,errors)
                            finally:
                                ctx.close()
                            ctx,page,blocked,errors = open_context(browser_type,i3_profile,locale,origin)
                            try:
                                record["i3_restart"] = restore_i3(page)
                                assert not blocked and not errors, (blocked,errors)
                            finally:
                                ctx.close()
                            i4_profile=Path(root)/(locale+"-migration")
                            ctx,page,blocked,errors=open_context(browser_type,i4_profile,locale,origin,legacy_origin)
                            try:
                                record["i4"]=exercise_i4(ctx,page,legacy_origin,errors)
                                assert not blocked and not errors,(blocked,errors)
                            finally:
                                ctx.close()
                            ctx,page,blocked,errors=open_context(browser_type,i4_profile,locale,origin,legacy_origin)
                            try:
                                record["i4_restart"]=restore_i4(ctx,page,legacy_origin,errors,record["i4"])
                                assert not blocked and not errors,(blocked,errors)
                            finally:
                                ctx.close()
                            record["i5_possession"]=exercise_possession(browser_type,Path(root)/(locale+"-possession"),locale,origin)
                            record["i5_bound"]=exercise_bound(browser_type,Path(root)/(locale+"-bound"),locale,origin)
                            record["i5_cross_revocation"]=exercise_cross_revocation(browser_type,Path(root)/(locale+"-cross-revoke"),locale,origin)
                            record["i5_revocation_failure"]=exercise_revocation_failure(browser_type,Path(root)/(locale+"-revoke-fault"),locale,origin)
                            record["i5_cross_hints"]=exercise_cross_hints(browser_type,Path(root)/(locale+"-cross-hints"),locale,origin)
                            record["i5_clinical_store"]=exercise_clinical_store(browser_type,Path(root)/(locale+"-clinical-store"),locale,origin)
                            record["i5_glucose_store"]=exercise_glucose_store(browser_type,Path(root)/(locale+"-glucose-store"),locale,origin)
                            record["i5_journal"]=exercise_journal(browser_type,Path(root)/(locale+"-journal"),locale,origin)
                            record["i5_journal_change"]=exercise_journal_change(browser_type,Path(root)/(locale+"-journal-change"),locale,origin)
                            record["result"] = "PASS"
                        except Exception as error:
                            record.update(result="FAIL", error=str(error)[:1500])
                        results.append(record)
                        print("D1_RUNTIME " + json.dumps(record,ensure_ascii=False),flush=True)
            finally:
                server.shutdown()
                legacy_server.shutdown()
    assert len(results)==2 and all(x["result"]=="PASS" for x in results), "D1 actual Drift encrypted checkpoint failed"
    print("D1_RUNTIME_PASS 2/2",flush=True)
    print("D1_I2_DURABLE_MUTATION_PASS 2/2",flush=True)
    print("D1_I3_ADMISSION_FENCE_PASS 2/2",flush=True)
    print("D1_I4_COPY_MIGRATION_PASS 2/2",flush=True)
    print("D1_I5_POSSESSION_PASS 2/2",flush=True)
    print("D1_I5_BOUND_ADMISSION_PASS 2/2",flush=True)
    print("D1_I5D_CLINICAL_PORT_PASS 2/2",flush=True)
    print("D1_D5_EXPLICIT_EVIDENCE_PASS 2/2",flush=True)
    print("D1_D5_EVIDENCE_MUTATION_PASS 2/2",flush=True)
    print("D1_D5_EVIDENCE_RESTART_PASS 2/2",flush=True)
    print("D1_D5_EVIDENCE_JOURNAL_PASS 2/2",flush=True)
    print("D1_I5_PROACTIVE_REVOCATION_PASS 2/2",flush=True)
    print("D1_I5_REVOCATION_FAULT_PASS 2/2",flush=True)
    print("D1_I5_CROSS_HINTS_PASS 2/2",flush=True)
    print("D1_I5_CLINICAL_STORE_PASS 2/2",flush=True)
    print("D1_I5_CLINICAL_STORAGE_PASS 2/2",flush=True)
    print("D1_I5_GLUCOSE_STORE_PASS 2/2",flush=True)
    print("D1_I5_JOURNAL_PASS 2/2",flush=True)
    print("D1_I5_JOURNAL_CHANGE_PASS 2/2",flush=True)


def run_evidence_ui():
    from contextlib import ExitStack
    assert ENGINE in ("chromium","webkit")
    assert os.environ["GITHUB_HEAD_REF"]=="phase2/d1-d5-convergence"
    records=[]
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    proof.mkdir(parents=True,exist_ok=True)
    cases=[(width,height,locale) for width,height in ((390,844),(430,932),(1280,860))
           for locale in ("fr-FR","ar-MA")]
    with tempfile.TemporaryDirectory(prefix="d1-ui-") as root, ExitStack() as stack:
        # Bind every origin before running any case, so no port can be reused.
        servers=[stack.enter_context(http.server.ThreadingHTTPServer(
            ("127.0.0.1",0),FontWitnessHandler)) for _ in cases]
        assert len({server.server_port for server in servers})==len(cases)
        try:
            with sync_playwright() as pw:
                browser_type=getattr(pw,ENGINE)
                for (width,height,locale),server in zip(cases,servers):
                    server.font_witness=[]
                    thread=threading.Thread(target=server.serve_forever,daemon=True)
                    thread.start()
                    origin=f"http://127.0.0.1:{server.server_port}"
                    try:
                        try:
                            record=exercise_evidence_ui(browser_type,Path(root)/f"ui-{locale}-{width}",locale,
                                                        origin,width,height,server.font_witness)
                        except Exception as error:
                            record={"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                                    "viewport":[width,height],"result":"FAIL","error":str(error)[:200],
                                    "serverCompletedFontGets":sorted(set(server.font_witness))}
                        records.append(record)
                        print("D1_D5_UI "+json.dumps(record,ensure_ascii=False),flush=True)
                    finally:
                        server.shutdown()
                        thread.join(timeout=5)
        finally:
            (proof/f"conv-ui-{ENGINE}-matrix.json").write_text(json.dumps(records,ensure_ascii=False))
    assert len(records)==6 and all(r["result"]=="PASS" for r in records),"D1 D5 UI matrix failed"
    for locale,family in (("fr-FR","notosanssymbols"),("ar-MA","notosansarabic")):
        matching=[r for r in records if r["locale"]==locale and r["expectedLocalFont"]==family
                  and r["spontaneousFontGet"] and family in r["localFonts"]]
        print("D1_D5_SPONTANEOUS_FONT_COVERAGE "+json.dumps({
            "engine":ENGINE,"locale":locale,"family":family,"observed":len(matching),"cases":3,
        }),flush=True)
        assert matching, "No spontaneous engine fallback request for "+family
    print("D1_D5_EVIDENCE_UI_PASS 6/6",flush=True)


def exercise_h1_ui(browser_type, profile, locale, origin, width, height):
    from PIL import Image
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    frames=[]
    stage="navigation"
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
    try:
        page.set_viewport_size({"width":width,"height":height})
        stage="mount"
        page.evaluate("""ar=>{
          window.__h1Fixture=null;
          window.d1MountH1Trend(ar, value=>{window.__h1Fixture=JSON.parse(value);});
        }""", locale=="ar-MA")
        page.wait_for_function("window.__h1Fixture !== null", timeout=20000)
        initial=page.evaluate("window.__h1Fixture")
        assert initial["selections"]==[]
        left,top,w,h=(initial[k] for k in ("left","top","width","height"))
        assert 0<=left and 0<=top and left+w<=width+1 and top+h<=height+1
        assert w>100 and abs(h-250)<1
        def shot(name):
            path=proof/f"h1-web-{ENGINE}-{locale}-{width}-{name}.png"
            page.screenshot(path=str(path),animations="disabled",timeout=15000)
            with Image.open(path) as im:
                rgb=im.convert("RGB")
                assert rgb.size==(width,height)
                assert len(rgb.getcolors(width*height) or [])>50
            frames.append({"file":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
        def tap(day):
            # Independent expected elapsed-time geometry; no JS event injection.
            page.mouse.click(left+46+(w-56)*day/7,top+100)
        def selected(expected):
            page.wait_for_function("(expected)=>JSON.stringify(window.__h1Fixture.selections)===JSON.stringify(expected)",arg=expected,timeout=10000)
        shot("initial")
        stage="day1"
        tap(.5)
        selected([1])
        stage="day2"
        tap(1.5)
        selected([1,4])
        stage="empty-day"
        tap(2.5)
        stage="day5"
        tap(4.5)
        selected([1,4,6])
        stage="axis-margin"
        page.mouse.click(left+10,top+100)
        # Flush frames; then a positive click proves the event queue continued.
        page.wait_for_timeout(150)
        tap(.5)
        selected([1,4,6,1])
        shot("selected")
        stage="egress-and-errors"
        assert not blocked and not errors
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "viewport":[width,height],"selections":[1,4,6,1],"blockedRequests":0,
                "pageErrors":0,"frames":frames,"result":"PASS"}
    except Exception as error:
        path=proof/f"h1-web-{ENGINE}-{locale}-{width}-failure.png"
        try:
            page.screenshot(path=str(path),timeout=5000)
        except Exception:
            pass
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "viewport":[width,height],"stage":stage,"errorType":type(error).__name__,
                "blockedRequests":len(blocked),"pageErrors":len(errors),"result":"FAIL"}
    finally:
        ctx.close()


def run_h1_ui():
    assert ENGINE in ("chromium","webkit")
    assert os.environ["GITHUB_HEAD_REF"]=="phase2/d1-d5-convergence"
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    proof.mkdir(parents=True,exist_ok=True)
    records=[]
    with tempfile.TemporaryDirectory(prefix="h1-ui-") as root:
        with http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler) as server:
            threading.Thread(target=server.serve_forever,daemon=True).start()
            origin=f"http://127.0.0.1:{server.server_port}"
            try:
                with sync_playwright() as pw:
                    browser_type=getattr(pw,ENGINE)
                    for width,height in ((390,844),(430,932),(1280,860)):
                        for locale in ("fr-FR","ar-MA"):
                            try:
                                record=exercise_h1_ui(browser_type,Path(root)/f"h1-{locale}-{width}",locale,origin,width,height)
                            except Exception as error:
                                record={"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,
                                        "locale":locale,"viewport":[width,height],"stage":"navigation",
                                        "errorType":type(error).__name__,"result":"FAIL"}
                            records.append(record)
                            print("H1_WEB "+json.dumps(record),flush=True)
            finally:
                server.shutdown()
                (proof/f"h1-web-{ENGINE}-matrix.json").write_text(json.dumps(records))
    assert len(records)==6 and all(r["result"]=="PASS" for r in records),"H1 Web matrix failed"
    print("H1_WEB_PASS 6/6",flush=True)



# Fault injection exists only in this synthetic Playwright fixture.
# Wrap the actual bridge AFTER genuine admission/read or durable mutation.
_H2_MOUNT_ANCHOR = "window.d1MountEvidenceUi(call,lock,cb=>{retired=cb;},arabic);"
_H2_MOUNT_WRAPPER = r"""
  let mode='normal', savedB=null, pending=null, held=false, delivered=false;
  const wrapper=async(action,json)=>{
    const args=JSON.parse(json);
    const selected=mode;
    const raw=await call(action,json);
    const response=JSON.parse(raw);
    if(selected==='recordB'&&action==='insert'&&args.owner===900002){
      if(response.binding.owner!==900002||response.rows.length!==1)
        throw Error('H2 invalid B fixture');
      savedB=response;mode='normal';
    }
    if(selected==='wrongOwner'&&action==='open'&&args.owner===900001){
      if(!savedB||response.binding.owner!==900001)throw Error('H2 fixture unavailable');
      mode='normal';
      // Genuine B rows and B owner/vault, but current A correlation coordinates.
      return JSON.stringify({...response,rows:savedB.rows,binding:{
        ...response.binding,owner:savedB.binding.owner,vault:savedB.binding.vault}});
    }
    if(selected==='holdAck'&&action==='insert'&&args.owner===900001){
      if(response.binding.owner!==900001||response.rows.length!==1||
         response.revision!==args.revision+1)throw Error('H2 invalid durable ACK');
      mode='normal';held=true;
      await new Promise(resolve=>{pending=resolve;});
      delivered=true;
    }
    return raw;
  };
  window.__h2Fixture=Object.freeze({
    setMode:value=>{
      if(!['recordB','wrongOwner','holdAck'].includes(value)||mode!=='normal')
        throw Error('Invalid fixture mode');
      mode=value;
    },
    ready:()=>savedB!==null,
    // Test-only synthetic fixture credential, transferred by the harness
    // to an independent document; never print or persist this value.
    replacementSecret:()=>secrets.get(900002),
    held:()=>held&&pending!==null,
    delivered:()=>delivered,
    release:()=>{if(pending===null)throw Error('No held ACK');const resume=pending;pending=null;resume();}
  });
  window.d1MountEvidenceUi(wrapper,lock,cb=>{retired=cb;},arabic);
"""
assert UI_MOUNT.count(_H2_MOUNT_ANCHOR)==1
H2_UI_MOUNT=UI_MOUNT.replace(_H2_MOUNT_ANCHOR,_H2_MOUNT_WRAPPER)


def exercise_h2_ui(browser_type, profile, locale, origin):
    from PIL import Image
    from playwright.sync_api import expect
    width,height=390,844
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    frames=[]
    stage="navigation"
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin)
    ar=locale=="ar-MA"
    def text(fr,arabic):
        return page.get_by_text(arabic if ar else fr,exact=True).first
    def click(fr,arabic):
        target=text(fr,arabic)
        expect(target).to_be_visible(timeout=20000)
        target.click(timeout=20000)
    def control(identifier):
        target=page.locator(f'[flt-semantics-identifier="{identifier}"]')
        expect(target).to_have_count(1,timeout=15000)
        expect(target).to_be_visible(timeout=15000)
        return target
    def semantics():
        page.wait_for_selector("flutter-view, flt-glass-pane",timeout=60000)
        placeholder=page.locator("flt-semantics-placeholder")
        if placeholder.count():
            placeholder.evaluate("(el)=>el.click()")
    def locked():
        expect(text("Coffre verrouillé","المخزن مقفل")).to_be_visible(timeout=20000)
        expect(page.get_by_text("7.83 mmol/L",exact=True)).to_have_count(0)
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_have_count(0)
    def enter(value):
        field=control("evidence-value")
        field.scroll_into_view_if_needed(timeout=10000)
        bounds=field.bounding_box(timeout=10000)
        assert bounds and bounds["width"]>0 and bounds["height"]>0
        page.mouse.click(bounds["x"]+bounds["width"]/2,bounds["y"]+bounds["height"]/2)
        native=page.locator("input:focus, textarea:focus")
        expect(native).to_have_count(1,timeout=10000)
        native.press("ControlOrMeta+a",timeout=10000)
        native.press_sequentially(value,delay=60,timeout=10000)
        expect(native).to_have_value(value,timeout=10000)
        control("evidence-mmoll").click(timeout=10000)
        control("evidence-save").click(timeout=10000)
    def shot(name):
        path=proof/f"h2-web-{ENGINE}-{locale}-{name}.png"
        page.screenshot(path=str(path),animations="disabled",timeout=15000)
        with Image.open(path) as im:
            rgb=im.convert("RGB")
            assert rgb.size==(width,height)
            assert len(rgb.getcolors(width*height) or [])>50
        frames.append({"file":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    try:
        page.set_viewport_size({"width":width,"height":height})
        semantics()
        stage="mount"
        page.evaluate(H2_UI_MOUNT,ar)
        semantics()
        locked()
        stage="prepare-real-B"
        click("Ouvrir profil B","فتح الملف B")
        expect(text("Aucune mesure explicite","لا توجد قياسات صريحة")).to_be_visible(timeout=20000)
        page.evaluate("window.__h2Fixture.setMode('recordB')")
        enter("8.2")
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible(timeout=20000)
        assert page.evaluate("window.__h2Fixture.ready()") is True
        shot("B-before")
        click("Verrouiller","قفل")
        locked()
        stage="wrong-owner-response"
        page.evaluate("window.__h2Fixture.setMode('wrongOwner')")
        click("Ouvrir profil A","فتح الملف A")
        expect(text("Saisie ou opération refusée.","تم رفض الإدخال أو العملية.")).to_be_visible(timeout=20000)
        locked()
        expect(text("Profil B","الملف B")).to_have_count(0)
        shot("wrong-owner-refused")
        stage="reopen-real-A"
        click("Ouvrir profil A","فتح الملف A")
        expect(text("Aucune mesure explicite","لا توجد قياسات صريحة")).to_be_visible(timeout=20000)
        page.evaluate("window.__h2Fixture.setMode('holdAck')")
        enter("7.83")
        stage="durable-ack-held"
        page.wait_for_function("window.__h2Fixture.held()",timeout=20000)
        expect(page.get_by_text("7.83 mmol/L",exact=True)).to_have_count(0)
        stage="revoke-and-switch"
        page.evaluate("window.d1BoundLock()")
        locked()
        click("Ouvrir profil B","فتح الملف B")
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible(timeout=20000)
        expect(text("Profil B","الملف B")).to_be_visible()
        stage="deliver-stale-ack"
        page.evaluate("window.__h2Fixture.release()")
        page.wait_for_function("window.__h2Fixture.delivered()",timeout=10000)
        # Flush the promise delivery and Flutter render frames, then inspect.
        page.evaluate("()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")
        page.wait_for_timeout(350)
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible()
        expect(page.get_by_text("7.83 mmol/L",exact=True)).to_have_count(0)
        expect(text("Profil B","الملف B")).to_be_visible()
        shot("late-A-ack-B-isolated")
        stage="readmit-A-durable"
        click("Verrouiller","قفل")
        locked()
        click("Ouvrir profil A","فتح الملف A")
        expect(page.get_by_text("7.83 mmol/L",exact=True)).to_be_visible(timeout=20000)
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_have_count(0)
        shot("A-readmitted")
        stage="cross-owner-delete-dialog"
        click("Supprimer","حذف")
        expect(text("Confirmer la suppression","تأكيد الحذف")).to_be_visible()
        stage="cross-owner-fence-replacement"
        # A different document acquires a real committed B lease; do not
        # invoke a lock or clinical operation in the old UI.
        secret=page.evaluate("window.__h2Fixture.replacementSecret()")
        second=ctx.new_page()
        second.on("pageerror",lambda error: errors.append(str(error)[:300]))
        second.goto(origin,wait_until="domcontentloaded")
        second.wait_for_function("typeof window.d1BoundProof === 'function'",timeout=60000)
        assert second.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secret})==2
        page.bring_to_front()
        locked()
        expect(text("Confirmer la suppression","تأكيد الحذف")).to_have_count(0)
        expect(page.locator('[flt-semantics-identifier="evidence-value"]')).to_have_count(0)
        assert second.evaluate("window.d1CrossSession.inspect()")["revision"]==2
        assert second.evaluate(I5_CROSS_FENCE)==900002
        shot("cross-owner-retired")
        assert second.evaluate("window.d1CrossSession.retire()") is True
        stage="same-owner-fence-replacement"
        click("Ouvrir profil B","فتح الملف B")
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible(timeout=20000)
        # Even the same authenticated owner with a new durable lease must
        # retire the previous visible session. No old-tab operation.
        assert second.evaluate(I5_CROSS_OPEN,{"owner":900002,"secret":secret})==2
        page.bring_to_front()
        locked()
        assert second.evaluate("window.d1CrossSession.inspect()")["revision"]==2
        assert second.evaluate(I5_CROSS_FENCE)==900002
        shot("same-owner-retired")
        assert second.evaluate("window.d1CrossSession.retire()") is True
        secret=None
        second.close()
        stage="final-egress"
        assert not blocked and not errors
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "viewport":[width,height],"wrongOwnerRefused":True,"lateAckSuppressed":True,
                "durableReadmission":True,"crossOwnerUiRetired":True,"sameOwnerUiRetired":True,
                "deleteDialogCleared":True,"newLeasePreserved":True,
                "blockedRequests":0,"pageErrors":0,"frames":frames,"result":"PASS"}
    except Exception as error:
        try:
            page.screenshot(path=str(proof/f"h2-web-{ENGINE}-{locale}-failure.png"),timeout=5000)
        except Exception:
            pass
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "stage":stage,"errorType":type(error).__name__,"blockedRequests":len(blocked),
                "pageErrors":len(errors),"result":"FAIL"}
    finally:
        ctx.close()


def run_h2_ui():
    assert ENGINE in ("chromium","webkit")
    assert os.environ["GITHUB_HEAD_REF"]=="phase2/d1-d5-convergence"
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    proof.mkdir(parents=True,exist_ok=True)
    records=[]
    with tempfile.TemporaryDirectory(prefix="h2-ui-") as root:
        with http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler) as server:
            threading.Thread(target=server.serve_forever,daemon=True).start()
            origin=f"http://127.0.0.1:{server.server_port}"
            try:
                with sync_playwright() as pw:
                    browser_type=getattr(pw,ENGINE)
                    for locale in ("fr-FR","ar-MA"):
                        try:
                            record=exercise_h2_ui(browser_type,Path(root)/f"h2-{locale}",locale,origin)
                        except Exception as error:
                            record={"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                                    "stage":"navigation","errorType":type(error).__name__,"result":"FAIL"}
                        records.append(record)
                        print("H2_WEB "+json.dumps(record),flush=True)
            finally:
                server.shutdown()
                (proof/f"h2-web-{ENGINE}-matrix.json").write_text(json.dumps(records))
    assert len(records)==2 and all(r["result"]=="PASS" for r in records),"H2 Web adversarial matrix failed"
    print("H2_WEB_PASS 2/2 scenarios=8/8",flush=True)



# H3 uses the real encrypted vault, not an in-memory list or a fake page port.
# The wrapper exists solely in the synthetic browser harness.
_H3_MOUNT_WRAPPER = r"""
  const baseTime=Date.UTC(2024,9,27,0,30)/1000;
  const id=n=>'ac123456-1234-4abc-8def-'+String(n+100).padStart(12,'0');
  const checkH3=(ok)=>{if(!ok)throw Error('H3 oracle mismatch');};
  window.__h3Stage='seed-admission';
  await window.d1BoundLogin(900001);
  let seed=await api.admitBoundClinical(900001,window.d1BoundEpoch(),await window.d1BoundProof(900001),secrets.get(900001));
  window.__h3Stage='seed-53';
  for(let i=1;i<=53;i++){
    const measured=i===53?baseTime+3600:i===52?baseTime-1:baseTime;
    const ack=await seed.insertEvidence(i,id(i),100.25+i,'mg/dL',measured);
    checkH3(ack.revision===i+1&&ack.evidence.loggedAtSeconds===measured&&
      ack.evidence.createdAtSeconds>measured);
  }
  window.__h3Stage='port-50-plus-3';
  const all=[id(53),...Array.from({length:51},(_,i)=>id(i+1)),id(52)];
  const first=await seed.readEvidenceJournal(54,1,4102444800,50,0);
  const second=await seed.readEvidenceJournal(54,1,4102444800,50,50);
  checkH3(first.nextOffset===50&&second.nextOffset===null&&
    first.rows.length===50&&second.rows.length===3&&
    JSON.stringify([...first.rows,...second.rows].map(r=>r.uuid))===JSON.stringify(all));
  window.__h3Stage='half-open-dst';
  const overlap1=await seed.readEvidenceJournal(54,baseTime,baseTime+3600,50,0);
  const overlap2=await seed.readEvidenceJournal(54,baseTime,baseTime+3600,50,50);
  checkH3(overlap1.rows.length===50&&overlap2.rows.length===1&&
    overlap2.nextOffset===null&&overlap1.rows.every(r=>r.loggedAtSeconds===baseTime)&&
    overlap2.rows[0].loggedAtSeconds===baseTime);
  checkH3((await seed.readEvidenceJournal(54,baseTime+3600,baseTime+3601,50,0)).rows[0].uuid===id(53));
  checkH3((await seed.readEvidenceJournal(54,baseTime-1,baseTime,50,0)).rows[0].uuid===id(52));
  window.__h3Stage='exclusive-end-refusal';
  let denied=false;
  try{await seed.insertEvidence(54,id(54),200.25,'mg/dL',4102444800);}
  catch(e){denied=String(e).includes('Invalid explicit measurement');}
  checkH3(denied);
  await seed.retire();
  seed=null;
  window.__h3Stage='mount-ready';
  let latest=null, edited=null, conflict=false, conflictCommitted=false;
  const wrapper=async(action,json)=>{
    const args=JSON.parse(json);
    if(conflict&&action==='page'){
      conflict=false;
      const ack=await active.insertEvidence(args.revision,id(54),190.25,'mg/dL',Math.floor(Date.now()/1000));
      checkH3(ack.revision===args.revision+1);
      conflictCommitted=true;
    }
    const response=JSON.parse(await call(action,json));
    latest=response;
    if(action==='edit'){
      const read=await active.readEvidence(args.uuid);
      checkH3(read.revision===response.revision);
      edited=read.evidence;
    }
    return JSON.stringify(response);
  };
  window.__h3Fixture=Object.freeze({
    page:()=>latest===null?null:{offset:latest.offset,revision:latest.revision,next:latest.nextOffset,
      rows:latest.rows.map(r=>({uuid:r.uuid,value:r.originalValue,logged:r.loggedAtSeconds,created:r.createdAtSeconds}))},
    edited:()=>edited,
    conflict:()=>{conflict=true;},
    committed:()=>conflictCommitted,
    secret:()=>secrets.get(900001),
  });
  window.d1MountEvidenceUi(wrapper,lock,cb=>{retired=cb;},arabic);
"""
assert UI_MOUNT.count(_H2_MOUNT_ANCHOR)==1
H3_UI_MOUNT=UI_MOUNT.replace(_H2_MOUNT_ANCHOR,_H3_MOUNT_WRAPPER)


def exercise_h3_ui(browser_type, profile, locale, origin):
    from PIL import Image
    from playwright.sync_api import expect
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo
    width,height=390,844
    timezone_id="Europe/Paris" if locale=="fr-FR" else "Africa/Casablanca"
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    frames=[]
    time_checks=[]
    stage="navigation"
    ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin,timezone_id=timezone_id)
    secret=None
    ar=locale=="ar-MA"
    def text(fr,arabic):
        return page.get_by_text(arabic if ar else fr,exact=True).first
    def click(fr,arabic):
        target=text(fr,arabic)
        target.scroll_into_view_if_needed(timeout=20000)
        expect(target).to_be_visible(timeout=20000)
        target.click(timeout=20000)
    def control(identifier):
        target=page.locator(f'[flt-semantics-identifier="{identifier}"]')
        expect(target).to_have_count(1,timeout=15000)
        target.scroll_into_view_if_needed(timeout=10000)
        expect(target).to_be_visible(timeout=15000)
        return target
    def enter(identifier,value):
        field=control(identifier)
        bounds=field.bounding_box(timeout=10000)
        assert bounds and bounds["width"]>0 and bounds["height"]>0
        page.mouse.click(bounds["x"]+bounds["width"]/2,bounds["y"]+bounds["height"]/2)
        native=page.locator("input:focus, textarea:focus")
        expect(native).to_have_count(1,timeout=10000)
        native.press("ControlOrMeta+a",timeout=10000)
        native.press_sequentially(value,delay=60,timeout=15000)
        expect(native).to_have_value(value,timeout=10000)
    def semantics():
        page.wait_for_selector("flutter-view, flt-glass-pane",timeout=60000)
        placeholder=page.locator("flt-semantics-placeholder")
        if placeholder.count():
            placeholder.evaluate("(el)=>el.click()")
    def shot(name):
        path=proof/f"h3-web-{ENGINE}-{locale}-{name}.png"
        page.screenshot(path=str(path),animations="disabled",timeout=15000)
        with Image.open(path) as im:
            rgb=im.convert("RGB")
            assert rgb.size==(width,height)
            assert len(rgb.getcolors(width*height) or [])>50
        frames.append({"file":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    def journal(n,revision):
        expected="صفحة "+str(n) if ar else "Page "+str(n)
        expect(page.get_by_text(expected,exact=True)).to_be_visible(timeout=20000)
        page.wait_for_function("v=>{const p=window.__h3Fixture.page();return p?.offset===v[0]&&p?.revision===v[1]}",
            arg=[(n-1)*10,revision],timeout=20000)
        return page.evaluate("window.__h3Fixture.page()")
    def next_page(n,revision):
        click("Suivant","التالي")
        return journal(n,revision)
    def oracle(seconds):
        return datetime.fromtimestamp(seconds,timezone.utc).astimezone(ZoneInfo(timezone_id)).isoformat(timespec="seconds")
    def time_check(label,seconds,visible=False):
        expected=oracle(seconds)
        observed=page.evaluate(r"""s=>{
          const diagnostic=JSON.parse(window.d1EvidenceTimeProbe(s));
          const date=new Date(s*1000);
          return {...diagnostic,dateOffsetMinutes:-date.getTimezoneOffset(),
            dateRoundtrip:Math.floor(date.getTime()/1000)};
        }""",seconds)
        record={"case":label,"seconds":seconds,"expected":expected,**observed,"visibleChecked":False}
        time_checks.append(record)
        # Emit diagnostics even if the named-zone result disagrees with tzdb.
        print("H3_TIME_DIAG "+json.dumps({"engine":ENGINE,"locale":locale,**record}),flush=True)
        assert observed["zone"]==timezone_id and observed["dateRoundtrip"]==seconds
        assert observed["namedLocal"]==expected, "Named-zone projection differs from independent tzdb"
        if visible:
            expect(page.get_by_text(expected,exact=True).first).to_be_visible(timeout=20000)
            record["visibleChecked"]=True
        return expected
    try:
        page.set_viewport_size({"width":width,"height":height})
        assert page.evaluate("Intl.DateTimeFormat().resolvedOptions().timeZone")==timezone_id
        stage="named-zone-oracle"
        # Independent legal boundary guard: an obsolete runner tzdb must fail,
        # not silently agree with an obsolete browser or redefine the oracle.
        # Decree 2.26.530: 2026-09-20 02:00 at UTC+1 -> 01:00 GMT.
        if timezone_id=="Africa/Casablanca":
            assert oracle(1789865999)=="2026-09-20T01:59:59+01:00", "Runner tzdb pre-transition mismatch"
            assert oracle(1789866000)=="2026-09-20T01:00:00+00:00", "Runner tzdb lacks IANA 2026c change"
            assert oracle(1795778145)=="2026-11-27T11:15:45+00:00", "Runner tzdb lacks current legal time"
        # Explicit UTC instants spanning both overlap/gap and Casablanca Ramadan.
        # Fixed instants are fixture inputs; expected strings use independent tzdb.
        for label,instant in (
            ("paris-spring-before","2024-03-31T00:59:59+00:00"),
            ("paris-spring-after","2024-03-31T01:00:00+00:00"),
            ("paris-overlap-first","2024-10-27T00:30:00+00:00"),
            ("paris-overlap-second","2024-10-27T01:30:00+00:00"),
            ("casablanca-ramadan","2026-03-01T12:00:00+00:00"),
            ("casablanca-after-ramadan","2026-04-01T12:00:00+00:00"),
            ("casablanca-legal-before","2026-09-20T00:59:59+00:00"),
            ("casablanca-legal-at","2026-09-20T01:00:00+00:00"),
            ("casablanca-legal-after","2026-09-20T01:00:01+00:00"),
            ("reported-regression","2026-11-27T11:15:45+00:00"),
            ("casablanca-no-seasonal-return","2027-07-01T12:00:00+00:00"),
        ):
            time_check(label,int(datetime.fromisoformat(instant).timestamp()))
        stage="seed-and-port-oracle"
        page.evaluate(H3_UI_MOUNT,ar)
        semantics()
        click("Ouvrir profil A","فتح الملف A")
        stage="six-page-traversal"
        first=journal(1,54)
        pages=[first]
        # Check both actual rendered overlap instants, not just the declared zone.
        time_check("visible-overlap-second",first["rows"][0]["logged"],visible=True)
        time_check("visible-overlap-first",first["rows"][1]["logged"],visible=True)
        shot("first-page")
        for n in range(2,7):
            pages.append(next_page(n,54))
        rows=[r for p in pages for r in p["rows"]]
        assert [len(p["rows"]) for p in pages]==[10,10,10,10,10,3]
        assert len({r["uuid"] for r in rows})==53 and pages[-1]["next"] is None
        assert [r["value"] for r in rows]==[153.25]+[100.25+i for i in range(1,52)]+[152.25]
        last=pages[-1]["rows"][0]
        assert last["value"]==150.25
        expect(page.get_by_text("150.25 mg/dL",exact=True)).to_be_visible(timeout=20000)
        shot("sixth-page")
        click("Précédent","السابق")
        assert journal(5,54)==pages[4]
        assert next_page(6,54)==pages[5]
        stage="edit-old-page"
        click("Modifier","تعديل")
        enter("evidence-value","175.25")
        control("evidence-save").click(timeout=10000)
        journal(1,55)
        edited=page.evaluate("window.__h3Fixture.edited()")
        assert edited["uuid"]==last["uuid"] and edited["originalValue"]==175.25
        assert edited["loggedAtSeconds"]==last["logged"] and edited["createdAtSeconds"]==last["created"]
        for n in range(2,7):
            next_page(n,55)
        expect(page.get_by_text("175.25 mg/dL",exact=True)).to_be_visible(timeout=20000)
        stage="historical-insert"
        click("Mesure antérieure (date et heure)","قياس سابق (التاريخ والوقت)")
        enter("evidence-time","2024-10-27T02:30:00")
        enter("evidence-value","7.83")
        control("evidence-mmoll").click(timeout=10000)
        control("evidence-save").click(timeout=10000)
        expect(text("Saisie ou opération refusée.","تم رفض الإدخال أو العملية.")).to_be_visible(timeout=20000)
        assert page.evaluate("window.__h3Fixture.page().revision")==55
        enter("evidence-time","2024-10-27T02:30:00+01:00")
        control("evidence-save").click(timeout=10000)
        result=journal(1,56)
        past=next(r for r in result["rows"] if r["value"]==7.83)
        assert past["logged"]==1729992600 and past["created"]>past["logged"]
        expect(page.get_by_text("7.83 mmol/L",exact=True)).to_be_visible(timeout=20000)
        time_check("visible-historical",past["logged"],visible=True)
        shot("historical-saved")
        stage="current-insert"
        before=page.evaluate("Math.floor(Date.now()/1000)")
        enter("evidence-value","8.2")
        control("evidence-mmoll").click(timeout=10000)
        control("evidence-save").click(timeout=10000)
        result=journal(1,57)
        now=next(r for r in result["rows"] if r["value"]==8.2)
        after=page.evaluate("Math.floor(Date.now()/1000)")
        assert before<=now["logged"]<=after and now["logged"]<=now["created"]<=after
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_be_visible(timeout=20000)
        time_check("visible-current",now["logged"],visible=True)
        shot("current-saved")
        stage="real-revision-conflict"
        page.evaluate("window.__h3Fixture.conflict()")
        click("Suivant","التالي")
        expect(text("Coffre verrouillé","المخزن مقفل")).to_be_visible(timeout=20000)
        assert page.evaluate("window.__h3Fixture.committed()") is True
        expect(page.get_by_text("8.2 mmol/L",exact=True)).to_have_count(0)
        shot("stale-page-refused")
        stage="readmit"
        click("Ouvrir profil A","فتح الملف A")
        restored=journal(1,58)
        assert any(r["value"]==190.25 for r in restored["rows"])
        time_check("visible-readmitted-current",now["logged"],visible=True)
        shot("readmitted")
        click("Verrouiller","قفل")
        expect(text("Coffre verrouillé","المخزن مقفل")).to_be_visible(timeout=20000)
        secret=page.evaluate("window.__h3Fixture.secret()")
        assert not blocked and not errors
        ctx.close()
        stage="restart-storage"
        ctx,page,blocked,errors=open_context(browser_type,profile,locale,origin,timezone_id=timezone_id)
        restart=page.evaluate(r"""async secret=>{
          const api=await import('/d1_admission_candidate.mjs');
          await window.d1BoundLogin(900001);
          const s=await api.admitBoundClinical(900001,window.d1BoundEpoch(),await window.d1BoundProof(900001),secret);
          const a=await s.readEvidenceJournal(58,1,4102444800,50,0);
          const b=await s.readEvidenceJournal(58,1,4102444800,50,50);
          const rows=[...a.rows,...b.rows];
          const e=rows.find(r=>r.originalValue===175.25);
          const historical=rows.find(r=>r.originalValue===7.83);
          await s.retire();
          return {count:rows.length,unique:new Set(rows.map(r=>r.uuid)).size,
            first:a.rows.length,last:b.rows.length,next:b.nextOffset,
            edited:e?.loggedAtSeconds,created:e?.createdAtSeconds,
            historical:historical?.loggedAtSeconds,conflict:rows.some(r=>r.originalValue===190.25)};
        }""",secret)
        assert restart=={"count":56,"unique":56,"first":50,"last":6,"next":None,
            "edited":last["logged"],"created":last["created"],"historical":1729992600,"conflict":True}
        assert not blocked and not errors
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "viewport":[width,height],"timezone":timezone_id,"seedCount":53,"pageCounts":[10,10,10,10,10,3],
                "halfOpenDst":True,"exclusiveEndRefused":True,"historicalExact":True,
                "currentExact":True,"editInstantPreserved":True,"stalePageRefused":True,
                "restartCount":56,"blockedRequests":0,"pageErrors":0,"frames":frames,
                "namedTimezoneChecks":time_checks,"result":"PASS"}
    except Exception as error:
        if stage=="seed-and-port-oracle":
            try:
                sub=page.evaluate("window.__h3Stage")
                if sub in ("seed-admission","seed-53","port-50-plus-3","half-open-dst","exclusive-end-refusal","mount-ready"):
                    stage=sub
            except Exception:
                pass
        try:
            page.screenshot(path=str(proof/f"h3-web-{ENGINE}-{locale}-failure.png"),timeout=5000)
        except Exception:
            pass
        return {"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                "stage":stage,"errorType":type(error).__name__,"blockedRequests":len(blocked),
                "pageErrors":len(errors),"namedTimezoneChecks":time_checks,"result":"FAIL"}
    finally:
        secret=None
        ctx.close()


def run_h3_ui():
    assert ENGINE in ("chromium","webkit")
    assert os.environ["GITHUB_HEAD_REF"]=="phase2/d1-d5-convergence"
    proof=Path(os.environ["RUNNER_TEMP"])/"d2-browser-proof"
    proof.mkdir(parents=True,exist_ok=True)
    records=[]
    with tempfile.TemporaryDirectory(prefix="h3-ui-") as root:
        with http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler) as server:
            threading.Thread(target=server.serve_forever,daemon=True).start()
            origin=f"http://127.0.0.1:{server.server_port}"
            try:
                with sync_playwright() as pw:
                    browser_type=getattr(pw,ENGINE)
                    for locale in ("fr-FR","ar-MA"):
                        try:
                            record=exercise_h3_ui(browser_type,Path(root)/f"h3-{locale}",locale,origin)
                        except Exception as error:
                            record={"source":os.environ["EXPECTED_SHA"],"engine":ENGINE,"locale":locale,
                                    "stage":"navigation","errorType":type(error).__name__,"result":"FAIL"}
                        records.append(record)
                        print("H3_WEB "+json.dumps(record),flush=True)
            finally:
                server.shutdown()
                (proof/f"h3-web-{ENGINE}-matrix.json").write_text(json.dumps(records))
    assert len(records)==2 and all(r["result"]=="PASS" for r in records),"H3 Web journal matrix failed"
    print("H3_WEB_PASS 2/2",flush=True)


if __name__=="__main__":
    if os.environ.get("H3_RUNTIME_UI_ONLY")=="1":
        run_h3_ui()
    elif os.environ.get("H2_RUNTIME_UI_ONLY")=="1":
        run_h2_ui()
    elif os.environ.get("H1_RUNTIME_UI_ONLY")=="1":
        run_h1_ui()
    elif os.environ.get("D1_RUNTIME_UI_ONLY")=="1":
        run_evidence_ui()
    else:
        run()
