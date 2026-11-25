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

WEB = Path(os.environ["D1_RUNTIME_WEB"]).resolve()
ENGINE = os.environ["D1_RUNTIME_ENGINE"]
MARKER = "D1_I1_SYNTHETIC_NOT_PATIENT"


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def log_message(self, *_):
        pass


def open_context(browser_type, profile, locale, origin, extra_origin=None):
    context = browser_type.launch_persistent_context(
        str(profile), headless=True, locale=locale,
        viewport={"width":390,"height":844}, service_workers="block",
    )
    blocked, errors = [], []
    def route(r):
        allowed = (origin,) if extra_origin is None else (origin, extra_origin)
        if any(r.request.url.startswith(o + "/") for o in allowed) and "/api/" not in r.request.url:
            r.continue_()
        else:
            blocked.append(r.request.url.split("?")[0])
            r.abort()
    context.route("**/*", route)
    page = context.pages[0] if context.pages else context.new_page()
    page.on("pageerror", lambda error: errors.append(str(error)[:300]))
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


if __name__=="__main__":
    run()
