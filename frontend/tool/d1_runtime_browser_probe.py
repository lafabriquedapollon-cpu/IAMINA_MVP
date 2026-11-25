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


def open_context(browser_type, profile, locale, origin):
    context = browser_type.launch_persistent_context(
        str(profile), headless=True, locale=locale,
        viewport={"width":390,"height":844}, service_workers="block",
    )
    blocked, errors = [], []
    def route(r):
        if r.request.url.startswith(origin + "/") and "/api/" not in r.request.url:
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



def run():
    assert ENGINE in ("chromium", "webkit")
    assert (WEB / "main.dart.js").stat().st_size > 1000
    results = []
    with tempfile.TemporaryDirectory(prefix="d1-runtime-") as root:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            origin = f"http://127.0.0.1:{server.server_port}"
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
                            record["result"] = "PASS"
                        except Exception as error:
                            record.update(result="FAIL", error=str(error)[:1500])
                        results.append(record)
                        print("D1_RUNTIME " + json.dumps(record,ensure_ascii=False),flush=True)
            finally:
                server.shutdown()
    assert len(results)==2 and all(x["result"]=="PASS" for x in results), "D1 actual Drift encrypted checkpoint failed"
    print("D1_RUNTIME_PASS 2/2",flush=True)
    print("D1_I2_DURABLE_MUTATION_PASS 2/2",flush=True)


if __name__=="__main__":
    run()
