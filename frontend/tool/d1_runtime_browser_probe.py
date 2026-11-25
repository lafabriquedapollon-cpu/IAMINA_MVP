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


if __name__=="__main__":
    run()
