"""D1 candidate archive: real browsers and real synthetic SQLite bytes.
No Drift runtime, real patient, migration, production key or remote service.
"""
import hashlib
import http.server
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading

from playwright.sync_api import sync_playwright

MODULE = Path(__file__).with_name("d1_archive_candidate.mjs").read_bytes()
OWNER = "amina_vault_v1_native_101"
SECRET = "synthetic-only-recovery-secret"
WORKER = b"""
self.onmessage = async ({data}) => {
  let handle;
  try {
    const root = await navigator.storage.getDirectory();
    const file = await root.getFileHandle('iamina-synthetic-archive.bin', {create: data.op === 'write'});
    handle = await file.createSyncAccessHandle();
    let result;
    if (data.op === 'write') {
      const bytes = new Uint8Array(data.bytes);
      handle.truncate(0);
      if (handle.write(bytes, {at: 0}) !== bytes.length) throw new Error('short write');
      handle.flush();
      result = bytes.length;
    } else if (data.op === 'read') {
      const size = handle.getSize();
      if (size < 53 || size > 33554484) throw new Error('bad size');
      const bytes = new Uint8Array(size);
      if (handle.read(bytes, {at: 0}) !== size) throw new Error('short read');
      result = Array.from(bytes);
    } else throw new Error('unknown operation');
    handle.close(); handle = undefined;
    self.postMessage({ok: true, result});
  } catch (_) {
    if (handle) handle.close();
    self.postMessage({ok: false});
  }
};
"""
STORAGE = """
async (arg) => {
  const {op, mode, bytes} = arg;
  if (mode === 'opfs') {
    return await new Promise((resolve, reject) => {
      const worker = new Worker('/opfs-worker.js');
      const timer = setTimeout(() => {worker.terminate(); reject(new Error('OPFS timeout'));}, 10000);
      worker.onmessage = ({data}) => {
        clearTimeout(timer); worker.terminate();
        if (data.ok) resolve(data.result); else reject(new Error('OPFS operation failed'));
      };
      worker.onerror = () => {clearTimeout(timer); worker.terminate(); reject(new Error('OPFS worker error'));};
      worker.postMessage({op, bytes});
    });
  }
  const db = await new Promise((resolve, reject) => {
    const req = indexedDB.open('iamina-d1-synthetic-archive', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('archive');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('archive', op === 'write' ? 'readwrite' : 'readonly');
      const store = tx.objectStore('archive');
      let result;
      const request = op === 'write' ? store.put(new Uint8Array(bytes), 'only') : store.get('only');
      request.onsuccess = () => {
        result = op === 'write' ? bytes.length : (request.result ? Array.from(request.result) : null);
      };
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('IDB transaction aborted'));
    });
  } finally { db.close(); }
}
"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        content = {
            "/": (b"<!doctype html><title>D1 synthetic recovery</title>", "text/html"),
            "/d1_archive_candidate.mjs": (MODULE, "text/javascript"),
            "/opfs-worker.js": (WORKER, "text/javascript"),
        }.get(self.path)
        if content is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content[1])
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content[0])

    def log_message(self, *_):
        pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture(path):
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sample (uuid TEXT PRIMARY KEY, quantity INTEGER NOT NULL)")
        db.executemany("INSERT INTO sample VALUES (?,?)", [("synthetic-a", 101), ("synthetic-b", 202)])
    return path.read_bytes()


def check_sqlite(path, data):
    path.write_bytes(data)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("SELECT * FROM sample ORDER BY uuid").fetchall() == [("synthetic-a", 101), ("synthetic-b", 202)]


def connect(engine, profile, locale, origin):
    context = engine.launch_persistent_context(str(profile), headless=True, locale=locale, service_workers="block")
    blocked = []
    def route(request_route):
        url = request_route.request.url
        if url.startswith(origin + "/"):
            request_route.continue_()
        else:
            blocked.append(url)
            request_route.abort()
    context.route("**/*", route)
    page = context.pages[0] if context.pages else context.new_page()
    assert page.goto(origin).status == 200
    return context, page, blocked


def run():
    sha = os.environ["EXPECTED_SHA"]
    with tempfile.TemporaryDirectory(prefix="d1-synthetic-") as td, http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        root = Path(td)
        raw = fixture(root / "source.sqlite")
        original_digest = digest(raw)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            with sync_playwright() as pw:
                records = []
                for engine_name, mode in (("chromium", "idb"), ("webkit", "opfs")):
                    for locale in ("fr-FR", "ar-MA"):
                        engine = getattr(pw, engine_name)
                        profile = root / f"{engine_name}-{locale}"
                        ctx, page, blocked = connect(engine, profile, locale, origin)
                        try:
                            sealed = bytes(page.evaluate("""async ({raw, secret, owner}) => {
                              const {sealArchive} = await import('/d1_archive_candidate.mjs');
                              return Array.from(await sealArchive(new Uint8Array(raw), secret, owner));
                            }""", {"raw": list(raw), "secret": SECRET, "owner": OWNER}))
                            assert raw not in sealed
                            assert page.evaluate(STORAGE, {"op": "write", "mode": mode, "bytes": list(sealed)}) == len(sealed)
                            assert not blocked, "Unexpected external request"
                        finally:
                            ctx.close()
                        ctx, page, blocked = connect(engine, profile, locale, origin)
                        try:
                            reopened = bytes(page.evaluate(STORAGE, {"op": "read", "mode": mode}))
                            assert reopened == sealed
                            results = page.evaluate("""async ({archive, secret, owner}) => {
                              const {openArchive} = await import('/d1_archive_candidate.mjs');
                              const data = new Uint8Array(archive);
                              const plaintext = await openArchive(data, secret, owner);
                              const altered = data.slice(); altered[altered.length-1] ^= 1;
                              const rejected = [];
                              for (const [a,s,o] of [[data,'wrong-synthetic-recovery-secret',owner],
                                  [data,secret,'amina_vault_v1_native_202'],[altered,secret,owner]]) {
                                try { await openArchive(a,s,o); rejected.push(false); }
                                catch (_) { rejected.push(true); }
                              }
                              return {plaintext: Array.from(plaintext), rejected};
                            }""", {"archive": list(reopened), "secret": SECRET, "owner": OWNER})
                            restored = bytes(results["plaintext"])
                            assert digest(restored) == original_digest
                            assert results["rejected"] == [True, True, True]
                            assert not blocked, "Unexpected external request"
                            check_sqlite(root / f"restore-{engine_name}-{locale}.sqlite", restored)
                            assert digest((root / "source.sqlite").read_bytes()) == original_digest
                            record = dict(source_sha=sha, engine=engine_name, locale=locale, storage=mode,
                                          archive_sha256=digest(sealed), restored_sha256=digest(restored),
                                          restart=True, negative_cases=3, sqlite_integrity="PASS", result="PASS")
                            records.append(record)
                            print("D1_ARCHIVE_BROWSER " + json.dumps(record), flush=True)
                        finally:
                            ctx.close()
                assert len(records) == 4
                print("D1_ARCHIVE_BROWSER_PASS 4/4", flush=True)
        finally:
            server.shutdown()


if __name__ == "__main__":
    run()
