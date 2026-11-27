"""H4 R1: same-run font artifact parity and isolated WebSocket negative proof."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import sys
import threading
from playwright.sync_api import sync_playwright
from h4_websocket_guard import attach_websocket_guard
from h4_egress_probe import exercise_egress


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fonts(app, runtime):
    relative = Path("assets/engine-font-fallback")
    expected = {
        "notosanssymbols/v43/rP2up3q65FkAtHfwd-eIS2brbDN6gxP34F9jRRCe4W3gfQ8gb_VFRkzrbQ.woff2",
        "notosansarabic/v28/nwpxtLGrOAZMl5nJ_wfgRg3DrWFZWsnVBJ_sS6tlqHHFlhQ5l3sQWIHPqzCfyGyvvnCBFQLaig.woff2",
    }
    inventories = []
    for target in (app, runtime):
        root = target / relative
        files = {p.relative_to(root).as_posix(): sha(p) for p in root.rglob("*") if p.is_file()}
        required = expected | {str(Path(p).parent / "OFL.txt") for p in expected}
        assert set(files) == required, "Missing or unexpected fallback asset"
        for name in expected:
            assert (root / name).read_bytes()[:4] == b"wOF2", "Invalid WOFF2 signature"
            assert "SIL OPEN FONT LICENSE" in (root / Path(name).parent / "OFL.txt").read_text().upper()
        bootstrap = (target / "flutter_bootstrap.js").read_text()
        assert bootstrap.count("// H4_ISOLATED_QUALIFICATION_NO_SW_STARTUP") == 1
        assert "registerIaminaServiceWorker" not in bootstrap and "iamina_service_worker.js?release_probe=" not in bootstrap
        assert bootstrap.count("fontFallbackBaseUrl:new URL('assets/engine-font-fallback/',document.baseURI).href") == 1
        inventories.append(files)
    assert inventories[0] == inventories[1], "App and runtime fallback assets differ"
    return inventories[0]


def websocket_negative(engine):
    hits = []
    class Witness(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path != "/fixture":
                self.send_error(403)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<!doctype html><html><body>H4 synthetic fixture</body></html>")
        def log_message(self, *_):
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Witness) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            with sync_playwright() as pw:
                browser = getattr(pw, engine).launch(headless=True)
                try:
                    context = browser.new_context(service_workers="block")
                    blocked = []
                    try:
                        attach_websocket_guard(context, blocked)
                        page = context.new_page()
                        assert page.goto(origin + "/fixture").status == 200
                        assert not blocked and "/fixture" in hits
                        page.evaluate("""(url) => {
                          setTimeout(() => {
                            window.h4socket = new WebSocket(url);
                            window.h4socket.onerror = () => {};
                          }, 25);
                        }""", origin.replace("http:", "ws:") + "/h4-negative")
                        for _ in range(30):
                            page.wait_for_timeout(100)
                            if blocked:
                                break
                        assert blocked == ["websocket_attempt"], "WebSocket attempt not observed exactly once"
                        page.wait_for_timeout(300)
                    finally:
                        context.close()
                    assert blocked == ["websocket_attempt"]
                    assert "/h4-negative" not in hits, "WebSocket reached upstream"
                finally:
                    browser.close()
            return {"blocked": len(blocked), "upstream_hits": hits.count("/h4-negative"), "positive_http": "/fixture" in hits}
        finally:
            server.shutdown()
            thread.join(timeout=5)


def render_local_fonts(engine, app, runtime, inventory, proof):
    """Separate real-browser decoder/paint proof; does not impersonate Flutter fallback traffic."""
    relative = "/assets/engine-font-fallback/"
    assets = {relative + name: digest for name, digest in inventory.items() if name.endswith(".woff2")}
    assert len(assets) == 2
    cases = [{"path": path, "sha": digest,
              "sample": "→" if "notosanssymbols/" in path else "سلام",
              "family": "H4Symbols" if "notosanssymbols/" in path else "H4Arabic"}
             for path, digest in sorted(assets.items())]
    missing = relative + "h4-missing.woff2"
    results = []
    with sync_playwright() as pw:
        browser = getattr(pw, engine).launch(headless=True)
        try:
            for label, target in (("app", app), ("runtime", runtime)):
                hits = []
                class Witness(http.server.SimpleHTTPRequestHandler):
                    def __init__(self, *args, **kwargs):
                        super().__init__(*args, directory=str(target), **kwargs)
                    def do_GET(self):
                        if self.path == "/__h4_font_fixture":
                            self.send_response(200)
                            self.send_header("Content-Type", "text/html; charset=utf-8")
                            self.end_headers()
                            self.wfile.write(b"<!doctype html><html><body><canvas width='320' height='180'></canvas></body></html>")
                        elif self.path in assets:
                            self.response_status = None
                            super().do_GET()
                            hits.append((self.path, self.response_status))
                        elif self.path == missing:
                            self.send_error(404)
                            hits.append((self.path, 404))
                        else:
                            self.send_error(403)
                    def send_response(self, code, message=None):
                        self.response_status = code
                        super().send_response(code, message)
                    def log_message(self, *_):
                        pass
                with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Witness) as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    blocked, errors = [], []
                    try:
                        origin = f"http://127.0.0.1:{server.server_port}"
                        context = browser.new_context(viewport={"width":390,"height":844}, service_workers="block")
                        try:
                            allowed = {origin + p for p in (*assets, missing, "/__h4_font_fixture")}
                            def route(r):
                                if r.request.method == "GET" and r.request.url in allowed:
                                    r.continue_()
                                else:
                                    blocked.append("unexpected_http")
                                    r.abort()
                            context.route("**/*", route)
                            attach_websocket_guard(context, blocked)
                            page = context.new_page()
                            page.on("pageerror", lambda _e: errors.append("page_error"))
                            assert page.goto(origin + "/__h4_font_fixture").status == 200
                            observed = page.evaluate("""async ({cases,missing}) => {
                              const canvas=document.querySelector('canvas'),ctx=canvas.getContext('2d');
                              const rows=[];
                              for(const [i,item] of cases.entries()){
                                const response=await fetch(item.path,{cache:'no-store'});
                                if(!response.ok)throw Error('local font HTTP failure');
                                const bytes=await response.arrayBuffer();
                                const sha=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),
                                  n=>n.toString(16).padStart(2,'0')).join('');
                                if(sha!==item.sha)throw Error('local font digest mismatch');
                                const face=new FontFace(item.family,bytes);
                                await face.load();
                                document.fonts.add(face);
                                if(face.status!=='loaded')throw Error('font decoder failed');
                                ctx.font='42px '+item.family;
                                ctx.fillStyle='black';
                                ctx.fillText(item.sample,16,60+i*80);
                                const data=ctx.getImageData(0,i*80,320,80).data;
                                let ink=0;
                                for(let j=3;j<data.length;j+=4)if(data[j])ink++;
                                if(ink<20)throw Error('blank glyph render');
                                rows.push({family:item.family,sha,status:face.status,inkPixels:ink});
                              }
                              let corruptRejected=false;
                              try{await new FontFace('H4Corrupt',new Uint8Array([0,1,2,3]).buffer).load();}
                              catch(_){corruptRejected=true;}
                              const absent=await fetch(missing,{cache:'no-store'});
                              if(!corruptRejected||absent.status!==404)throw Error('font negative accepted');
                              return {rows,corruptRejected,missingStatus:absent.status};
                            }""", {"cases":cases,"missing":missing})
                            assert len(observed["rows"]) == 2
                            assert all(row["status"] == "loaded" and row["inkPixels"] >= 20 for row in observed["rows"])
                            shot = proof / f"h4-font-render-{engine}-{label}.png"
                            page.screenshot(path=str(shot))
                        finally:
                            context.close()
                        assert not blocked and not errors, "Font fixture egress or runtime error"
                        assert sorted(hits) == sorted([(path, 200) for path in assets] + [(missing, 404)]), hits
                        results.append({"target":label,"observed":observed,"serverHits":len(hits),
                                        "screenshot":shot.name,"screenshotSha256":sha(shot)})
                    finally:
                        server.shutdown()
                        thread.join(timeout=5)
        finally:
            browser.close()
    assert len(results) == 2
    return results


def main():
    engine, app, runtime = sys.argv[1:]
    assert engine in ("chromium", "webkit")
    source = os.environ["EXPECTED_SHA"]
    assert re.fullmatch(r"[0-9a-f]{40}", source)
    proof = Path(os.environ["RUNNER_TEMP"]) / "d2-browser-proof"
    proof.mkdir(parents=True, exist_ok=True)
    inventory = fonts(Path(app), Path(runtime))
    result = {"source": source, "engine": engine, "font_assets": inventory,
              "font_render": render_local_fonts(engine, Path(app), Path(runtime), inventory, proof),
              "websocket_negative": websocket_negative(engine),
              "egress": exercise_egress(engine), "result": "PASS",
              "scope": "synthetic harness; explicit browser decoder separate from spontaneous Flutter fallback; not universal network containment"}
    (proof / f"h4-r1-{engine}.json").write_text(json.dumps(result, indent=2))
    print("H4_R1_PASS " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
