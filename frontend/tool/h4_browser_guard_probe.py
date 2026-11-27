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


def main():
    engine, app, runtime = sys.argv[1:]
    assert engine in ("chromium", "webkit")
    source = os.environ["EXPECTED_SHA"]
    assert re.fullmatch(r"[0-9a-f]{40}", source)
    result = {"source": source, "engine": engine, "font_assets": fonts(Path(app), Path(runtime)),
              "websocket_negative": websocket_negative(engine), "result": "PASS",
              "scope": "synthetic harness; not universal network containment"}
    proof = Path(os.environ["RUNNER_TEMP"]) / "d2-browser-proof"
    proof.mkdir(parents=True, exist_ok=True)
    (proof / f"h4-r1-{engine}.json").write_text(json.dumps(result, indent=2))
    print("H4_R1_PASS " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
