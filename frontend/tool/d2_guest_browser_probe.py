"""D2 compiled candidate real-browser evidence; no remote identity or patient DB."""
import hashlib
import http.server
import json
import os
import platform
import re
from pathlib import Path
import threading

from playwright.sync_api import sync_playwright, expect
from h4_websocket_guard import attach_websocket_guard
from h4_egress_guard import static_request_allowed, attach_direct_transport_guard, NoServiceWorkerScripts
from PIL import Image

WEB = Path("frontend/build/web").resolve()
PROOF = Path(os.environ["RUNNER_TEMP"]) / "d2-browser-proof"
COPY = {
    "fr-FR": ("Accueil", "Mesures", "Rapports", "Profil", "Ajouter une mesure", "Identification", "Retour", "Connexion indisponible dans cette version de test."),
    "ar-MA": ("الرئيسية", "القياسات", "التقارير", "الملف الشخصي", "إضافة قياس", "تسجيل الدخول", "رجوع", "تسجيل الدخول غير متاح في هذه النسخة التجريبية."),
}


class Handler(NoServiceWorkerScripts, http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def do_GET(self):
        if self.path.startswith("/api/"):
            self.send_error(403)
            return
        super().do_GET()

    def log_message(self, *_):
        pass


def shot(page, name, *, require_complete=True):
    path = PROOF / (name + ".png")
    page.screenshot(path=str(path), animations="disabled", timeout=15000)
    with Image.open(path) as image:
        rgb = image.convert("RGB")
        assert rgb.size == (page.viewport_size["width"], page.viewport_size["height"])
        colors = rgb.getcolors(rgb.width * rgb.height)
        result = {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "rgb_sha256": hashlib.sha256(rgb.tobytes()).hexdigest(),
                  "unique_colors": len(colors) if colors else 0,
                  "complete": bool(colors and len(colors) > 50)}
    if require_complete:
        assert result["complete"], "Blank or visually incomplete canvas"
    return result


def enable_semantics(page):
    page.wait_for_selector("flutter-view, flt-glass-pane", timeout=60000)
    placeholder = page.locator("flt-semantics-placeholder")
    if placeholder.count():
        placeholder.evaluate("(element) => element.click()")


def named(page, label):
    return page.get_by_text(label, exact=True).first


def navigation(page, label):
    # Flutter navigation widgets expose accessible names, not necessarily DOM
    # text nodes. Include its localized position/selection suffix, not another
    # section heading. Never click by guessed screen coordinates.
    pattern = re.compile(r"^" + re.escape(label) + r"(?:\s|$)")
    candidates = page.get_by_role("tab", name=pattern).or_(page.get_by_role("button", name=pattern))
    return candidates


def run():
    PROOF.mkdir(parents=True, exist_ok=True)
    assert (WEB / "main.dart.js").stat().st_size > 1000
    build_sha = hashlib.sha256((WEB / "main.dart.js").read_bytes()).hexdigest()
    records = []
    cutover = os.environ.get("D1_CUTOVER_PROBE") == "1"
    target = os.environ.get("D2_BROWSER_TARGET", "diagnostic-all")
    # One Web reference platform per engine. The Linux WebKit port remains
    # reproducible as a separate diagnostic; its historical FAIL is not a PASS.
    if target == "chromium":
        assert platform.system() == "Linux"
        engines = ("chromium",)
    elif target == "webkit":
        assert platform.system() == "Darwin"
        engines = ("webkit",)
    elif target == "diagnostic-all":
        engines = ("chromium", "webkit")
    else:
        raise AssertionError("Unknown browser qualification target")
    print(f"D2_WEB_TARGET {target} platform={platform.system()}", flush=True)
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            with sync_playwright() as pw:
                for engine in engines:
                    browser = getattr(pw, engine).launch(headless=True)
                    try:
                        # Mobile FR/AR first, then desktop FR/AR, on the same Web build.
                        for w, h in ((390, 844), (1180, 860)):
                            for locale, copy in COPY.items():
                                name = f"{engine}-{locale}-{w}"
                                record = dict(source_sha=os.environ["EXPECTED_SHA"], build_sha256=build_sha,
                                              engine=engine, browser_version=browser.version, locale=locale, viewport=[w,h], platform=platform.system(), qualification_target=target)
                                ctx = browser.new_context(locale=locale, viewport={"width":w,"height":h},
                                                          device_scale_factor=1, service_workers="block")
                                blocked, errors, frames = [], [], []
                                legacy_requests = []
                                page = None
                                try:
                                    def route(r):
                                        url = r.request.url
                                        if cutover and any(url.split("?")[0].endswith("/"+name) for name in ("sqlite3.wasm","drift_worker.js")):
                                            legacy_requests.append(url.split("?")[0])
                                            r.abort()
                                            return
                                        if static_request_allowed(r.request, (origin,)):
                                            r.continue_()
                                        else:
                                            blocked.append(url.split("?")[0])
                                            r.abort()
                                    ctx.route("**/*", route)
                                    attach_websocket_guard(ctx, blocked)
                                    attach_direct_transport_guard(ctx, blocked)
                                    if cutover:
                                        ctx.add_init_script("""(() => {
                                          window.__d1StorageAttempts = [];
                                          const deny = (proto, name) => {
                                            if (typeof proto?.[name] !== "function") return;
                                            proto[name] = function() {
                                              window.__d1StorageAttempts.push(name);
                                              throw new Error("Persistent storage access forbidden");
                                            };
                                          };
                                          deny(IDBFactory.prototype, "open");
                                          deny(IDBFactory.prototype, "deleteDatabase");
                                          deny(globalThis.StorageManager?.prototype, "getDirectory");
                                          deny(Storage.prototype, "setItem");
                                        })()""")
                                    page = ctx.new_page()
                                    page.on("pageerror", lambda e: errors.append(str(e)[:200]))
                                    page.goto(origin, wait_until="domcontentloaded")
                                    enable_semantics(page)
                                    home, measures, reports, profile, add, identity, back, disabled = copy
                                    expect(named(page, add)).to_be_visible(timeout=30000)
                                    frames.append(shot(page, name+"-guest"))
                                    destination_actions = (
                                        ("Traitements", "Importer un document", "Accéder à mon profil", add)
                                        if locale == "fr-FR" else
                                        ("الأدوية", "استيراد مستند", "الوصول إلى ملفي", add)
                                    )
                                    for label, action in zip((measures, reports, profile, home), destination_actions):
                                        nav = navigation(page, label)
                                        expect(nav).to_have_count(1, timeout=10000)
                                        nav.click(timeout=10000)
                                        expect(named(page, action)).to_be_visible(timeout=10000)
                                    expect(named(page, add)).to_be_visible()
                                    named(page, add).click(timeout=10000)
                                    expect(named(page, disabled)).to_be_visible(timeout=10000)
                                    frames.append(shot(page, name+"-identity"))
                                    page.get_by_role("button", name=back, exact=True).click(timeout=10000)
                                    expect(named(page, add)).to_be_visible(timeout=10000)
                                    if locale == "ar-MA" and w == 390:
                                        # Keep the before/after oracle strict, including pixels.
                                        # Semantics alone do not establish that Flutter painted.
                                        page.wait_for_timeout(350)
                                        before = shot(page, name+"-before-resize", require_complete=False)
                                        frames.append(before)
                                        try:
                                            page.set_viewport_size({"width":391,"height":844})
                                            expect(named(page, add)).to_be_visible(timeout=10000)
                                            page.wait_for_timeout(350)
                                            frames.append(shot(page, name+"-width391", require_complete=False))
                                        finally:
                                            page.set_viewport_size({"width":390,"height":844})
                                        expect(named(page, add)).to_be_visible(timeout=10000)
                                        page.wait_for_timeout(350)
                                        after = []
                                        for frame in (1, 2):
                                            observed = shot(page, name+f"-resize-{frame}", require_complete=False)
                                            frames.append(observed)
                                            after.append(observed)
                                            if frame == 1:
                                                page.wait_for_timeout(500)
                                        record["resize_observations"] = {"before": before, "after": after}
                                        assert before["complete"], "Canvas incomplete before resize"
                                        assert frames[-3]["complete"], "Canvas incomplete at width 391"
                                        assert all(f["complete"] for f in after), "Blank or visually incomplete canvas after resize"
                                        assert all(f["rgb_sha256"] == before["rgb_sha256"] for f in after), "Post-resize RGB mismatch"
                                    if cutover:
                                        storage = page.evaluate("""async () => ({
                                          attempts: window.__d1StorageAttempts,
                                          databases: (await indexedDB.databases()).map(d => d.name),
                                          local: localStorage.length, session: sessionStorage.length,
                                          caches: await caches.keys()
                                        })""")
                                        record["cutover_storage"] = storage
                                        record["legacy_storage_requests"] = legacy_requests
                                        assert not legacy_requests, legacy_requests
                                        assert storage == {"attempts": [], "databases": [], "local": 0, "session": 0, "caches": []}, storage
                                    assert not blocked, "Guest made non-static network request"
                                    assert not errors, "Browser runtime error"
                                    record.update(result="PASS", screenshots=frames, blocked_requests=0, page_errors=0)
                                except Exception as error:
                                    record.update(result="FAIL", error=str(error)[:500], blocked_requests=blocked,
                                                  page_errors=errors, screenshots=frames)
                                    if page is not None:
                                        try:
                                            record["aria_tree"] = page.locator("body").aria_snapshot(timeout=5000)[:12000]
                                            frames.append(shot(page, name+"-failure", require_complete=False))
                                        except Exception as diagnostic:
                                            record["diagnostic_error"] = str(diagnostic)[:300]
                                finally:
                                    ctx.close()
                                records.append(record)
                                print("D2_BROWSER " + json.dumps(record, ensure_ascii=False), flush=True)
                                (PROOF / "matrix.json").write_text(json.dumps(records, ensure_ascii=False, indent=2))
                    finally:
                        browser.close()
            assert len(records) == len(engines) * 4
            assert all(r["result"] == "PASS" for r in records), "D2 candidate browser matrix failed"
            print(f"D2_BROWSER_PASS {len(records)}/{len(records)}")
            if cutover:
                print(f"D1_I5_CUTOVER_WEB_PASS {len(records)}/{len(records)}", flush=True)
        finally:
            server.shutdown()


if __name__ == "__main__":
    run()
