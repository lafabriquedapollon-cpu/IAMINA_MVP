"""Separate portable encrypted-file proof. Does not replace OPFS or Drift gates."""
import http.server
import json
import os
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright

from d1_archive_browser_probe import Handler, OWNER, SECRET, check_sqlite, connect, digest, fixture


def run():
    sha = os.environ["EXPECTED_SHA"]
    with tempfile.TemporaryDirectory(prefix="d1-portable-synthetic-") as td, http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        root = Path(td)
        raw = fixture(root / "source.sqlite")
        original_digest = digest(raw)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        passed = 0
        failures = []
        try:
            with sync_playwright() as pw:
                for source_engine, destination_engine in (("chromium", "webkit"), ("webkit", "chromium")):
                    for locale in ("fr-FR", "ar-MA"):
                        record = dict(source_sha=sha, source_engine=source_engine, destination_engine=destination_engine,
                                      locale=locale, transport="download-file-input")
                        label = f"{source_engine}-{destination_engine}-{locale}"
                        archive = root / f"{label}.bin"
                        try:
                            ctx, page, blocked = connect(getattr(pw, source_engine), root / f"{label}-source", locale, origin)
                            try:
                                sealed = bytes(page.evaluate("""async ({raw, secret, owner}) => {
                                  const {sealArchive} = await import('/d1_archive_candidate.mjs');
                                  const sealed = await sealArchive(new Uint8Array(raw), secret, owner);
                                  window.syntheticSealed = sealed;
                                  const url = URL.createObjectURL(new Blob([sealed], {type: 'application/octet-stream'}));
                                  const link = document.createElement('a');
                                  link.href = url; link.download = 'synthetic-backup.bin';
                                  link.textContent = 'Download encrypted archive'; link.id = 'download';
                                  document.body.append(link);
                                  return Array.from(sealed);
                                }""", {"raw": list(raw), "secret": SECRET, "owner": OWNER}))
                                assert raw not in sealed
                                with page.expect_download(timeout=15000) as event:
                                    page.locator("#download").click()
                                download = event.value
                                assert download.suggested_filename == "synthetic-backup.bin"
                                download.save_as(str(archive))
                                assert archive.read_bytes() == sealed
                                assert not blocked
                            finally:
                                ctx.close()
                            ctx, page, blocked = connect(getattr(pw, destination_engine), root / f"{label}-destination", locale, origin)
                            try:
                                page.evaluate("""() => {
                                  const input = document.createElement('input');
                                  input.type = 'file'; input.id = 'archive';
                                  document.body.append(input);
                                }""")
                                page.locator("#archive").set_input_files(str(archive))
                                result = page.evaluate("""async ({secret, owner}) => {
                                  const {openArchive} = await import('/d1_archive_candidate.mjs');
                                  const files = document.getElementById('archive').files;
                                  if (files.length !== 1) throw new Error('Expected a single archive');
                                  const data = new Uint8Array(await files[0].arrayBuffer());
                                  const plain = await openArchive(data, secret, owner);
                                  const tampered = data.slice(); tampered[tampered.length - 1] ^= 1;
                                  const rejected = [];
                                  for (const [a,s,o] of [[data,'wrong-synthetic-secret-passphrase',owner],
                                      [data,secret,'amina_vault_v1_native_202'],[tampered,secret,owner]]) {
                                    try { await openArchive(a,s,o); rejected.push(false); }
                                    catch (_) { rejected.push(true); }
                                  }
                                  return {archive: Array.from(data), plain: Array.from(plain), rejected};
                                }""", {"secret": SECRET, "owner": OWNER})
                                assert bytes(result["archive"]) == sealed
                                restored = bytes(result["plain"])
                                assert digest(restored) == original_digest
                                assert result["rejected"] == [True, True, True]
                                assert not blocked
                                check_sqlite(root / f"{label}-restored.sqlite", restored)
                                assert digest((root / "source.sqlite").read_bytes()) == original_digest
                                record.update(result="PASS", archive_sha256=digest(sealed), restored_sha256=digest(restored),
                                              new_profile=True, negative_cases=3, sqlite_integrity="PASS")
                                passed += 1
                            finally:
                                ctx.close()
                        except Exception as error:
                            record.update(result="FAIL", error=str(error)[:500])
                            failures.append(label)
                        print("D1_PORTABLE_BROWSER " + json.dumps(record), flush=True)
            assert passed + len(failures) == 4
            assert passed == 4 and not failures, f"Portable file matrix: {passed}/4 PASS"
            print("D1_PORTABLE_BROWSER_PASS 4/4", flush=True)
        finally:
            server.shutdown()


if __name__ == "__main__":
    run()
