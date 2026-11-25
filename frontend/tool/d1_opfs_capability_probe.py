"""D1 capability probe: no writes, no security override and no patient data."""
import http.server
import json
import os
import platform
from pathlib import Path
import tempfile
import threading

from playwright.sync_api import sync_playwright
from d1_archive_browser_probe import Handler, connect


def run():
    with tempfile.TemporaryDirectory(prefix="d1-capability-") as td, http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        records = []
        try:
            with sync_playwright() as pw:
                for host in ("127.0.0.1", "localhost"):
                    origin = f"http://{host}:{server.server_port}"
                    record = dict(source_sha=os.environ["EXPECTED_SHA"], platform=platform.system(),
                                  platform_release=platform.release(), origin_host=host,
                                  engine="webkit", persistent=True)
                    ctx = None
                    try:
                        ctx, page, blocked = connect(pw.webkit, Path(td) / host, "fr-FR", origin)
                        info = page.evaluate("""async () => {
                          const state = {origin: location.origin, secure: isSecureContext,
                            storage: typeof navigator.storage, directory: typeof navigator.storage?.getDirectory,
                            crypto: typeof crypto?.subtle, userAgent: navigator.userAgent};
                          try {
                            if (typeof navigator.storage?.getDirectory !== 'function') {
                              state.directoryOpened = false;
                            } else {
                              const root = await navigator.storage.getDirectory();
                              state.directoryOpened = root.kind === 'directory';
                            }
                          } catch (error) {
                            state.directoryOpened = false;
                            state.errorName = error.name;
                            state.errorMessage = String(error.message).slice(0, 180);
                          }
                          return state;
                        }""")
                        assert not blocked
                        assert info["origin"] == origin
                        record.update(info)
                    except Exception as error:
                        record.update(probeError=str(error)[:350])
                    finally:
                        if ctx is not None:
                            ctx.close()
                    records.append(record)
                    print("D1_OPFS_CAPABILITY " + json.dumps(record), flush=True)
            assert len(records) == 2
        finally:
            server.shutdown()


if __name__ == "__main__":
    run()
