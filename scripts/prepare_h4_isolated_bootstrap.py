"""Remove only the known custom SW bootstrap suffix from isolated CI artifacts.

This is not a production PWA build transformation. Fail closed on source or
compiled suffix drift. The browser and server guards remain independently active.
"""
import hashlib
from pathlib import Path
import sys

ANCHOR = "const IAMINA_HOSTED_REVIEW ="
LOADER = "_flutter.loader.load({config:{fontFallbackBaseUrl:new URL('assets/engine-font-fallback/',document.baseURI).href}});"
MARKER = "// H4_ISOLATED_QUALIFICATION_NO_SW_STARTUP"


def strip_startup(compiled, source):
    assert source.count(ANCHOR) == 1, "SW source anchor drift"
    assert compiled.count(ANCHOR) == 1, "SW compiled anchor drift"
    assert compiled.count(LOADER) == 1 and MARKER not in compiled
    suffix = source[source.index(ANCHOR):]
    assert "navigator.serviceWorker" in suffix
    assert "registerIaminaServiceWorker" in suffix
    assert "iamina_service_worker.js?release_probe=" in suffix
    prefix, actual = compiled.split(ANCHOR, 1)
    assert (ANCHOR + actual).rstrip() == suffix.rstrip(), "SW suffix differs from tracked source"
    assert prefix.rstrip().endswith(LOADER), "Unexpected code between loader and SW startup"
    return prefix + MARKER + "\n"


def prepare(target, template):
    bootstrap = Path(target) / "flutter_bootstrap.js"
    source = Path(template).read_text(encoding="utf-8")
    original = bootstrap.read_text(encoding="utf-8")
    edited = strip_startup(original, source)
    bootstrap.write_text(edited, encoding="utf-8")
    print("H4_ISOLATED_SW_STARTUP_REMOVED", Path(target).name,
          hashlib.sha256(original.encode()).hexdigest(),
          hashlib.sha256(edited.encode()).hexdigest(), flush=True)


if __name__ == "__main__":
    assert len(sys.argv) == 4
    for target in sys.argv[1:3]:
        prepare(target, sys.argv[3])
