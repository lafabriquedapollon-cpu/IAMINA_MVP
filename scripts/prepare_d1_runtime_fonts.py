"""Prepare actual local engine fallback fonts in the isolated Web artifacts.

No downloads, no patient build changes; source fonts are the pinned OFL assets.
"""
import hashlib
from pathlib import Path
import shutil
import sys
from fontTools.ttLib import TTFont

FONTS = (
    ("NotoSansSymbols", "Noto Sans Symbols", "f7e7e04b4a24b6c78893d50cbfd2b2f6cae49617ab047bfef668d252adb128f7",
     "notosanssymbols/v43/rP2up3q65FkAtHfwd-eIS2brbDN6gxP34F9jRRCe4W3gfQ8gb_VFRkzrbQ.woff2",
     "LICENSE-notosanssymbols.txt"),
    ("NotoSansArabic", "Noto Sans Arabic", "63111b5b2e074dd48cc67692e0a2726d86ee94c1c37fe8598257b7b4e87e869e",
     "notosansarabic/v28/nwpxtLGrOAZMl5nJ_wfgRg3DrWFZWsnVBJ_sS6tlqHHFlhQ5l3sQWIHPqzCfyGyvvnCBFQLaig.woff2",
     "LICENSE-notosansarabic.txt"),
)


def prepare(runtime, source):
    runtime, source = Path(runtime), Path(source)
    bootstrap = runtime / "flutter_bootstrap.js"
    original = bootstrap.read_text(encoding="utf-8")
    old = "_flutter.loader.load();"
    assert original.count(old) == 1 and "fontFallbackBaseUrl" not in original
    fallback = runtime / "assets/engine-font-fallback"
    assert not fallback.exists()
    outputs = {
        "NotoSansSymbols": ("a2a392332ee13e6413150f3cabd1f9fe76718442a1e8a8a3a027e413702a1333",
                            "b118dd41337806a5d4797052c77caf3bd096aed783e5eb21b4d11154351e1ac0"),
        "NotoSansArabic": ("d383af9d4bce176d3d619bdc9b35c8d494ac15e410ce7efafc4ed9621bbc3d19",
                           "07fc70bfeb985cc1a87a8587d0a0c80bab11c86c9dc3fd95b6f0cb332f983e96"),
    }
    for name, family, digest, relative, license_name in FONTS:
        src = runtime / "assets/assets/fonts" / (name + ".ttf")
        assert hashlib.sha256(src.read_bytes()).hexdigest() == digest
        assert src.read_bytes() == (source / src.name).read_bytes()
        license_file = source / license_name
        assert "SIL OPEN FONT LICENSE" in license_file.read_text(encoding="utf-8").upper()
        target = fallback / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with TTFont(src, recalcTimestamp=False) as font:
            assert font["name"].getDebugName(1) == family
            cmap = font.getBestCmap()
            assert cmap
            font.flavor = "woff2"
            font.save(target)
        with TTFont(target) as converted:
            assert converted.flavor == "woff2"
            assert converted["name"].getDebugName(1) == family
            assert converted.getBestCmap() == cmap
        assert hashlib.sha256(target.read_bytes()).hexdigest() == outputs[name][0], "WOFF2 output drift"
        assert hashlib.sha256(license_file.read_bytes()).hexdigest() == outputs[name][1], "OFL drift"
        shutil.copyfile(license_file, target.parent / "OFL.txt")
        print("D1_LOCAL_ENGINE_FONT", name, len(cmap),
              hashlib.sha256(target.read_bytes()).hexdigest(), flush=True)
    bootstrap.write_text(original.replace(old,
        "_flutter.loader.load({config:{fontFallbackBaseUrl:"
        "new URL('assets/engine-font-fallback/',document.baseURI).href}});"),
        encoding="utf-8")
    print("D1_LOCAL_ENGINE_FONTS_READY 2/2", flush=True)


if __name__ == "__main__":
    assert len(sys.argv) == 3
    prepare(sys.argv[1], sys.argv[2])
