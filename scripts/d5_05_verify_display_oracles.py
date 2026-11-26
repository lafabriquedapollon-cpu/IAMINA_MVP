"""Independent display oracle: Decimal only, no product code."""
import json
from decimal import Decimal, ROUND_HALF_UP, localcontext
from pathlib import Path

fixture = json.loads((Path(__file__).resolve().parents[1] /
    "frontend/test/fixtures/d5_05_display_oracles.json").read_text())
assert fixture["status"] == "CANDIDATE_NOT_RUNTIME"
assert fixture["rounding"] == "ROUND_HALF_UP"
assert len(fixture["cases"]) == 19
assert len({(r["sourceUnit"], r["raw"], r["displayUnit"]) for r in fixture["cases"]}) == 19
with localcontext() as ctx:
    ctx.prec = 60
    factor = Decimal("180.1559") / 10
    for row in fixture["cases"]:
        source, target = row["sourceUnit"], row["displayUnit"]
        assert source in {"mg/dL", "mmol/L"} and target in {"mg/dL", "mmol/L"}
        raw = Decimal(row["raw"])
        assert raw.is_finite() and raw > 0
        value = raw if source == target else raw * factor if source == "mmol/L" else raw / factor
        rounded = value.quantize(Decimal("1" if target == "mg/dL" else "0.1"), rounding=ROUND_HALF_UP)
        assert (str(rounded) if rounded else None) == row["display"], row
print("D5_05_DECIMAL_DISPLAY_ORACLES=PASS 19/19; candidate only")
