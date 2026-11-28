"""Independent D5-01 oracle check. Never imports product code."""
from decimal import Decimal, localcontext, ROUND_HALF_UP
from pathlib import Path
import json

fixture = json.loads((Path(__file__).resolve().parents[1] / "frontend/test/fixtures/d5_01_glucose_oracles.json").read_text())
assert fixture["molarMassGramPerMol"] == "180.1559"
assert len(fixture["cases"]) == 14
assert len({(c["sourceUnit"], c["raw"]) for c in fixture["cases"]}) == 14
with localcontext() as ctx:
    ctx.prec = 40
    factor = Decimal("180.1559") / Decimal(10)
    for case in fixture["cases"]:
        raw = Decimal(case["raw"])
        assert raw > 0
        unit = case["sourceUnit"]
        assert unit in {"mg/dL", "mmol/L"}
        mg = raw if unit == "mg/dL" else raw * factor
        mmol = raw if unit == "mmol/L" else raw / factor
        assert mg == Decimal(case["mgDl"]), case
        assert abs(mmol - Decimal(case["mmolL"])) <= Decimal("1e-15"), case
    difference = fixture["legacyDivergence"]
    assert difference["status"] == "UNRESOLVED_POLICY"
    raw = Decimal(difference["rawMgDl"])
    assert str((raw / factor).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)) == difference["stagedDisplay"]
    assert str((raw / Decimal("18.018")).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)) == difference["legacyDisplay"]
print("D5_01_INDEPENDENT_NUMERIC_ORACLES=PASS 14/14; legacy divergence OPEN")
