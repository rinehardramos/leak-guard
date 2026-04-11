"""
Ground-truth fixture tests for leak-guard scanner.

Reads tests/fixtures/ground_truth.toml and verifies:
- expect=tp: scan_all(text=context) returns at least one finding,
             and if rule_id != "gitleaks" and rule_id != "", that exact rule_id appears
- expect=fp: scan_all(text=context) returns no findings

Gitleaks-tagged fixtures are skipped automatically when the gitleaks binary
is not present on PATH.

Fixtures whose note contains "[SCANNER-BUG]" are marked xfail — they document
real false-positive or false-negative bugs in the scanner and will be promoted
to hard failures once the underlying bug is fixed.
"""
import sys
from pathlib import Path

import pytest

# Make scanner importable from the hooks directory
sys.path.insert(0, str(Path(__file__).parent.parent / "plugins" / "leak-guard" / "hooks"))
import scanner as sc

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "ground_truth.toml"

GITLEAKS_AVAILABLE = bool(sc.find_gitleaks())


def load_fixtures():
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]
    with open(FIXTURES_PATH, "rb") as f:
        data = tomllib.load(f)
    return data.get("fixture", [])


FIXTURES = load_fixtures()

# Fixture IDs that document known scanner bugs — marked xfail so the suite
# stays green while the bugs are tracked.
SCANNER_BUG_IDS = {
    fx["id"] for fx in FIXTURES if "[SCANNER-BUG]" in fx.get("note", "")
}


@pytest.mark.parametrize(
    "fixture",
    FIXTURES,
    ids=[f["id"] for f in FIXTURES],
)
class TestGroundTruth:
    def test_fixture(self, fixture):
        fid = fixture["id"]
        context = fixture["context"]
        expect = fixture["expect"]
        rule_id = fixture.get("rule_id", "")
        note = fixture.get("note", "")

        # Skip gitleaks-dependent TPs when gitleaks is absent
        if rule_id == "gitleaks" and not GITLEAKS_AVAILABLE:
            pytest.skip("gitleaks binary not found on PATH")

        # Mark known scanner bugs as expected failures
        if fid in SCANNER_BUG_IDS:
            pytest.xfail(f"Known scanner bug — {note}")

        findings = sc.scan_all(text=context, source_label=f"<fixture:{fid}>")

        if expect == "fp":
            assert not findings, (
                f"[{fid}] Expected NO findings but got: "
                + ", ".join(f"{f.rule_id}={f.preview}" for f in findings)
                + f"\nNote: {note}"
            )

        elif expect == "tp":
            assert findings, (
                f"[{fid}] Expected finding (rule_id={rule_id!r}) but scanner returned nothing.\n"
                f"Context: {context!r}\nNote: {note}"
            )
            if rule_id and rule_id != "gitleaks":
                matched_ids = [f.rule_id for f in findings]
                assert rule_id in matched_ids, (
                    f"[{fid}] Expected rule_id={rule_id!r} but got: {matched_ids}\n"
                    f"Context: {context!r}\nNote: {note}"
                )

        else:
            pytest.fail(f"[{fid}] Unknown expect value: {expect!r}")
