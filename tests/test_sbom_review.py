"""Evidence-integrity and missing-data checks for the local SBOM exercise."""
import copy
import json
import subprocess
import sys

import pytest

from tools.sbom_review import markdown, review, snapshot


@pytest.fixture
def bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [
        {"bom-ref": "package-1", "name": "Example_Package", "version": "1.0"}],
        "vulnerabilities": [{"id": "TEST-ONLY-ADVISORY", "affects": [{"ref": "package-1"}]}]}


def test_links_advisory_to_exact_component_and_keeps_unknown_score(bom):
    result = review(bom, "example-package==1.0")
    assert result["findings"][0]["affected_components"][0]["version"] == "1.0"
    assert result["unscored_advisories"] == 1
    assert "Unknown" in markdown(result)


def test_retains_supplied_score_source_without_calculating_one(bom):
    bom["vulnerabilities"][0]["ratings"] = [{"method": "CVSSv31", "score": 8.1, "source": {"name": "Synthetic test"}}]
    result = review(bom, "example-package==1.0")
    assert result["unscored_advisories"] == 0
    assert result["findings"][0]["ratings_as_supplied"][0]["score"] == 8.1


@pytest.mark.parametrize("score", [-1, 11, float("nan"), True, "9.8"])
def test_rejects_invalid_rating(bom, score):
    bom["vulnerabilities"][0]["ratings"] = [{"score": score}]
    with pytest.raises(ValueError, match="Invalid supplied rating"):
        review(bom, "example-package==1.0")


def test_missing_component_fails(bom):
    with pytest.raises(ValueError, match="Inventory differs"):
        review(bom, "example-package==1.0\nother==2")


def test_version_mismatch_fails(bom):
    with pytest.raises(ValueError, match="Inventory differs"):
        review(bom, "example-package==2.0")


def test_dangling_advisory_reference_fails(bom):
    bom["vulnerabilities"][0]["affects"][0]["ref"] = "missing"
    with pytest.raises(ValueError, match="Dangling"):
        review(bom, "example-package==1.0")


def test_duplicate_component_fails(bom):
    bom["components"].append(copy.deepcopy(bom["components"][0]))
    with pytest.raises(ValueError, match="Duplicate component"):
        review(bom, "example-package==1.0")


def test_advisory_without_targets_fails(bom):
    bom["vulnerabilities"][0]["affects"] = []
    with pytest.raises(ValueError, match="without affected"):
        review(bom, "example-package==1.0")


@pytest.mark.parametrize("requirements", ["", "thing>=1", "thing==1\nthing==2"])
def test_incomplete_or_ambiguous_snapshot_fails(requirements):
    with pytest.raises(ValueError):
        snapshot(requirements)


def test_clean_report_keeps_limitations(bom):
    bom["vulnerabilities"] = []
    result = review(bom, "example-package==1.0")
    assert result["advisory_records"] == 0
    assert "not proof of safety" in result["interpretation"]


def test_cli_emits_hashed_json_and_markdown(bom, tmp_path):
    source, lock, output = (tmp_path / name for name in ("bom.json", "snapshot.txt", "review"))
    source.write_text(json.dumps(bom))
    lock.write_text("example-package==1.0")
    subprocess.run([sys.executable, "tools/sbom_review.py", str(source), str(lock), "--output", str(output)], check=True)
    report = json.loads(output.with_suffix(".json").read_text())
    assert len(report["input_sha256"][source.name]) == 64
    assert "TEST-ONLY-ADVISORY" in output.with_suffix(".md").read_text()


def test_repeated_advisory_ids_are_retained_without_inflating_distinct_count(bom):
    bom["vulnerabilities"].append(copy.deepcopy(bom["vulnerabilities"][0]))
    result = review(bom, "example-package==1.0")
    assert result["advisory_records"] == 2
    assert result["distinct_advisory_ids"] == 1
