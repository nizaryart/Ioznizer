"""
Tests for report validation.

Fixtures are drawn from defects seen in real runs rather than invented: a
technique ID reported under another technique's name, two behaviours citing the
same address, and an evidence location that is prose rather than code.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.validators import (  # noqa: E402
    load_attack_reference,
    validate_report,
    validate_attack_techniques,
    validate_evidence_locations,
    inject_file_hashes,
    _lookup_by_name,
    _names_match,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def reference():
    """The bundled ATT&CK reference; skip everything if it is missing."""
    ref = load_attack_reference()
    if not ref:
        pytest.skip("ATT&CK reference data not generated")
    return ref


def make_report(techniques=None, behaviours=None):
    return {
        "threat_intelligence": {"mitre_attack_techniques": techniques or []},
        "technical_analysis": {"malicious_behaviors": behaviours or []},
        "indicators_of_compromise": {},
    }


@pytest.fixture
def decomp_dir(tmp_path):
    """An analysis directory containing two decompiled functions."""
    (tmp_path / "decomp.txt").write_text(
        "// ===== FUNCTION FUN_0804a330 @ 0x0804a330 =====\n"
        "void FUN_0804a330(void) { return; }\n\n"
        "// ===== FUNCTION FUN_08049ad0 @ 0x08049ad0 =====\n"
        "void FUN_08049ad0(void) { return; }\n"
    )
    return tmp_path


# ---------------------------------------------------------------------------
# ATT&CK reference data
# ---------------------------------------------------------------------------

def test_reference_contains_known_techniques(reference):
    assert reference["T1498"]["name"] == "Network Denial of Service"
    assert reference["T1595.002"]["name"] == "Vulnerability Scanning"
    # The pairing that was wrong in a real report.
    assert reference["T1590.005"]["name"] == "IP Addresses"


def test_reference_is_substantial(reference):
    assert len(reference) > 500


# ---------------------------------------------------------------------------
# Technique validation
# ---------------------------------------------------------------------------

def test_valid_technique_passes(reference):
    report = make_report([
        {"technique_id": "T1498", "technique_name": "Network Denial of Service"}
    ])
    findings = validate_attack_techniques(report, reference)

    assert findings == []
    kept = report["threat_intelligence"]["mitre_attack_techniques"]
    assert len(kept) == 1
    assert kept[0]["validated"] is True


def test_malformed_id_rejected(reference):
    """Regression: a run once emitted an Arabic-script technique ID."""
    report = make_report([
        {"technique_id": "Tشرطة", "technique_name": "Nonsense"}
    ])
    findings = validate_attack_techniques(report, reference)

    assert report["threat_intelligence"]["mitre_attack_techniques"] == []
    assert len(report["threat_intelligence"]["unvalidated_techniques"]) == 1
    assert any(f["severity"] == "error" for f in findings)


def test_unknown_id_rejected(reference):
    report = make_report([
        {"technique_id": "T9999", "technique_name": "Invented Technique"}
    ])
    validate_attack_techniques(report, reference)

    assert report["threat_intelligence"]["mitre_attack_techniques"] == []
    rejected = report["threat_intelligence"]["unvalidated_techniques"][0]
    assert "not a published" in rejected["validation_error"]


def test_paraphrased_name_is_normalised(reference):
    """A near-miss name for the right ID should be corrected, not rejected."""
    report = make_report([
        {"technique_id": "T1027", "technique_name": "Obfuscated/Stored Files"}
    ])
    findings = validate_attack_techniques(report, reference)

    kept = report["threat_intelligence"]["mitre_attack_techniques"]
    assert len(kept) == 1
    assert kept[0]["technique_name"] == "Obfuscated Files or Information"
    assert kept[0]["reported_name"] == "Obfuscated/Stored Files"
    assert all(f["severity"] == "warning" for f in findings)


def test_wrong_id_for_named_technique_is_rejected_not_renamed(reference):
    """
    The defect this check exists for: T1590.005 is "IP Addresses", but the
    model reported it as "Vulnerability Scanning" (which is T1595.002).
    Renaming would attach an SSDP description to an unrelated technique.
    """
    report = make_report([{
        "technique_id": "T1590.005",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "description": "SSDP discovery for amplification targets",
    }])
    findings = validate_attack_techniques(report, reference)

    assert report["threat_intelligence"]["mitre_attack_techniques"] == []
    rejected = report["threat_intelligence"]["unvalidated_techniques"][0]
    assert "T1595.002" in rejected["validation_error"]
    assert any(f["severity"] == "error" for f in findings)


def test_parent_prefixed_subtechnique_name_accepted(reference):
    """"Application Layer Protocol: Web Protocols" is a normal way to write T1071.001."""
    report = make_report([{
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
    }])
    findings = validate_attack_techniques(report, reference)

    assert len(report["threat_intelligence"]["mitre_attack_techniques"]) == 1
    assert findings == []


def test_missing_reference_does_not_reject(reference):
    """Without reference data, techniques must pass through untouched."""
    report = make_report([
        {"technique_id": "T1498", "technique_name": "Network Denial of Service"}
    ])
    findings = validate_attack_techniques(report, {})

    assert len(report["threat_intelligence"]["mitre_attack_techniques"]) == 1
    assert findings[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# Name helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("reported,canonical,expected", [
    ("Network Denial of Service", "Network Denial of Service", True),
    ("network denial of service", "Network Denial of Service", True),
    ("Application Layer Protocol: Web Protocols", "Web Protocols", True),
    ("Vulnerability Scanning", "IP Addresses", False),
    ("", "Web Protocols", False),
])
def test_names_match(reported, canonical, expected):
    assert _names_match(reported, canonical) is expected


def test_lookup_by_name(reference):
    assert _lookup_by_name("Vulnerability Scanning", reference) == "T1595.002"
    assert _lookup_by_name("not a real technique name", reference) is None


# ---------------------------------------------------------------------------
# Evidence locations
# ---------------------------------------------------------------------------

def test_verified_evidence_location(decomp_dir):
    report = make_report(behaviours=[
        {"behavior_type": "SYN Flood", "evidence_location": "FUN_0804a330 @ 0x0804a330"}
    ])
    tool_log = [{"tool": "decompile_function", "arguments": {"function_name": "FUN_0804a330"}}]

    findings = validate_evidence_locations(report, decomp_dir, tool_log)

    assert report["technical_analysis"]["malicious_behaviors"][0]["evidence_verified"] is True
    assert findings == []


def test_duplicate_evidence_location_flagged(decomp_dir):
    """Two behaviours citing one address: seen in a real report for the bypass variants."""
    report = make_report(behaviours=[
        {"behavior_type": "SYN Flood", "evidence_location": "FUN_0804a330 @ 0x0804a330"},
        {"behavior_type": "TCP Bypass Flood", "evidence_location": "FUN_0804a330 @ 0x0804a330"},
    ])
    tool_log = [{"tool": "decompile_function", "arguments": {"function_name": "FUN_0804a330"}}]

    findings = validate_evidence_locations(report, decomp_dir, tool_log)

    behaviours = report["technical_analysis"]["malicious_behaviors"]
    assert behaviours[0]["evidence_verified"] is True
    assert behaviours[1]["evidence_verified"] is False
    assert "already cited" in behaviours[1]["evidence_issues"][0]
    assert len(findings) == 1


def test_prose_evidence_location_flagged(decomp_dir):
    report = make_report(behaviours=[
        {"behavior_type": "SSDP", "evidence_location": "String references in .rodata"}
    ])
    findings = validate_evidence_locations(report, decomp_dir, [])

    entry = report["technical_analysis"]["malicious_behaviors"][0]
    assert entry["evidence_verified"] is False
    assert "no code reference" in entry["evidence_issues"][0]
    assert len(findings) == 1


def test_uninspected_function_flagged(decomp_dir):
    """The function exists, but this run never opened it."""
    report = make_report(behaviours=[
        {"behavior_type": "UDP Flood", "evidence_location": "FUN_08049ad0 @ 0x08049ad0"}
    ])
    tool_log = [{"tool": "decompile_function", "arguments": {"function_name": "FUN_0804a330"}}]

    validate_evidence_locations(report, decomp_dir, tool_log)

    entry = report["technical_analysis"]["malicious_behaviors"][0]
    assert entry["evidence_verified"] is False
    assert "never decompiled" in " ".join(entry["evidence_issues"])


def test_no_decomp_directory_is_tolerated():
    report = make_report(behaviours=[
        {"behavior_type": "X", "evidence_location": "FUN_1234 @ 0x1234"}
    ])
    validate_evidence_locations(report, None, [])
    assert "evidence_verified" in report["technical_analysis"]["malicious_behaviors"][0]


# ---------------------------------------------------------------------------
# Hash injection
# ---------------------------------------------------------------------------

def test_hashes_injected():
    report = make_report()
    inject_file_hashes(report, {"hashes": {
        "md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64, "size_bytes": 111920
    }})

    hashes = report["indicators_of_compromise"]["file_hashes"]
    assert hashes["sha256"] == "c" * 64
    assert hashes["size_bytes"] == 111920


def test_hashes_absent_is_noop():
    report = make_report()
    findings = inject_file_hashes(report, {})
    assert findings == []
    assert "file_hashes" not in report["indicators_of_compromise"]


# ---------------------------------------------------------------------------
# Entry point behaviour
# ---------------------------------------------------------------------------

def test_validate_report_adds_summary(reference):
    report = make_report([
        {"technique_id": "T1498", "technique_name": "Network Denial of Service"}
    ])
    out, summary = validate_report(report, attack_reference=reference)

    assert out["validation"] is summary
    assert summary["status"] == "completed"
    assert summary["errors"] == 0


def test_validate_report_never_raises_on_garbage():
    """A validator that aborts report generation is worse than none."""
    for garbage in ({}, {"threat_intelligence": "not a dict"},
                    {"technical_analysis": {"malicious_behaviors": "nope"}},
                    {"threat_intelligence": {"mitre_attack_techniques": [None, 42]}}):
        out, summary = validate_report(dict(garbage))
        assert summary["status"] in ("completed", "aborted")
        assert "validation" in out


def test_validate_report_on_real_report_shape(reference, decomp_dir):
    """End-to-end over a report carrying every defect class at once."""
    report = {
        "threat_intelligence": {"mitre_attack_techniques": [
            {"technique_id": "T1498", "technique_name": "Network Denial of Service"},
            {"technique_id": "T1590.005", "technique_name": "Active Scanning: Vulnerability Scanning"},
            {"technique_id": "BOGUS", "technique_name": "Nope"},
        ]},
        "technical_analysis": {"malicious_behaviors": [
            {"behavior_type": "SYN Flood", "evidence_location": "FUN_0804a330 @ 0x0804a330"},
            {"behavior_type": "TCP Bypass", "evidence_location": "FUN_0804a330 @ 0x0804a330"},
            {"behavior_type": "SSDP", "evidence_location": "strings in .rodata"},
        ]},
        "indicators_of_compromise": {},
    }
    tool_log = [{"tool": "decompile_function", "arguments": {"function_name": "FUN_0804a330"}}]

    out, summary = validate_report(
        report, analysis_dir=decomp_dir,
        extractor_info={"hashes": {"md5": "a", "sha1": "b", "sha256": "c", "size_bytes": 1}},
        tool_log=tool_log, attack_reference=reference,
    )

    assert summary["errors"] == 2          # T1590.005 mismatch + BOGUS format
    assert summary["warnings"] == 2        # duplicate location + prose location
    assert len(out["threat_intelligence"]["mitre_attack_techniques"]) == 1
    assert len(out["threat_intelligence"]["unvalidated_techniques"]) == 2
    assert out["indicators_of_compromise"]["file_hashes"]["sha256"] == "c"
