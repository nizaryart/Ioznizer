"""
Report validation.

Everything in a generated report is asserted by a language model: the ATT&CK
mappings, the evidence locations, the IOC list. Where the model is confidently
wrong the report is confidently wrong, and a reader has no way to tell which
parts were checked.

This module runs mechanical checks between "model produced JSON" and "report
written to disk", using ground truth the pipeline already holds — MITRE's
published technique list, the decompiled function set, the real tool log, and
hashes computed by the extractor.

It deliberately does not judge whether a finding is *reasonable*. Checking that
T1590.005 is named "IP Addresses" is a lookup; deciding whether "Fallback
Channels" was a sensible mapping is not, and pretending otherwise would be
worse than leaving it to the reader.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .tool_dispatcher import DECOMP_FUNC_MARKER
except ImportError:  # direct execution
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from agent.tool_dispatcher import DECOMP_FUNC_MARKER

ATTACK_DATA = Path(__file__).resolve().parent / "data" / "attack_techniques.json"

# T1055 or T1055.011
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

# Function names as they appear in evidence locations, e.g. FUN_0804a330, main
FUNCTION_TOKEN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]{2,})\b")

# Hex addresses, e.g. 0x0804a330
ADDRESS_TOKEN = re.compile(r"\b0x[0-9a-fA-F]+\b")


# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

def load_attack_reference(path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load the bundled ATT&CK technique map.

    Returns an empty map if the file is missing or unreadable; validation then
    reports itself as unavailable rather than rejecting valid techniques.
    """
    path = path or ATTACK_DATA
    try:
        data = json.loads(Path(path).read_text())
        return data.get("techniques", {}) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def _names_match(reported: str, canonical: str) -> bool:
    """
    Compare a reported technique name against the canonical one.

    Sub-technique names are commonly written parent-prefixed, so
    "Application Layer Protocol: Web Protocols" is accepted for the canonical
    "Web Protocols".
    """
    reported = (reported or "").strip().lower()
    canonical = (canonical or "").strip().lower()

    if not reported:
        return False
    if reported == canonical:
        return True

    # "Parent: Sub" form
    tail = reported.rsplit(":", 1)[-1].strip()
    return tail == canonical


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _lookup_by_name(name: str, reference: Dict[str, Any]) -> Optional[str]:
    """
    Find the technique ID whose canonical name matches `name`.

    Used to tell a paraphrase ("Obfuscated/Stored Files" for "Obfuscated Files
    or Information") apart from the model having chosen the wrong ID entirely
    ("Vulnerability Scanning" reported under T1590.005, which is IP Addresses).
    """
    target = (name or "").strip().lower()
    if not target:
        return None

    # Sub-technique names are often written parent-prefixed.
    tail = target.rsplit(":", 1)[-1].strip()

    for tid, meta in reference.items():
        canonical = (meta.get("name") or "").strip().lower()
        if canonical and canonical in (target, tail):
            return tid
    return None


def validate_attack_techniques(report: Dict[str, Any],
                               reference: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Validate reported ATT&CK techniques against MITRE's published list.

    Entries that fail are moved to `threat_intelligence.unvalidated_techniques`
    with a reason. They are not deleted: the description may still be useful,
    and silently dropping them would hide what the model actually produced.
    """
    findings = []

    intel = report.get("threat_intelligence")
    if not isinstance(intel, dict):
        return findings

    techniques = intel.get("mitre_attack_techniques")
    if not isinstance(techniques, list):
        return findings

    if not reference:
        findings.append({
            "check": "attack_techniques",
            "severity": "info",
            "message": "ATT&CK reference data unavailable; techniques not validated",
        })
        return findings

    validated = []
    rejected = []

    for entry in techniques:
        if not isinstance(entry, dict):
            continue

        tid = str(entry.get("technique_id", "")).strip()
        name = entry.get("technique_name", "")

        if not TECHNIQUE_ID.match(tid):
            entry["validation_error"] = f"malformed technique ID: {tid!r}"
            rejected.append(entry)
            findings.append({
                "check": "attack_techniques",
                "severity": "error",
                "message": f"Malformed technique ID {tid!r} rejected",
            })
            continue

        known = reference.get(tid)
        if known is None:
            entry["validation_error"] = f"{tid} is not a published ATT&CK technique"
            rejected.append(entry)
            findings.append({
                "check": "attack_techniques",
                "severity": "error",
                "message": f"{tid} is not a published ATT&CK technique",
            })
            continue

        if known.get("revoked") or known.get("deprecated"):
            state = "revoked" if known.get("revoked") else "deprecated"
            entry["validation_error"] = f"{tid} is {state} in ATT&CK"
            rejected.append(entry)
            findings.append({
                "check": "attack_techniques",
                "severity": "warning",
                "message": f"{tid} ({known.get('name')}) is {state}",
            })
            continue

        # Valid ID, wrong name. Two very different cases hide here.
        if not _names_match(name, known.get("name", "")):
            # If the reported name is itself a published technique, the model
            # picked the wrong ID for the technique it meant. Renaming would
            # silently attach its description to an unrelated technique, so
            # the entry is rejected instead of "corrected".
            intended = _lookup_by_name(name, reference)
            if intended and intended != tid:
                entry["validation_error"] = (
                    f"ID/name mismatch: {tid} is {known.get('name')!r}, but the "
                    f"reported name {name!r} is {intended}"
                )
                rejected.append(entry)
                findings.append({
                    "check": "attack_techniques",
                    "severity": "error",
                    "message": (
                        f"{tid} ({known.get('name')}) was reported as {name!r}, "
                        f"which is {intended} - rejected rather than renamed"
                    ),
                })
                continue

            # Otherwise it is a paraphrase of the right technique; normalise it.
            findings.append({
                "check": "attack_techniques",
                "severity": "warning",
                "message": (
                    f"{tid} was reported as {name!r}; normalised to "
                    f"{known.get('name')!r}"
                ),
            })
            entry["reported_name"] = name
            entry["technique_name"] = known.get("name")

        entry["validated"] = True
        validated.append(entry)

    intel["mitre_attack_techniques"] = validated
    if rejected:
        intel["unvalidated_techniques"] = rejected

    return findings


def parse_decompiled_functions(analysis_dir: Path) -> Dict[str, str]:
    """Map function name -> entry address from decomp.txt."""
    decomp = Path(analysis_dir) / "decomp.txt"
    if not decomp.exists():
        return {}

    functions = {}
    for match in DECOMP_FUNC_MARKER.finditer(decomp.read_text(errors="ignore")):
        functions[match.group("name").strip()] = match.group("address").strip()
    return functions


def _normalise_address(addr: str) -> str:
    """0x0804a330, 0804a330 and 804a330 all compare equal."""
    return (addr or "").lower().replace("0x", "").lstrip("0") or "0"


def _inspected_functions(tool_log: List[Dict[str, Any]]) -> set:
    """Names and addresses the run actually decompiled."""
    inspected = set()
    for entry in tool_log or []:
        if entry.get("tool") != "decompile_function":
            continue
        args = entry.get("arguments") or {}
        for key in ("function_name", "address"):
            value = args.get(key)
            if value:
                inspected.add(str(value).lower().lstrip("0x").lstrip("0") or "0")
                inspected.add(str(value).lower())
    return inspected


def validate_evidence_locations(report: Dict[str, Any],
                                analysis_dir: Optional[Path],
                                tool_log: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Check that each reported behaviour points at real, inspected code.

    Catches three failure modes seen in practice: a bare string match used
    where a code location belongs, a function the binary does not contain, and
    the same address cited for two different behaviours.
    """
    findings = []

    technical = report.get("technical_analysis")
    if not isinstance(technical, dict):
        return findings

    behaviours = technical.get("malicious_behaviors")
    if not isinstance(behaviours, list) or not behaviours:
        return findings

    known = parse_decompiled_functions(analysis_dir) if analysis_dir else {}
    known_addresses = {_normalise_address(a) for a in known.values()}
    inspected = _inspected_functions(tool_log)

    seen_locations: Dict[str, str] = {}

    for entry in behaviours:
        if not isinstance(entry, dict):
            continue

        location = str(entry.get("evidence_location", "")).strip()
        behaviour = str(entry.get("behavior_type", "unnamed"))
        reasons = []

        functions = [
            token for token in FUNCTION_TOKEN.findall(location)
            if token in known
        ] if known else []
        addresses = ADDRESS_TOKEN.findall(location)

        if not functions and not addresses:
            reasons.append("no code reference: cites text rather than a function or address")
        elif known and not functions:
            # Addresses present but no recognised function name. An address
            # only counts as evidence if it is a function entry point: a
            # .rodata address points at the string that prompted the finding,
            # not at the code implementing it.
            unknown = [
                token for token in FUNCTION_TOKEN.findall(location)
                if token.startswith("FUN_") or token.startswith("sub_")
            ]
            if unknown:
                reasons.append(
                    f"function not present in the decompilation: {', '.join(unknown[:3])}"
                )
            elif addresses and not any(
                _normalise_address(addr) in known_addresses for addr in addresses
            ):
                reasons.append(
                    f"{addresses[0]} is not a decompiled function entry point"
                )

        if functions and inspected:
            was_inspected = any(
                fn.lower() in inspected or known.get(fn, "").lower() in inspected
                for fn in functions
            )
            if not was_inspected:
                reasons.append("function was never decompiled during this run")

        # Duplicate detection keys on the code reference, not the whole string,
        # so differing prose around the same address still collides.
        key = (functions[0] if functions else (addresses[0] if addresses else "")).lower()
        if key:
            if key in seen_locations:
                reasons.append(
                    f"same code location already cited for {seen_locations[key]!r}"
                )
            else:
                seen_locations[key] = behaviour

        entry["evidence_verified"] = not reasons
        if reasons:
            entry["evidence_issues"] = reasons
            findings.append({
                "check": "evidence_locations",
                "severity": "warning",
                "message": f"{behaviour}: " + "; ".join(reasons),
            })

    return findings


def inject_file_hashes(report: Dict[str, Any],
                       extractor_info: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Write the sample's hashes into the IOC section.

    These are computed by the extractor, so there is no reason to ask a model
    for them and no reason to accept its version if it disagrees.
    """
    findings = []

    hashes = (extractor_info or {}).get("hashes")
    if not hashes:
        return findings

    iocs = report.setdefault("indicators_of_compromise", {})
    if not isinstance(iocs, dict):
        return findings

    iocs["file_hashes"] = {
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes.get("sha256"),
        "size_bytes": hashes.get("size_bytes"),
    }

    findings.append({
        "check": "file_hashes",
        "severity": "info",
        "message": "Sample hashes injected from the extractor",
    })
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def validate_report(report: Dict[str, Any],
                    analysis_dir: Optional[Path] = None,
                    extractor_info: Optional[Dict[str, Any]] = None,
                    tool_log: Optional[List[Dict[str, Any]]] = None,
                    attack_reference: Optional[Dict[str, Any]] = None
                    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Run every check and annotate the report.

    Returns (report, summary). Never raises: a validator that aborts report
    generation would be worse than no validator, so unexpected failures are
    recorded as a finding and the report is returned unchanged.
    """
    findings: List[Dict[str, Any]] = []

    try:
        reference = attack_reference if attack_reference is not None else load_attack_reference()
        findings += validate_attack_techniques(report, reference)
        findings += validate_evidence_locations(report, analysis_dir, tool_log)
        findings += inject_file_hashes(report, extractor_info)
        status = "completed"
    except Exception as e:  # defensive: never break report generation
        findings.append({
            "check": "validator",
            "severity": "error",
            "message": f"Validation aborted: {e}",
        })
        status = "aborted"

    summary = {
        "status": status,
        "errors": sum(1 for f in findings if f.get("severity") == "error"),
        "warnings": sum(1 for f in findings if f.get("severity") == "warning"),
        "findings": findings,
    }

    report["validation"] = summary
    return report, summary
