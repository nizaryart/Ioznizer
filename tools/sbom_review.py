#!/usr/bin/env python3
"""Review a flat CycloneDX inventory against a pinned Python audit snapshot.

This is a local learning exercise, not an SBOM generator or a reachability
analyzer. pip-audit generates the input. No network requests or package installs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def snapshot(text: str) -> set[tuple[str, str]]:
    packages = set()
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)", line)
        if not match:
            raise ValueError(f"Unsupported requirement (exact pins only): {line}")
        name, version = canonical(match[1]), match[2]
        if name in names:
            raise ValueError(f"Duplicate dependency: {name}")
        names.add(name)
        packages.add((name, version))
    if not packages:
        raise ValueError("Empty dependency snapshot")
    return packages


def review(bom: dict, lock: str) -> dict:
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.4":
        raise ValueError("This exercise supports CycloneDX JSON 1.4 only")
    components = bom.get("components", [])
    if not components:
        raise ValueError("Empty inventory")
    refs = {}
    inventory = set()
    for component in components:
        if component.get("components"):
            raise ValueError("Nested components are outside this flat-inventory exercise")
        ref, name, version = (component.get(k) for k in ("bom-ref", "name", "version"))
        if not all(isinstance(x, str) and x for x in (ref, name, version)):
            raise ValueError("Each component requires a reference, name and version")
        if ref in refs or (canonical(name), version) in inventory:
            raise ValueError("Duplicate component reference or identity")
        refs[ref] = {"name": name, "version": version, "bom_ref": ref}
        inventory.add((canonical(name), version))
    expected = snapshot(lock)
    if inventory != expected:
        raise ValueError(f"Inventory differs from audit snapshot: missing={sorted(expected-inventory)}, extra={sorted(inventory-expected)}")

    findings = []
    for vulnerability in bom.get("vulnerabilities", []):
        identifier = vulnerability.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("Missing advisory ID")
        targets = vulnerability.get("affects", [])
        if not targets:
            raise ValueError(f"Advisory without affected components: {identifier}")
        affected = []
        for target in targets:
            ref = target.get("ref")
            if ref not in refs:
                raise ValueError(f"Dangling affected-component reference: {ref}")
            affected.append(refs[ref])
        ratings = []
        for rating in vulnerability.get("ratings", []):
            method = rating.get("method", "unknown")
            score = rating.get("score")
            if score is not None:
                if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
                    raise ValueError(f"Invalid supplied rating: {score}")
            ratings.append({"method": method, "score": score,
                            "source": rating.get("source", {}), "vector": rating.get("vector")})
        findings.append({"advisory_id": identifier, "affected_components": affected,
                         "ratings_as_supplied": ratings,
                         "review_status": "OPEN — assess applicability and remediation",
                         "recommendation": vulnerability.get("recommendation", "Review advisory and available fixes")})
    return {"scope": "Flat Python audit snapshot; not the complete application/system SBOM",
            "specification": "CycloneDX 1.4", "components": len(inventory),
            "inventory_matches_snapshot": True, "advisory_records": len(findings),
            "distinct_advisory_ids": len({f["advisory_id"] for f in findings}),
            "unscored_advisories": sum(not any(r["score"] is not None for r in f["ratings_as_supplied"]) for f in findings),
            "findings": findings,
            "interpretation": "A missing CVSS score is unknown, not low severity. A clean feed result is not proof of safety."}


def markdown(result: dict) -> str:
    # JSON is the authoritative output. Escape user-controlled Markdown text.
    def safe(value):
        return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")
    lines = ["# Local SBOM review", "", result["scope"], "",
             f"Components: **{result['components']}**; inventory matches snapshot: **yes**.",
             f"Advisory records: **{result['advisory_records']}**; distinct IDs: **{result['distinct_advisory_ids']}**; records without supplied scores: **{result['unscored_advisories']}**.",
             "", result["interpretation"], "",
             "| Advisory | Affected component | Supplied score(s) | Status |", "|---|---|---|---|"]
    for finding in result["findings"]:
        scores = ", ".join(f"{safe(r['method'])}: {r['score']}" for r in finding["ratings_as_supplied"] if r["score"] is not None) or "Unknown"
        for component in finding["affected_components"]:
            lines.append(f"| {safe(finding['advisory_id'])} | {safe(component['name'])} {safe(component['version'])} | {scores} | OPEN |")
    lines += ["", "## Input evidence", ""]
    for name, digest in result.get("input_sha256", {}).items():
        lines.append(f"- {safe(name)}: `{digest}`")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bom", type=Path)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw_bom, raw_lock = args.bom.read_bytes(), args.snapshot.read_bytes()
        result = review(json.loads(raw_bom), raw_lock.decode())
        result["input_sha256"] = {args.bom.name: hashlib.sha256(raw_bom).hexdigest(),
                                  args.snapshot.name: hashlib.sha256(raw_lock).hexdigest()}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
        args.output.with_suffix(".md").write_text(markdown(result))
    except (ValueError, OSError, TypeError, KeyError) as exc:
        parser.exit(2, f"Review failed: {exc}\n")


if __name__ == "__main__":
    main()
