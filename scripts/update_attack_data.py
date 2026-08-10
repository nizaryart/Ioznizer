#!/usr/bin/env python3
"""
Regenerate the bundled MITRE ATT&CK technique reference.

The analyser validates every technique ID a model reports against this file.
It is distilled from MITRE's official STIX bundle (~52 MB) down to the ID,
canonical name and lifecycle flags (~60 KB), so validation runs offline and
an analysis never depends on attack.mitre.org being reachable.

Usage:
    python3 scripts/update_attack_data.py                  # download and rebuild
    python3 scripts/update_attack_data.py --from-file X    # rebuild from a local bundle
    python3 scripts/update_attack_data.py --check          # report drift, write nothing
"""

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

OUTPUT = Path(__file__).resolve().parent.parent / "agent" / "data" / "attack_techniques.json"


def load_bundle(source: str = None) -> dict:
    if source:
        print(f"[+] Reading {source}")
        return json.loads(Path(source).read_text())

    print(f"[+] Downloading {STIX_URL}")
    with urllib.request.urlopen(STIX_URL, timeout=300) as response:
        raw = response.read()
    print(f"[+] Downloaded {len(raw) / 1024 / 1024:.1f} MB")
    return json.loads(raw)


def distil(bundle: dict) -> dict:
    """Reduce the STIX bundle to an id -> metadata map."""
    techniques = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        # The ATT&CK ID lives in the mitre-attack external reference; other
        # references point at source material and must be ignored.
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                technique_id = ref["external_id"]
                break

        if not technique_id:
            continue

        techniques[technique_id] = {
            "name": obj.get("name", ""),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "revoked": bool(obj.get("revoked", False)),
            "subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        }

    # Collection version, when the bundle carries one.
    version = None
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            break

    return {
        "source": STIX_URL,
        "attack_version": version,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "technique_count": len(techniques),
        "techniques": dict(sorted(techniques.items())),
    }


def report_drift(old: dict, new: dict) -> None:
    """Print what changed, so an update is reviewable rather than opaque."""
    old_t = old.get("techniques", {})
    new_t = new.get("techniques", {})

    added = sorted(set(new_t) - set(old_t))
    removed = sorted(set(old_t) - set(new_t))
    renamed = sorted(
        tid for tid in set(old_t) & set(new_t)
        if old_t[tid].get("name") != new_t[tid].get("name")
    )
    newly_deprecated = sorted(
        tid for tid in set(old_t) & set(new_t)
        if not old_t[tid].get("deprecated") and new_t[tid].get("deprecated")
    )

    print(f"\n  previous : {len(old_t)} techniques (generated {old.get('generated', '?')})")
    print(f"  current  : {len(new_t)} techniques")
    print(f"  added    : {len(added)}    {', '.join(added[:6])}{' ...' if len(added) > 6 else ''}")
    print(f"  removed  : {len(removed)}    {', '.join(removed[:6])}{' ...' if len(removed) > 6 else ''}")
    print(f"  renamed  : {len(renamed)}    {', '.join(renamed[:6])}{' ...' if len(renamed) > 6 else ''}")
    print(f"  newly deprecated: {len(newly_deprecated)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-file", help="use a local STIX bundle instead of downloading")
    parser.add_argument("--check", action="store_true", help="report drift without writing")
    args = parser.parse_args()

    try:
        bundle = load_bundle(args.from_file)
    except Exception as e:
        print(f"[ERROR] Could not load the STIX bundle: {e}")
        return 1

    new = distil(bundle)
    print(f"[+] Distilled {new['technique_count']} techniques")

    if OUTPUT.exists():
        try:
            report_drift(json.loads(OUTPUT.read_text()), new)
        except json.JSONDecodeError:
            print("[WARNING] Existing data file is not valid JSON; it will be replaced")

    if args.check:
        print("\n[+] --check given, nothing written")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n")
    size_kb = OUTPUT.stat().st_size / 1024
    print(f"\n[+] Wrote {OUTPUT} ({size_kb:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
