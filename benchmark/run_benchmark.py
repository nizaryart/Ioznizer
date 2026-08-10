#!/usr/bin/env python3
"""
Score Ioznizer against labelled samples.

Validation checks that a report is well-formed; this checks whether it is
right. Each case states what a correct analysis must and must not conclude,
and the harness reports pass/fail per assertion rather than a single opaque
number.

Because the analyser is non-deterministic, --repeat runs each case several
times and reports the spread. A tool that classifies the same binary three
different ways is not usable for triage, and that only shows up when measured.

Usage:
    python3 benchmark/run_benchmark.py                    # all cases, once
    python3 benchmark/run_benchmark.py --repeat 3         # measure variance
    python3 benchmark/run_benchmark.py --case ddos-bot    # one case
    python3 benchmark/run_benchmark.py --report out.json  # machine-readable
"""

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = Path(__file__).resolve().parent / "cases.json"

GREEN, RED, YELLOW, GREY, BOLD, RESET = (
    "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[1m", "\033[0m"
)


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

def check_case(report: dict, expect: dict) -> list:
    """Return [(passed, description, detail), ...] for one report."""
    results = []

    summary = report.get("executive_summary") or {}
    technical = report.get("technical_analysis") or {}
    iocs = report.get("indicators_of_compromise") or {}

    classification = str(summary.get("classification", "")).lower()
    score = summary.get("risk_score")
    behaviours = technical.get("malicious_behaviors") or []
    capabilities = " ".join(str(c).lower() for c in summary.get("key_capabilities") or [])

    if "risk_min" in expect:
        ok = isinstance(score, (int, float)) and score >= expect["risk_min"]
        results.append((ok, f"risk_score >= {expect['risk_min']}", f"got {score}"))

    if "risk_max" in expect:
        ok = isinstance(score, (int, float)) and score <= expect["risk_max"]
        results.append((ok, f"risk_score <= {expect['risk_max']}", f"got {score}"))

    if "classification_any" in expect:
        hits = [w for w in expect["classification_any"] if w in classification]
        results.append((
            bool(hits),
            f"classification mentions one of {expect['classification_any']}",
            f"got {classification!r}",
        ))

    if "classification_none" in expect:
        bad = [w for w in expect["classification_none"] if w in classification]
        results.append((
            not bad,
            f"classification avoids {expect['classification_none']}",
            f"got {classification!r}" + (f" (matched {bad})" if bad else ""),
        ))

    if "min_behaviours" in expect:
        ok = len(behaviours) >= expect["min_behaviours"]
        results.append((ok, f">= {expect['min_behaviours']} behaviours", f"got {len(behaviours)}"))

    if "max_behaviours" in expect:
        ok = len(behaviours) <= expect["max_behaviours"]
        results.append((ok, f"<= {expect['max_behaviours']} behaviours", f"got {len(behaviours)}"))

    if "iocs_include_ips" in expect:
        found = [str(i) for i in (iocs.get("network_iocs") or {}).get("ips") or []]
        missing = [ip for ip in expect["iocs_include_ips"] if ip not in found]
        results.append((
            not missing,
            f"IOCs include {expect['iocs_include_ips']}",
            f"missing {missing}" if missing else "all present",
        ))

    if "capabilities_any" in expect:
        hits = [w for w in expect["capabilities_any"] if w in capabilities]
        results.append((
            bool(hits),
            f"capabilities mention one of {expect['capabilities_any']}",
            f"{len(hits)} matched",
        ))

    return results


def quality_metrics(report: dict) -> dict:
    """Evidence quality, independent of whether the verdict is correct."""
    technical = report.get("technical_analysis") or {}
    behaviours = [b for b in (technical.get("malicious_behaviors") or [])
                  if isinstance(b, dict)]
    validation = report.get("validation") or {}

    verified = sum(1 for b in behaviours if b.get("evidence_verified") is True)

    return {
        "behaviours": len(behaviours),
        "evidence_verified": verified,
        "evidence_verified_pct": round(100 * verified / len(behaviours)) if behaviours else None,
        "validation_errors": validation.get("errors", 0),
        "validation_warnings": validation.get("warnings", 0),
        "degraded": "raw_analysis" in report,
    }


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run_once(sample: Path, timeout: int) -> tuple:
    """Run the pipeline and return (report_dict|None, seconds, error|None)."""
    before = {p.name for p in (ROOT / "reports").glob("*.json")}
    started = time.time()

    try:
        proc = subprocess.run(
            [str(ROOT / "run.sh"), str(sample)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, time.time() - started, f"timed out after {timeout}s"

    elapsed = time.time() - started

    after = {p.name for p in (ROOT / "reports").glob("*.json")}
    fresh = sorted(after - before)
    if not fresh:
        tail = proc.stdout.decode(errors="ignore").strip().splitlines()[-5:]
        return None, elapsed, "no report produced: " + " | ".join(tail)

    report_path = ROOT / "reports" / fresh[-1]
    try:
        report = json.loads(report_path.read_text())
    except json.JSONDecodeError as e:
        return None, elapsed, f"report is not valid JSON: {e}"

    # A degraded report is not a result. The pipeline still writes one when the
    # LLM stage fails (quota exhausted, provider down), and scoring it would
    # record an infrastructure failure as an analytical verdict - a benign
    # sample would "pass" its no-behaviours assertion for entirely the wrong
    # reason.
    summary = report.get("executive_summary") or {}
    if report.get("raw_analysis") is not None or summary.get("extraction_status"):
        reason = summary.get("extraction_status", "structured output unavailable")
        return None, elapsed, f"analysis did not complete ({reason})"

    return report, elapsed, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=1, help="runs per case (default 1)")
    parser.add_argument("--case", help="run a single case by name")
    parser.add_argument("--timeout", type=int, default=1200, help="per-run timeout in seconds")
    parser.add_argument("--report", help="write machine-readable results to this path")
    args = parser.parse_args()

    spec = json.loads(CASES.read_text())
    cases = spec["cases"]
    if args.case:
        cases = [c for c in cases if c["name"] == args.case]
        if not cases:
            print(f"No case named {args.case!r}")
            return 1

    results = []
    total_assertions = passed_assertions = 0

    for case in cases:
        sample = ROOT / case["path"]
        print(f"\n{BOLD}{case['name']}{RESET}  ({case['label']})")
        print(f"  {GREY}{case.get('notes','')}{RESET}")

        if not sample.exists():
            print(f"  {YELLOW}skipped{RESET}: {case['path']} not present")
            results.append({"case": case["name"], "status": "skipped"})
            continue

        if case.get("sha256"):
            actual = sha256(sample)
            if actual != case["sha256"]:
                print(f"  {YELLOW}skipped{RESET}: sha256 mismatch")
                print(f"    expected {case['sha256']}")
                print(f"    actual   {actual}")
                results.append({"case": case["name"], "status": "skipped",
                                "reason": "sha256 mismatch"})
                continue

        runs = []
        for i in range(args.repeat):
            label = f"  run {i+1}/{args.repeat}" if args.repeat > 1 else "  run"
            print(f"{label} ... ", end="", flush=True)

            report, elapsed, error = run_once(sample, args.timeout)
            if error:
                print(f"{RED}error{RESET} ({elapsed:.0f}s): {error}")
                runs.append({"error": error, "seconds": elapsed})
                continue

            checks = check_case(report, case.get("expect", {}))
            quality = quality_metrics(report)
            ok = sum(1 for c in checks if c[0])

            colour = GREEN if ok == len(checks) else RED
            print(f"{colour}{ok}/{len(checks)}{RESET} ({elapsed:.0f}s)"
                  f"  risk={(report.get('executive_summary') or {}).get('risk_score')}"
                  f"  behaviours={quality['behaviours']}"
                  f"  verified={quality['evidence_verified_pct']}%")

            for good, description, detail in checks:
                if not good:
                    print(f"      {RED}✗{RESET} {description} — {detail}")

            runs.append({
                "checks": [{"passed": g, "check": d, "detail": t} for g, d, t in checks],
                "passed": ok,
                "total": len(checks),
                "seconds": elapsed,
                "quality": quality,
                "classification": (report.get("executive_summary") or {}).get("classification"),
                "risk_score": (report.get("executive_summary") or {}).get("risk_score"),
            })
            total_assertions += len(checks)
            passed_assertions += ok

        # Variance across repeats is itself a result.
        scored = [r for r in runs if "passed" in r]
        if args.repeat > 1 and scored:
            classifications = {r["classification"] for r in scored}
            scores = [r["risk_score"] for r in scored
                      if isinstance(r["risk_score"], (int, float))]
            print(f"  {BOLD}variance{RESET}: {len(classifications)} distinct "
                  f"classification(s) across {len(scored)} runs")
            if len(scores) > 1:
                print(f"            risk_score {min(scores)}-{max(scores)} "
                      f"(stdev {statistics.stdev(scores):.1f})")
            if len(classifications) > 1:
                for c in classifications:
                    print(f"            {GREY}- {c}{RESET}")

        results.append({"case": case["name"], "label": case["label"], "runs": runs})

    print(f"\n{BOLD}{'=' * 60}{RESET}")
    if total_assertions:
        pct = 100 * passed_assertions / total_assertions
        colour = GREEN if pct == 100 else (YELLOW if pct >= 80 else RED)
        print(f"{colour}{passed_assertions}/{total_assertions} assertions passed "
              f"({pct:.0f}%){RESET}")
    else:
        print("No assertions evaluated.")

    if args.report:
        Path(args.report).write_text(json.dumps({
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "repeat": args.repeat,
            "assertions": {"passed": passed_assertions, "total": total_assertions},
            "results": results,
        }, indent=2))
        print(f"Written to {args.report}")

    return 0 if passed_assertions == total_assertions else 1


if __name__ == "__main__":
    sys.exit(main())
