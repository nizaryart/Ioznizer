# CycloneDX dependency-review exercise

**Local personal exercise prepared on 31 October 2026 with AI assistance.**
It extends Ioznizer's existing dependency-audit work. Review the implementation
and reproduce the commands before discussing it as hands-on experience.
It is not an automotive project, a production deployment or an SPDX implementation.

## What it demonstrates

1. Generate CycloneDX JSON using PyPA's `pip-audit` rather than inventing a format.
2. Match every flat inventory component to an exact name/version in the audit snapshot.
3. Link each advisory record to existing component references; reject dangling references.
4. Retain supplied ratings with their source/method. Missing CVSS remains **unknown**.
5. Produce JSON/Markdown review reports with SHA-256 hashes of both inputs.
6. Exercise a known-vulnerable **uninstalled** Jinja2 requirement as a negative control.

`tools/sbom_review.py` is a consistency checker, not a scanner or CVSS calculator.
It does not determine exploitability, runtime reachability or remediation success.
Advisories remain OPEN for human applicability review. It never installs or runs
the analyzed packages.

## Recorded results

Evidence is in [sbom-evidence/](sbom-evidence/):

| Check | Result in this session |
|---|---|
| Runtime inventory | 15 components, all match `requirements-runtime.lock` |
| Runtime advisory scan | No known advisories reported by the queried feed at check time |
| Uninstalled negative control | pip-audit exit 1; affected component and advisory links present |
| Negative-control counts | 10 raw audit records; 6 CycloneDX records; 5 distinct advisory IDs in both outputs |
| CycloneDX validation | Both generated files pass the official JSON 1.4 schema |
| Full project tests | 44 passed: 26 previous checks plus 18 SBOM-review test cases |
| New checker SAST | No medium/high findings from Bandit |

The source feed included repeated advisory IDs. The review preserves records and
reports distinct IDs separately rather than presenting duplicates as independent
vulnerabilities. The raw JSON contains CVE/GHSA aliases, while this version of
pip-audit's CycloneDX output primarily uses PYSEC identifiers. Neither negative-control
output supplied CVSS ratings; no score was inferred from an identifier or description.

## Reproduce

From the repository root, with Python 3.10+ (tested here with Python 3.14):

```bash
python3 -m venv /tmp/ioznizer-sbom
/tmp/ioznizer-sbom/bin/python -m pip install 'pip-audit==2.10.1' 'cyclonedx-python-lib[json-validation]==11.12.0' 'pytest==9.2.0'
/tmp/ioznizer-sbom/bin/python -m pytest -q tests

/tmp/ioznizer-sbom/bin/python -m pip_audit -r requirements-runtime.lock --no-deps --disable-pip --strict -f cyclonedx-json -o docs/sbom-evidence/runtime.cdx.json
/tmp/ioznizer-sbom/bin/python tools/sbom_review.py docs/sbom-evidence/runtime.cdx.json requirements-runtime.lock --output docs/sbom-evidence/runtime-review

/tmp/ioznizer-sbom/bin/python -m pip_audit -r docs/sbom-evidence/negative-control.txt --no-deps --disable-pip --strict -f cyclonedx-json -o docs/sbom-evidence/negative-control.cdx.json
# Inspect this command's exit status: 1 is expected for the known-vulnerable fixture.
# Network/collection errors are not proof that the negative control worked.
/tmp/ioznizer-sbom/bin/python tools/sbom_review.py docs/sbom-evidence/negative-control.cdx.json docs/sbom-evidence/negative-control.txt --output docs/sbom-evidence/negative-control-review
```

Run commands individually and inspect their output. The generation commands query
public advisory services; reports and counts may change. No vulnerable fixture is
installed. Schema validation can be repeated with:

```bash
/tmp/ioznizer-sbom/bin/python - <<'PY'
from pathlib import Path
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
validator = JsonStrictValidator(SchemaVersion.V1_4)
for path in Path('docs/sbom-evidence').glob('*.cdx.json'):
    errors = validator.validate_str(path.read_text())
    if errors:
        raise ValueError(str(errors))
    print(path, 'valid')
PY
```

## Limits and next steps

- This is a flat Python **audit-snapshot inventory**, not a complete product SBOM.
  It omits operating-system/native packages, embedded components and a dependency graph.
- Exact agreement with the snapshot does not prove the snapshot includes every runtime dependency.
  The snapshot is not enforced by the original setup script and lacks distribution hashes.
- Full schema validation is a separate step; the Python checker validates its supported
  subset and explicitly rejects nested inventories and versions other than 1.4.
- No SPDX generation, VEX assertions, automatic remediation or hosted CI run is claimed.
- A component list is not enough to assess risk. A next iteration would add authoritative
  advisory enrichment, applicability decisions and upgrade/retest evidence.

References: [PyPA pip-audit](https://github.com/pypa/pip-audit),
[CycloneDX specification and schema](https://github.com/CycloneDX/specification).
The generator, library and specifications retain their respective upstream licenses.
The new checker is part of this repository under its existing license.
