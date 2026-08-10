"""
Decompiler backends.

Decompilation is the half of the workflow that disassembly cannot cover: the
agent reasons far better about `socket(2,3,6)` than about the equivalent i386
instruction sequence.

Backends are tried in order of output quality:

  GhidraBackend    - headless Ghidra, driven by ghidra_scripts/ExportDecompiledC.java
  Radare2Backend   - r2's `pdc`, lower fidelity but a single package install
  NullBackend      - reports honestly that no decompiler is installed

The NullBackend exists so that a missing decompiler produces a clear message
rather than a placeholder that the agent might read as real evidence.
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

# Emitted by ExportDecompiledC.java and by Radare2Backend, and parsed by the
# decompile_function tool to slice this file into individual functions.
# Keep in sync with _DECOMP_FUNC_MARKER in agent/tool_dispatcher.py.
FUNCTION_MARKER = "// ===== FUNCTION {name} @ {address} ====="

GHIDRA_SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra_scripts"
GHIDRA_SCRIPT_NAME = "ExportDecompiledC.java"

DEFAULT_TIMEOUT = int(os.getenv("DECOMPILER_TIMEOUT", "900"))


class DecompilerError(RuntimeError):
    """Decompilation was attempted and failed."""


def _sandbox_prefix(writable: List[Path]) -> List[str]:
    """
    Build a bubblewrap prefix that confines the decompiler.

    The decompiler never executes the sample, so this is defence in depth: it
    contains a malformed input exploiting the analyser's own parsers, and it
    removes network access outright. Disable with IOZNIZER_SANDBOX=0.

    Java resolves `user.home` from /etc/passwd rather than $HOME, so the real
    home directory is masked with a scratch one instead of setting HOME.
    """
    if os.getenv("IOZNIZER_SANDBOX", "1") == "0":
        return []
    if not shutil.which("bwrap"):
        return []

    home = Path.home()
    scratch_home = writable[0] / "sandbox-home"
    scratch_home.mkdir(parents=True, exist_ok=True)

    cmd = [
        "bwrap",
        "--ro-bind", "/", "/",
        "--dev-bind", "/dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/var/tmp",
        "--unshare-net",
        "--die-with-parent",
        "--new-session",
    ]
    for path in writable:
        cmd += ["--bind", str(path), str(path)]
    cmd += ["--bind", str(scratch_home), str(home)]
    return cmd


class DecompilerBackend:
    """Base class for decompiler backends."""

    name = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def decompile(self, sample: Path, out_file: Path, timeout: int = DEFAULT_TIMEOUT) -> str:
        raise NotImplementedError


class GhidraBackend(DecompilerBackend):
    """
    Headless Ghidra.

    Located via GHIDRA_HOME, or by finding analyzeHeadless on PATH.
    """

    name = "ghidra"

    def __init__(self, ghidra_home: Optional[str] = None):
        self.ghidra_home = ghidra_home or os.getenv("GHIDRA_HOME")
        self._headless = self._find_headless()

    def _find_headless(self) -> Optional[Path]:
        if self.ghidra_home:
            candidate = Path(self.ghidra_home) / "support" / "analyzeHeadless"
            if candidate.is_file():
                return candidate

        on_path = shutil.which("analyzeHeadless")
        if on_path:
            return Path(on_path)

        # Installations are usually version-suffixed (ghidra_12.1.2_PUBLIC), so
        # the well-known locations have to be globbed rather than matched
        # literally; distribution packages (e.g. Kali) also relocate the
        # support scripts under /usr/share.
        candidates = [Path("/usr/share/ghidra/support/analyzeHeadless")]
        for root in (Path("/opt"), Path.home()):
            try:
                candidates.extend(
                    sorted(root.glob("ghidra*/support/analyzeHeadless"), reverse=True)
                )
            except OSError:
                continue

        for candidate in candidates:
            if candidate.is_file():
                return candidate

        return None

    def available(self) -> bool:
        return self._headless is not None

    def decompile(self, sample: Path, out_file: Path, timeout: int = DEFAULT_TIMEOUT) -> str:
        if not self.available():
            raise DecompilerError(
                "Ghidra not found. Set GHIDRA_HOME to your Ghidra installation."
            )

        with tempfile.TemporaryDirectory(prefix="ioznizer-ghidra-") as tmp:
            work = Path(tmp)
            project_dir = work / "project"
            project_dir.mkdir()

            # Ghidra compiles the .java script and writes class files beside it,
            # so the script directory must be writable.
            script_dir = work / "scripts"
            shutil.copytree(GHIDRA_SCRIPT_DIR, script_dir)

            staged_out = work / "decomp.c"

            # The sandbox masks the real home directory, so the sample is copied
            # into the work tree rather than referenced where it lies. The copy
            # is stripped of its execute bit: nothing here ever runs the sample.
            staged_sample = work / f"sample{sample.suffix}"
            shutil.copyfile(sample, staged_sample)
            staged_sample.chmod(0o400)

            cmd = _sandbox_prefix([work]) + [
                str(self._headless),
                str(project_dir), "ioznizer",
                "-import", str(staged_sample),
                "-scriptPath", str(script_dir),
                "-postScript", GHIDRA_SCRIPT_NAME, str(staged_out), "0", "60",
                "-deleteProject",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                raise DecompilerError(
                    f"Ghidra timed out after {timeout}s. Raise DECOMPILER_TIMEOUT "
                    f"for large binaries."
                )

            if not staged_out.exists():
                tail = result.stdout.decode(errors="ignore").strip().splitlines()[-15:]
                raise DecompilerError(
                    "Ghidra produced no output.\n" + "\n".join(tail)
                )

            output = staged_out.read_text(errors="ignore")

            # Cross-references are exported alongside the pseudo-C by the same
            # Ghidra run; they back the find_references tool.
            staged_xrefs = Path(str(staged_out) + ".xrefs")
            xrefs = staged_xrefs.read_text(errors="ignore") if staged_xrefs.exists() else None

        out_file.write_text(output)
        if xrefs is not None:
            (out_file.parent / "xrefs.txt").write_text(xrefs)
        return output


class Radare2Backend(DecompilerBackend):
    """
    radare2's built-in pseudo-decompiler (`pdc`).

    Lower fidelity than Ghidra, especially on stripped binaries, but installs
    as a single package. Offered as a fallback so the pipeline is usable
    without a Ghidra install.
    """

    name = "radare2"

    def available(self) -> bool:
        return shutil.which("r2") is not None or shutil.which("radare2") is not None

    def _binary(self) -> str:
        return shutil.which("r2") or shutil.which("radare2")

    def decompile(self, sample: Path, out_file: Path, timeout: int = DEFAULT_TIMEOUT) -> str:
        if not self.available():
            raise DecompilerError("radare2 not found on PATH.")

        r2 = self._binary()

        with tempfile.TemporaryDirectory(prefix="ioznizer-r2-") as tmp:
            work = Path(tmp)
            sandbox = _sandbox_prefix([work])

            # Staged into the work tree for the same reason as the Ghidra path:
            # the sandbox masks the home directory the sample may live under.
            staged_sample = work / f"sample{sample.suffix}"
            shutil.copyfile(sample, staged_sample)
            staged_sample.chmod(0o400)

            # Pass 1: enumerate functions after full analysis.
            listing = subprocess.run(
                sandbox + [r2, "-q", "-e", "scr.color=0", "-c", "aaa;aflj", str(staged_sample)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            )

            try:
                functions = json.loads(listing.stdout.decode(errors="ignore") or "[]")
            except json.JSONDecodeError:
                raise DecompilerError("Could not parse radare2 function listing.")

            if not functions:
                raise DecompilerError("radare2 found no functions to decompile.")

            # Pass 2: decompile each function, emitting the shared marker format.
            script_lines = ["aaa"]
            for func in functions:
                name = func.get("name", "unknown")
                offset = func.get("offset", 0)
                marker = FUNCTION_MARKER.format(name=name, address=hex(offset))
                script_lines.append(f"?e {marker}")
                script_lines.append(f"pdc @ {offset}")
                script_lines.append("?e")

            script_file = work / "decompile.r2"
            script_file.write_text("\n".join(script_lines))

            result = subprocess.run(
                sandbox + [r2, "-q", "-e", "scr.color=0", "-i", str(script_file), str(staged_sample)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            )

        header = (
            f"// Decompiled by radare2 (pdc)\n"
            f"// Program: {sample.name}\n"
            f"// Functions: {len(functions)}\n\n"
        )
        output = header + result.stdout.decode(errors="ignore")
        out_file.write_text(output)
        return output


class NullBackend(DecompilerBackend):
    """Used when no decompiler is installed."""

    name = "none"

    def available(self) -> bool:
        return True

    def decompile(self, sample: Path, out_file: Path, timeout: int = DEFAULT_TIMEOUT) -> str:
        output = (
            "// No decompiler available.\n"
            "//\n"
            "// Decompilation was skipped because neither Ghidra nor radare2 was found.\n"
            "// Install one of the following and re-run:\n"
            "//\n"
            "//   Ghidra (preferred): set GHIDRA_HOME=/path/to/ghidra\n"
            "//   radare2:            apt install radare2\n"
            "//\n"
            "// Disassembly is still available via the disasm section.\n"
        )
        out_file.write_text(output)
        return output


def get_decompiler(preferred: Optional[str] = None) -> DecompilerBackend:
    """
    Select a decompiler backend.

    Args:
        preferred: force a backend by name ('ghidra', 'radare2', 'none').
                   Defaults to the DECOMPILER_BACKEND environment variable.
    """
    preferred = preferred or os.getenv("DECOMPILER_BACKEND")

    backends = {
        "ghidra": GhidraBackend,
        "radare2": Radare2Backend,
        "none": NullBackend,
    }

    if preferred:
        key = preferred.lower()
        if key not in backends:
            raise ValueError(
                f"Unknown decompiler backend: {preferred}. "
                f"Choose from: {', '.join(backends)}"
            )
        backend = backends[key]()
        if not backend.available():
            raise DecompilerError(
                f"Requested decompiler '{preferred}' is not available on this system."
            )
        return backend

    for backend_cls in (GhidraBackend, Radare2Backend):
        backend = backend_cls()
        if backend.available():
            return backend

    return NullBackend()
