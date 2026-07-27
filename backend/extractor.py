"""
Static extraction backend.

Runs binutils against an ELF sample and writes the raw artifacts that the
analysis agent later queries through its tools.
"""

import hashlib
import subprocess
from pathlib import Path
import sys
import shutil
import re

try:
    from .decompiler import get_decompiler, DecompilerError
except ImportError:  # direct execution: python3 backend/extractor.py
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from backend.decompiler import get_decompiler, DecompilerError


class CommandError(RuntimeError):
    """A required external command failed."""


class StaticExtractor:
    def __init__(self, sample_path: str, output_dir=None):
        """
        Initialize the static extractor.

        Args:
            sample_path: Path to the ELF sample file
            output_dir: Output directory for analysis files (default: analysis/ at project root)
        """
        self.sample = Path(sample_path).resolve()

        # Set default output directory to analysis/ at project root
        if output_dir is None:
            project_root = Path(__file__).resolve().parent.parent
            self.out_dir = project_root / "analysis"
        else:
            self.out_dir = Path(output_dir)

        self.out_dir.mkdir(exist_ok=True, parents=True)

        if not self.sample.exists():
            raise FileNotFoundError(f"Sample not found: {self.sample}")

        # Validate it's an ELF file
        if not self._is_elf_file():
            raise ValueError(f"File is not a valid ELF file: {self.sample}")

        # Check required tools
        self._check_required_tools()

        # Detect architecture
        self.architecture = self._detect_architecture()

        # Populated by extract_decompilation() / compute_hashes()
        self.decompiler = None
        self.hashes = None

    def _is_elf_file(self):
        """Check if file is a valid ELF file."""
        try:
            with open(self.sample, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception:
            return False

    def _check_required_tools(self):
        """Check if required tools are available."""
        required_tools = ['readelf', 'objdump', 'strings']
        missing_tools = []

        for tool in required_tools:
            if not shutil.which(tool):
                missing_tools.append(tool)

        if missing_tools:
            raise RuntimeError(
                f"Required tools not found: {', '.join(missing_tools)}\n"
                f"Please install binutils package (apt-get install binutils)"
            )

    def _detect_architecture(self):
        """
        Detect the architecture of the ELF file.
        Returns architecture string (e.g., 'arm', 'i386', 'i386:x86-64', 'mips')
        """
        try:
            output = self._run(["readelf", "-h", "-W", str(self.sample)])
        except CommandError as e:
            print(f"[WARNING] Could not read ELF header: {e}")
            output = ""

        # Parse machine type from readelf output
        machine_match = re.search(r'Machine:\s+(.+)', output)
        if machine_match:
            machine = machine_match.group(1).strip().lower()

            # Map to objdump architecture flags
            arch_map = {
                'advanced micro devices x86-64': 'i386:x86-64',
                'intel 80386': 'i386',
                'aarch64': 'aarch64',
                'x86-64': 'i386:x86-64',
                'mips r3000': 'mips',
                'powerpc': 'powerpc',
                'sparc': 'sparc',
                'arm': 'arm',
                'mips': 'mips',
            }

            for key, value in arch_map.items():
                if key in machine:
                    return value

            # Try to extract architecture from machine string
            if 'arm' in machine:
                return 'arm'
            elif 'x86' in machine or '386' in machine or 'amd64' in machine:
                return 'i386:x86-64' if '64' in machine else 'i386'
            elif 'mips' in machine:
                return 'mips'

        # Fallback: try the file command
        if shutil.which('file'):
            try:
                file_output = self._run(["file", "-b", str(self.sample)]).lower()
            except CommandError:
                file_output = ""

            if 'aarch64' in file_output:
                return 'aarch64'
            elif 'arm' in file_output:
                return 'arm'
            elif 'x86-64' in file_output or 'amd64' in file_output:
                return 'i386:x86-64'
            elif '386' in file_output or 'i386' in file_output:
                return 'i386'
            elif 'mips' in file_output:
                return 'mips'

        return None

    def _run(self, cmd, timeout: int = 300):
        """
        Run a command and return its decoded stdout.

        The command is passed as an argument list and executed without a shell,
        so sample paths containing spaces or shell metacharacters are handled
        literally rather than being re-parsed by /bin/sh.

        Raises:
            CommandError: if the command is missing, fails, or times out.
        """
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=True,
            )
            return result.stdout.decode(errors="ignore")
        except FileNotFoundError:
            raise CommandError(f"Tool not found: {cmd[0]}")
        except subprocess.TimeoutExpired:
            raise CommandError(f"Timed out after {timeout}s: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            detail = (e.stderr or b"").decode(errors="ignore").strip()
            if not detail:
                detail = (e.stdout or b"").decode(errors="ignore").strip()
            raise CommandError(
                f"{cmd[0]} failed (exit {e.returncode}): {detail or 'no output'}"
            )

    def compute_hashes(self):
        """
        Hash the sample.

        The report's IOC section is incomplete without these: a file hash is
        the first indicator any analyst pivots on.
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(self.sample, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                md5.update(block)
                sha1.update(block)
                sha256.update(block)

        self.hashes = {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "size_bytes": self.sample.stat().st_size,
        }
        return self.hashes

    def extract_metadata(self):
        """Extract ELF metadata using readelf, prefixed with file identity."""
        output = self._run(["readelf", "-a", "-W", str(self.sample)])

        hashes = self.hashes or self.compute_hashes()
        header = (
            "=== FILE IDENTITY ===\n"
            f"filename : {self.sample.name}\n"
            f"size     : {hashes['size_bytes']} bytes\n"
            f"md5      : {hashes['md5']}\n"
            f"sha1     : {hashes['sha1']}\n"
            f"sha256   : {hashes['sha256']}\n\n"
        )

        output = header + output
        (self.out_dir / "metadata.txt").write_text(output)
        return output

    def extract_strings(self):
        """Extract strings from the binary."""
        output = self._run(["strings", "-a", str(self.sample)])
        (self.out_dir / "strings.txt").write_text(output)
        return output

    def extract_symbols(self):
        """
        Extract symbols, imports and exports.

        `readelf -s -W` is the authoritative source here: it dumps both .dynsym
        and .symtab, and -W prevents readelf from truncating long symbol names
        (without it, __libc_start_main is emitted as "_[...]"). The Ndx column
        distinguishes imports (UND) from defined exports, which is what the
        get_imports / get_exports tools parse.
        """
        symbols_output = self._run(["readelf", "-s", "-W", str(self.sample)])

        # objdump -x adds section/segment layout and relocation context. It does
        # not emit a dynamic symbol table (that requires -T), so it is kept for
        # context only and is not parsed for imports.
        try:
            headers_output = self._run(["objdump", "-x", str(self.sample)])
        except CommandError as e:
            headers_output = f"[unavailable] {e}"

        output = f"=== SYMBOLS (readelf -s -W) ===\n{symbols_output}\n\n"
        output += f"=== HEADERS & SECTIONS (objdump -x) ===\n{headers_output}"

        (self.out_dir / "symbols.txt").write_text(output)
        return output

    def extract_disassembly(self):
        """
        Extract disassembly using objdump with architecture-specific flags.
        The agent can later request specific addresses or functions.
        """
        base = ["objdump", "-d", str(self.sample)]
        attempts = []

        if self.architecture:
            attempts.append((self.architecture, ["objdump", "-d", "-m", self.architecture, str(self.sample)]))
        attempts.append((None, base))

        # Last resort: probe common architectures
        if not self.architecture:
            for arch in ['i386:x86-64', 'i386', 'arm', 'aarch64']:
                attempts.append((arch, ["objdump", "-d", "-m", arch, str(self.sample)]))

        last_error = None
        for arch, cmd in attempts:
            try:
                output = self._run(cmd)
            except CommandError as e:
                last_error = e
                if arch:
                    print(f"[WARNING] Disassembly with -m {arch} failed, trying next option...")
                continue

            if arch and arch != self.architecture:
                print(f"[+] Found working architecture: {arch}")
                self.architecture = arch

            (self.out_dir / "disasm.txt").write_text(output)
            return output

        raise CommandError(f"Disassembly failed for all attempted architectures: {last_error}")

    def extract_decompilation(self):
        """
        Decompile the sample to pseudo-C.

        Uses Ghidra when available and falls back to radare2, then to an
        explicit "no decompiler installed" note. A decompiler failure is
        reported but does not abort extraction: disassembly alone is still a
        usable basis for analysis.
        """
        out_file = self.out_dir / "decomp.txt"
        backend = get_decompiler()
        self.decompiler = backend.name

        print(f"[+] Decompiler backend: {backend.name}")

        try:
            return backend.decompile(self.sample, out_file)
        except DecompilerError as e:
            print(f"[WARNING] Decompilation failed: {e}")
            output = (
                f"// Decompilation failed using backend '{backend.name}'.\n"
                f"// {e}\n"
                f"//\n"
                f"// Disassembly is still available via the disasm section.\n"
            )
            out_file.write_text(output)
            self.decompiler = f"{backend.name} (failed)"
            return output

    def run_all(self):
        """
        Run all extraction methods.

        Extraction failures raise rather than being written into the analysis
        files: a captured error string would otherwise be handed to the agent
        as if it were binary evidence.
        """
        print(f"[+] Starting extraction for: {self.sample.name}")
        print(f"[+] Architecture detected: {self.architecture or 'unknown'}")
        print(f"[+] Output directory: {self.out_dir}")

        print("[+] Hashing sample...")
        self.compute_hashes()
        print(f"    sha256: {self.hashes['sha256']}")

        print("[+] Extracting metadata...")
        self.extract_metadata()

        print("[+] Extracting strings...")
        self.extract_strings()

        print("[+] Extracting symbols & imports...")
        self.extract_symbols()

        print("[+] Extracting disassembly...")
        self.extract_disassembly()

        print("[+] Decompiling...")
        self.extract_decompilation()

        print("[+] Extraction complete.")
        print(f"[+] Analysis files saved to: {self.out_dir}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 extractor.py <sample_path>")
        sys.exit(1)

    sample_path = sys.argv[1]

    try:
        print(f"[+] Running static extraction for: {sample_path}")
        extractor = StaticExtractor(sample_path)
        extractor.run_all()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
