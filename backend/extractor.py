import subprocess
from pathlib import Path
import sys
import shutil
import re


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
        Returns architecture string (e.g., 'arm', 'i386', 'x86-64', 'mips')
        """
        try:
            # Use readelf to get machine type
            result = subprocess.check_output(
                f"readelf -h {self.sample}",
                shell=True,
                stderr=subprocess.STDOUT
            )
            output = result.decode(errors="ignore")
            
            # Parse machine type from readelf output
            machine_match = re.search(r'Machine:\s+(\S+)', output)
            if machine_match:
                machine = machine_match.group(1).lower()
                
                # Map to objdump architecture flags
                arch_map = {
                    'arm': 'arm',
                    'aarch64': 'aarch64',
                    'intel 80386': 'i386',
                    'advanced micro devices x86-64': 'i386:x86-64',
                    'x86-64': 'i386:x86-64',
                    'mips': 'mips',
                    'mips r3000': 'mips',
                    'powerpc': 'powerpc',
                    'sparc': 'sparc',
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
            
            # Fallback: try file command
            result = subprocess.check_output(
                f"file {self.sample}",
                shell=True,
                stderr=subprocess.STDOUT
            )
            file_output = result.decode(errors="ignore").lower()
            
            if 'arm' in file_output:
                return 'arm'
            elif 'x86-64' in file_output or 'amd64' in file_output:
                return 'i386:x86-64'
            elif '386' in file_output or 'i386' in file_output:
                return 'i386'
            elif 'mips' in file_output:
                return 'mips'
            
            return None
        except Exception as e:
            print(f"[WARNING] Could not detect architecture: {e}")
            return None
    
    def _run(self, cmd: str):
        """Run shell command and return decoded output."""
        try:
            result = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, timeout=300
            )
            return result.decode(errors="ignore")
        except subprocess.TimeoutExpired:
            return f"[ERROR] Command timed out: {cmd}"
        except subprocess.CalledProcessError as e:
            error_output = e.output.decode(errors="ignore") if e.output else ""
            return f"[ERROR] Command failed: {cmd}\n{error_output}"
        except Exception as e:
            return f"[ERROR] {str(e)}"
    
    def extract_metadata(self):
        """Extract ELF metadata using readelf."""
        output = self._run(f"readelf -a {self.sample}")
        (self.out_dir / "metadata.txt").write_text(output)
        return output
    
    def extract_strings(self):
        """Extract strings from the binary."""
        output = self._run(f"strings -a {self.sample}")
        (self.out_dir / "strings.txt").write_text(output)
        return output
    
    def extract_symbols(self):
        """Extract symbols and imports using readelf and objdump."""
        # Get symbols from readelf
        symbols_output = self._run(f"readelf -s {self.sample}")
        
        # Get headers and imports from objdump
        headers_output = self._run(f"objdump -x {self.sample}")
        
        # Combine outputs
        output = f"=== SYMBOLS (readelf -s) ===\n{symbols_output}\n\n"
        output += f"=== HEADERS & IMPORTS (objdump -x) ===\n{headers_output}"
        
        (self.out_dir / "symbols.txt").write_text(output)
        return output
    
    def extract_disassembly(self):
        """
        Extract disassembly using objdump with architecture-specific flags.
        LLM can later request specific addresses.
        """
        # Build objdump command with architecture flag if detected
        if self.architecture:
            # Try architecture-specific disassembly first
            cmd = f"objdump -d -m {self.architecture} {self.sample}"
            output = self._run(cmd)
            
            # If that fails, try without architecture flag
            if "[ERROR]" in output or "can't disassemble" in output.lower():
                print(f"[WARNING] Architecture-specific disassembly failed, trying generic...")
                cmd = f"objdump -d {self.sample}"
                output = self._run(cmd)
        else:
            # No architecture detected, try generic
            cmd = f"objdump -d {self.sample}"
            output = self._run(cmd)
            
            # If generic fails, try with common architectures
            if "[ERROR]" in output or "can't disassemble" in output.lower():
                print(f"[WARNING] Generic disassembly failed, trying common architectures...")
                for arch in ['i386:x86-64', 'i386', 'arm', 'aarch64']:
                    cmd = f"objdump -d -m {arch} {self.sample}"
                    test_output = self._run(cmd)
                    if "[ERROR]" not in test_output and "can't disassemble" not in test_output.lower():
                        output = test_output
                        self.architecture = arch
                        print(f"[+] Found working architecture: {arch}")
                        break
        
        (self.out_dir / "disasm.txt").write_text(output)
        return output
    
    def extract_decompilation(self):
        """Placeholder for decompilation via Ghidra headless."""
        output = "[TODO] Decompilation via Ghidra headless\n"
        output += f"Architecture detected: {self.architecture or 'unknown'}\n"
        (self.out_dir / "decomp.txt").write_text(output)
        return output
    
    def run_all(self):
        """Run all extraction methods."""
        print(f"[+] Starting extraction for: {self.sample.name}")
        print(f"[+] Architecture detected: {self.architecture or 'unknown'}")
        print(f"[+] Output directory: {self.out_dir}")
        
        print("[+] Extracting metadata...")
        self.extract_metadata()
        
        print("[+] Extracting strings...")
        self.extract_strings()
        
        print("[+] Extracting symbols & imports...")
        self.extract_symbols()
        
        print("[+] Extracting disassembly...")
        self.extract_disassembly()
        
        print("[+] Extracting decompilation (placeholder)...")
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
