"""
Tool Dispatcher for executing tool requests from the LLM.
Executes tools and returns structured results.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import re


# A row of `readelf -s -W` output:
#      1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.2.5 (2)
_SYMBOL_ROW = re.compile(
    r"^\s*(?P<num>\d+):\s+"
    r"(?P<value>[0-9a-fA-F]+)\s+"
    r"(?P<size>\S+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<bind>\S+)\s+"
    r"(?P<vis>\S+)\s+"
    r"(?P<ndx>\S+)"
    r"(?:\s+(?P<name>.*))?$"
)

# `Symbol table '.dynsym' contains 19 entries:`
_SYMBOL_TABLE_HEADER = re.compile(r"Symbol table '(?P<table>[^']+)' contains")

# A function definition header in `objdump -d` output:
# 00000000000012e2 <shuffle>:
_FUNC_DEF = r"^(?P<addr>[0-9a-fA-F]+)\s+<{name}>:\s*$"

# `0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]`
_NEEDED_LIB = re.compile(r"\(NEEDED\).*\[(?P<lib>[^\]]+)\]")

# Function boundary marker written into decomp.txt by the decompiler backends.
# Must stay in sync with FUNCTION_MARKER in backend/decompiler.py.
DECOMP_FUNC_MARKER = re.compile(
    r"^//\s*=====\s*FUNCTION\s+(?P<name>.+?)\s+@\s+(?P<address>\S+)\s*=====\s*$",
    re.MULTILINE,
)


def _clean_symbol_name(raw: str):
    """
    Split a readelf symbol name into (name, version).

    readelf appends the symbol version and a version index, e.g.
    `free@GLIBC_2.2.5 (2)` -> ("free", "GLIBC_2.2.5").
    """
    name = raw.strip()
    if not name:
        return None, None

    # Drop the trailing version index, e.g. " (2)"
    name = re.sub(r"\s+\(\d+\)$", "", name).strip()

    version = None
    if "@" in name:
        name, _, version = name.partition("@")
        version = version.lstrip("@") or None

    return (name.strip() or None), version


class ToolDispatcher:
    """Dispatches and executes tool requests from the LLM."""

    def __init__(self, analysis_dir: Path):
        """
        Initialize tool dispatcher.

        Args:
            analysis_dir: Path to the analysis directory containing *.txt files
        """
        self.analysis_dir = Path(analysis_dir)
        self.tool_log = []  # Log of all tool executions

        # Verify analysis directory exists
        if not self.analysis_dir.exists():
            raise ValueError(f"Analysis directory not found: {self.analysis_dir}")

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool request.

        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments

        Returns:
            Dict with 'success', 'result', and 'error' keys
        """
        try:
            if tool_name == "read_section":
                result = self._read_section(
                    arguments.get("section"),
                    arguments.get("start_line"),
                    arguments.get("end_line")
                )
            elif tool_name == "disassemble_address":
                result = self._disassemble_address(
                    arguments.get("address"),
                    arguments.get("end_address"),
                    arguments.get("function_name")
                )
            elif tool_name == "search_strings":
                result = self._search_strings(
                    arguments.get("pattern"),
                    arguments.get("max_results", 20)
                )
            elif tool_name == "analyze_symbol":
                result = self._analyze_symbol(arguments.get("symbol_name"))
            elif tool_name == "get_imports":
                result = self._get_imports(
                    arguments.get("library"),
                    arguments.get("function")
                )
            elif tool_name == "get_exports":
                result = self._get_exports(arguments.get("function"))
            elif tool_name == "decompile_function":
                result = self._decompile_function(
                    arguments.get("function_name"),
                    arguments.get("address")
                )
            elif tool_name == "list_functions":
                result = self._list_functions(
                    arguments.get("pattern"),
                    arguments.get("max_results", 100)
                )
            elif tool_name == "find_references":
                result = self._find_references(
                    arguments.get("string"),
                    arguments.get("address"),
                    arguments.get("max_results", 20)
                )
            elif tool_name == "search_decompiled":
                result = self._search_decompiled(
                    arguments.get("pattern"),
                    arguments.get("max_results", 15)
                )
            else:
                return {
                    "success": False,
                    "error": f"Unknown tool: {tool_name}",
                    "result": None
                }

            # Log the tool execution
            self.tool_log.append({
                "tool": tool_name,
                "arguments": arguments,
                "success": result.get("success", True)
            })

            return result

        except Exception as e:
            error_msg = f"Tool execution error: {str(e)}"
            self.tool_log.append({
                "tool": tool_name,
                "arguments": arguments,
                "success": False,
                "error": error_msg
            })
            return {
                "success": False,
                "error": error_msg,
                "result": None
            }

    # ------------------------------------------------------------------
    # Symbol table parsing
    # ------------------------------------------------------------------

    def _parse_symbols(self) -> List[Dict[str, Any]]:
        """
        Parse every symbol row out of the readelf section of symbols.txt.

        Returns a list of dicts with name, version, type, bind, ndx, value,
        table and a `defined` flag (Ndx != UND).
        """
        symbols_file = self.analysis_dir / "symbols.txt"
        if not symbols_file.exists():
            return []

        content = symbols_file.read_text()
        symbols = []
        current_table = None

        for line in content.split("\n"):
            header = _SYMBOL_TABLE_HEADER.search(line)
            if header:
                current_table = header.group("table")
                continue

            match = _SYMBOL_ROW.match(line)
            if not match:
                continue

            name, version = _clean_symbol_name(match.group("name") or "")
            if not name:
                continue  # Unnamed entries (index 0, section symbols) carry no signal

            ndx = match.group("ndx")
            symbols.append({
                "name": name,
                "version": version,
                "type": match.group("type"),
                "bind": match.group("bind"),
                "ndx": ndx,
                "value": match.group("value"),
                "table": current_table,
                "defined": ndx not in ("UND", "UNDEF"),
            })

        return symbols

    def _shared_libraries(self) -> List[str]:
        """Read DT_NEEDED entries from metadata.txt."""
        metadata_file = self.analysis_dir / "metadata.txt"
        if not metadata_file.exists():
            return []

        libs = []
        for line in metadata_file.read_text().split("\n"):
            match = _NEEDED_LIB.search(line)
            if match:
                lib = match.group("lib")
                if lib not in libs:
                    libs.append(lib)
        return libs

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _read_section(self, section: str, start_line: Optional[int] = None,
                     end_line: Optional[int] = None) -> Dict[str, Any]:
        """Read a section from analysis files."""
        section_files = {
            "metadata": "metadata.txt",
            "strings": "strings.txt",
            "symbols": "symbols.txt",
            "disasm": "disasm.txt",
            "decomp": "decomp.txt"
        }

        if section not in section_files:
            return {
                "success": False,
                "error": f"Unknown section: {section}. Valid sections: {', '.join(section_files)}",
                "result": None
            }

        file_path = self.analysis_dir / section_files[section]
        if not file_path.exists():
            return {
                "success": False,
                "error": f"Section file not found: {file_path}",
                "result": None
            }

        try:
            all_lines = file_path.read_text().split('\n')
            total_lines = len(all_lines)

            # Report the size of the underlying file, not the size of the slice,
            # so the caller can page through it across multiple requests.
            start = (start_line or 1) - 1
            start = max(0, min(start, total_lines))
            end = end_line if end_line is not None else total_lines
            end = max(start, min(end, total_lines))

            selected = all_lines[start:end]

            return {
                "success": True,
                "result": '\n'.join(selected),
                "section": section,
                "total_lines": total_lines,
                "returned_lines": len(selected),
                "start_line": start + 1,
                "end_line": end,
                "truncated": end < total_lines or start > 0,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error reading section: {str(e)}",
                "result": None
            }

    def _disassemble_address(self, address: Optional[str] = None,
                            end_address: Optional[str] = None,
                            function_name: Optional[str] = None) -> Dict[str, Any]:
        """Get disassembly for specific address or function."""
        disasm_file = self.analysis_dir / "disasm.txt"
        if not disasm_file.exists():
            return {
                "success": False,
                "error": "Disassembly file not found",
                "result": None
            }

        try:
            content = disasm_file.read_text()

            if function_name:
                # Anchor to the function's definition header. Matching a bare
                # "<name>" would also hit call sites such as
                #   call 1180 <shuffle>
                # and return the caller's body instead of the callee's.
                def_pattern = re.compile(
                    _FUNC_DEF.format(name=re.escape(function_name)), re.MULTILINE
                )
                match = def_pattern.search(content)
                if not match:
                    return {
                        "success": False,
                        "error": (
                            f"Function not found: {function_name}. "
                            "The binary may be stripped; try disassemble_address with a raw address."
                        ),
                        "result": None
                    }

                start_pos = match.start()
                # The next definition header ends this function.
                next_func = re.compile(
                    r"^[0-9a-fA-F]+\s+<[^>]+>:\s*$", re.MULTILINE
                ).search(content, match.end())
                end_pos = next_func.start() if next_func else len(content)

                return {
                    "success": True,
                    "result": content[start_pos:end_pos].rstrip(),
                    "function_name": function_name,
                    "address": match.group("addr"),
                }

            elif address:
                addr_clean = address.lower().replace('0x', '').lstrip('0') or '0'
                lines = content.split('\n')

                # objdump pads addresses with leading zeroes and indents them.
                addr_pattern = re.compile(rf"^\s*0*{re.escape(addr_clean)}:", re.IGNORECASE)

                for i, line in enumerate(lines):
                    if addr_pattern.match(line):
                        start = max(0, i - 2)
                        end = min(len(lines), i + 20)
                        return {
                            "success": True,
                            "result": '\n'.join(lines[start:end]),
                            "address": address,
                            "function_name": None,
                        }

                return {
                    "success": False,
                    "error": f"Address not found in disassembly: {address}",
                    "result": None
                }
            else:
                return {
                    "success": False,
                    "error": "Either address or function_name must be provided",
                    "result": None
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Error disassembling: {str(e)}",
                "result": None
            }

    def _search_strings(self, pattern: str, max_results: int = 20) -> Dict[str, Any]:
        """Search for strings matching a pattern."""
        strings_file = self.analysis_dir / "strings.txt"
        if not strings_file.exists():
            return {
                "success": False,
                "error": "Strings file not found",
                "result": None
            }

        if not pattern:
            return {
                "success": False,
                "error": "A search pattern is required",
                "result": None
            }

        try:
            lines = strings_file.read_text().split('\n')

            pattern_lower = pattern.lower()
            all_matches = [line for line in lines if pattern_lower in line.lower()]
            matches = all_matches[:max_results]

            return {
                "success": True,
                "result": matches,
                "pattern": pattern,
                "count": len(matches),
                "total_found": len(all_matches),
                "truncated": len(all_matches) > len(matches),
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error searching strings: {str(e)}",
                "result": None
            }

    def _analyze_symbol(self, symbol_name: str) -> Dict[str, Any]:
        """Analyze a specific symbol."""
        if not symbol_name:
            return {
                "success": False,
                "error": "A symbol_name is required",
                "result": None
            }

        symbols = self._parse_symbols()
        if not symbols:
            return {
                "success": False,
                "error": "No symbol table found (binary may be stripped)",
                "result": None
            }

        target = symbol_name.lower()
        exact = [s for s in symbols if s["name"].lower() == target]
        partial = [s for s in symbols if target in s["name"].lower() and s not in exact]

        results = exact + partial
        if not results:
            return {
                "success": False,
                "error": f"Symbol not found: {symbol_name}",
                "result": None
            }

        return {
            "success": True,
            "result": results,
            "symbol_name": symbol_name,
            "exact_matches": len(exact),
            "occurrences": len(results),
        }

    def _get_imports(self, library: Optional[str] = None,
                    function: Optional[str] = None) -> Dict[str, Any]:
        """
        Get imported functions and libraries.

        Imports are undefined (Ndx == UND) symbols in the symbol tables: the
        binary references them but does not define them, so the dynamic linker
        must resolve them at load time.
        """
        symbols = self._parse_symbols()
        libraries = self._shared_libraries()

        # An absent symbol table is an analytical finding, not a tool failure:
        # a stripped, statically linked binary legitimately has no imports, and
        # that fact is itself evidence. Report it as a successful empty result.
        if not symbols:
            return {
                "success": True,
                "result": [],
                "count": 0,
                "shared_libraries": libraries,
                "symbol_table_present": False,
                "note": (
                    "No symbol table present (binary is stripped). "
                    + ("Shared libraries are still declared via DT_NEEDED."
                       if libraries else
                       "No DT_NEEDED entries either, which indicates a statically "
                       "linked binary invoking syscalls directly.")
                ),
                "filter": {"library": library, "function": function},
            }

        seen = set()
        imports = []
        for sym in symbols:
            if sym["defined"]:
                continue

            key = (sym["name"], sym["version"])
            if key in seen:
                continue
            seen.add(key)

            if library and library.lower() not in (sym["version"] or "").lower():
                continue
            if function and function.lower() not in sym["name"].lower():
                continue

            imports.append({
                "function": sym["name"],
                "version": sym["version"],
                "type": sym["type"],
                "bind": sym["bind"],
            })

        note = None
        if not imports and not libraries:
            note = (
                "No imports and no DT_NEEDED entries. This is typical of a "
                "statically linked binary that invokes syscalls directly."
            )

        return {
            "success": True,
            "result": imports,
            "count": len(imports),
            "shared_libraries": libraries,
            "note": note,
            "filter": {"library": library, "function": function}
        }

    def _get_exports(self, function: Optional[str] = None) -> Dict[str, Any]:
        """
        Get exported functions.

        Exports are symbols the binary itself defines (Ndx is a section index,
        not UND) with global or weak binding. Filtering on `defined` is what
        keeps imported libc functions out of this list.
        """
        symbols = self._parse_symbols()

        if not symbols:
            return {
                "success": True,
                "result": [],
                "count": 0,
                "symbol_table_present": False,
                "note": (
                    "No symbol table present (binary is stripped), so no exports "
                    "can be enumerated. Use disassemble_address with raw addresses."
                ),
                "filter": {"function": function},
            }

        seen = set()
        exports = []
        for sym in symbols:
            if not sym["defined"]:
                continue
            if sym["bind"] not in ("GLOBAL", "WEAK"):
                continue
            if sym["type"] not in ("FUNC", "OBJECT", "IFUNC"):
                continue

            if sym["name"] in seen:
                continue
            seen.add(sym["name"])

            if function and function.lower() not in sym["name"].lower():
                continue

            exports.append({
                "function": sym["name"],
                "type": sym["type"],
                "bind": sym["bind"],
                "address": sym["value"],
            })

        return {
            "success": True,
            "result": exports,
            "count": len(exports),
            "filter": {"function": function}
        }

    # ------------------------------------------------------------------
    # Decompilation
    # ------------------------------------------------------------------

    def _decompiled_functions(self) -> List[Dict[str, Any]]:
        """
        Slice decomp.txt into individual functions using the marker emitted by
        the decompiler backends.
        """
        decomp_file = self.analysis_dir / "decomp.txt"
        if not decomp_file.exists():
            return []

        content = decomp_file.read_text(errors="ignore")
        markers = list(DECOMP_FUNC_MARKER.finditer(content))

        functions = []
        for i, match in enumerate(markers):
            end = markers[i + 1].start() if i + 1 < len(markers) else len(content)
            functions.append({
                "name": match.group("name").strip(),
                "address": match.group("address").strip(),
                "code": content[match.end():end].strip(),
            })
        return functions

    def _decompiler_unavailable_reason(self) -> Optional[str]:
        """Return the backend's explanation if decompilation did not produce code."""
        decomp_file = self.analysis_dir / "decomp.txt"
        if not decomp_file.exists():
            return "No decompilation output was produced (decomp.txt is missing)."

        head = decomp_file.read_text(errors="ignore")[:600].strip()
        return head or "Decompilation output is empty."

    def _decompile_function(self, function_name: Optional[str] = None,
                           address: Optional[str] = None) -> Dict[str, Any]:
        """Return the decompiled pseudo-C for one function."""
        if not function_name and not address:
            return {
                "success": False,
                "error": "Either function_name or address must be provided",
                "result": None
            }

        functions = self._decompiled_functions()
        if not functions:
            return {
                "success": False,
                "error": f"No decompiled functions available. {self._decompiler_unavailable_reason()}",
                "result": None
            }

        match = None

        if function_name:
            target = function_name.lower()
            match = next((f for f in functions if f["name"].lower() == target), None)
            if match is None:
                partial = [f for f in functions if target in f["name"].lower()]
                if len(partial) == 1:
                    match = partial[0]
                elif partial:
                    return {
                        "success": False,
                        "error": (
                            f"Ambiguous function name '{function_name}'. Candidates: "
                            + ", ".join(f["name"] for f in partial[:10])
                        ),
                        "result": None
                    }

        if match is None and address:
            # Compare numerically so 0x8048190, 08048190 and 8048190 all match.
            try:
                want = int(address, 16)
            except (TypeError, ValueError):
                want = None

            if want is not None:
                for func in functions:
                    try:
                        if int(func["address"], 16) == want:
                            match = func
                            break
                    except (TypeError, ValueError):
                        continue

        if match is None:
            return {
                "success": False,
                "error": (
                    f"Function not found: {function_name or address}. "
                    f"Use list_functions to see the {len(functions)} available functions."
                ),
                "result": None
            }

        return {
            "success": True,
            "result": match["code"],
            "function_name": match["name"],
            "address": match["address"],
        }

    def _list_functions(self, pattern: Optional[str] = None,
                       max_results: int = 100) -> Dict[str, Any]:
        """List functions recovered by the decompiler."""
        functions = self._decompiled_functions()
        if not functions:
            return {
                "success": False,
                "error": f"No decompiled functions available. {self._decompiler_unavailable_reason()}",
                "result": None
            }

        if pattern:
            needle = pattern.lower()
            selected = [f for f in functions if needle in f["name"].lower()]
        else:
            selected = functions

        total = len(selected)
        selected = selected[:max_results]

        return {
            "success": True,
            "result": [
                {"name": f["name"], "address": f["address"], "lines": f["code"].count("\n") + 1}
                for f in selected
            ],
            "count": len(selected),
            "total_found": total,
            "total_functions": len(functions),
            "truncated": total > len(selected),
            "filter": {"pattern": pattern},
        }

    def _find_references(self, string: Optional[str] = None,
                        address: Optional[str] = None,
                        max_results: int = 20) -> Dict[str, Any]:
        """
        Resolve a string or address to the functions that reference it.

        Reads xrefs.txt, exported by the decompiler backend as tab-separated
        records: type, address, name, comma-separated referencing functions.
        """
        if not string and not address:
            return {
                "success": False,
                "error": "Either string or address must be provided",
                "result": None
            }

        xref_file = self.analysis_dir / "xrefs.txt"
        if not xref_file.exists():
            return {
                "success": False,
                "error": (
                    "No cross-reference data available. It is produced by the Ghidra "
                    "backend; if decompilation was skipped, use search_strings and "
                    "disassemble_address instead."
                ),
                "result": None
            }

        want_addr = None
        if address:
            try:
                want_addr = int(address, 16)
            except (TypeError, ValueError):
                want_addr = None

        needle = string.lower() if string else None
        matches = []

        for line in xref_file.read_text(errors="ignore").split("\n"):
            if not line or line.startswith("#"):
                continue

            parts = line.split("\t")
            if len(parts) < 4:
                continue

            kind, addr, name, callers = parts[0], parts[1], parts[2], parts[3]

            if needle is not None:
                if needle not in name.lower():
                    continue
            else:
                try:
                    if int(addr, 16) != want_addr:
                        continue
                except (TypeError, ValueError):
                    continue

            matches.append({
                "type": kind,
                "address": addr,
                "name": name,
                "referenced_by": [c for c in callers.split(",") if c],
            })

        if not matches:
            return {
                "success": True,
                "result": [],
                "count": 0,
                "note": (
                    "No cross-references found. The string may be unreferenced, or "
                    "built at runtime rather than stored as a literal."
                ),
            }

        total = len(matches)
        return {
            "success": True,
            "result": matches[:max_results],
            "count": min(total, max_results),
            "total_found": total,
            "truncated": total > max_results,
        }

    def _search_decompiled(self, pattern: str, max_results: int = 15) -> Dict[str, Any]:
        """Search the decompiled pseudo-C, grouping hits by function."""
        if not pattern:
            return {
                "success": False,
                "error": "A search pattern is required",
                "result": None
            }

        functions = self._decompiled_functions()
        if not functions:
            return {
                "success": False,
                "error": f"No decompiled code available. {self._decompiler_unavailable_reason()}",
                "result": None
            }

        needle = pattern.lower()
        hits = []

        for func in functions:
            lines = [
                line.strip()
                for line in func["code"].split("\n")
                if needle in line.lower()
            ]
            if lines:
                hits.append({
                    "function": func["name"],
                    "address": func["address"],
                    "match_count": len(lines),
                    "matches": lines[:5],
                })

        hits.sort(key=lambda h: -h["match_count"])
        total = len(hits)

        return {
            "success": True,
            "result": hits[:max_results],
            "pattern": pattern,
            "count": min(total, max_results),
            "total_found": total,
            "truncated": total > max_results,
        }

    def get_tool_log(self) -> List[Dict[str, Any]]:
        """Get the log of all tool executions."""
        return self.tool_log
