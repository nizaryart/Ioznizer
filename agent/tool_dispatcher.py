"""
Tool Dispatcher for executing tool requests from the LLM.
Executes tools and returns structured results.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import re
import subprocess


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
                "error": f"Unknown section: {section}",
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
            content = file_path.read_text()
            lines = content.split('\n')
            
            if start_line is not None or end_line is not None:
                start = (start_line or 1) - 1  # Convert to 0-indexed
                end = end_line if end_line is not None else len(lines)
                lines = lines[start:end]
                content = '\n'.join(lines)
            
            return {
                "success": True,
                "result": content,
                "section": section,
                "total_lines": len(content.split('\n'))
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
                # Search for function by name
                pattern = rf"<{re.escape(function_name)}>"
                match = re.search(pattern, content)
                if match:
                    # Extract function disassembly
                    start_pos = match.start()
                    # Find next function or end
                    next_func = re.search(r'\n[0-9a-f]+ <[^>]+>:\n', content[start_pos + 1:])
                    if next_func:
                        end_pos = start_pos + next_func.start()
                    else:
                        end_pos = len(content)
                    result = content[start_pos:end_pos]
                else:
                    return {
                        "success": False,
                        "error": f"Function not found: {function_name}",
                        "result": None
                    }
            elif address:
                # Search for address
                addr_clean = address.replace('0x', '').replace('0X', '')
                pattern = rf"^\s*{re.escape(addr_clean)}:"
                lines = content.split('\n')
                matching_lines = []
                found = False
                
                for i, line in enumerate(lines):
                    if re.match(pattern, line):
                        found = True
                        # Include context (previous and next lines)
                        start = max(0, i - 2)
                        end = min(len(lines), i + 20)  # Show ~20 lines
                        matching_lines = lines[start:end]
                        break
                
                if not found:
                    return {
                        "success": False,
                        "error": f"Address not found: {address}",
                        "result": None
                    }
                
                result = '\n'.join(matching_lines)
            else:
                return {
                    "success": False,
                    "error": "Either address or function_name must be provided",
                    "result": None
                }
            
            return {
                "success": True,
                "result": result,
                "address": address,
                "function_name": function_name
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
        
        try:
            content = strings_file.read_text()
            lines = content.split('\n')
            
            # Case-insensitive search
            pattern_lower = pattern.lower()
            matches = [line for line in lines if pattern_lower in line.lower()]
            
            if len(matches) > max_results:
                matches = matches[:max_results]
            
            return {
                "success": True,
                "result": matches,
                "pattern": pattern,
                "count": len(matches),
                "total_found": len([l for l in lines if pattern_lower in l.lower()])
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error searching strings: {str(e)}",
                "result": None
            }
    
    def _analyze_symbol(self, symbol_name: str) -> Dict[str, Any]:
        """Analyze a specific symbol."""
        symbols_file = self.analysis_dir / "symbols.txt"
        if not symbols_file.exists():
            return {
                "success": False,
                "error": "Symbols file not found",
                "result": None
            }
        
        try:
            content = symbols_file.read_text()
            
            # Search for symbol in content
            pattern = rf"\b{re.escape(symbol_name)}\b"
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            results = []
            for match in matches:
                # Extract context around the match
                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)
                context = content[start:end]
                results.append(context)
            
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
                "occurrences": len(results)
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error analyzing symbol: {str(e)}",
                "result": None
            }
    
    def _get_imports(self, library: Optional[str] = None,
                    function: Optional[str] = None) -> Dict[str, Any]:
        """Get imported functions and libraries."""
        symbols_file = self.analysis_dir / "symbols.txt"
        if not symbols_file.exists():
            return {
                "success": False,
                "error": "Symbols file not found",
                "result": None
            }
        
        try:
            content = symbols_file.read_text()
            
            # Parse imports from objdump -x output
            imports = []
            in_dynamic_section = False
            
            for line in content.split('\n'):
                if 'DYNAMIC SYMBOL TABLE' in line or 'Dynamic symbols' in line:
                    in_dynamic_section = True
                    continue
                
                if in_dynamic_section:
                    # Look for import entries
                    if 'UND' in line or 'UNDEF' in line:
                        parts = line.split()
                        if len(parts) >= 8:
                            func_name = parts[-1] if parts[-1] else parts[-2]
                            lib_name = None
                            
                            # Try to extract library name
                            if '@' in func_name:
                                func_name, lib_name = func_name.split('@', 1)
                            
                            if library is None or (lib_name and library.lower() in lib_name.lower()):
                                if function is None or function.lower() in func_name.lower():
                                    imports.append({
                                        "function": func_name,
                                        "library": lib_name
                                    })
            
            return {
                "success": True,
                "result": imports,
                "count": len(imports),
                "filter": {"library": library, "function": function}
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error getting imports: {str(e)}",
                "result": None
            }
    
    def _get_exports(self, function: Optional[str] = None) -> Dict[str, Any]:
        """Get exported functions."""
        symbols_file = self.analysis_dir / "symbols.txt"
        if not symbols_file.exists():
            return {
                "success": False,
                "error": "Symbols file not found",
                "result": None
            }
        
        try:
            content = symbols_file.read_text()
            
            # Parse exports from symbols
            exports = []
            
            for line in content.split('\n'):
                # Look for exported symbols (typically in symbol table)
                if 'FUNC' in line or 'OBJECT' in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        symbol_name = parts[-1] if parts[-1] else parts[-2]
                        if function is None or function.lower() in symbol_name.lower():
                            exports.append(symbol_name)
            
            return {
                "success": True,
                "result": exports,
                "count": len(exports),
                "filter": {"function": function}
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error getting exports: {str(e)}",
                "result": None
            }
    
    def get_tool_log(self) -> List[Dict[str, Any]]:
        """Get the log of all tool executions."""
        return self.tool_log

