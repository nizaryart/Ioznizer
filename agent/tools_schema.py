"""
Tool definitions for LLM agent.
Defines the tools available to the LLM for analyzing malware samples.
"""

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "read_section",
            "description": "Read a specific section from the analysis files. Sections include: metadata, strings, symbols, disasm (disassembly), or decomp (decompilation).",
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": ["metadata", "strings", "symbols", "disasm", "decomp"],
                        "description": "The section to read from the analysis files"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Optional: Start line number (1-indexed). If not provided, reads from beginning."
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Optional: End line number (1-indexed). If not provided, reads to end."
                    }
                },
                "required": ["section"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "disassemble_address",
            "description": "Get disassembly for a specific address or address range. Useful for analyzing specific functions or code sections.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The address to disassemble (hex format, e.g., '0x1234' or '1234')"
                    },
                    "end_address": {
                        "type": "string",
                        "description": "Optional: End address for range disassembly (hex format)"
                    },
                    "function_name": {
                        "type": "string",
                        "description": "Optional: Function name to disassemble instead of address"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": "Search for specific strings or patterns in the extracted strings. Useful for finding suspicious strings, URLs, file paths, or other indicators.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "The string or pattern to search for (case-insensitive substring match)"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default: 20)",
                        "default": 20
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_symbol",
            "description": "Get detailed information about a specific symbol (function, variable, etc.) from the symbols file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "The name of the symbol to analyze"
                    }
                },
                "required": ["symbol_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_imports",
            "description": "List all imported functions and libraries. Useful for identifying suspicious API calls or dependencies.",
            "parameters": {
                "type": "object",
                "properties": {
                    "library": {
                        "type": "string",
                        "description": "Optional: Filter imports by library name (e.g., 'libc', 'libssl')"
                    },
                    "function": {
                        "type": "string",
                        "description": "Optional: Search for specific function name in imports"
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "decompile_function",
            "description": (
                "Get the decompiled pseudo-C for a single function. This is usually "
                "far more informative than raw disassembly: library calls, control flow "
                "and string references are already resolved. Prefer this over "
                "disassemble_address when investigating what a function actually does. "
                "For stripped binaries the decompiler assigns synthetic names such as "
                "FUN_0804a330; use list_functions first to find candidates."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {
                        "type": "string",
                        "description": "Function name, e.g. 'main' or 'FUN_0804a330'"
                    },
                    "address": {
                        "type": "string",
                        "description": "Entry point address in hex, e.g. '0x0804a330'. Used if function_name is not given."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_functions",
            "description": (
                "List the functions recovered by the decompiler, with entry point "
                "addresses. Use this to orient yourself before drilling into a "
                "specific function, or to find functions whose names match a pattern."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Optional: only return functions whose name contains this substring (case-insensitive)"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of functions to return (default: 100)",
                        "default": 100
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_references",
            "description": (
                "Find which functions reference a string or an address. This is the "
                "bridge from a lead to the code behind it: after search_strings finds "
                "an interesting literal, use this to learn which function uses it, "
                "then decompile_function to read what that function does. Also works "
                "on a function address to find its callers."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "string": {
                        "type": "string",
                        "description": "Substring of the referenced string, e.g. '[syn_flood] started'"
                    },
                    "address": {
                        "type": "string",
                        "description": "Address in hex, e.g. '0x0804a330'. Returns functions referencing it."
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum matches to return (default: 20)",
                        "default": 20
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_decompiled",
            "description": (
                "Search the decompiled pseudo-C for a pattern and return the matching "
                "functions with the matching lines. Use this to find behaviour by the "
                "calls it makes, e.g. 'socket', 'connect', 'kill', '/proc/'. Unlike "
                "search_strings, which only covers extracted string literals, this "
                "searches the actual reconstructed code."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Case-insensitive substring to find in the decompiled code"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum matching functions to return (default: 15)",
                        "default": 15
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_exports",
            "description": "List all exported functions. Useful for understanding what the binary exposes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "function": {
                        "type": "string",
                        "description": "Optional: Search for specific function name in exports"
                    }
                },
                "required": []
            }
        }
    }
]


def get_tools_schema():
    """Get the tools schema for LLM function calling."""
    return TOOLS_SCHEMA

