# How The AI Uses Tools

This document explains how the AI (Large Language Model) uses tools in the Ioznizer malware analysis system.

---

## Overview

The Ioznizer system uses an **iterative tool-based analysis approach** where an LLM (Large Language Model) analyzes malware samples by:

1. Receiving initial static analysis data
2. Analyzing the data to identify suspicious patterns
3. **Requesting tools** to gather more detailed information when needed
4. Analyzing tool results and iterating until a comprehensive analysis is complete
5. Producing a structured JSON report

The AI doesn't execute tools directly—instead, it **requests** tools through a standardized function-calling interface, and the system executes them on its behalf.

---

## Architecture: Three Key Components

### 1. Tool Schema (`agent/tools_schema.py`)

**Purpose:** Defines what tools are available to the AI and how to call them.

The tool schema is a JSON Schema definition that describes:
- **Tool names**: What the AI can request (e.g., `read_section`, `search_strings`)
- **Tool descriptions**: What each tool does (the AI uses this to decide when to call it)
- **Parameters**: What arguments each tool accepts (types, descriptions, required fields)

**Example Tool Definition:**

```python
{
    "type": "function",
    "function": {
        "name": "read_section",
        "description": "Read a specific section from the analysis files...",
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
                    "description": "Optional: Start line number (1-indexed)..."
                }
            },
            "required": ["section"]
        }
    }
}
```

**Why JSON Schema?**
- Standard format for OpenAI function calling
- The LLM understands the schema and can call tools appropriately
- Type validation ensures correct parameters are provided

### 2. Tool Dispatcher (`agent/tool_dispatcher.py`)

**Purpose:** Executes tool requests from the AI and returns results.

The `ToolDispatcher` class:
- Receives tool execution requests (tool name + arguments)
- Executes the corresponding Python function
- Returns structured results (success/failure, data, errors)
- Logs all tool executions for debugging

**Execution Flow:**

```python
# AI requests: read_section(section="strings", start_line=1, end_line=100)
tool_result = dispatcher.execute_tool("read_section", {
    "section": "strings",
    "start_line": 1,
    "end_line": 100
})

# Returns:
{
    "success": True,
    "result": "actual file content...",
    "section": "strings",
    "total_lines": 100
}
```

### 3. Analysis Agent (`agent/analyze.py`)

**Purpose:** Orchestrates the conversation between the AI and the tool system.

The `MalwareAnalyzer` class:
- Initializes the conversation with system prompt and initial data
- Sends conversation history to the LLM **with tools schema attached**
- Receives LLM responses (which may include tool call requests)
- Executes requested tools via the dispatcher
- Sends tool results back to the LLM
- Iterates until the AI produces a final analysis

---

## The Iterative Workflow

Here's how the AI uses tools during analysis:

### Step 1: Initial Setup

```python
# System prompt tells the AI what tools are available
system_prompt = """You are a malware analysis assistant...
AVAILABLE TOOLS:
- read_section: Read specific sections from analysis files
- search_strings: Search for suspicious strings
- disassemble_address: Get disassembly for addresses
..."""

# Initial data is sent to the AI
initial_message = """Analyze this malware sample:
[metadata.txt content]
[strings.txt content]
..."""
```

### Step 2: AI Requests Tools

The AI analyzes the initial data and decides it needs more information. It requests tools:

```json
{
  "tool_calls": [
    {
      "id": "call_123",
      "type": "function",
      "function": {
        "name": "search_strings",
        "arguments": "{\"pattern\": \"http\", \"max_results\": 20}"
      }
    }
  ]
}
```

### Step 3: System Executes Tools

The system executes the requested tools:

```python
# For each tool call:
tool_name = "search_strings"
tool_args = {"pattern": "http", "max_results": 20}
tool_result = dispatcher.execute_tool(tool_name, tool_args)

# Result is formatted and sent back to AI
tool_response = {
    "role": "tool",
    "tool_call_id": "call_123",
    "content": "Tool search_strings executed successfully:\n[results...]"
}
```

### Step 4: AI Analyzes Tool Results

The AI receives tool results and continues its analysis. It may:
- Request more tools based on findings
- Analyze the results and produce final conclusions
- Iterate multiple times to gather comprehensive information

### Step 5: Final Analysis

When the AI has enough information, it produces a structured JSON report without requesting more tools.

---

## Available Tools

The system provides 6 tools for malware analysis:

### 1. `read_section`
**Purpose:** Read specific sections from analysis files

**Parameters:**
- `section` (required): One of `metadata`, `strings`, `symbols`, `disasm`, `decomp`
- `start_line` (optional): Start line number (1-indexed)
- `end_line` (optional): End line number (1-indexed)

**Example Usage:**
```python
read_section(section="strings", start_line=1, end_line=50)
```

**When AI Uses It:**
- Needs to examine specific parts of analysis files
- Initial data was truncated and needs full content
- Wants to focus on a particular section

### 2. `disassemble_address`
**Purpose:** Get disassembly for specific addresses or functions

**Parameters:**
- `address` (optional): Hex address (e.g., "0x1234")
- `end_address` (optional): End address for range
- `function_name` (optional): Function name to disassemble

**Example Usage:**
```python
disassemble_address(function_name="main")
disassemble_address(address="0x401000", end_address="0x401050")
```

**When AI Uses It:**
- Wants to analyze specific suspicious functions
- Needs to understand code flow at specific addresses
- Investigating control flow or logic

### 3. `search_strings`
**Purpose:** Search for patterns in extracted strings

**Parameters:**
- `pattern` (required): String or pattern to search for (case-insensitive)
- `max_results` (optional): Maximum results to return (default: 20)

**Example Usage:**
```python
search_strings(pattern="http://", max_results=10)
search_strings(pattern="password")
```

**When AI Uses It:**
- Looking for suspicious URLs, IPs, or domains
- Searching for hardcoded credentials or paths
- Finding indicators of compromise (IOCs)

### 4. `analyze_symbol`
**Purpose:** Get detailed information about a specific symbol

**Parameters:**
- `symbol_name` (required): Name of the symbol to analyze

**Example Usage:**
```python
analyze_symbol(symbol_name="connect")
analyze_symbol(symbol_name="strcpy")
```

**When AI Uses It:**
- Investigating specific functions or variables
- Understanding symbol relationships
- Analyzing imported/exported symbols

### 5. `get_imports`
**Purpose:** List imported functions and libraries

**Parameters:**
- `library` (optional): Filter by library name (e.g., "libc", "libssl")
- `function` (optional): Search for specific function name

**Example Usage:**
```python
get_imports()  # Get all imports
get_imports(library="libc")  # Filter by library
get_imports(function="socket")  # Find specific function
```

**When AI Uses It:**
- Identifying suspicious API calls
- Understanding dependencies
- Analyzing network/file system operations

### 6. `get_exports`
**Purpose:** List exported functions

**Parameters:**
- `function` (optional): Search for specific function name

**Example Usage:**
```python
get_exports()  # Get all exports
get_exports(function="main")  # Find specific export
```

**When AI Uses It:**
- Understanding what the binary exposes
- Analyzing entry points
- Identifying exported functionality

---

## How The AI Decides to Use Tools

The AI uses several strategies to decide when and which tools to call:

### 1. **Hypothesis-Driven Investigation**
- AI forms hypotheses from initial data
- Requests tools to verify or explore hypotheses
- Example: "I see a suspicious URL pattern, let me search for all URLs"

### 2. **Gap-Filling**
- AI identifies missing information
- Requests tools to fill gaps
- Example: "I need to see the full disassembly of function X"

### 3. **Deep Dives**
- AI finds something interesting and wants more detail
- Requests specific tools to investigate deeper
- Example: "This address looks suspicious, let me disassemble it"

### 4. **Efficiency Considerations**
- AI avoids redundant tool calls
- Uses tools strategically to minimize iterations
- Example: Searches for patterns before reading entire files

---

## Example Analysis Flow

Here's a realistic example of how the AI might use tools:

### Iteration 1: Initial Analysis
```
AI receives: metadata.txt, strings.txt (truncated), symbols.txt, disasm.txt

AI reasoning: "I see some suspicious strings. Let me search for network-related patterns."
AI requests: search_strings(pattern="http")
```

### Iteration 2: Following Leads
```
AI receives: Tool results showing URLs like "http://malicious.com/c2"

AI reasoning: "Found C2 URLs. Let me check what functions use these strings."
AI requests: 
  - search_strings(pattern="malicious.com")
  - get_imports(function="connect")
```

### Iteration 3: Code Analysis
```
AI receives: Import results showing socket/network functions

AI reasoning: "Network functions are imported. Let me see the disassembly of the main function."
AI requests: disassemble_address(function_name="main")
```

### Iteration 4: Final Analysis
```
AI receives: Disassembly showing network communication code

AI reasoning: "I have enough information. This is a backdoor with C2 communication."
AI produces: Final JSON analysis report (no more tool calls)
```

---

## Technical Implementation Details

### Tool Call Format

When the AI requests a tool, it uses OpenAI's function calling format:

```json
{
  "tool_calls": [
    {
      "id": "call_abc123",
      "type": "function",
      "function": {
        "name": "search_strings",
        "arguments": "{\"pattern\": \"http\", \"max_results\": 20}"
      }
    }
  ]
}
```

### Tool Response Format

Tool results are sent back to the AI in this format:

```json
{
  "role": "tool",
  "tool_call_id": "call_abc123",
  "content": "Tool search_strings executed successfully:\n[actual results...]"
}
```

### Conversation History

The conversation history maintains the full context:

```python
conversation_history = [
    {"role": "system", "content": "You are a malware analyst..."},
    {"role": "user", "content": "Analyze this sample: [data]"},
    {"role": "assistant", "content": "...", "tool_calls": [...]},
    {"role": "tool", "tool_call_id": "...", "content": "[results]"},
    {"role": "assistant", "content": "Based on the results..."},
    # ... continues until final analysis
]
```

---

## Key Design Principles

### 1. **AI-Driven Tool Selection**
- The AI decides which tools to use and when
- The system doesn't force tool usage
- AI can complete analysis without tools if initial data is sufficient

### 2. **Iterative Refinement**
- AI can make multiple tool calls in sequence
- Each iteration builds on previous findings
- Continues until comprehensive analysis is achieved

### 3. **Structured Results**
- All tools return structured data (success/failure, results, metadata)
- Consistent format helps AI process results
- Error handling ensures graceful failures

### 4. **Tool Logging**
- All tool executions are logged
- Helps debug and understand AI's investigation strategy
- Useful for improving tool descriptions and prompts

---

## Benefits of This Approach

1. **Flexibility**: AI can adapt its investigation strategy based on findings
2. **Efficiency**: AI only requests tools when needed, avoiding unnecessary operations
3. **Comprehensiveness**: Iterative approach ensures thorough analysis
4. **Transparency**: Tool usage is logged and visible
5. **Extensibility**: New tools can be added by updating the schema and dispatcher

---

## Summary

The AI uses tools through a **request-execute-analyze** cycle:

1. **Request**: AI analyzes data and requests tools via function calls
2. **Execute**: System executes tools using the `ToolDispatcher`
3. **Analyze**: AI receives results and continues analysis
4. **Iterate**: Process repeats until comprehensive analysis is complete
5. **Report**: AI produces final structured JSON report

This approach allows the AI to perform deep, hypothesis-driven malware analysis by dynamically gathering information as needed, rather than being limited to static initial data.

