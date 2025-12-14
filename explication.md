# Malware Detector by Code Analysis - Complete Code Explanation

This document provides a comprehensive explanation of the entire codebase, walking through each component from initialization to final report generation.

---

## Table of Contents

1. [Entry Point: run.sh](#1-entry-point-runsh)
2. [Main Orchestration: main.py](#2-main-orchestration-mainpy)
3. [Configuration: config.py](#3-configuration-configpy)
4. [Phase 1: Static Extraction - backend/extractor.py](#4-phase-1-static-extraction---backendextractorpy)
5. [Phase 2: LLM Analysis - Agent Components](#5-phase-2-llm-analysis---agent-components)
   - [OpenRouter Client](#51-openrouter-client-agentopenrouter_clientpy)
   - [Tools Schema](#52-tools-schema-agenttools_schemapy)
   - [Tool Dispatcher](#53-tool-dispatcher-agenttool_dispatcherpy)
   - [Analysis Agent](#54-analysis-agent-agentanalyzepy)
6. [Phase 3: Report Generation - agent/report_generator.py](#6-phase-3-report-generation---agentreport_generatorpy)
7. [Complete Workflow Diagram](#7-complete-workflow-diagram)

---

## 1. Entry Point: run.sh

**File:** `run.sh`

This is the shell script wrapper that starts the entire analysis process.

```bash
#!/bin/bash
# Wrapper script to run the malware detector with virtual environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
```

**What it does:**
- Gets the script's directory and changes to it
- Ensures we're in the project root directory

```bash
# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "[ERROR] Virtual environment not found..."
    exit 1
fi
```

**What it does:**
- Checks if a Python virtual environment exists in `venv/`
- Activates it (this ensures all Python dependencies are available)
- If no venv exists, shows an error and exits

```bash
# Run the main script
python3 main.py "$@"
```

**What it does:**
- Executes `main.py` with all command-line arguments passed through (`"$@"`)
- The `"$@"` passes all arguments from the shell command to Python

**Example usage:**
```bash
./run.sh samples/malware.elf
```
This activates the venv and runs `python3 main.py samples/malware.elf`

---

## 2. Main Orchestration: main.py

**File:** `main.py`

This is the central orchestrator that coordinates all three phases of the analysis.

### 2.1 Initialization and Setup

```python
# File: main.py (lines 16-21)
# Load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
```

**What it does:**
- Tries to load environment variables from a `.env` file
- This allows API keys and configuration to be stored in `.env` instead of hardcoding
- If `python-dotenv` isn't installed, it continues without it (graceful degradation)

```python
# File: main.py (lines 23-25)
# Add backend and agent to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent / "agent"))
```

**What it does:**
- Adds the `backend/` and `agent/` directories to Python's module search path
- This allows importing modules like `from backend.extractor import StaticExtractor`

```python
# File: main.py (lines 27-30)
from backend.extractor import StaticExtractor
from agent.analyze import analyze_sample
from agent.report_generator import generate_reports
from config import Config
```

**What it does:**
- Imports the three main components:
  - `StaticExtractor`: Handles static analysis extraction
  - `analyze_sample`: Performs LLM-powered analysis
  - `generate_reports`: Creates JSON and Markdown reports
  - `Config`: Configuration management

### 2.2 Main Function Flow

```python
# File: main.py (lines 33-40)
def main():
    if len(sys.argv) < 2:
        print("Usage: ./the_project_executable /samples/malware.elf")
        sys.exit(1)
    
    sample_path = Path(sys.argv[1])
```

**What it does:**
- Checks if a sample path was provided as command-line argument
- `sys.argv[1]` is the first argument after the script name
- If missing, shows usage and exits
- Converts the path to a `Path` object for easier manipulation

### 2.3 Phase 1: Static Extraction

```python
# File: main.py (lines 51-52)
# Phase 1: Static Analysis Extraction
extractor = StaticExtractor(sample_path)
extractor.run_all()
```

**What it does:**
- Creates a `StaticExtractor` instance with the sample path
- Calls `run_all()` which performs all extraction operations
- This generates files in `analysis/` directory:
  - `metadata.txt` - ELF header and metadata
  - `strings.txt` - Extracted strings
  - `symbols.txt` - Symbols and imports
  - `disasm.txt` - Disassembly
  - `decomp.txt` - Placeholder for decompilation

```python
# File: main.py (lines 54-58)
# Collect extractor info for report
extractor_info = {
    "architecture": extractor.architecture,
    "output_directory": str(extractor.out_dir)
}
```

**What it does:**
- Saves information about the extraction for later use in reports
- Architecture (e.g., "i386", "arm") is detected during extraction
- Output directory path is saved

### 2.4 Phase 2: LLM Analysis

```python
# File: main.py (lines 65-67)
# Get API key from config (has fallback default)
api_key = Config.OPENROUTER_API_KEY
model = Config.OPENROUTER_MODEL
```

**What it does:**
- Retrieves API key from `Config` class
- `Config.OPENROUTER_API_KEY` checks:
  1. Environment variable `OPENROUTER_API_KEY`
  2. Falls back to `DEFAULT_API_KEY` in `config.py`
- Gets the model name (default: "openai/gpt-oss-120b:free")

```python
# File: main.py (lines 69-86)
if not api_key:
    # Skip LLM analysis, create empty results
else:
    analysis_results = analyze_sample(
        extractor.out_dir,
        api_key=api_key,
        model=model
    )
```

**What it does:**
- If no API key, creates empty analysis results (extraction-only mode)
- Otherwise, calls `analyze_sample()` which:
  - Loads the analysis files from `extractor.out_dir`
  - Sends them to the LLM via OpenRouter
  - Performs iterative analysis with tool-based investigation
  - Returns structured analysis results

**Error Handling:**
- Catches `ValueError` for configuration issues (e.g., data policy not set)
- Catches general exceptions and continues with extraction-only results
- This ensures the pipeline always completes, even if LLM fails

### 2.5 Phase 3: Report Generation

```python
# File: main.py (lines 122-126)
report_paths = generate_reports(
    sample_path,
    analysis_results,
    extractor_info=extractor_info
)
```

**What it does:**
- Takes the analysis results and generates reports
- Creates both JSON and Markdown formats
- Saves to `reports/` directory with timestamp
- Returns paths to generated files

---

## 3. Configuration: config.py

**File:** `config.py`

Centralized configuration management for the entire project.

### 3.1 Environment Loading

```python
# File: config.py (lines 11-15)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
```

**What it does:**
- Loads `.env` file at module import time
- This makes environment variables available to all modules

### 3.2 API Key Configuration

```python
# File: config.py (lines 23-24)
DEFAULT_API_KEY = "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"
OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY") or DEFAULT_API_KEY
```

**What it does:**
- Defines a default API key as fallback
- Checks environment variable first, then uses default
- Priority: `OPENROUTER_API_KEY` env var → `DEFAULT_API_KEY`

### 3.3 Directory Configuration

```python
PROJECT_ROOT: Path = Path(__file__).parent
ANALYSIS_DIR: Path = PROJECT_ROOT / "analysis"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"
SAMPLES_DIR: Path = PROJECT_ROOT / "samples"
```

**What it does:**
- Defines all directory paths relative to project root
- Uses `Path` objects for cross-platform compatibility
- These directories are created automatically if they don't exist

### 3.4 Analysis Settings

```python
MAX_ANALYSIS_ITERATIONS: int = int(os.getenv("MAX_ANALYSIS_ITERATIONS", "20"))
LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.7"))
LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "2000"))
```

**What it does:**
- Configurable analysis parameters
- Can be overridden via environment variables
- Defaults provide reasonable values

---

## 4. Phase 1: Static Extraction - backend/extractor.py

**File:** `backend/extractor.py`

This module performs static analysis extraction from ELF binaries using standard Linux tools.

### 4.1 Class Initialization

```python
# File: backend/extractor.py (lines 8-26)
class StaticExtractor:
    def __init__(self, sample_path: str, output_dir=None):
        self.sample = Path(sample_path).resolve()
        
        if output_dir is None:
            project_root = Path(__file__).resolve().parent.parent
            self.out_dir = project_root / "analysis"
        else:
            self.out_dir = Path(output_dir)
        
        self.out_dir.mkdir(exist_ok=True, parents=True)
```

**What it does:**
- Resolves the sample path to absolute path
- Sets output directory to `analysis/` at project root by default
- Creates the output directory if it doesn't exist

### 4.2 File Validation

```python
# File: backend/extractor.py (lines 28-33)
if not self.sample.exists():
    raise FileNotFoundError(f"Sample not found: {self.sample}")

if not self._is_elf_file():
    raise ValueError(f"File is not a valid ELF file: {self.sample}")
```

**What it does:**
- Checks if the file exists
- Validates it's an ELF file by checking the magic bytes (`\x7fELF`)

```python
# File: backend/extractor.py (lines 41-48)
def _is_elf_file(self):
    with open(self.sample, 'rb') as f:
        magic = f.read(4)
        return magic == b'\x7fELF'
```

**What it does:**
- Reads first 4 bytes of the file
- ELF files always start with `\x7fELF` (0x7F followed by "ELF")

### 4.3 Tool Validation

```python
# File: backend/extractor.py (lines 50-63)
def _check_required_tools(self):
    required_tools = ['readelf', 'objdump', 'strings']
    missing_tools = []
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing_tools.append(tool)
    
    if missing_tools:
        raise RuntimeError(f"Required tools not found: {', '.join(missing_tools)}")
```

**What it does:**
- Checks if required command-line tools are available
- Uses `shutil.which()` to find tools in PATH
- Raises error if any tool is missing (prevents failures later)

### 4.4 Architecture Detection

```python
# File: backend/extractor.py (lines 65-129)
def _detect_architecture(self):
    result = subprocess.check_output(f"readelf -h {self.sample}", ...)
    output = result.decode(errors="ignore")
    
    machine_match = re.search(r'Machine:\s+(\S+)', output)
    if machine_match:
        machine = machine_match.group(1).lower()
        # Map to objdump architecture flags
        arch_map = {
            'arm': 'arm',
            'intel 80386': 'i386',
            'x86-64': 'i386:x86-64',
            # ... more mappings
        }
```

**What it does:**
- Runs `readelf -h` to get ELF header information
- Parses the "Machine:" field from output
- Maps machine types to objdump architecture flags
- This is critical because `objdump -d` needs the correct architecture flag

**Why it matters:**
- Different architectures (ARM, x86, MIPS) have different instruction sets
- Without the correct architecture flag, disassembly fails with "can't disassemble for architecture UNKNOWN!"

### 4.5 Command Execution

```python
# File: backend/extractor.py (lines 131-144)
def _run(self, cmd: str):
    try:
        result = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=300
        )
        return result.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out: {cmd}"
    except subprocess.CalledProcessError as e:
        return f"[ERROR] Command failed: {cmd}\n{error_output}"
```

**What it does:**
- Executes shell commands safely
- Captures both stdout and stderr
- Has timeout protection (300 seconds max)
- Returns error messages as strings instead of crashing
- This allows the pipeline to continue even if one extraction fails

### 4.6 Extraction Methods

#### Metadata Extraction

```python
# File: backend/extractor.py (lines 146-150)
def extract_metadata(self):
    output = self._run(f"readelf -a {self.sample}")
    (self.out_dir / "metadata.txt").write_text(output)
    return output
```

**What it does:**
- Runs `readelf -a` (all information)
- Gets ELF header, section headers, program headers, etc.
- Saves to `metadata.txt`

#### Strings Extraction

```python
# File: backend/extractor.py (lines 152-156)
def extract_strings(self):
    output = self._run(f"strings -a {self.sample}")
    (self.out_dir / "strings.txt").write_text(output)
    return output
```

**What it does:**
- Runs `strings -a` (all strings, including null-terminated)
- Extracts printable strings from the binary
- Often reveals URLs, file paths, suspicious commands

#### Symbols Extraction

```python
# File: backend/extractor.py (lines 158-171)
def extract_symbols(self):
    symbols_output = self._run(f"readelf -s {self.sample}")
    headers_output = self._run(f"objdump -x {self.sample}")
    
    output = f"=== SYMBOLS (readelf -s) ===\n{symbols_output}\n\n"
    output += f"=== HEADERS & IMPORTS (objdump -x) ===\n{headers_output}"
    (self.out_dir / "symbols.txt").write_text(output)
```

**What it does:**
- Gets symbol table from `readelf -s`
- Gets dynamic symbols and imports from `objdump -x`
- Combines both into one file
- Shows function names, imported libraries, exported symbols

#### Disassembly Extraction

```python
# File: backend/extractor.py (lines 173-207)
def extract_disassembly(self):
    if self.architecture:
        cmd = f"objdump -d -m {self.architecture} {self.sample}"
        output = self._run(cmd)
        
        if "[ERROR]" in output or "can't disassemble" in output.lower():
            # Try generic fallback
            cmd = f"objdump -d {self.sample}"
            output = self._run(cmd)
```

**What it does:**
- Uses architecture-specific disassembly (`-m {architecture}`)
- If that fails, tries generic disassembly
- If generic fails, tries common architectures one by one
- This ensures disassembly works even with unknown architectures

**Why architecture matters:**
- `objdump -d` without `-m` flag assumes x86-64
- ARM binaries will fail without `-m arm`
- The architecture detection ensures correct flags are used

### 4.7 Run All Method

```python
# File: backend/extractor.py (lines 216-238)
def run_all(self):
    print(f"[+] Starting extraction for: {self.sample.name}")
    print(f"[+] Architecture detected: {self.architecture or 'unknown'}")
    
    self.extract_metadata()
    self.extract_strings()
    self.extract_symbols()
    self.extract_disassembly()
    self.extract_decompilation()
    
    print("[+] Extraction complete.")
```

**What it does:**
- Orchestrates all extraction methods in sequence
- Provides user feedback for each step
- All files are saved to `analysis/` directory

---

## 5. Phase 2: LLM Analysis - Agent Components

This phase uses an LLM (via OpenRouter) to analyze the extracted data with iterative reasoning and tool-based investigation.

### 5.1 OpenRouter Client: agent/openrouter_client.py

**Purpose:** Handles all communication with OpenRouter API.

#### Initialization

```python
# File: agent/openrouter_client.py (lines 23-48)
class OpenRouterClient:
    def __init__(self, api_key: Optional[str] = None, model: str = "openai/gpt-oss-120b:free"):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY") or DEFAULT_API_KEY
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )
```

**What it does:**
- Gets API key from parameter, environment variable, or config default
- Sets up OpenAI client with OpenRouter's base URL
- This makes OpenRouter API compatible with OpenAI SDK

**Why OpenRouter:**
- Provides access to multiple LLM models
- Uses OpenAI-compatible API
- Supports free models like `openai/gpt-oss-120b:free`

#### Rate Limiting

```python
def _rate_limit(self):
    elapsed = time.time() - self.last_request_time
    if elapsed < self.min_request_interval:
        time.sleep(self.min_request_interval - elapsed)
    self.last_request_time = time.time()
```

**What it does:**
- Ensures minimum 100ms between API requests
- Prevents hitting rate limits
- Tracks last request time

#### Chat Completion

```python
# File: agent/openrouter_client.py (lines 61-104)
def chat_completion(self, messages, tools=None, tool_choice="auto", 
                   temperature=0.7, max_tokens=None, enable_reasoning=True):
    params = {
        "model": self.model,
        "messages": messages,
        "temperature": temperature,
    }
    
    if tools:
        params["tools"] = tools
        params["tool_choice"] = tool_choice or "auto"
    
    if enable_reasoning:
        params["extra_body"] = {"reasoning": {"enabled": True}}
```

**What it does:**
- Prepares API request parameters
- Adds tools for function calling (allows LLM to request tools)
- Enables reasoning mode (for o1-style models)
- `extra_body` is OpenRouter-specific parameter for reasoning

#### Response Processing

```python
for choice in response.choices:
    choice_dict = {
        "index": choice.index,
        "message": {
            "role": choice.message.role,
            "content": choice.message.content,
        },
        "finish_reason": choice.finish_reason,
    }
    
    # Handle reasoning_details (as per OpenRouter official example)
    if hasattr(choice.message, "reasoning_details") and choice.message.reasoning_details:
        choice_dict["message"]["reasoning_details"] = choice.message.reasoning_details
    
    # Handle tool calls if present
    if hasattr(choice.message, "tool_calls") and choice.message.tool_calls:
        choice_dict["message"]["tool_calls"] = [...]
```

**What it does:**
- Converts OpenAI SDK response to dictionary format
- Preserves `reasoning_details` (internal reasoning from o1 models)
- Extracts tool calls if LLM requested any tools
- This matches OpenRouter's official implementation pattern

#### Error Handling

```python
except openai.NotFoundError as e:
    if "data policy" in error_msg.lower():
        raise ValueError(
            "OpenRouter data policy not configured.\n"
            "Please visit https://openrouter.ai/settings/privacy..."
        )
```

**What it does:**
- Catches specific OpenRouter errors
- Provides user-friendly error messages with solutions
- Data policy errors are common and need clear guidance

### 5.2 Tools Schema: agent/tools_schema.py

**Purpose:** Defines the tools available to the LLM for function calling.

```python
# File: agent/tools_schema.py (lines 6-135)
TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "read_section",
            "description": "Read a specific section from analysis files...",
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": ["metadata", "strings", "symbols", "disasm", "decomp"],
                        "description": "The section to read"
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Optional: Start line number"
                    }
                },
                "required": ["section"]
            }
        }
    },
    # ... more tools
]
```

**What it does:**
- Defines tools in JSON Schema format (OpenAI function calling standard)
- Each tool has:
  - `name`: Function name the LLM will call
  - `description`: What the tool does (LLM uses this to decide when to call it)
  - `parameters`: Input schema with types, descriptions, required fields

**Available Tools:**
1. **read_section**: Read analysis file sections (metadata, strings, symbols, disasm, decomp)
2. **disassemble_address**: Get disassembly for specific addresses or functions
3. **search_strings**: Search for patterns in extracted strings
4. **analyze_symbol**: Get detailed info about a symbol
5. **get_imports**: List imported functions and libraries
6. **get_exports**: List exported functions

**Why JSON Schema:**
- Standard format for OpenAI function calling
- LLM understands the schema and can call tools appropriately
- Type validation ensures correct parameters

### 5.3 Tool Dispatcher: agent/tool_dispatcher.py

**Purpose:** Executes tool requests from the LLM and returns results.

#### Initialization

```python
class ToolDispatcher:
    def __init__(self, analysis_dir: Path):
        self.analysis_dir = Path(analysis_dir)
        self.tool_log = []
        
        if not self.analysis_dir.exists():
            raise ValueError(f"Analysis directory not found: {self.analysis_dir}")
```

**What it does:**
- Stores path to analysis directory (where `*.txt` files are)
- Initializes tool execution log
- Validates directory exists

#### Tool Execution

```python
# File: agent/tool_dispatcher.py (lines 29-95)
def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if tool_name == "read_section":
        result = self._read_section(...)
    elif tool_name == "disassemble_address":
        result = self._disassemble_address(...)
    # ... more tools
    
    self.tool_log.append({
        "tool": tool_name,
        "arguments": arguments,
        "success": result.get("success", True)
    })
    
    return result
```

**What it does:**
- Routes tool requests to appropriate handler method
- Logs all tool executions for report generation
- Returns structured result with `success`, `result`, and `error` keys

#### Tool Implementations

**read_section:**
```python
def _read_section(self, section: str, start_line=None, end_line=None):
    section_files = {
        "metadata": "metadata.txt",
        "strings": "strings.txt",
        # ...
    }
    
    file_path = self.analysis_dir / section_files[section]
    content = file_path.read_text()
    
    if start_line or end_line:
        lines = content.split('\n')
        lines = lines[start:end]
        content = '\n'.join(lines)
    
    return {"success": True, "result": content}
```

**What it does:**
- Maps section names to file names
- Reads the file content
- Optionally extracts specific line ranges
- Returns content for LLM to analyze

**search_strings:**
```python
def _search_strings(self, pattern: str, max_results: int = 20):
    content = strings_file.read_text()
    lines = content.split('\n')
    
    pattern_lower = pattern.lower()
    matches = [line for line in lines if pattern_lower in line.lower()]
    
    return {"success": True, "result": matches[:max_results]}
```

**What it does:**
- Searches for pattern in strings file
- Case-insensitive matching
- Limits results to prevent overwhelming the LLM
- Useful for finding suspicious strings like "http://", "password", etc.

**disassemble_address:**
```python
def _disassemble_address(self, address=None, function_name=None):
    content = disasm_file.read_text()
    
    if function_name:
        pattern = rf"<{re.escape(function_name)}>"
        match = re.search(pattern, content)
        # Extract function disassembly
    elif address:
        # Search for address and extract surrounding lines
```

**What it does:**
- Searches disassembly file for specific addresses or functions
- Extracts relevant code sections
- Provides context (surrounding instructions)
- Allows LLM to analyze specific code areas

**get_imports:**
```python
def _get_imports(self, library=None, function=None):
    content = symbols_file.read_text()
    
    for line in content.split('\n'):
        if 'UND' in line or 'UNDEF' in line:  # Undefined = imported
            # Parse function and library names
            imports.append({"function": func_name, "library": lib_name})
```

**What it does:**
- Parses symbols file for imported functions
- "UND" or "UNDEF" in symbol table means imported (undefined in this binary)
- Filters by library or function name if specified
- Returns list of imports for analysis

### 5.4 Analysis Agent: agent/analyze.py

**Purpose:** Main agent that orchestrates LLM analysis with iterative reasoning and tool usage.

#### Initialization

```python
# File: agent/analyze.py (lines 24-47)
class MalwareAnalyzer:
    def __init__(self, analysis_dir: Path, api_key=None, model="openai/gpt-oss-120b:free"):
        self.analysis_dir = Path(analysis_dir)
        self.client = OpenRouterClient(api_key=api_key, model=model)
        self.dispatcher = ToolDispatcher(self.analysis_dir)
        self.tools_schema = get_tools_schema()
        
        self.conversation_history = []
        self.tool_results = []
        
        self.analysis_content = self._load_analysis_files()
```

**What it does:**
- Initializes OpenRouter client for API communication
- Creates tool dispatcher for executing LLM tool requests
- Loads tools schema (defines available tools)
- Initializes conversation history (for iterative reasoning)
- Loads analysis file contents (sends to LLM initially)

#### Loading Analysis Files

```python
# File: agent/analyze.py (lines 49-80)
def _load_analysis_files(self, max_chars_per_file: int = 10000) -> str:
    files_to_load = {
        "metadata": "metadata.txt",
        "strings": "strings.txt",
        "symbols": "symbols.txt",
        "disasm": "disasm.txt",
        "decomp": "decomp.txt"
    }
    
    for name, filename in files_to_load.items():
        file_path = self.analysis_dir / filename
        if file_path.exists():
            content = file_path.read_text()
            if len(content) > max_chars_per_file:
                content = content[:max_chars_per_file] + f"\n... (truncated)"
            analysis_content.append(f"=== {name.upper()} ({filename}) ===\n{content}\n")
    
    return "\n".join(analysis_content)
```

**What it does:**
- Reads all analysis files from `analysis/` directory
- Truncates very long files (10KB per file) to stay within token limits
- Combines all files into one text block
- This is sent to the LLM as initial context

**Why send actual content:**
- LLM needs the actual data to analyze, not just summaries
- Allows LLM to see suspicious strings, function names, etc.
- LLM can then use tools to dig deeper into specific areas

#### System Prompt

```python
def _create_system_prompt(self) -> str:
    return """You are a professional malware analysis assistant...
    
    CRITICAL REQUIREMENT: Your final analysis MUST be provided as a valid JSON object...
    
    WORKFLOW:
    1. You will receive initial static analysis data
    2. Analyze this data to identify suspicious patterns
    3. If you need more detailed information, use the available tools
    4. Continue iterating: analyze → use tools → analyze results → repeat
    5. When you have a comprehensive understanding, provide your final analysis as structured JSON
    
    FINAL OUTPUT FORMAT:
    {
      "executive_summary": {...},
      "technical_analysis": {...},
      "indicators_of_compromise": {...},
      ...
    }
    """
```

**What it does:**
- Defines the LLM's role and instructions
- Specifies the workflow (iterative analysis with tools)
- Provides exact JSON structure required
- Sets expectations for output format

**Why detailed prompt:**
- LLMs need clear instructions for structured output
- The JSON structure is complex, so it's provided explicitly
- Ensures consistent output format

#### Main Analysis Loop

```python
# File: agent/analyze.py (lines 246-313)
def analyze(self, max_iterations: int = 20) -> Dict[str, Any]:
    # Initialize conversation
    system_message = {"role": "system", "content": self._create_system_prompt()}
    initial_message = {"role": "user", "content": f"Analyze this malware sample...\n{self.analysis_content}"}
    
    self.conversation_history = [system_message, initial_message]
    
    iteration = 0
    final_analysis = None
    
    while iteration < max_iterations:
        iteration += 1
        
        # Get LLM response
        response = self.client.chat_completion(
            messages=self.conversation_history,
            tools=self.tools_schema,
            tool_choice="auto",
            max_tokens=4000
        )
```

**What it does:**
- Sets up conversation with system prompt and initial data
- Enters iterative loop (up to 20 iterations)
- Sends conversation history to LLM
- Includes tools schema so LLM can request tools
- `tool_choice="auto"` lets LLM decide when to use tools

**The Iterative Process:**

```python
choice = response["choices"][0]
message = choice["message"]
tool_calls = message.get("tool_calls", [])

if tool_calls:
    # LLM requested tools - execute them
    for tool_call in tool_calls:
        tool_name = tool_call["function"]["name"]
        tool_args = json.loads(tool_call["function"]["arguments"])
        
        # Execute tool
        tool_result = self.dispatcher.execute_tool(tool_name, tool_args)
        
        # Format result for LLM
        tool_response = f"Tool {tool_name} executed successfully:\n{result_content}"
        
        # Add to conversation
        tool_messages.append({
            "role": "tool",
            "tool_call_id": tool_id,
            "content": tool_response
        })
    
    # Add assistant message with tool calls
    self.conversation_history.append(assistant_msg)
    # Add tool results
    self.conversation_history.extend(tool_messages)
    # Continue loop - LLM will analyze tool results
    
else:
    # No tool calls - this might be final analysis
    if has_structure or has_json:
        final_analysis = content
        break  # Exit loop
```

**What it does:**
- Checks if LLM requested tools (function calls)
- If tools requested:
  1. Execute each tool
  2. Format results
  3. Add tool results to conversation history
  4. Continue loop (LLM receives tool results and continues reasoning)
- If no tools:
  - Check if response looks like final analysis (has JSON structure)
  - If yes, save and exit
  - If no, continue (might be intermediate reasoning)

**Why iterative:**
- LLM can't see all data at once (token limits)
- LLM can ask for specific information when needed
- Allows hypothesis-driven investigation
- More efficient than sending everything upfront

#### Completion Detection

```python
# Check if this looks like a final conclusion
has_structure = any(keyword in content.lower() for keyword in 
                  ["executive_summary", "technical_analysis", 
                   "indicators_of_compromise", ...])

if has_structure or has_json or len(content) > 500:
    final_analysis = content
    break
```

**What it does:**
- Detects when LLM has provided final analysis
- Looks for JSON structure keywords
- Checks for JSON braces
- Considers substantial content (>500 chars) as potentially final
- Stops iteration when final analysis is received

#### Return Results

```python
return {
    "analysis": final_analysis or "Analysis incomplete",
    "conversation_history": self.conversation_history,
    "tool_results": self.tool_results,
    "tool_log": self.dispatcher.get_tool_log(),
    "iterations": iteration
}
```

**What it does:**
- Returns complete analysis results
- Includes conversation history (for debugging/review)
- Includes all tool execution results
- Includes tool usage log
- Returns iteration count

---

## 6. Phase 3: Report Generation - agent/report_generator.py

**Purpose:** Parses LLM analysis and generates structured JSON and Markdown reports.

### 6.1 Report Generation Entry Point

```python
def generate_report(self, sample_path, analysis_results, extractor_info=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sample_name = sample_path.stem
    
    # Parse LLM analysis and extract structured data
    structured_report = self._parse_and_structure_analysis(...)
    
    # Generate JSON report
    json_path = self.output_dir / f"{sample_name}_{timestamp}.json"
    self._generate_json_report(structured_report, json_path)
    
    # Generate Markdown report
    md_path = self.output_dir / f"{sample_name}_{timestamp}.md"
    self._generate_markdown_report(structured_report, md_path)
```

**What it does:**
- Creates timestamped filenames
- Parses LLM analysis into structured format
- Generates both JSON and Markdown reports
- Returns paths to generated files

### 6.2 JSON Extraction

```python
def _parse_and_structure_analysis(self, ...):
    analysis_text = analysis_results.get("analysis", "")
    conversation_history = analysis_results.get("conversation_history", [])
    
    # Try to extract JSON from LLM response
    json_data = self._extract_json_from_text(analysis_text)
    
    # If not found, search conversation history
    if not json_data and conversation_history:
        for msg in reversed(conversation_history):
            if msg.get("role") == "assistant" and "{" in msg.get("content", ""):
                json_data = self._extract_json_from_text(msg["content"])
                if json_data:
                    break
```

**What it does:**
- First tries to extract JSON from `analysis_text` (final analysis)
- If not found, searches conversation history (JSON might be in earlier message)
- Searches in reverse (most recent first)
- Combines messages if JSON is split across multiple messages

### 6.3 Balanced JSON Extraction

```python
# File: agent/report_generator.py (lines 195-242)
def _extract_balanced_json(self, text: str) -> Optional[Dict[str, Any]]:
    brace_count = 0
    start_idx = text.find('{')
    
    in_string = False
    escape_next = False
    
    for i in range(start_idx, len(text)):
        char = text[i]
        
        if escape_next:
            escape_next = False
            continue
        
        if char == '\\':
            escape_next = True
            continue
        
        if char == '"' and not escape_next:
            in_string = not in_string
            continue
        
        if not in_string:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    # Found complete JSON object
                    json_str = text[start_idx:i+1]
                    return json.loads(json_str)
```

**What it does:**
- Finds the first `{` character
- Tracks brace count (increments on `{`, decrements on `}`)
- **Critical:** Ignores braces inside strings (handles string escaping)
- When brace_count reaches 0, we have a complete JSON object
- Extracts and parses the JSON

**Why this is needed:**
- LLM might output JSON with extra text before/after
- Need to extract just the JSON part
- Must handle braces inside strings (e.g., `"text {with braces}"`)
- Must handle escaped characters (`\"`, `\\`)

### 6.4 Fallback Text Parsing

```python
def _parse_text_analysis(self, text: str, tool_results: List[Dict]) -> Dict[str, Any]:
    structured = {
        "executive_summary": self._parse_executive_summary(text),
        "technical_analysis": self._parse_technical_analysis(text, tool_results),
        "indicators_of_compromise": self._parse_iocs(text, tool_results),
        # ...
    }
    return structured
```

**What it does:**
- If JSON extraction fails, parses unstructured text
- Uses regex to extract information
- Extracts from tool results (IPs, domains, imports, etc.)
- Creates structured format from unstructured text

**Example parsing:**
```python
def _parse_executive_summary(self, text: str):
    # Extract classification
    for classification in ["DDoS bot", "Backdoor", ...]:
        if classification.lower() in text.lower():
            summary["classification"] = classification
            break
    
    # Extract risk score
    risk_match = re.search(r'risk[:\s]+(\d+)', text.lower())
    if risk_match:
        summary["risk_score"] = int(risk_match.group(1))
```

### 6.5 IOC Extraction

```python
def _parse_iocs(self, text: str, tool_results: List[Dict]):
    iocs = {
        "network_iocs": {"ips": [], "domains": [], "urls": []},
        # ...
    }
    
    # Extract from tool results
    for tool_result in tool_results:
        if tool_result.get("tool") == "search_strings":
            strings = tool_result.get("result", {}).get("result", [])
            for s in strings:
                # Extract IPs
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s)
                if ip_match:
                    iocs["network_iocs"]["ips"].append(ip_match.group(0))
                
                # Extract URLs
                url_match = re.search(r'https?://[^\s]+', s)
                if url_match:
                    iocs["network_iocs"]["urls"].append(url_match.group(0))
```

**What it does:**
- Extracts IOCs from tool results
- Uses regex to find IPs, URLs, domains in strings
- Deduplicates entries
- Organizes into structured categories

### 6.6 Structure Validation

```python
def _ensure_complete_structure(self, structured: Dict[str, Any], tool_results: List[Dict]):
    # Ensure executive_summary
    if "executive_summary" not in structured:
        structured["executive_summary"] = {
            "classification": "Unknown",
            "key_capabilities": [],
            "risk_level": "Medium",
            "risk_score": 50,
            "primary_evasion_techniques": []
        }
    
    # Ensure all other sections...
    return structured
```

**What it does:**
- Ensures all required JSON sections exist
- Provides default values for missing sections
- Prevents KeyError when accessing report data
- Guarantees consistent report structure

### 6.7 Report Writing

```python
# File: agent/report_generator.py (lines 489-493)
def _generate_json_report(self, report_data: Dict[str, Any], output_path: Path):
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
```

**What it does:**
- Writes structured JSON to file
- `indent=2` makes it human-readable
- `ensure_ascii=False` preserves Unicode characters
- Saves to `reports/` directory with timestamp

---

## 7. Complete Workflow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    USER RUNS: ./run.sh                      │
│                  samples/malware.elf                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  run.sh: Activates venv, calls python3 main.py "$@"         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  main.py: main()                                             │
│  ├─ Loads .env file (API keys)                              │
│  ├─ Imports: StaticExtractor, analyze_sample, generate_reports│
│  └─ Parses command-line argument (sample path)              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE 1: Static Extraction                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ StaticExtractor(sample_path)                         │   │
│  │ ├─ Validates ELF file (checks magic bytes)           │   │
│  │ ├─ Checks required tools (readelf, objdump, strings)│   │
│  │ ├─ Detects architecture (ARM/x86/MIPS/etc.)         │   │
│  │ └─ extractor.run_all()                               │   │
│  │    ├─ extract_metadata() → analysis/metadata.txt     │   │
│  │    ├─ extract_strings() → analysis/strings.txt      │   │
│  │    ├─ extract_symbols() → analysis/symbols.txt      │   │
│  │    ├─ extract_disassembly() → analysis/disasm.txt   │   │
│  │    └─ extract_decompilation() → analysis/decomp.txt │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE 2: LLM Analysis                                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ analyze_sample(extractor.out_dir, api_key, model)    │   │
│  │                                                       │   │
│  │ MalwareAnalyzer.__init__()                           │   │
│  │ ├─ Creates OpenRouterClient                          │   │
│  │ ├─ Creates ToolDispatcher                            │   │
│  │ ├─ Loads tools_schema                                 │   │
│  │ └─ Loads analysis files content                      │   │
│  │                                                       │   │
│  │ analyzer.analyze() - ITERATIVE LOOP                  │   │
│  │                                                       │   │
│  │ [ITERATION 1]                                        │   │
│  │ ├─ Sends system prompt + analysis files to LLM       │   │
│  │ ├─ LLM analyzes data                                 │   │
│  │ └─ LLM responds with:                                │   │
│  │    ├─ Tool requests (read_section, search_strings...)│   │
│  │    └─ OR final JSON analysis                         │   │
│  │                                                       │   │
│  │ [IF TOOL REQUESTS]                                   │   │
│  │ ├─ ToolDispatcher.execute_tool() for each request    │   │
│  │ ├─ Reads files, searches strings, etc.               │   │
│  │ ├─ Returns tool results to LLM                        │   │
│  │ └─ Continue to next iteration                        │   │
│  │                                                       │   │
│  │ [ITERATION 2-N]                                      │   │
│  │ ├─ LLM receives tool results                         │   │
│  │ ├─ LLM continues analysis                             │   │
│  │ ├─ May request more tools                            │   │
│  │ └─ Eventually provides final JSON analysis           │   │
│  │                                                       │   │
│  │ Returns: {analysis, conversation_history,            │   │
│  │          tool_results, tool_log, iterations}         │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  PHASE 3: Report Generation                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ generate_reports(sample_path, analysis_results, ...)  │   │
│  │                                                       │   │
│  │ ReportGenerator.generate_report()                    │   │
│  │ ├─ _parse_and_structure_analysis()                   │   │
│  │ │  ├─ Extracts JSON from LLM response                │   │
│  │ │  ├─ Searches conversation history if needed         │   │
│  │ │  ├─ Falls back to text parsing if JSON not found   │   │
│  │ │  ├─ Extracts IOCs from tool results                │   │
│  │ │  └─ Ensures complete structure                     │   │
│  │ │                                                     │   │
│  │ ├─ _generate_json_report()                           │   │
│  │ │  └─ Writes structured JSON to file                 │   │
│  │ │                                                     │   │
│  │ └─ _generate_markdown_report()                       │   │
│  │    └─ Writes human-readable Markdown                  │   │
│  │                                                       │   │
│  │ Returns: {json: path, markdown: path}                │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  COMPLETE: Reports saved to reports/ directory              │
│  - sample_name_TIMESTAMP.json (structured JSON)            │
│  - sample_name_TIMESTAMP.md (human-readable)                │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Key Design Decisions

### 8.1 Why Iterative Analysis?

**Problem:** LLMs have token limits. Can't send all analysis data at once.

**Solution:** 
- Send initial data (truncated to 10KB per file)
- LLM can request specific sections via tools
- Iterative loop allows deep investigation
- More efficient than sending everything

### 8.2 Why Tool-Based Investigation?

**Problem:** LLM needs to investigate specific areas but can't see all data.

**Solution:**
- Tools allow LLM to query specific information
- `read_section` for detailed file reading
- `search_strings` for pattern matching
- `disassemble_address` for code analysis
- LLM decides what to investigate based on initial analysis

### 8.3 Why Architecture Detection?

**Problem:** `objdump -d` fails on non-x86 binaries without architecture flag.

**Solution:**
- Detect architecture from ELF header
- Use appropriate `-m {architecture}` flag
- Fallback to trying common architectures
- Ensures disassembly works for ARM, MIPS, etc.

### 8.4 Why JSON Extraction with Fallback?

**Problem:** LLM might output JSON in different formats or locations.

**Solution:**
- Try multiple extraction methods:
  1. Extract from final analysis text
  2. Search conversation history
  3. Use balanced brace matching
  4. Fallback to text parsing
- Ensures reports are always generated

### 8.5 Why Preserve reasoning_details?

**Problem:** OpenRouter o1 models provide internal reasoning.

**Solution:**
- Preserve `reasoning_details` in conversation history
- Matches OpenRouter official implementation
- Allows LLM to continue reasoning from previous state
- Improves analysis quality

---

## 9. Data Flow Summary

1. **Input:** ELF binary file path
2. **Extraction:** Binary → analysis/*.txt files (metadata, strings, symbols, disasm)
3. **LLM Input:** Analysis files content → LLM (initial context)
4. **Iterative Loop:**
   - LLM analyzes → requests tools → tools execute → results back to LLM → repeat
5. **LLM Output:** Structured JSON analysis
6. **Report Generation:** JSON extraction → structure validation → file writing
7. **Output:** JSON and Markdown reports in `reports/` directory

---

## 10. Error Handling Strategy

The system uses **graceful degradation**:

- **Extraction fails:** Error message, exit
- **LLM API fails:** Continue with extraction-only results
- **Tool execution fails:** Log error, continue with other tools
- **JSON extraction fails:** Fallback to text parsing
- **Report generation fails:** Show error, but extraction completed

This ensures the pipeline always produces some output, even if parts fail.

---

## 11. Configuration Priority

1. **Command-line parameters** (highest priority)
2. **Environment variables** (`.env` file)
3. **Config defaults** (`config.py`)

This allows flexibility: override defaults via env vars, or use hardcoded defaults.

---

## 12. Key Files Summary

| File | Purpose | Key Functionality |
|------|---------|-------------------|
| `run.sh` | Entry point | Activates venv, runs main.py |
| `main.py` | Orchestrator | Coordinates all three phases |
| `config.py` | Configuration | API keys, settings, directories |
| `backend/extractor.py` | Static analysis | ELF extraction, architecture detection |
| `agent/openrouter_client.py` | API client | OpenRouter communication, reasoning support |
| `agent/tools_schema.py` | Tool definitions | Defines 6 tools for LLM |
| `agent/tool_dispatcher.py` | Tool execution | Executes LLM tool requests |
| `agent/analyze.py` | Analysis agent | Iterative LLM analysis loop |
| `agent/report_generator.py` | Report generation | JSON/Markdown report creation |

---

## 13. Conclusion

This malware detector implements a complete pipeline:

1. **Static Extraction:** Uses standard Linux tools to extract binary information
2. **LLM Analysis:** Uses OpenRouter API with iterative reasoning and tool-based investigation
3. **Report Generation:** Creates structured JSON and human-readable Markdown reports

The system is designed to be:
- **Robust:** Handles errors gracefully, continues even if parts fail
- **Flexible:** Configurable via environment variables
- **Extensible:** Easy to add new tools or analysis methods
- **Professional:** Generates structured reports matching industry standards

The iterative reasoning approach allows the LLM to perform deep, hypothesis-driven analysis while staying within token limits.

---

*End of Code Explanation*

