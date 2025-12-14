# Malware Detector - Quick Summary

## Overview

A malware analysis system that performs static analysis on ELF binaries using traditional tools (readelf, objdump, strings) combined with LLM-powered intelligent analysis via OpenRouter API.

---

## Three-Phase Workflow

```
ELF Binary → Static Extraction → LLM Analysis → Report Generation
```

### Phase 1: Static Extraction
- **Component:** `backend/extractor.py` (StaticExtractor class)
- **What it does:**
  - Validates ELF file (checks magic bytes `\x7fELF`)
  - Detects architecture (ARM/x86/MIPS/etc.)
  - Extracts metadata, strings, symbols, disassembly
  - Saves to `analysis/*.txt` files
- **Key feature:** Architecture detection ensures correct `objdump` flags for disassembly

### Phase 2: LLM Analysis
- **Component:** `agent/analyze.py` (MalwareAnalyzer class)
- **What it does:**
  - Loads analysis files and sends to LLM via OpenRouter
  - **Iterative reasoning loop:**
    1. LLM analyzes initial data
    2. LLM requests tools if needed (read_section, search_strings, etc.)
    3. Tools execute and return results
    4. LLM continues analysis with tool results
    5. Repeats until final JSON analysis is provided
- **Key feature:** Tool-based investigation allows deep analysis without token limit issues

### Phase 3: Report Generation
- **Component:** `agent/report_generator.py` (ReportGenerator class)
- **What it does:**
  - Extracts JSON from LLM response (with fallback parsing)
  - Validates and structures report
  - Generates JSON and Markdown reports
  - Saves to `reports/` directory with timestamp

---

## Key Components

| Component | File | Purpose |
|-----------|------|---------|
| **Entry Point** | `run.sh` | Activates venv, runs main.py |
| **Orchestrator** | `main.py` | Coordinates all three phases |
| **Static Extractor** | `backend/extractor.py` | ELF binary analysis |
| **LLM Client** | `agent/openrouter_client.py` | OpenRouter API communication |
| **Tool Dispatcher** | `agent/tool_dispatcher.py` | Executes LLM tool requests |
| **Analysis Agent** | `agent/analyze.py` | Iterative LLM analysis loop |
| **Report Generator** | `agent/report_generator.py` | Creates structured reports |
| **Configuration** | `config.py` | API keys, settings, directories |

---

## Available Tools (for LLM)

The LLM can request these tools during analysis:

1. **read_section** - Read specific analysis file sections (metadata, strings, symbols, disasm, decomp)
2. **disassemble_address** - Get disassembly for specific addresses or functions
3. **search_strings** - Search for patterns in extracted strings
4. **analyze_symbol** - Get detailed information about symbols
5. **get_imports** - List imported functions and libraries
6. **get_exports** - List exported functions

---

## Data Flow

```
1. User runs: ./run.sh samples/malware.elf
   ↓
2. run.sh activates venv → python3 main.py
   ↓
3. main.py creates StaticExtractor
   ↓
4. StaticExtractor extracts binary data → analysis/*.txt files
   ↓
5. main.py calls analyze_sample()
   ↓
6. MalwareAnalyzer loads analysis files → sends to LLM
   ↓
7. LLM analyzes → requests tools → tools execute → results back to LLM
   ↓
8. Iterative loop continues until LLM provides final JSON
   ↓
9. main.py calls generate_reports()
   ↓
10. ReportGenerator extracts JSON → validates → writes reports
   ↓
11. Reports saved: reports/sample_TIMESTAMP.json and .md
```

---

## Configuration

- **API Key:** From `OPENROUTER_API_KEY` env var, `.env` file, or `config.py` default
- **Model:** `openai/gpt-oss-120b:free` (configurable)
- **Directories:**
  - `analysis/` - Static extraction output
  - `reports/` - Generated reports
  - `samples/` - Input samples

---

## Key Design Decisions

### 1. Iterative Analysis
- **Why:** Token limits prevent sending all data at once
- **How:** LLM requests specific information via tools when needed
- **Benefit:** More efficient, allows deep investigation

### 2. Architecture Detection
- **Why:** `objdump -d` fails on non-x86 binaries without architecture flag
- **How:** Detects from ELF header, uses `-m {architecture}` flag
- **Benefit:** Works with ARM, MIPS, and other architectures

### 3. Tool-Based Investigation
- **Why:** LLM needs to investigate specific areas but can't see all data
- **How:** Tools allow LLM to query specific information on-demand
- **Benefit:** Hypothesis-driven analysis, efficient resource usage

### 4. JSON Extraction with Fallback
- **Why:** LLM might output JSON in different formats or locations
- **How:** Multiple extraction methods (code blocks, balanced braces, conversation history)
- **Benefit:** Always generates reports, even if JSON format varies

### 5. Graceful Degradation
- **Why:** System should produce output even if parts fail
- **How:** Error handling at each phase, continues with partial results
- **Benefit:** Robust pipeline, always produces some output

---

## Report Structure

The generated JSON report includes:

- **executive_summary** - Classification, risk level, key capabilities
- **technical_analysis** - Binary properties, malicious behaviors, network capabilities
- **indicators_of_compromise** - Network IOCs, host-based IOCs, YARA rules
- **threat_intelligence** - MITRE ATT&CK mapping, threat actor affiliation
- **recommendations** - Detection, mitigation, further analysis
- **metadata** - Timestamp, methodology, confidence levels

---

## Error Handling

- **Extraction fails:** Error message, exit
- **LLM API fails:** Continue with extraction-only results
- **Tool execution fails:** Log error, continue with other tools
- **JSON extraction fails:** Fallback to text parsing
- **Report generation fails:** Show error, but extraction completed

**Principle:** Always produce some output, even if parts fail.

---

## Usage

```bash
# Activate venv and run
./run.sh samples/malware.elf

# Or directly
python3 main.py samples/malware.elf
```

**Output:**
- `analysis/*.txt` - Static extraction files
- `reports/sample_TIMESTAMP.json` - Structured JSON report
- `reports/sample_TIMESTAMP.md` - Human-readable Markdown report

---

## Requirements

- **System tools:** `readelf`, `objdump`, `strings` (from binutils package)
- **Python packages:** `openai`, `python-dotenv` (see `requirements.txt`)
- **API:** OpenRouter API key (free tier available)

---

## Quick Reference

**Entry Point:** `run.sh` → `main.py`

**Three Phases:**
1. Static extraction → `backend/extractor.py`
2. LLM analysis → `agent/analyze.py` (iterative with tools)
3. Report generation → `agent/report_generator.py`

**Key Innovation:** Iterative LLM analysis with tool-based deep investigation allows comprehensive analysis while staying within token limits.

---

*For detailed explanations, see `explication.md`*

