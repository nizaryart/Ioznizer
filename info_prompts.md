# LLM Prompts Documentation

This document explains all prompts sent to the LLM, their purpose, structure, and location in the codebase.

---

## Overview

The system uses **two main prompts** to guide the LLM:
1. **System Prompt** - Defines the LLM's role, workflow, and output requirements
2. **Initial User Message** - Provides the actual malware analysis data and task instructions

These prompts work together to ensure the LLM produces structured, comprehensive malware analysis reports.

---

## 1. System Prompt

### Location in Code
**File:** `agent/analyze.py`  
**Method:** `_create_system_prompt()` (lines 82-219)  
**Called from:** `analyze()` method when initializing conversation (line 264)

### Purpose
The system prompt defines:
- The LLM's role and expertise
- The analysis workflow
- Available tools and how to use them
- Required output format (JSON structure)
- Critical requirements and constraints

### Full Prompt Structure

```python
def _create_system_prompt(self) -> str:
    return """You are a professional malware analysis assistant with expertise in ELF binary analysis and threat intelligence reporting.

CRITICAL REQUIREMENT: Your final analysis MUST be provided as a valid JSON object matching the exact structure specified below.

WORKFLOW:
1. You will receive initial static analysis data (metadata, strings, symbols, disassembly, etc.)
2. Analyze this data to identify suspicious patterns
3. If you need more detailed information, use the available tools to query specific sections
4. Continue iterating: analyze → use tools if needed → analyze results → repeat until complete
5. When you have a comprehensive understanding, provide your final analysis as structured JSON

AVAILABLE TOOLS (use when you need more information):
- read_section: Read specific sections from analysis files (metadata, strings, symbols, disasm, decomp)
- disassemble_address: Get disassembly for specific addresses or functions
- search_strings: Search for suspicious strings or patterns
- analyze_symbol: Get detailed information about symbols
- get_imports: List imported functions and libraries
- get_exports: List exported functions

TOOL USAGE STRATEGY:
- Use tools efficiently - avoid redundant queries
- Focus on hypothesis-driven investigation
- Extract ALL key findings from tool results into structured fields
- Never leave arrays empty when findings are confirmed

FINAL OUTPUT FORMAT:
[Detailed JSON structure specification...]

CRITICAL REQUIREMENTS:
- Extract ALL key findings from tool results into structured fields
- Never leave "malicious_behaviors" or "indicators_of_compromise" arrays empty when malicious behavior is confirmed
- Generate concrete YARA rule snippets based on actual binary strings/patterns
- Map findings to MITRE ATT&CK framework (use technique IDs like T1055, T1071, etc.)
- Calculate risk score (1-100) based on: impact, propagation, persistence, evasion sophistication
- Provide actionable recommendations for each finding
- Tag each finding with confidence level (High/Medium/Low)
- Deduplicate strings and artifacts
- No null values for critical assessment fields
- No markdown formatting in JSON string fields

AVOID:
- Markdown formatting in JSON
- Duplicate entries in arrays
- Null values for critical fields
- Unstructured prose in analysis sections
- Redundant tool calls

Be thorough, use tools as needed, and provide your final analysis as valid JSON."""
```

### Key Sections Explained

#### 1. Role Definition
```
"You are a professional malware analysis assistant with expertise in ELF binary analysis and threat intelligence reporting."
```
- **Purpose:** Sets the LLM's identity and expertise level
- **Why:** Helps LLM adopt appropriate analysis mindset and terminology

#### 2. Critical Requirement
```
"CRITICAL REQUIREMENT: Your final analysis MUST be provided as a valid JSON object matching the exact structure specified below."
```
- **Purpose:** Emphasizes the output format requirement
- **Why:** LLMs sometimes provide prose instead of structured JSON; this makes it explicit

#### 3. Workflow (5 Steps)
```
WORKFLOW:
1. You will receive initial static analysis data...
2. Analyze this data to identify suspicious patterns
3. If you need more detailed information, use the available tools...
4. Continue iterating: analyze → use tools → analyze results → repeat
5. When you have a comprehensive understanding, provide your final analysis as structured JSON
```
- **Purpose:** Defines the iterative analysis process
- **Why:** Guides LLM through the expected reasoning flow

#### 4. Available Tools
Lists all 6 tools with brief descriptions:
- `read_section` - Read analysis file sections
- `disassemble_address` - Get disassembly for addresses/functions
- `search_strings` - Search for patterns in strings
- `analyze_symbol` - Get symbol details
- `get_imports` - List imported functions/libraries
- `get_exports` - List exported functions

**Purpose:** Informs LLM what tools are available  
**Why:** LLM needs to know what it can request during analysis

#### 5. Tool Usage Strategy
```
- Use tools efficiently - avoid redundant queries
- Focus on hypothesis-driven investigation
- Extract ALL key findings from tool results into structured fields
- Never leave arrays empty when findings are confirmed
```
- **Purpose:** Guides efficient tool usage
- **Why:** Prevents wasteful tool calls and ensures complete data extraction

#### 6. Final Output Format
Provides complete JSON structure with all required fields:
- `executive_summary` - Classification, risk level, capabilities
- `technical_analysis` - Binary properties, malicious behaviors, network capabilities
- `indicators_of_compromise` - Network IOCs, host-based IOCs, YARA rules
- `threat_intelligence` - MITRE ATT&CK mapping, threat actor info
- `tool_usage_analysis` - Tools used, investigation strategy
- `recommendations` - Detection, mitigation, further analysis
- `metadata` - Timestamp, methodology, confidence levels

**Purpose:** Specifies exact JSON structure expected  
**Why:** Ensures consistent, parseable output format

#### 7. Critical Requirements
Lists 10+ specific requirements:
- Extract ALL findings from tool results
- Never leave arrays empty when findings exist
- Generate concrete YARA rules
- Map to MITRE ATT&CK framework
- Calculate risk score (1-100)
- Tag findings with confidence levels
- Deduplicate artifacts
- No null values for critical fields
- No markdown in JSON strings

**Purpose:** Ensures quality and completeness  
**Why:** Prevents common LLM output issues (empty arrays, missing data, formatting problems)

#### 8. Avoid Section
Lists what NOT to do:
- Markdown formatting in JSON
- Duplicate entries
- Null values for critical fields
- Unstructured prose
- Redundant tool calls

**Purpose:** Prevents common mistakes  
**Why:** Negative examples help LLM avoid problematic outputs

### When It's Used

The system prompt is:
1. **Created once** when `MalwareAnalyzer` instance calls `analyze()`
2. **Sent as first message** in conversation history with `role: "system"`
3. **Preserved throughout** the entire iterative analysis loop
4. **Never modified** during the conversation

**Code location:**
```python
# In agent/analyze.py, analyze() method (line 262-265)
system_message = {
    "role": "system",
    "content": self._create_system_prompt()
}
self.conversation_history = [system_message, initial_message]
```

---

## 2. Initial User Message

### Location in Code
**File:** `agent/analyze.py`  
**Method:** `analyze()` (lines 267-293)  
**Variable:** `initial_message`

### Purpose
The initial user message:
- Provides the actual malware analysis data (extracted from binary)
- Reinforces the JSON output requirement
- Lists specific analysis tasks
- Reminds LLM about tool usage
- Summarizes required JSON sections

### Full Prompt Structure

```python
initial_message = {
    "role": "user",
    "content": f"""Analyze this malware sample. I've extracted the following static analysis data from the ELF binary:

{self.analysis_content}

CRITICAL: Your final output MUST be a valid JSON object matching the structure specified in the system prompt.

Analyze this data and identify:
1. Malicious behaviors and indicators
2. Suspicious strings, API calls, and functions
3. Network communication patterns
4. File system operations
5. Process manipulation
6. Anti-analysis techniques

If you need more detailed information about specific sections, addresses, or strings, use the available tools to query deeper.

After your comprehensive analysis, provide your findings as a structured JSON object with all required sections:
- executive_summary (classification, risk_score, key_capabilities)
- technical_analysis (binary_properties, malicious_behaviors, network_capabilities)
- indicators_of_compromise (network_iocs, host_based_iocs, behavioral_iocs, yara_rules)
- threat_intelligence (mitre_attack_techniques, threat_actor_affiliation)
- recommendations (detection, mitigation, further_analysis)

Extract ALL findings from tool results. Never leave arrays empty when findings are confirmed."""
}
```

### Key Components Explained

#### 1. Task Introduction
```
"Analyze this malware sample. I've extracted the following static analysis data from the ELF binary:"
```
- **Purpose:** Sets context for the analysis task
- **Why:** Clearly states what the LLM should do

#### 2. Analysis Data
```
{self.analysis_content}
```
- **Purpose:** Contains actual extracted data from binary
- **Content:** Combined content from:
  - `metadata.txt` - ELF headers, sections
  - `strings.txt` - Extracted strings
  - `symbols.txt` - Symbols and imports
  - `disasm.txt` - Disassembly
  - `decomp.txt` - Decompilation (placeholder)
- **Size:** Up to 10,000 characters per file (truncated if longer)
- **Format:** Each file section is prefixed with `=== SECTION_NAME (filename) ===`

**How it's generated:**
```python
# In agent/analyze.py, _load_analysis_files() method (lines 49-80)
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

#### 3. Critical Reminder
```
"CRITICAL: Your final output MUST be a valid JSON object matching the structure specified in the system prompt."
```
- **Purpose:** Reinforces JSON output requirement
- **Why:** Repetition helps ensure LLM follows the format

#### 4. Analysis Tasks (6 Items)
```
Analyze this data and identify:
1. Malicious behaviors and indicators
2. Suspicious strings, API calls, and functions
3. Network communication patterns
4. File system operations
5. Process manipulation
6. Anti-analysis techniques
```
- **Purpose:** Provides specific analysis focus areas
- **Why:** Guides LLM to look for common malware characteristics

#### 5. Tool Usage Reminder
```
"If you need more detailed information about specific sections, addresses, or strings, use the available tools to query deeper."
```
- **Purpose:** Encourages tool usage when needed
- **Why:** LLM might hesitate to use tools; this prompts it

#### 6. Required Sections Summary
```
"After your comprehensive analysis, provide your findings as a structured JSON object with all required sections:
- executive_summary (classification, risk_score, key_capabilities)
- technical_analysis (binary_properties, malicious_behaviors, network_capabilities)
- indicators_of_compromise (network_iocs, host_based_iocs, behavioral_iocs, yara_rules)
- threat_intelligence (mitre_attack_techniques, threat_actor_affiliation)
- recommendations (detection, mitigation, further_analysis)"
```
- **Purpose:** Lists all required JSON sections
- **Why:** Quick reference for LLM to ensure completeness

#### 7. Final Reminder
```
"Extract ALL findings from tool results. Never leave arrays empty when findings are confirmed."
```
- **Purpose:** Emphasizes data extraction from tools
- **Why:** Prevents empty arrays when data exists

### When It's Used

The initial user message is:
1. **Created once** at the start of `analyze()` method
2. **Sent as second message** in conversation history (after system prompt)
3. **Contains dynamic data** (`self.analysis_content` is loaded from files)
4. **Never modified** during iterations

**Code location:**
```python
# In agent/analyze.py, analyze() method (line 267-293)
initial_message = {
    "role": "user",
    "content": f"""Analyze this malware sample...{self.analysis_content}..."""
}
self.conversation_history = [system_message, initial_message]
```

---

## 3. Conversation Flow

### Message Sequence

The conversation follows this structure:

```
[Message 1] System Prompt
  - Role: "system"
  - Content: System prompt (defines role, workflow, tools, JSON structure)
  
[Message 2] Initial User Message
  - Role: "user"
  - Content: Analysis task + actual malware data
  
[Message 3+] Iterative Loop
  - [3] Assistant response (analysis + tool requests OR final JSON)
  - [4] Tool results (if tools were requested)
  - [5] Assistant response (continued analysis)
  - [6] Tool results (if more tools requested)
  - ... continues until final JSON is provided
```

### Example Conversation

```
[System] "You are a professional malware analysis assistant..."
[User] "Analyze this malware sample. I've extracted... [analysis data]"
[Assistant] "I'll analyze this sample. Let me start by examining the strings for suspicious patterns."
[Assistant] [Tool Call: search_strings("http://")]
[Tool] "Tool search_strings executed successfully: ['http://c2.malware.com', 'http://...']"
[Assistant] "I found C2 URLs. Let me check the disassembly for network functions."
[Assistant] [Tool Call: get_imports(library="libc")]
[Tool] "Tool get_imports executed successfully: [socket, connect, send, recv, ...]"
[Assistant] "Based on my analysis, here is the structured JSON report: {...}"
```

### Code Implementation

**File:** `agent/analyze.py`  
**Method:** `analyze()` (lines 246-528)

```python
# Initialize conversation (lines 262-295)
system_message = {"role": "system", "content": self._create_system_prompt()}
initial_message = {"role": "user", "content": f"Analyze this malware...{self.analysis_content}..."}
self.conversation_history = [system_message, initial_message]

# Iterative loop (lines 300-496)
while iteration < max_iterations:
    # Send conversation to LLM
    response = self.client.chat_completion(
        messages=self.conversation_history,
        tools=self.tools_schema,
        tool_choice="auto"
    )
    
    # Process response
    message = response["choices"][0]["message"]
    
    if message.get("tool_calls"):
        # LLM requested tools - execute them
        # Add tool results to conversation_history
    else:
        # LLM provided analysis - check if final
        if has_json_structure:
            final_analysis = message["content"]
            break
```

---

## 4. Tool Response Messages

### Location in Code
**File:** `agent/analyze.py`  
**Method:** `analyze()` (lines 347-417)

### Purpose
When LLM requests tools, the system executes them and sends results back as tool messages.

### Format

```python
tool_messages.append({
    "role": "tool",
    "tool_call_id": tool_id,  # Matches the tool call ID from LLM
    "content": tool_response   # Result from tool execution
})
```

### Example Tool Response

```python
# In agent/analyze.py, analyze() method (lines 381-395)
if tool_result.get("success"):
    result_content = str(tool_result.get("result", ""))
    # Truncate very long results
    if len(result_content) > 5000:
        result_content = result_content[:5000] + "\n... (truncated, use read_section for full content)"
    tool_response = f"Tool {tool_name} executed successfully:\n{result_content}"
else:
    tool_response = f"Tool {tool_name} failed: {tool_result.get('error', 'Unknown error')}"
```

### Tool Response Content

**Success case:**
```
"Tool search_strings executed successfully:
['http://c2.malware.com', 'password123', '/tmp/backdoor', ...]"
```

**Failure case:**
```
"Tool disassemble_address failed: Address not found: 0x1234"
```

### When Tool Messages Are Added

1. LLM sends assistant message with `tool_calls` array
2. System executes each tool via `ToolDispatcher.execute_tool()`
3. System formats tool results as tool messages
4. Tool messages are added to `conversation_history`
5. Loop continues - LLM receives tool results and continues analysis

**Code location:**
```python
# In agent/analyze.py, analyze() method (lines 347-417)
if tool_calls:
    tool_messages = []
    for tool_call in tool_calls:
        tool_result = self.dispatcher.execute_tool(tool_name, tool_args)
        tool_messages.append({
            "role": "tool",
            "tool_call_id": tool_id,
            "content": tool_response
        })
    self.conversation_history.extend(tool_messages)
```

---

## 5. Prompt Engineering Decisions

### Why Two Separate Prompts?

**System Prompt:**
- Defines role and constraints (persistent throughout conversation)
- Provides JSON structure specification
- Lists available tools
- Sets workflow expectations

**Initial User Message:**
- Contains actual data (too large for system prompt)
- Provides specific task instructions
- Reinforces critical requirements
- Dynamic content (changes per sample)

**Benefit:** Separation allows system prompt to be static while user message contains dynamic data.

### Why Emphasize JSON Format?

**Problem:** LLMs often provide prose or markdown instead of structured JSON.

**Solution:**
- Mentioned 3+ times in prompts
- Provided complete JSON structure example
- Listed all required sections
- Added "CRITICAL REQUIREMENT" emphasis

**Result:** Higher success rate for structured JSON output.

### Why List Tools in Prompt?

**Problem:** LLM needs to know what tools are available.

**Solution:**
- Listed all 6 tools with descriptions in system prompt
- Reminded about tool usage in initial message
- Tool schemas also sent to LLM (via `tools` parameter)

**Result:** LLM can make informed tool selection decisions.

### Why Iterative Workflow?

**Problem:** Can't send all analysis data at once (token limits).

**Solution:**
- System prompt defines iterative workflow
- Initial message provides overview data
- Tools allow deep investigation on-demand
- LLM decides when to use tools

**Result:** Efficient use of tokens while allowing comprehensive analysis.

### Why Multiple Reminders?

**Problem:** LLMs sometimes forget requirements mid-conversation.

**Solution:**
- JSON requirement mentioned in system prompt
- JSON requirement repeated in initial message
- JSON sections listed in initial message
- "Extract ALL findings" emphasized multiple times

**Result:** Better adherence to requirements throughout analysis.

---

## 6. Prompt Customization

### How to Modify Prompts

**System Prompt:**
- **File:** `agent/analyze.py`
- **Method:** `_create_system_prompt()` (lines 82-219)
- **Modify:** Edit the return string

**Initial User Message:**
- **File:** `agent/analyze.py`
- **Method:** `analyze()` (lines 267-293)
- **Modify:** Edit the `initial_message` content

### Common Modifications

**Add new analysis tasks:**
```python
# In initial_message content, add to the list:
"Analyze this data and identify:
1. Malicious behaviors and indicators
2. Suspicious strings, API calls, and functions
3. Network communication patterns
4. [NEW] Cryptocurrency mining indicators  # Add here
5. File system operations
..."
```

**Modify JSON structure:**
```python
# In _create_system_prompt(), update the JSON structure:
{
  "executive_summary": {...},
  "technical_analysis": {...},
  "[NEW_SECTION]": {...},  # Add new section
  ...
}
```

**Change tool descriptions:**
```python
# In _create_system_prompt(), update tool descriptions:
"AVAILABLE TOOLS:
- read_section: [Updated description]
- [NEW_TOOL]: [Description]  # Add new tool
..."
```

**Note:** If adding new tools, also update:
- `agent/tools_schema.py` - Tool schema definition
- `agent/tool_dispatcher.py` - Tool execution logic

---

## 7. Prompt Testing

### How to Test Prompt Changes

1. **Modify prompts** in `agent/analyze.py`
2. **Run analysis** on a test sample:
   ```bash
   ./run.sh samples/test.elf
   ```
3. **Check output:**
   - Does LLM follow the workflow?
   - Does it use tools appropriately?
   - Does it produce valid JSON?
   - Are all required sections present?

### Common Issues

**LLM ignores JSON requirement:**
- Add more emphasis ("CRITICAL", "MUST")
- Provide complete JSON example
- List all required sections explicitly

**LLM doesn't use tools:**
- Emphasize tool usage in initial message
- Provide examples of when to use tools
- Check tool descriptions are clear

**LLM produces incomplete JSON:**
- Add more specific requirements
- List all required fields
- Emphasize "Never leave arrays empty"

**LLM makes redundant tool calls:**
- Add "avoid redundant queries" to tool strategy
- Emphasize efficiency in tool usage

---

## 8. Summary

### Prompt Files

| Prompt Type | File | Method | Lines |
|-------------|------|--------|-------|
| System Prompt | `agent/analyze.py` | `_create_system_prompt()` | 82-219 |
| Initial User Message | `agent/analyze.py` | `analyze()` | 267-293 |
| Tool Responses | `agent/analyze.py` | `analyze()` | 381-395 |

### Key Points

1. **System Prompt** defines role, workflow, tools, and JSON structure
2. **Initial User Message** provides actual data and task instructions
3. **Tool Messages** return execution results to LLM
4. **Iterative Loop** allows LLM to request tools and continue reasoning
5. **Multiple Reminders** ensure LLM follows requirements
6. **JSON Emphasis** ensures structured output

### Prompt Flow

```
System Prompt (static) → Initial User Message (dynamic data) → 
Iterative Loop (LLM ↔ Tools) → Final JSON Analysis
```

---

*For code implementation details, see `explication.md`*

