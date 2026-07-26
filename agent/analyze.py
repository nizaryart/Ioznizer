"""
Main Analysis Agent for malware analysis using LLM.
Implements iterative reasoning with tool-based deep inspection.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# Try relative imports first, fallback to absolute
try:
    from .openrouter_client import OpenRouterClient
    from .tool_dispatcher import ToolDispatcher
    from .tools_schema import get_tools_schema
except ImportError:
    # Fallback for direct execution
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from agent.openrouter_client import OpenRouterClient
    from agent.tool_dispatcher import ToolDispatcher
    from agent.tools_schema import get_tools_schema


class MalwareAnalyzer:
    """Main agent for analyzing malware samples using LLM."""
    
    def __init__(self, analysis_dir: Path, api_key: Optional[str] = None, 
                 model: str = "openai/gpt-oss-120b:free"):
        """
        Initialize the malware analyzer.
        
        Args:
            analysis_dir: Path to analysis directory with extracted files
            api_key: OpenRouter API key (optional, uses env var if not provided)
            model: Model identifier
        """
        self.analysis_dir = Path(analysis_dir)
        self.client = OpenRouterClient(api_key=api_key, model=model)
        self.dispatcher = ToolDispatcher(self.analysis_dir)
        self.tools_schema = get_tools_schema()
        
        # Conversation history
        self.conversation_history: List[Dict[str, str]] = []
        self.tool_results: List[Dict[str, Any]] = []
        
        # Load analysis files content (will be sent to LLM)
        self.analysis_content = self._load_analysis_files()
    
    def _load_analysis_files(self, max_chars_per_file: int = 10000) -> str:
        """
        Load actual analysis file contents for initial context.
        Sends the actual file contents, not just summaries.
        """
        files_to_load = {
            "metadata": "metadata.txt",
            "strings": "strings.txt",
            "symbols": "symbols.txt",
            "disasm": "disasm.txt",
            "decomp": "decomp.txt"
        }
        
        analysis_content = []
        
        for name, filename in files_to_load.items():
            file_path = self.analysis_dir / filename
            if file_path.exists():
                try:
                    content = file_path.read_text()
                    # Truncate if too long, but keep it substantial
                    if len(content) > max_chars_per_file:
                        content = content[:max_chars_per_file] + f"\n... (truncated, total length: {len(file_path.read_text())} chars)"
                    
                    analysis_content.append(f"=== {name.upper()} ({filename}) ===\n{content}\n")
                except Exception as e:
                    analysis_content.append(f"=== {name.upper()} ({filename}) ===\n[ERROR reading file: {e}]\n")
        
        if not analysis_content:
            return "No analysis files found."
        
        return "\n".join(analysis_content)
    
    def _create_system_prompt(self) -> str:
        """Create the system prompt for malware analysis."""
        return """You are a professional malware analysis assistant with expertise in ELF binary analysis and threat intelligence reporting.

CRITICAL REQUIREMENT: Your final analysis MUST be provided as a valid JSON object matching the exact structure specified below.

WORKFLOW:
1. You will receive initial static analysis data (metadata, strings, symbols, disassembly, etc.)
2. Analyze this data to identify suspicious patterns
3. If you need more detailed information, use the available tools to query specific sections
4. Continue iterating: analyze → use tools if needed → analyze results → repeat until complete
5. When you have a comprehensive understanding, provide your final analysis as structured JSON

AVAILABLE TOOLS (use when you need more information):
- list_functions: List functions recovered by the decompiler, with addresses
- decompile_function: Get decompiled pseudo-C for one function (most informative tool)
- read_section: Read specific sections from analysis files (metadata, strings, symbols, disasm, decomp)
- disassemble_address: Get raw disassembly for specific addresses or functions
- search_strings: Search for suspicious strings or patterns
- analyze_symbol: Get detailed information about symbols
- get_imports: List imported functions and libraries
- get_exports: List exported functions

TOOL USAGE STRATEGY:
- Work like a reverse engineer: find a lead, then read the code behind it
- Prefer decompile_function over disassemble_address. Pseudo-C already resolves
  library calls, control flow and string references, so it yields far more
  reliable conclusions than reading raw instructions
- A typical investigation: search_strings finds a suspicious literal ->
  list_functions or the disassembly locates the function referencing it ->
  decompile_function reveals what that function actually does
- Stripped binaries have synthetic names such as FUN_0804a330; this is normal,
  and you should still decompile them
- Cite concrete evidence (function name, address) for every behaviour you report
- Use tools efficiently - avoid redundant queries
- Extract ALL key findings from tool results into structured fields
- Never leave arrays empty when findings are confirmed

FINAL OUTPUT FORMAT:
When you have completed your analysis, you MUST provide a valid JSON object with this exact structure:

{
  "executive_summary": {
    "classification": "string (e.g., DDoS bot, Backdoor, Downloader)",
    "key_capabilities": ["capability1", "capability2", "capability3"],
    "risk_level": "Low|Medium|High|Critical",
    "risk_score": 1-100,
    "primary_evasion_techniques": ["technique1", "technique2"]
  },
  "technical_analysis": {
    "binary_properties": {
      "architecture": "string",
      "linking": "static|dynamic",
      "imports": ["import1", "import2"],
      "packing_indicators": ["indicator1", "indicator2"]
    },
    "malicious_behaviors": [
      {
        "behavior_type": "string",
        "evidence_location": "string (address/function name)",
        "confidence_level": "High|Medium|Low",
        "description": "string"
      }
    ],
    "network_capabilities": {
      "c2_communication": ["C2 indicator1", "C2 indicator2"],
      "scanning": ["scanning indicator"],
      "attack_vectors": ["vector1", "vector2"]
    },
    "persistence_evasion": {
      "persistence_techniques": ["technique1"],
      "evasion_techniques": ["technique1"]
    },
    "anti_analysis": ["feature1", "feature2"]
  },
  "indicators_of_compromise": {
    "network_iocs": {
      "ips": ["ip1", "ip2"],
      "domains": ["domain1"],
      "urls": ["url1"]
    },
    "host_based_iocs": {
      "file_paths": ["path1"],
      "process_names": ["process1"],
      "registry_keys": []
    },
    "behavioral_iocs": {
      "api_calls": ["api1", "api2"],
      "system_modifications": ["modification1"]
    },
    "yara_rules": [
      {
        "rule_name": "string",
        "rule_snippet": "string (YARA rule text)"
      }
    ]
  },
  "threat_intelligence": {
    "threat_actor_affiliation": "string or null",
    "campaign_associations": ["campaign1"],
    "mitre_attack_techniques": [
      {
        "technique_id": "T1234",
        "technique_name": "string",
        "description": "string"
      }
    ]
  },
  "tool_usage_analysis": {
    "tools_used": ["tool1", "tool2"],
    "investigation_strategy": "string",
    "key_findings_from_tools": ["finding1", "finding2"]
  },
  "recommendations": {
    "detection": ["recommendation1", "recommendation2"],
    "mitigation": ["step1", "step2"],
    "further_analysis": ["suggestion1"]
  },
  "metadata": {
    "analysis_methodology": "string",
    "confidence_levels": {
      "overall_confidence": "High|Medium|Low",
      "key_findings_confidence": "High|Medium|Low"
    },
    "hex_patterns": ["pattern1", "pattern2"],
    "opcodes": ["opcode1"]
  }
}

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
    
    @staticmethod
    def _is_report_json(text: str) -> bool:
        """
        Decide whether a response is the final report.

        A response counts only if it parses as JSON and carries the report's
        top-level keys. Testing for length or for the presence of a keyword
        accepts intermediate commentary, which ends the run with nothing to
        report.
        """
        start = text.find("{")
        if start == -1:
            return False

        depth = 0
        in_string = False
        escape = False

        for i in range(start, len(text)):
            char = text[i]

            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue

            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        # strict=False for the same reason as the report
                        # generator: models emit literal newlines in strings.
                        parsed = json.loads(text[start:i + 1], strict=False)
                    except json.JSONDecodeError:
                        return False
                    return (
                        isinstance(parsed, dict)
                        and "executive_summary" in parsed
                    )

        return False

    def _chunk_content(self, content: str, max_length: int = 5000) -> List[str]:
        """Chunk large content into smaller pieces."""
        if len(content) <= max_length:
            return [content]
        
        chunks = []
        lines = content.split('\n')
        current_chunk = []
        current_length = 0
        
        for line in lines:
            line_length = len(line) + 1  # +1 for newline
            if current_length + line_length > max_length and current_chunk:
                chunks.append('\n'.join(current_chunk))
                current_chunk = [line]
                current_length = line_length
            else:
                current_chunk.append(line)
                current_length += line_length
        
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks
    
    def analyze(self, max_iterations: int = 20) -> Dict[str, Any]:
        """
        Perform iterative malware analysis.
        
        Args:
            max_iterations: Maximum number of LLM interaction iterations
        
        Returns:
            Dict with analysis results, findings, and tool usage log
        """
        print("[+] Starting LLM analysis...")
        print(f"[+] Analysis directory: {self.analysis_dir}")
        print(f"[+] Model: {self.client.model}")
        print()
        
        # Initialize conversation
        system_message = {
            "role": "system",
            "content": self._create_system_prompt()
        }
        
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
        
        self.conversation_history = [system_message, initial_message]
        
        iteration = 0
        final_analysis = None

        # Convergence tracking. Without these the agent can spend every
        # iteration on tool calls and never be asked for its verdict, which
        # yields a run that did useful investigation but reported nothing.
        consecutive_empty = 0
        seen_tool_calls = set()
        forced_final = False

        while iteration < max_iterations:
            iteration += 1

            # Reserve the last iterations for the answer itself: withdraw the
            # tools and require the JSON verdict. Also triggered when the model
            # stalls, returning neither content nor tool calls.
            force_final = (
                iteration >= max_iterations - 1
                or consecutive_empty >= 3
            )

            if force_final and not forced_final:
                forced_final = True
                self.conversation_history.append({
                    "role": "user",
                    "content": (
                        "Stop investigating and report now. Output ONLY the final "
                        "JSON object described in the system prompt, populated from "
                        "everything you have already found. No tool calls, no prose, "
                        "no markdown fences. Begin your response with '{'."
                    )
                })
                print(f"[ITERATION {iteration}] Requesting final report (tools withdrawn)...")
            else:
                print(f"[ITERATION {iteration}] Sending request to LLM...")

            try:
                # Get LLM response
                print(f"[DEBUG] Sending {len(self.conversation_history)} messages to LLM...")
                response = self.client.chat_completion(
                    messages=self.conversation_history,
                    tools=None if force_final else self.tools_schema,
                    tool_choice=None if force_final else "auto",
                    temperature=0.7,
                    max_tokens=4000  # Increased for complete JSON reports
                )
                
                if not response.get("choices"):
                    print("[ERROR] No response from LLM")
                    break
                
                choice = response["choices"][0]
                message = choice["message"]
                
                # Debug output
                content_len = len(message.get("content") or "")
                tool_calls = message.get('tool_calls', [])
                has_reasoning = "reasoning_details" in message
                print(f"[DEBUG] Response details:")
                print(f"  - Content length: {content_len}")
                print(f"  - Tool calls: {len(tool_calls) if tool_calls else 0}")
                print(f"  - Has reasoning_details: {has_reasoning}")
                if content_len > 0:
                    preview_text = (message.get("content") or "")[:100]
                    print(f"  - Content preview: {preview_text}...")
                
                # Add assistant message to history (preserve reasoning_details as per OpenRouter example)
                assistant_msg = {
                    "role": "assistant",
                    "content": message.get("content") or "",
                }
                
                # Preserve reasoning_details if present (as per OpenRouter official example)
                if "reasoning_details" in message:
                    assistant_msg["reasoning_details"] = message["reasoning_details"]
                    print(f"[DEBUG] Preserved reasoning_details in conversation history")
                
                # Handle tool calls
                tool_calls = message.get("tool_calls", [])
                
                if tool_calls:
                    consecutive_empty = 0
                    print(f"[+] LLM requested {len(tool_calls)} tool(s) - executing...")
                    tool_messages = []

                    for tool_call in tool_calls:
                        tool_id = tool_call["id"]
                        tool_name = tool_call["function"]["name"]
                        tool_args_str = tool_call["function"]["arguments"]
                        
                        try:
                            tool_args = json.loads(tool_args_str)
                        except json.JSONDecodeError:
                            tool_args = {}
                        
                        print(f"  [TOOL] {tool_name}({tool_args})")
                        
                        # Execute tool
                        try:
                            tool_result = self.dispatcher.execute_tool(tool_name, tool_args)
                        except Exception as e:
                            print(f"  [ERROR] Tool execution failed: {e}")
                            import traceback
                            traceback.print_exc()
                            tool_result = {
                                "success": False,
                                "error": str(e),
                                "result": None
                            }
                        self.tool_results.append({
                            "tool": tool_name,
                            "arguments": tool_args,
                            "result": tool_result
                        })
                        
                        # Format tool result for LLM
                        if tool_result.get("success"):
                            result_content = str(tool_result.get("result", ""))
                            # Truncate very long results
                            if len(result_content) > 5000:
                                result_content = result_content[:5000] + "\n... (truncated, use read_section for full content)"
                            tool_response = f"Tool {tool_name} executed successfully:\n{result_content}"
                        else:
                            tool_response = f"Tool {tool_name} failed: {tool_result.get('error', 'Unknown error')}"

                        # Repeated identical calls are the main way runs burn
                        # their iteration budget without gaining information.
                        signature = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
                        if signature in seen_tool_calls:
                            tool_response = (
                                "NOTE: you have already made this exact call and "
                                "received this result. Do not repeat it. Move on to a "
                                "different question or produce your final JSON report.\n\n"
                                + tool_response
                            )
                        seen_tool_calls.add(signature)

                        tool_messages.append({
                            "role": "tool",
                            "tool_call_id": tool_id,
                            "content": tool_response
                        })
                        print(f"  [✓] Tool {tool_name} completed")
                    
                    # Add assistant message with tool calls (preserve reasoning_details)
                    if "reasoning_details" in assistant_msg:
                        # Keep reasoning_details when adding tool calls
                        pass
                    assistant_msg["tool_calls"] = [
                        {
                            "id": tc["id"],
                            "type": tc["type"],
                            "function": {
                                "name": tc["function"]["name"],
                                "arguments": tc["function"]["arguments"]
                            }
                        }
                        for tc in tool_calls
                    ]
                    
                    self.conversation_history.append(assistant_msg)
                    
                    # Add tool results - LLM will continue reasoning with these results
                    self.conversation_history.extend(tool_messages)
                    print(f"[+] Tool results sent to LLM, waiting for continued analysis...")
                    # Continue loop to get LLM's response to tool results
                    
                else:
                    # No tool calls - this might be the final analysis
                    self.conversation_history.append(assistant_msg)
                    
                    content = message.get("content") or ""
                    if content:
                        consecutive_empty = 0
                        print("[+] LLM provided analysis:")
                        preview = content[:500] + "..." if len(content) > 500 else content
                        print(preview)
                        print()

                        # Acceptance requires a parseable report, not merely a
                        # long reply. Length alone previously let intermediate
                        # prose end the run, producing an empty report.
                        if self._is_report_json(content):
                            final_analysis = content
                            print("[+] Final report received (valid JSON).")
                            break

                        if forced_final:
                            # The model was explicitly asked for the report and
                            # this is what it gave. Keep it so the raw response
                            # survives into the report for a human to read.
                            final_analysis = content
                            print("[WARNING] Final response was not valid JSON; keeping raw text.")
                            break

                        print("[+] Response is not a complete report yet, continuing...")
                    else:
                        consecutive_empty += 1
                        print(f"[WARNING] Empty response from LLM "
                              f"({consecutive_empty} in a row)")
                
                # Termination is decided above, by whether a parseable report was
                # produced. Length-based heuristics previously accepted any long
                # reply as final and ended runs before the report existed.

            except ValueError as e:
                # User-friendly configuration errors
                error_msg = str(e)
                print(f"\n[ERROR] Configuration Issue:")
                print(f"  {error_msg}")
                print("\n[INFO] The analysis will continue with extraction-only results.")
                print("[INFO] Fix the configuration issue and re-run to get LLM analysis.\n")
                break
            except Exception as e:
                error_msg = str(e)
                # Check if it's a data policy error
                if "data policy" in error_msg.lower() or "privacy" in error_msg.lower():
                    print(f"\n[ERROR] OpenRouter Configuration Required:")
                    print(f"  {error_msg}")
                    print("\n[INFO] Please visit https://openrouter.ai/settings/privacy")
                    print("[INFO] Configure your privacy/data policy settings for free models.")
                    print("[INFO] The analysis will continue with extraction-only results.\n")
                else:
                    print(f"[ERROR] Analysis iteration failed: {e}")
                    import traceback
                    traceback.print_exc()
                break
        
        if not final_analysis:
            # Extract last assistant message as final analysis
            for msg in reversed(self.conversation_history):
                if msg.get("role") == "assistant" and msg.get("content"):
                    content = msg["content"]
                    # Prefer messages with JSON structure
                    if "{" in content and "executive_summary" in content.lower():
                        final_analysis = content
                        break
                    elif not final_analysis:
                        final_analysis = content
        
        # Ensure we have the full analysis text
        if final_analysis:
            print(f"[DEBUG] Final analysis length: {len(final_analysis)}")
            if len(final_analysis) < 100:
                print(f"[WARNING] Final analysis seems too short, checking conversation history...")
                # Try to get longer content from conversation
                for msg in reversed(self.conversation_history):
                    if msg.get("role") == "assistant" and msg.get("content"):
                        content = msg["content"]
                        if len(content) > len(final_analysis):
                            final_analysis = content
        
        return {
            "analysis": final_analysis or "Analysis incomplete",
            "conversation_history": self.conversation_history,
            "tool_results": self.tool_results,
            "tool_log": self.dispatcher.get_tool_log(),
            "iterations": iteration
        }


def analyze_sample(analysis_dir: Path, api_key: Optional[str] = None,
                  model: str = "openai/gpt-oss-120b:free",
                  max_iterations: int = 20) -> Dict[str, Any]:
    """
    Analyze a malware sample.

    Args:
        analysis_dir: Path to analysis directory
        api_key: OpenRouter API key
        model: Model identifier
        max_iterations: Agent loop ceiling (MAX_ANALYSIS_ITERATIONS)

    Returns:
        Analysis results dict
    """
    analyzer = MalwareAnalyzer(analysis_dir, api_key=api_key, model=model)
    return analyzer.analyze(max_iterations=max_iterations)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <analysis_dir>")
        sys.exit(1)
    
    analysis_dir = Path(sys.argv[1])
    results = analyze_sample(analysis_dir)
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"Iterations: {results['iterations']}")
    print(f"Tools used: {len(results['tool_log'])}")
    print("\nFinal Analysis:")
    print(results['analysis'])

