"""
Report Generator for malware analysis results.
Generates structured JSON reports matching professional malware analysis format.
"""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List


class ReportGenerator:
    """Generate structured malware analysis reports in JSON format."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory to save reports (default: reports/ at project root)
        """
        if output_dir is None:
            project_root = Path(__file__).resolve().parent.parent
            self.output_dir = project_root / "reports"
        else:
            self.output_dir = Path(output_dir)
        
        self.output_dir.mkdir(exist_ok=True, parents=True)
    
    def generate_report(
        self,
        sample_path: Path,
        analysis_results: Dict[str, Any],
        extractor_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Path]:
        """
        Generate structured JSON report.
        
        Args:
            sample_path: Path to the analyzed sample
            analysis_results: Results from MalwareAnalyzer.analyze()
            extractor_info: Optional info from StaticExtractor (architecture, etc.)
        
        Returns:
            Dict with 'json' and 'markdown' keys pointing to report file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sample_name = sample_path.stem
        
        # Parse LLM analysis and extract structured data
        structured_report = self._parse_and_structure_analysis(
            sample_path, analysis_results, extractor_info, timestamp
        )
        
        # Generate JSON report
        json_path = self.output_dir / f"{sample_name}_{timestamp}.json"
        self._generate_json_report(structured_report, json_path)
        
        # Generate Markdown report (simplified)
        md_path = self.output_dir / f"{sample_name}_{timestamp}.md"
        self._generate_markdown_report(structured_report, md_path)
        
        return {
            "json": json_path,
            "markdown": md_path
        }
    
    def _parse_and_structure_analysis(
        self,
        sample_path: Path,
        analysis_results: Dict[str, Any],
        extractor_info: Optional[Dict[str, Any]],
        timestamp: str
    ) -> Dict[str, Any]:
        """Parse LLM analysis and structure into professional JSON format."""
        analysis_text = analysis_results.get("analysis", "")
        tool_results = analysis_results.get("tool_results", [])
        tool_log = analysis_results.get("tool_log", [])
        conversation_history = analysis_results.get("conversation_history", [])
        
        print(f"[DEBUG] Analysis text length: {len(analysis_text)}")
        if analysis_text:
            print(f"[DEBUG] Analysis text preview: {analysis_text[:300]}...")
        
        # Try to extract JSON from LLM response
        json_data = self._extract_json_from_text(analysis_text)
        
        # If not found, try searching in conversation history for complete JSON
        if not json_data and conversation_history:
            print(f"[DEBUG] Searching conversation history for JSON...")
            # Combine all assistant messages that might contain JSON
            combined_content = ""
            for msg in reversed(conversation_history):
                if msg.get("role") == "assistant" and msg.get("content"):
                    content = msg["content"]
                    if "{" in content:
                        # Prepend to combine (most recent first)
                        combined_content = content + "\n" + combined_content
                        # Try extracting from this message first
                        json_data = self._extract_json_from_text(content)
                        if json_data:
                            print(f"[+] Found JSON in conversation history")
                            break
            
            # If still not found, try combined content
            if not json_data and combined_content:
                print(f"[DEBUG] Trying combined content from conversation history (length: {len(combined_content)})...")
                json_data = self._extract_json_from_text(combined_content)
                if json_data:
                    print(f"[+] Found JSON in combined conversation history")
        
        # If JSON found, use it; otherwise parse from text
        if json_data:
            print(f"[+] Successfully extracted JSON from LLM response")
            print(f"[DEBUG] JSON keys: {list(json_data.keys())}")
            structured = json_data
        else:
            print(f"[WARNING] Could not extract JSON, falling back to text parsing")
            structured = self._parse_text_analysis(analysis_text, tool_results)
        
        # Enhance with extractor info
        if extractor_info:
            if "technical_analysis" not in structured:
                structured["technical_analysis"] = {}
            if "binary_properties" not in structured["technical_analysis"]:
                structured["technical_analysis"]["binary_properties"] = {}
            
            bp = structured["technical_analysis"]["binary_properties"]
            if extractor_info.get("architecture"):
                bp["architecture"] = extractor_info["architecture"]
        
        # Add metadata
        structured["report_metadata"] = {
            "sample_path": str(sample_path),
            "sample_name": sample_path.name,
            "analysis_timestamp": timestamp,
            "analysis_date": datetime.now().isoformat(),
            "analysis_methodology": "Static analysis with LLM-powered iterative reasoning",
            "tool_usage": {
                "total_tools_used": len(tool_log),
                "tools_used": [log.get("tool") for log in tool_log if log.get("tool")],
                "tool_log": tool_log
            }
        }
        
        # Ensure all required sections exist with proper structure
        structured = self._ensure_complete_structure(structured, tool_results)
        
        return structured
    
    def _extract_json_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON object from text response."""
        if not text:
            return None
        
        # Try code block first (most common format)
        # Find the code block boundaries, then extract balanced JSON inside
        code_block_match = re.search(r'```json\s*(\{[\s\S]*?)\s*```', text, re.DOTALL)
        if code_block_match:
            json_content = code_block_match.group(1)
            # Extract balanced JSON from the content
            json_data = self._extract_balanced_json(json_content)
            if json_data:
                return json_data
        
        # Try code block without json marker
        code_block_match = re.search(r'```\s*(\{[\s\S]*?)\s*```', text, re.DOTALL)
        if code_block_match:
            json_content = code_block_match.group(1)
            json_data = self._extract_balanced_json(json_content)
            if json_data:
                return json_data
        
        # Try to find JSON object - match balanced braces
        json_data = self._extract_balanced_json(text)
        if json_data:
            return json_data
        
        # Last resort: try simple regex (might be incomplete)
        json_match = re.search(r'\{[\s\S]{100,}\}', text)  # At least 100 chars
        if json_match:
            try:
                json_str = json_match.group(0)
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"[DEBUG] Failed to parse JSON (simple regex): {e}")
        
        print(f"[DEBUG] No valid JSON found in text (length: {len(text)})")
        if len(text) > 200:
            print(f"[DEBUG] Text preview: {text[:200]}...")
        
        return None
    
    def _extract_balanced_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON with properly balanced braces."""
        brace_count = 0
        start_idx = text.find('{')
        if start_idx == -1:
            return None
        
        # Track string state to ignore braces inside strings
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
                        try:
                            return json.loads(json_str)
                        except json.JSONDecodeError as e:
                            print(f"[DEBUG] Failed to parse balanced JSON: {e}")
                            # Try to find next complete JSON object
                            start_idx = text.find('{', i+1)
                            if start_idx == -1:
                                break
                            brace_count = 0
                            in_string = False
                            escape_next = False
                            continue
        
        return None
    
    def _parse_text_analysis(self, text: str, tool_results: List[Dict]) -> Dict[str, Any]:
        """Parse unstructured text analysis into structured format."""
        structured = {
            "executive_summary": self._parse_executive_summary(text),
            "technical_analysis": self._parse_technical_analysis(text, tool_results),
            "indicators_of_compromise": self._parse_iocs(text, tool_results),
            "threat_intelligence": self._parse_threat_intelligence(text),
            "tool_usage_analysis": self._parse_tool_usage(tool_results),
            "recommendations": self._parse_recommendations(text),
            "metadata": self._parse_metadata(text)
        }
        return structured
    
    def _parse_executive_summary(self, text: str) -> Dict[str, Any]:
        """Parse executive summary from text."""
        summary = {
            "classification": "Unknown",
            "key_capabilities": [],
            "risk_level": "Medium",
            "risk_score": 50,
            "primary_evasion_techniques": []
        }
        
        # Extract classification
        for classification in ["DDoS bot", "Backdoor", "Downloader", "Trojan", "Worm", "Ransomware"]:
            if classification.lower() in text.lower():
                summary["classification"] = classification
                break
        
        # Extract risk level
        risk_match = re.search(r'risk[:\s]+(low|medium|high|critical)', text.lower())
        if risk_match:
            summary["risk_level"] = risk_match.group(1).capitalize()
        
        # Extract risk score
        score_match = re.search(r'risk[:\s]+(\d+)', text.lower())
        if score_match:
            summary["risk_score"] = int(score_match.group(1))
        else:
            # Map risk level to score
            risk_scores = {"Low": 25, "Medium": 50, "High": 75, "Critical": 95}
            summary["risk_score"] = risk_scores.get(summary["risk_level"], 50)
        
        return summary
    
    def _parse_technical_analysis(self, text: str, tool_results: List[Dict]) -> Dict[str, Any]:
        """Parse technical analysis section."""
        analysis = {
            "binary_properties": {
                "architecture": "unknown",
                "linking": "unknown",
                "imports": [],
                "packing_indicators": []
            },
            "malicious_behaviors": [],
            "network_capabilities": {
                "c2_communication": [],
                "scanning": [],
                "attack_vectors": []
            },
            "persistence_evasion": {
                "persistence_techniques": [],
                "evasion_techniques": []
            },
            "anti_analysis": []
        }
        
        # Extract from tool results
        for tool_result in tool_results:
            tool_name = tool_result.get("tool", "")
            result = tool_result.get("result", {})
            
            if tool_name == "get_imports" and result.get("success"):
                imports = result.get("result", [])
                if isinstance(imports, list):
                    analysis["binary_properties"]["imports"] = [
                        imp.get("function", "") if isinstance(imp, dict) else str(imp)
                        for imp in imports[:20]
                    ]
        
        return analysis
    
    def _parse_iocs(self, text: str, tool_results: List[Dict]) -> Dict[str, Any]:
        """Parse indicators of compromise."""
        iocs = {
            "network_iocs": {
                "ips": [],
                "domains": [],
                "urls": []
            },
            "host_based_iocs": {
                "file_paths": [],
                "process_names": [],
                "registry_keys": []
            },
            "behavioral_iocs": {
                "api_calls": [],
                "system_modifications": []
            },
            "yara_rules": []
        }
        
        # Extract from tool results
        for tool_result in tool_results:
            tool_name = tool_result.get("tool", "")
            result = tool_result.get("result", {})
            
            if tool_name == "search_strings" and result.get("success"):
                strings = result.get("result", [])
                if isinstance(strings, list):
                    for s in strings:
                        s_str = str(s).strip()
                        # Extract IPs
                        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s_str)
                        if ip_match:
                            iocs["network_iocs"]["ips"].append(ip_match.group(0))
                        
                        # Extract URLs
                        url_match = re.search(r'https?://[^\s]+', s_str)
                        if url_match:
                            iocs["network_iocs"]["urls"].append(url_match.group(0))
                        
                        # Extract domains
                        domain_match = re.search(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b', s_str)
                        if domain_match:
                            iocs["network_iocs"]["domains"].append(domain_match.group(0))
        
        # Deduplicate
        for category in iocs.values():
            if isinstance(category, dict):
                for key, value in category.items():
                    if isinstance(value, list):
                        category[key] = list(dict.fromkeys(value))  # Preserve order
        
        return iocs
    
    def _parse_threat_intelligence(self, text: str) -> Dict[str, Any]:
        """Parse threat intelligence section."""
        return {
            "threat_actor_affiliation": None,
            "campaign_associations": [],
            "mitre_attack_techniques": []
        }
    
    def _parse_tool_usage(self, tool_results: List[Dict]) -> Dict[str, Any]:
        """Parse tool usage analysis."""
        tools_used = list(set([tr.get("tool", "") for tr in tool_results if tr.get("tool")]))
        return {
            "tools_used": tools_used,
            "investigation_strategy": "Iterative analysis with tool-based deep inspection",
            "key_findings_from_tools": []
        }
    
    def _parse_recommendations(self, text: str) -> Dict[str, Any]:
        """Parse recommendations section."""
        return {
            "detection": [],
            "mitigation": [],
            "further_analysis": []
        }
    
    def _parse_metadata(self, text: str) -> Dict[str, Any]:
        """Parse metadata section."""
        return {
            "analysis_methodology": "Static analysis with LLM-powered iterative reasoning",
            "confidence_levels": {
                "overall_confidence": "Medium",
                "key_findings_confidence": "Medium"
            },
            "hex_patterns": [],
            "opcodes": []
        }
    
    def _ensure_complete_structure(self, structured: Dict[str, Any], tool_results: List[Dict]) -> Dict[str, Any]:
        """Ensure all required sections exist with proper defaults."""
        # Ensure executive_summary
        if "executive_summary" not in structured:
            structured["executive_summary"] = {
                "classification": "Unknown",
                "key_capabilities": [],
                "risk_level": "Medium",
                "risk_score": 50,
                "primary_evasion_techniques": []
            }
        
        # Ensure technical_analysis
        if "technical_analysis" not in structured:
            structured["technical_analysis"] = {}
        
        ta = structured["technical_analysis"]
        if "binary_properties" not in ta:
            ta["binary_properties"] = {"architecture": "unknown", "linking": "unknown", "imports": [], "packing_indicators": []}
        if "malicious_behaviors" not in ta:
            ta["malicious_behaviors"] = []
        if "network_capabilities" not in ta:
            ta["network_capabilities"] = {"c2_communication": [], "scanning": [], "attack_vectors": []}
        if "persistence_evasion" not in ta:
            ta["persistence_evasion"] = {"persistence_techniques": [], "evasion_techniques": []}
        if "anti_analysis" not in ta:
            ta["anti_analysis"] = []
        
        # Ensure indicators_of_compromise
        if "indicators_of_compromise" not in structured:
            structured["indicators_of_compromise"] = {
                "network_iocs": {"ips": [], "domains": [], "urls": []},
                "host_based_iocs": {"file_paths": [], "process_names": [], "registry_keys": []},
                "behavioral_iocs": {"api_calls": [], "system_modifications": []},
                "yara_rules": []
            }
        
        # Ensure threat_intelligence
        if "threat_intelligence" not in structured:
            structured["threat_intelligence"] = {
                "threat_actor_affiliation": None,
                "campaign_associations": [],
                "mitre_attack_techniques": []
            }
        
        # Ensure tool_usage_analysis
        if "tool_usage_analysis" not in structured:
            structured["tool_usage_analysis"] = {
                "tools_used": [],
                "investigation_strategy": "",
                "key_findings_from_tools": []
            }
        
        # Ensure recommendations
        if "recommendations" not in structured:
            structured["recommendations"] = {
                "detection": [],
                "mitigation": [],
                "further_analysis": []
            }
        
        # Ensure metadata
        if "metadata" not in structured:
            structured["metadata"] = {
                "analysis_methodology": "Static analysis with LLM-powered iterative reasoning",
                "confidence_levels": {"overall_confidence": "Medium", "key_findings_confidence": "Medium"},
                "hex_patterns": [],
                "opcodes": []
            }
        
        return structured
    
    def _generate_json_report(self, report_data: Dict[str, Any], output_path: Path):
        """Generate structured JSON report."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved: {output_path}")
    
    def _generate_markdown_report(self, report_data: Dict[str, Any], output_path: Path):
        """Generate simplified Markdown report."""
        md_lines = []
        
        # Header
        md_lines.append("# Malware Analysis Report")
        md_lines.append("")
        if "report_metadata" in report_data:
            md_lines.append(f"**Sample:** `{report_data['report_metadata'].get('sample_name', 'unknown')}`")
            md_lines.append(f"**Analysis Date:** {report_data['report_metadata'].get('analysis_date', 'unknown')}")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")
        
        # Executive Summary
        if "executive_summary" in report_data:
            es = report_data["executive_summary"]
            md_lines.append("## Executive Summary")
            md_lines.append("")
            md_lines.append(f"- **Classification:** {es.get('classification', 'Unknown')}")
            md_lines.append(f"- **Risk Level:** {es.get('risk_level', 'Unknown')} (Score: {es.get('risk_score', 0)})")
            md_lines.append("")
        
        # Technical Analysis
        if "technical_analysis" in report_data:
            ta = report_data["technical_analysis"]
            md_lines.append("## Technical Analysis")
            md_lines.append("")
            if "binary_properties" in ta:
                bp = ta["binary_properties"]
                md_lines.append(f"- **Architecture:** {bp.get('architecture', 'unknown')}")
            md_lines.append("")
        
        # IOCs
        if "indicators_of_compromise" in report_data:
            iocs = report_data["indicators_of_compromise"]
            md_lines.append("## Indicators of Compromise")
            md_lines.append("")
            if "network_iocs" in iocs:
                ni = iocs["network_iocs"]
                if ni.get("ips"):
                    md_lines.append(f"- **IPs:** {', '.join(ni['ips'][:10])}")
                if ni.get("domains"):
                    md_lines.append(f"- **Domains:** {', '.join(ni['domains'][:10])}")
            md_lines.append("")
        
        # Footer
        md_lines.append("---")
        md_lines.append("")
        md_lines.append("*Full structured JSON report available in the corresponding .json file*")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(md_lines))
        print(f"[+] Markdown report saved: {output_path}")


def generate_reports(
    sample_path: Path,
    analysis_results: Dict[str, Any],
    extractor_info: Optional[Dict[str, Any]] = None,
    output_dir: Optional[Path] = None
) -> Dict[str, Path]:
    """
    Generate structured malware analysis reports.
    
    Args:
        sample_path: Path to analyzed sample
        analysis_results: Results from analyzer
        extractor_info: Optional extractor metadata
        output_dir: Optional output directory
    
    Returns:
        Dict with paths to generated reports
    """
    generator = ReportGenerator(output_dir=output_dir)
    return generator.generate_report(sample_path, analysis_results, extractor_info)
