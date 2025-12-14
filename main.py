#!/usr/bin/env python3
"""
Malware Detector by Code Analysis
Main entry point for the malware analysis system.

Workflow:
1. Static extraction (Backend Extractor)
2. LLM analysis (Agent with OpenRouter)
3. Report generation (JSON/Markdown)
"""

import sys
import os
from pathlib import Path

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, continue without it

# Add backend and agent to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent / "agent"))

from backend.extractor import StaticExtractor
from agent.analyze import analyze_sample
from agent.report_generator import generate_reports
from config import Config


def main():
    """Main entry point for malware analysis."""
    if len(sys.argv) < 2:
        print("Usage: ./the_project_executable /samples/malware.elf")
        print("   or: python3 main.py /samples/malware.elf")
        sys.exit(1)
    
    sample_path = Path(sys.argv[1])
    
    try:
        print("=" * 60)
        print("Malware Detector by Code Analysis")
        print("=" * 60)
        print()
        
        # Phase 1: Static Extraction
        print("[PHASE 1] Static Analysis Extraction")
        print("-" * 60)
        extractor = StaticExtractor(sample_path)
        extractor.run_all()
        
        # Collect extractor info for report
        extractor_info = {
            "architecture": extractor.architecture,
            "output_directory": str(extractor.out_dir)
        }
        print()
        
        # Phase 2: LLM Analysis
        print("[PHASE 2] LLM Analysis")
        print("-" * 60)
        
        # Get API key from config (has fallback default)
        api_key = Config.OPENROUTER_API_KEY
        model = Config.OPENROUTER_MODEL
        
        if not api_key:
            print("[WARNING] OPENROUTER_API_KEY not set. Skipping LLM analysis.")
            analysis_results = {
                "analysis": "LLM analysis skipped - API key not configured",
                "iterations": 0,
                "tool_log": [],
                "tool_results": [],
                "conversation_history": []
            }
        else:
            print(f"[+] Using API key: {api_key[:20]}...")
            print(f"[+] Model: {model}")
            try:
                analysis_results = analyze_sample(
                    extractor.out_dir,
                    api_key=api_key,
                    model=model
                )
            except ValueError as e:
                # Configuration errors (data policy, etc.)
                error_msg = str(e)
                print(f"\n[ERROR] OpenRouter Configuration Issue:")
                if "data policy" in error_msg.lower():
                    print("  OpenRouter requires privacy/data policy configuration.")
                    print("  Visit: https://openrouter.ai/settings/privacy")
                    print("  Enable 'Free model publication' or adjust your data policy settings.")
                else:
                    print(f"  {error_msg}")
                print("\n[INFO] Continuing with extraction-only analysis...\n")
                analysis_results = {
                    "analysis": f"LLM analysis skipped due to configuration issue.\n\nError: {error_msg}\n\nPlease configure OpenRouter privacy settings at https://openrouter.ai/settings/privacy",
                    "iterations": 0,
                    "tool_log": [],
                    "tool_results": [],
                    "conversation_history": []
                }
            except Exception as e:
                print(f"[ERROR] LLM analysis failed: {e}")
                import traceback
                traceback.print_exc()
                analysis_results = {
                    "analysis": f"LLM analysis failed: {str(e)}\n\nExtraction completed successfully. Review the analysis files in: {extractor.out_dir}",
                    "iterations": 0,
                    "tool_log": [],
                    "tool_results": [],
                    "conversation_history": []
                }
        print()
        
        # Phase 3: Report Generation
        print("[PHASE 3] Report Generation")
        print("-" * 60)
        try:
            report_paths = generate_reports(
                sample_path,
                analysis_results,
                extractor_info=extractor_info
            )
            print(f"[+] Reports generated:")
            print(f"    JSON: {report_paths['json']}")
            print(f"    Markdown: {report_paths['markdown']}")
        except Exception as e:
            print(f"[ERROR] Report generation failed: {e}")
            import traceback
            traceback.print_exc()
        print()
        
        print("=" * 60)
        print("Analysis pipeline complete")
        print("=" * 60)
        
    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Invalid file: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[ERROR] System error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
