"""
Agent package for LLM-powered malware analysis.
"""

# Lazy imports to avoid requiring openai at package import time
# Import only tools_schema which doesn't require external dependencies
from .tools_schema import get_tools_schema

__all__ = [
    "MalwareAnalyzer",
    "analyze_sample",
    "OpenRouterClient",
    "ToolDispatcher",
    "ReportGenerator",
    "generate_reports",
    "get_tools_schema",
]

# Lazy imports - these will be imported when needed
def __getattr__(name):
    if name == "MalwareAnalyzer" or name == "analyze_sample":
        from .analyze import MalwareAnalyzer, analyze_sample
        return MalwareAnalyzer if name == "MalwareAnalyzer" else analyze_sample
    elif name == "OpenRouterClient":
        from .openrouter_client import OpenRouterClient
        return OpenRouterClient
    elif name == "ToolDispatcher":
        from .tool_dispatcher import ToolDispatcher
        return ToolDispatcher
    elif name == "ReportGenerator" or name == "generate_reports":
        from .report_generator import ReportGenerator, generate_reports
        return ReportGenerator if name == "ReportGenerator" else generate_reports
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

