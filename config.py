"""
Configuration management for Malware Detector.
Supports environment variables and default values.
"""

import os
from pathlib import Path
from typing import Optional

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, continue without it


class Config:
    """Configuration settings for the malware detector."""
    
    # OpenRouter API settings
    # Default API key (fallback if not in environment)
    DEFAULT_API_KEY = "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"
    OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY") or DEFAULT_API_KEY
    OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free")
    
    # Directories
    PROJECT_ROOT: Path = Path(__file__).parent
    ANALYSIS_DIR: Path = PROJECT_ROOT / "analysis"
    REPORTS_DIR: Path = PROJECT_ROOT / "reports"
    SAMPLES_DIR: Path = PROJECT_ROOT / "samples"
    
    # Analysis settings
    MAX_ANALYSIS_ITERATIONS: int = int(os.getenv("MAX_ANALYSIS_ITERATIONS", "20"))
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.7"))
    LLM_MAX_TOKENS: int = int(os.getenv("LLM_MAX_TOKENS", "2000"))
    
    # Tool settings
    TOOL_RESULT_MAX_LENGTH: int = int(os.getenv("TOOL_RESULT_MAX_LENGTH", "3000"))
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration."""
        errors = []
        
        if not cls.OPENROUTER_API_KEY:
            errors.append("OPENROUTER_API_KEY not set (optional, but required for LLM analysis)")
        
        # Create directories if they don't exist
        cls.ANALYSIS_DIR.mkdir(exist_ok=True, parents=True)
        cls.REPORTS_DIR.mkdir(exist_ok=True, parents=True)
        cls.SAMPLES_DIR.mkdir(exist_ok=True, parents=True)
        
        if errors:
            print("[WARNING] Configuration issues:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True
    
    @classmethod
    def get_info(cls) -> dict:
        """Get configuration information."""
        return {
            "model": cls.OPENROUTER_MODEL,
            "api_key_set": cls.OPENROUTER_API_KEY is not None,
            "analysis_dir": str(cls.ANALYSIS_DIR),
            "reports_dir": str(cls.REPORTS_DIR),
            "max_iterations": cls.MAX_ANALYSIS_ITERATIONS
        }

