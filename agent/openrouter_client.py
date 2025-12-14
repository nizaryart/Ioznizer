"""
OpenRouter API Client for LLM integration.
Supports openai/gpt-oss-120b:free model via OpenRouter.
"""

import os
import time
from typing import Dict, List, Optional, Any
import openai
from openai import OpenAI

# Try to import config for default API key
try:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from config import Config
    DEFAULT_API_KEY = Config.DEFAULT_API_KEY
except ImportError:
    DEFAULT_API_KEY = None


class OpenRouterClient:
    """Client for interacting with OpenRouter API."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "openai/gpt-oss-120b:free"):
        """
        Initialize OpenRouter client.
        
        Args:
            api_key: OpenRouter API key (defaults to OPENROUTER_API_KEY env var or config default)
            model: Model identifier (default: openai/gpt-oss-120b:free)
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY") or DEFAULT_API_KEY
        if not self.api_key:
            raise ValueError(
                "OpenRouter API key not found. "
                "Set OPENROUTER_API_KEY environment variable or pass api_key parameter."
            )
        
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"
        
        # Initialize OpenAI client with OpenRouter endpoint
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
    
    def _rate_limit(self):
        """Apply rate limiting."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()
    
    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        tool_choice: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        max_retries: int = 3,
        enable_reasoning: bool = True
    ) -> Dict[str, Any]:
        """
        Send chat completion request to OpenRouter.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions for function calling
            tool_choice: Tool choice mode ('auto', 'none', or specific tool)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
            max_retries: Number of retries on failure
            enable_reasoning: Enable reasoning mode (for o1 models)
        
        Returns:
            Response dict with 'choices', 'usage', etc.
        """
        self._rate_limit()
        
        # Prepare request parameters
        params = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        
        if tools:
            params["tools"] = tools
            params["tool_choice"] = tool_choice or "auto"
        
        if max_tokens:
            params["max_tokens"] = max_tokens
        
        # Add reasoning support (as per OpenRouter official example)
        if enable_reasoning:
            params["extra_body"] = {"reasoning": {"enabled": True}}
        
        # Retry logic
        last_error = None
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(**params)
                
                # Convert response to dict format
                result = {
                    "id": response.id,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                        "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                        "total_tokens": response.usage.total_tokens if response.usage else 0,
                    }
                }
                
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
                        choice_dict["message"]["tool_calls"] = [
                            {
                                "id": tc.id,
                                "type": tc.type,
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                }
                            }
                            for tc in choice.message.tool_calls
                        ]
                    else:
                        # Ensure tool_calls is an empty list if not present
                        choice_dict["message"]["tool_calls"] = []
                    
                    result["choices"].append(choice_dict)
                
                return result
                
            except openai.RateLimitError as e:
                last_error = e
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"[WARNING] Rate limit hit, waiting {wait_time}s before retry...")
                time.sleep(wait_time)
            except openai.NotFoundError as e:
                # Handle 404 errors (data policy, model not found, etc.)
                last_error = e
                error_msg = str(e)
                if "data policy" in error_msg.lower() or "privacy" in error_msg.lower():
                    raise ValueError(
                        "OpenRouter data policy not configured.\n"
                        "Please visit https://openrouter.ai/settings/privacy and configure your privacy settings.\n"
                        "You need to enable 'Free model publication' or adjust your data policy settings."
                    ) from e
                else:
                    raise ValueError(f"Model or endpoint not found: {error_msg}") from e
            except openai.APIError as e:
                last_error = e
                error_msg = str(e)
                # Check for specific error messages
                if "data policy" in error_msg.lower():
                    raise ValueError(
                        "OpenRouter data policy not configured.\n"
                        "Please visit https://openrouter.ai/settings/privacy and configure your privacy settings."
                    ) from e
                if attempt < max_retries - 1:
                    wait_time = 1 * (attempt + 1)
                    print(f"[WARNING] API error, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise
            except Exception as e:
                last_error = e
                raise
        
        # If we get here, all retries failed
        raise Exception(f"Failed after {max_retries} retries: {last_error}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            "model": self.model,
            "provider": "OpenRouter",
            "base_url": self.base_url,
        }

