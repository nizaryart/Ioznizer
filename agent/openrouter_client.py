"""
OpenRouter API Client for LLM integration.
Supports nvidia/nemotron-3-ultra-550b-a55b:free model via OpenRouter.
"""

import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import openai
from openai import OpenAI



class OpenRouterClient:
    """Client for interacting with OpenRouter API."""
    
    def __init__(self, api_key: Optional[str] = None, model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"):
        """
        Initialize OpenRouter client.
        
        Args:
            api_key: OpenRouter API key (defaults to OPENROUTER_API_KEY env var or config default)
            model: Model identifier (default: nvidia/nemotron-3-ultra-550b-a55b:free)
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
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
        temperature: float = 0.15,
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

                # OpenRouter answers HTTP 200 with an error payload when an
                # upstream provider fails (capacity exhaustion, model errors).
                # The SDK does not raise for that, it just leaves `choices`
                # empty, so it has to be detected here. Without this a single
                # transient provider hiccup discards an entire analysis run.
                if not getattr(response, "choices", None):
                    detail = ""
                    error_field = getattr(response, "error", None)
                    if error_field:
                        detail = str(error_field)[:200]

                    last_error = RuntimeError(
                        f"Provider returned no choices: {detail or 'empty response'}"
                    )

                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        print(f"[WARNING] Empty response from provider"
                              f"{f' ({detail})' if detail else ''}; "
                              f"retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        continue

                    raise last_error

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
                            # Normalised to a string: the API returns null
                            # content whenever the model replies with tool
                            # calls instead of prose.
                            "content": choice.message.content or "",
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
                detail = str(e)

                # A daily quota is not a transient condition: retrying it on a
                # seconds-scale backoff burns time and still fails. Detect it
                # and stop immediately with something the user can act on.
                if "free-models-per-day" in detail or "per-day" in detail:
                    reset_hint = ""
                    match = re.search(r"'X-RateLimit-Reset':\s*'(\d+)'", detail)
                    if match:
                        try:
                            reset = datetime.fromtimestamp(
                                int(match.group(1)) / 1000, timezone.utc
                            )
                            hours = (reset - datetime.now(timezone.utc)).total_seconds() / 3600
                            reset_hint = (
                                f"\nQuota resets at {reset:%Y-%m-%d %H:%M} UTC "
                                f"(in {hours:.1f} hours)."
                            )
                        except (ValueError, OverflowError):
                            pass

                    raise ValueError(
                        "OpenRouter daily free-model quota exhausted."
                        f"{reset_hint}\n"
                        "Options: wait for the reset, add credits at "
                        "https://openrouter.ai/settings/credits, or set "
                        "OPENROUTER_MODEL to a paid model."
                    ) from e

                wait_time = 2 ** attempt  # Exponential backoff
                print(f"[WARNING] Rate limit hit, waiting {wait_time}s before retry...")
                time.sleep(wait_time)
            except openai.AuthenticationError as e:
                # Retrying a rejected key only wastes time. Raise ValueError so
                # main.py reports it as a configuration problem rather than an
                # unhandled traceback.
                raise ValueError(
                    "OpenRouter rejected the API key.\n"
                    "Check OPENROUTER_API_KEY in .env, or create a key at "
                    "https://openrouter.ai/keys"
                ) from e
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

