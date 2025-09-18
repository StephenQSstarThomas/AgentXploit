"""
Centralized LLM client with robust error handling and retry logic
"""

from typing import Dict, List, Optional


class LLMClient:
    """Centralized LLM client with robust error handling and retry logic"""

    @staticmethod
    def call_llm(model: str, messages: List[Dict], max_tokens: int = 1000,
                 temperature: float = 0.1, timeout: int = 30, max_retries: int = 3) -> Optional[str]:
        """
        Centralized LLM call with error handling and retry logic

        Args:
            model: LLM model name
            messages: Chat messages
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries

        Returns:
            LLM response text or None if all retries failed
        """
        import time
        import litellm
        from litellm import completion

        litellm.drop_params = True

        for attempt in range(max_retries):
            try:
                response = completion(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=timeout
                    # Note: max_retries is handled by our outer loop, not LiteLLM
                )

                content = response.choices[0].message.content
                if content and len(content.strip()) > 0:
                    return content.strip()

            except KeyboardInterrupt:
                print(f"  LLM call interrupted (attempt {attempt + 1}/{max_retries})")
                if attempt == max_retries - 1:
                    return None
                continue

            except Exception as e:
                error_msg = str(e)
                print(f"  LLM call failed (attempt {attempt + 1}/{max_retries}): {error_msg}")

                if attempt == max_retries - 1:
                    return None
                else:
                    time.sleep(1)  # Wait before retry
                    continue

        return None

    @staticmethod
    def get_model() -> str:
        """Get configured LLM model"""
        try:
            from ...config import settings
            # Try EXPLOIT_AGENT_MODEL first, then fall back to DEFAULT_MODEL
            return getattr(settings, 'EXPLOIT_AGENT_MODEL', settings.DEFAULT_MODEL)
        except:
            # Fallback: try environment directly
            import os
            return os.getenv("EXPLOIT_AGENT_MODEL", os.getenv("DEFAULT_MODEL", "openai/gpt-4o"))