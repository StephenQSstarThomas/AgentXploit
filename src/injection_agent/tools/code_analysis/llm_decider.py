"""
LLM helper for code snippet analysis only - agents handle their own decisions
"""

import os
from typing import Dict, Any
from litellm import completion


class LLMHelper:
    """LLM helper for code snippet analysis only - agents make their own task decisions"""
    
    def __init__(self):
        self._setup_api_key()
    
    def _setup_api_key(self):
        """Setup OpenAI API key from environment or config"""
        if not os.environ.get("OPENAI_API_KEY"):
            try:
                from ...config import settings
                api_key = settings.get_openai_api_key()
                os.environ["OPENAI_API_KEY"] = api_key
            except Exception:
                pass
    
    def analyze_code_snippet(self, code: str, file_path: str, max_retries: int = 2) -> Dict[str, Any]:
        """Analyze code snippet for insights - used only for supplemental analysis"""

        if not code or not code.strip():
            return {"error": "Empty code snippet", "file": file_path}

        # Truncate very long code snippets to avoid token limits
        truncated_code = code[:1500] if len(code) > 1500 else code

        prompt = f"""Analyze this code snippet from {file_path}:

```
{truncated_code}
```

Provide a brief analysis covering:
1. Purpose: What does this code do?
2. Risk: Any security concerns? (high/medium/low/none)
3. Patterns: Key patterns or frameworks used
4. Quality: Code quality assessment

Keep response under 200 words and focused."""

        for attempt in range(max_retries + 1):
            try:
                from ...config import settings
                response = completion(
                    model=settings.LLM_HELPER_MODEL,  # Use configured model for snippet analysis
                    messages=[
                        {"role": "system", "content": "You are a code analysis assistant. Provide concise, accurate analysis."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2,  # Slightly higher for more varied analysis
                    max_tokens=250,  # Reasonable limit for brief analysis
                    timeout=30  # 30 second timeout
                )

                content = response.choices[0].message.content

                if content and len(content.strip()) > 10:  # Ensure meaningful response
                    return {
                        "analysis": content.strip(),
                        "file": file_path,
                        "model_used": settings.LLM_HELPER_MODEL,
                        "attempt": attempt + 1,
                        "truncated": len(code) > 1500
                    }
                else:
                    if attempt < max_retries:
                        continue  # Try again for empty responses

            except Exception as e:
                error_msg = str(e)
                if attempt < max_retries:
                    continue  # Try again for errors
                else:
                    return {
                        "error": f"LLM analysis failed after {max_retries + 1} attempts: {error_msg}",
                        "file": file_path,
                        "last_attempt_error": error_msg
                    }

        return {"error": "LLM analysis returned empty response", "file": file_path}