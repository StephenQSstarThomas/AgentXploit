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
    
    def analyze_code_snippet(self, code: str, file_path: str) -> Dict[str, Any]:
        """Analyze code snippet for insights - used only for supplemental analysis"""
        
        prompt = f"""Analyze this code snippet from {file_path}:

```
{code[:1000]}  # Limit to first 1000 chars
```

Provide:
1. Purpose: What does this code do?
2. Risk: Any security concerns? (high/medium/low)
3. Patterns: Key patterns or frameworks used

Keep response brief and focused."""
        
        try:
            from ...config import settings
            response = completion(
                model=settings.LLM_HELPER_MODEL,  # Use configured model for snippet analysis
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=300
            )
            
            content = response.choices[0].message.content
            return {"analysis": content, "file": file_path}
            
        except Exception as e:
            return {"error": str(e), "file": file_path}