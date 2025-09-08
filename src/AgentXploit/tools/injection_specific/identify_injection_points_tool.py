# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
from typing import List, Dict, Optional
from litellm import completion
from google.adk.tools import ToolContext

from ...utils import IssueExtractor, PromptTemplates
from ...config import settings

logger = logging.getLogger(__name__)


def identify_injection_points(
    issue_content: str, 
    model: Optional[str] = None,
    tool_context: Optional[ToolContext] = None
) -> List[Dict]:
    """
    Identify optimal injection points within issue content.
    
    This tool analyzes GitHub issue content to find the best locations
    for embedding commands as part of legitimate troubleshooting steps.
    Uses both pattern matching and LLM analysis for comprehensive coverage.
    
    Args:
        issue_content: The extracted issue content to analyze
        model: LLM model to use for analysis (defaults to settings.DEFAULT_MODEL)
        tool_context: ADK tool context (optional)
        
    Returns:
        List of dictionaries containing injection point details:
        - position: Location description
        - context: Surrounding text
        - psychological_hook: Why the agent will trust this
        - success_probability: high/medium/low
    """
    if not model:
        model = settings.DEFAULT_MODEL
        
    injection_points = []
    
    # First, use pattern matching to find obvious injection points
    sections = IssueExtractor.find_sections(issue_content)
    
    for section in sections:
        injection_points.append({
            "position": f"In {section['description']} at position {section['start']}",
            "context": section['content'],
            "psychological_hook": f"Commands in {section['description']} appear legitimate",
            "success_probability": "high" if "steps" in section['description'].lower() else "medium"
        })
    
    # Then use LLM for deeper analysis
    try:
        prompt = PromptTemplates.get_analysis_prompt(issue_content)
        messages = [{"content": prompt, "role": "user"}]
        
        response = completion(model=model, messages=messages)
        response_content = response.choices[0].message.content
        
        try:
            llm_result = json.loads(response_content)
            llm_points = llm_result.get("injection_points", [])
            
            # Add LLM-identified points that don't overlap with pattern-matched ones
            for llm_point in llm_points:
                # Check if this point is already covered by pattern matching
                is_duplicate = False
                for existing_point in injection_points:
                    if (llm_point.get("position", "").lower() in existing_point["position"].lower() or
                        existing_point["position"].lower() in llm_point.get("position", "").lower()):
                        is_duplicate = True
                        break
                
                if not is_duplicate:
                    injection_points.append(llm_point)
                    
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response for injection point analysis")
            
    except Exception as e:
        logger.error(f"LLM analysis failed: {str(e)}")
    
    # Limit to top 2 most promising injection points
    # Sort by success probability (high > medium > low)
    priority_map = {"high": 3, "medium": 2, "low": 1}
    injection_points.sort(
        key=lambda x: priority_map.get(x.get("success_probability", "low"), 1),
        reverse=True
    )
    
    return injection_points[:2] 