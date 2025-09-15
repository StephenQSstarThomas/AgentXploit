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

import logging
from typing import Optional, Dict, Any, List
from google.adk.tools import ToolContext

from ..injection_specific.identify_injection_points_tool import identify_injection_points
from ...utils import IssueExtractor
from ...config import settings

logger = logging.getLogger(__name__)


def find_injection_points(
    content: str,
    content_type: str = "issue",
    analysis_depth: str = "comprehensive",
    max_points: int = 5,
    model: Optional[str] = None,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Find optimal injection points within content for vulnerability research.
    
    This tool analyzes content structure to identify the best locations
    for embedding commands that appear natural and essential for
    troubleshooting or debugging purposes.
    
    Args:
        content: Content to analyze for injection points
        content_type: Type of content (issue, documentation, code, etc.)
        analysis_depth: Depth of analysis (quick, standard, comprehensive)
        max_points: Maximum number of injection points to identify
        model: LLM model to use (defaults to settings.DEFAULT_MODEL)
        tool_context: ADK tool context (optional)
    
    Returns:
        Analysis of identified injection points with success probabilities
    """
    
    try:
        logger.info(f"Finding injection points in {content_type} content")
        
        # Extract issue content if it's wrapped in issue tags
        if content_type == "issue":
            issue_content, _, _ = IssueExtractor.extract_issue_content(content)
            if issue_content:
                analysis_content = issue_content
            else:
                analysis_content = content
        else:
            analysis_content = content
        
        # Use existing injection point identification tool
        injection_points = identify_injection_points(
            issue_content=analysis_content,
            model=model or settings.DEFAULT_MODEL,
            tool_context=tool_context
        )
        
        # Limit to requested number of points
        if len(injection_points) > max_points:
            injection_points = injection_points[:max_points]
        
        # Generate comprehensive summary
        summary = _generate_injection_points_summary(
            injection_points,
            content_type,
            analysis_depth,
            len(analysis_content)
        )
        
        logger.info(f"Found {len(injection_points)} injection points in content")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to find injection points: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_injection_points_summary(
    points: List[Dict[str, Any]],
    content_type: str,
    analysis_depth: str,
    content_length: int
) -> str:
    """Generate comprehensive summary of injection points"""
    
    if not points:
        return f"""
Injection Point Analysis Complete:

Content Type: {content_type}
Content Length: {content_length} characters
Analysis Depth: {analysis_depth}
Injection Points Found: 0

No viable injection points identified in the content.
Consider using different injection strategies or content modification.
"""
    
    # Count points by success probability
    high_prob = len([p for p in points if p.get("success_probability") == "high"])
    medium_prob = len([p for p in points if p.get("success_probability") == "medium"])
    low_prob = len([p for p in points if p.get("success_probability") == "low"])
    
    summary = f"""
Injection Point Analysis Complete:

Content Type: {content_type}
Content Length: {content_length} characters
Analysis Depth: {analysis_depth}
Injection Points Found: {len(points)}

Success Probability Distribution:
  High:   {high_prob} points
  Medium: {medium_prob} points
  Low:    {low_prob} points

Identified Injection Points:
"""
    
    for i, point in enumerate(points, 1):
        position = point.get("position", "Unknown position")
        context = point.get("context", "No context")[:100]
        hook = point.get("psychological_hook", "Unknown hook")
        probability = point.get("success_probability", "unknown")
        
        # Truncate context if too long
        if len(point.get("context", "")) > 100:
            context += "..."
        
        summary += f"""
{i}. Position: {position}
   Context: {context}
   Psychological Hook: {hook}
   Success Probability: {probability.upper()}
   
"""
    
    # Add strategic recommendations
    best_points = [p for p in points if p.get("success_probability") == "high"]
    if best_points:
        summary += "Strategic Recommendations:\n"
        summary += f"- Focus on the {len(best_points)} high-probability injection points\n"
        summary += "- Use technical justification for maximum credibility\n"
        summary += "- Embed commands within legitimate troubleshooting steps\n"
    else:
        summary += "Strategic Recommendations:\n"
        summary += "- Consider content modification to create better injection opportunities\n"
        summary += "- Use authority-based injection strategies\n"
        summary += "- Focus on creating urgency around the injected commands\n"
    
    summary += "\nAll injection points are for security research and vulnerability demonstration purposes.\n"
    
    return summary