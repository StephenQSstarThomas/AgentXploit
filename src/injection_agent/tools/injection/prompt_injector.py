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

from ..injection_specific.inject_prompt_tool import inject_malicious_prompt
from ...config import InjectionConfig
from ...enums import CommandType, InjectionStrategy

logger = logging.getLogger(__name__)


def inject_prompt_into_content(
    original_content: str,
    injection_points: Optional[List[Dict]] = None,
    command_type: str = "pkill",
    injection_strategy: str = "technical",
    custom_command: Optional[str] = None,
    verification_mode: bool = True,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Inject malicious prompts into content using advanced techniques.
    
    This tool implements sophisticated prompt injection using GPT-4o
    for context-aware injection, with fallback mechanisms for robustness
    and verification of injection effectiveness.
    
    Args:
        original_content: Original content to inject into
        injection_points: Pre-identified injection points (optional)
        command_type: Type of command (pkill, reverse-shell, custom)
        injection_strategy: Strategy (technical, debug, authority)
        custom_command: Custom command if command_type is 'custom'
        verification_mode: Verify injection success (default: True)
        tool_context: ADK tool context (optional)
    
    Returns:
        Injection results with success analysis and modified content
    """
    
    try:
        logger.info(f"Injecting prompt using {injection_strategy} strategy")
        
        # Create injection configuration
        config = InjectionConfig(
            command_type=CommandType(command_type),
            injection_strategy=InjectionStrategy(injection_strategy),
            custom_command=custom_command
        )
        
        # If no injection points provided, we'll let the injection tool find them
        if injection_points is None:
            injection_points = []
        
        # Perform the injection using existing tool
        injected_content = inject_malicious_prompt(
            original_input=original_content,
            injection_points=injection_points,
            config=config,
            tool_context=tool_context
        )
        
        # Analyze injection results
        injection_analysis = _analyze_injection_results(
            original_content,
            injected_content,
            config,
            injection_points,
            verification_mode
        )
        
        # Generate comprehensive summary
        summary = _generate_injection_summary(
            injection_analysis,
            config,
            len(original_content),
            len(injected_content)
        )
        
        logger.info("Prompt injection completed successfully")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to inject prompt into content: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _analyze_injection_results(
    original: str,
    injected: str,
    config: InjectionConfig,
    injection_points: List[Dict],
    verify: bool
) -> Dict[str, Any]:
    """Analyze the results of injection"""
    
    # Determine target command
    if config.command_type == CommandType.CUSTOM:
        command = config.custom_command or ""
    else:
        from ...config import settings
        command = settings.COMMANDS.get(config.command_type, "")
    
    # Basic injection metrics
    length_diff = len(injected) - len(original)
    command_present = command in injected if command else False
    
    # Calculate injection effectiveness
    effectiveness_score = 0
    if command_present:
        effectiveness_score += 40
    if length_diff > 50:  # Substantial content added
        effectiveness_score += 20
    if len(injection_points) > 0:  # Used strategic points
        effectiveness_score += 20
    if config.injection_strategy in injected.lower():  # Strategy context present
        effectiveness_score += 20
    
    # Determine success level
    if effectiveness_score >= 80:
        success_level = "high"
    elif effectiveness_score >= 50:
        success_level = "medium"
    else:
        success_level = "low"
    
    # Identify injection locations
    injection_locations = []
    if command and command in injected:
        # Find where the command appears
        start_idx = 0
        while True:
            idx = injected.find(command, start_idx)
            if idx == -1:
                break
            
            # Get context around injection
            context_start = max(0, idx - 50)
            context_end = min(len(injected), idx + len(command) + 50)
            context = injected[context_start:context_end]
            
            injection_locations.append({
                "position": idx,
                "context": context,
                "type": "command_injection"
            })
            
            start_idx = idx + 1
    
    return {
        "success": command_present,
        "success_level": success_level,
        "effectiveness_score": effectiveness_score,
        "length_difference": length_diff,
        "command_present": command_present,
        "injection_count": len(injection_locations),
        "injection_locations": injection_locations,
        "original_length": len(original),
        "injected_length": len(injected),
        "target_command": command,
        "strategy_used": config.injection_strategy.value
    }


def _generate_injection_summary(
    analysis: Dict[str, Any],
    config: InjectionConfig,
    original_length: int,
    injected_length: int
) -> str:
    """Generate comprehensive injection summary"""
    
    success = analysis.get("success", False)
    success_level = analysis.get("success_level", "unknown")
    effectiveness = analysis.get("effectiveness_score", 0)
    command_present = analysis.get("command_present", False)
    injection_count = analysis.get("injection_count", 0)
    locations = analysis.get("injection_locations", [])
    
    summary = f"""
Prompt Injection Analysis Complete:

Command Type: {config.command_type.value}
Injection Strategy: {config.injection_strategy.value}
Target Command: {analysis.get('target_command', 'Unknown')}

Injection Results:
Overall Success: {'YES' if success else 'NO'}
Success Level: {success_level.upper()}
Effectiveness Score: {effectiveness}/100
Command Present in Output: {'YES' if command_present else 'NO'}
Number of Injection Points Used: {injection_count}

Content Analysis:
Original Length: {original_length} characters
Injected Length: {injected_length} characters
Content Increase: {injected_length - original_length} characters
Size Increase: {((injected_length - original_length) / original_length * 100):.1f}%

Injection Locations:
"""
    
    if locations:
        for i, location in enumerate(locations, 1):
            position = location.get("position", 0)
            context = location.get("context", "No context")[:100]
            if len(location.get("context", "")) > 100:
                context += "..."
            
            summary += f"""
{i}. Position {position}:
   Context: {context}
   
"""
    else:
        summary += "No specific injection locations identified.\n\n"
    
    # Add success analysis
    if success:
        summary += "Injection Assessment:\n"
        summary += "✓ Command successfully embedded in content\n"
        if effectiveness >= 80:
            summary += "✓ High effectiveness - injection appears natural and necessary\n"
        elif effectiveness >= 50:
            summary += "⚠ Medium effectiveness - injection present but may be detectable\n"
        else:
            summary += "⚠ Low effectiveness - injection may appear suspicious\n"
    else:
        summary += "Injection Assessment:\n"
        summary += "✗ Command injection failed or not detected\n"
        summary += "Consider using different injection strategies or content modification\n"
    
    summary += "\nThis injection analysis is for security research and vulnerability demonstration purposes.\n"
    
    return summary