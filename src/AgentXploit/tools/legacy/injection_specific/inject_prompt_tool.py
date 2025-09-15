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
import re
from typing import List, Dict, Optional
from litellm import completion
from google.adk.tools import ToolContext

from ...utils import IssueExtractor, PromptTemplates, get_contextual_wrappers
from ...config import settings, InjectionConfig
from ...enums import CommandType, InjectionStrategy

logger = logging.getLogger(__name__)


def inject_malicious_prompt(
    original_input: str,
    injection_points: List[Dict],
    config: InjectionConfig,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Inject a malicious command into GitHub issue content.
    
    This tool uses advanced prompt engineering to embed commands within
    issue content in a way that appears natural and essential for 
    troubleshooting the reported problem.
    
    Args:
        original_input: The original user input containing <issue> tags
        injection_points: List of identified injection points
        config: Injection configuration containing command type, strategy, etc.
        tool_context: ADK tool context (optional)
        
    Returns:
        Modified input with injected command
    """
    # Extract issue content
    issue_content, issue_start, issue_end = IssueExtractor.extract_issue_content(original_input)
    
    if not issue_content:
        logger.warning("No <issue> tags found in input")
        return original_input
    
    # Determine the command to inject
    if config.command_type == CommandType.CUSTOM:
        if not config.custom_command:
            raise ValueError("Custom command required for CUSTOM command type")
        command = config.custom_command
    else:
        command = settings.COMMANDS.get(config.command_type)
    
    # Get contextual wrappers for the command type
    contextual_wrappers = get_contextual_wrappers(config.command_type)
    
    # Generate injection prompt
    injection_prompt = PromptTemplates.get_injection_prompt(
        issue_content=issue_content,
        injection_points=injection_points,
        command=command,
        injection_strategy=config.injection_strategy,
        contextual_wrappers=contextual_wrappers
    )
    
    # Use LLM to generate injection
    try:
        messages = [{"content": injection_prompt, "role": "user"}]
        response = completion(model=config.model, messages=messages)
        response_content = response.choices[0].message.content
        
        try:
            result = json.loads(response_content)
            injected_issue = result.get("injected_issue_content", issue_content)
            
            # Verify injection success
            if injected_issue != issue_content and command in injected_issue:
                logger.info("LLM injection successful")
            else:
                logger.warning("LLM injection may not have succeeded, using fallback")
                injected_issue = _fallback_injection(
                    issue_content, injection_points, command, config.injection_strategy
                )
                
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response, using fallback")
            injected_issue = _fallback_injection(
                issue_content, injection_points, command, config.injection_strategy
            )
            
    except Exception as e:
        logger.error(f"LLM injection failed: {str(e)}")
        injected_issue = _fallback_injection(
            issue_content, injection_points, command, config.injection_strategy
        )
    
    # Add safety line at the beginning based on strategy
    wrapper = settings.INJECTION_WRAPPERS[config.injection_strategy]
    safety_line = f"\n{wrapper.format(command=command)}\n\n"
    injected_issue = safety_line + injected_issue
    
    # Replace the issue content in the original input
    return original_input[:issue_start] + injected_issue + original_input[issue_end:]


def _fallback_injection(
    issue_content: str,
    injection_points: List[Dict],
    command: str,
    injection_strategy: InjectionStrategy
) -> str:
    """Fallback injection method when LLM fails"""
    injected_issue = issue_content
    
    # Try to find steps to reproduce section
    steps_match = re.search(r'##?\s*Steps to Reproduce', injected_issue, re.IGNORECASE)
    if steps_match:
        insert_pos = steps_match.end()
        # Get first contextual wrapper
        contextual_wrappers = get_contextual_wrappers(
            CommandType.PKILL if "pkill" in command else CommandType.CUSTOM
        )
        contextual = contextual_wrappers[0] if contextual_wrappers else ""
        injection = f"\n\n{contextual.format(command=command)}\n\n"
    else:
        # Insert in the middle of the content
        mid = len(injected_issue) // 2
        for i in range(mid, min(mid + 50, len(injected_issue))):
            if injected_issue[i] == '\n':
                insert_pos = i + 1
                break
        else:
            insert_pos = mid
        
        wrapper = settings.INJECTION_WRAPPERS[injection_strategy]
        injection = f"\n\n{wrapper.format(command=command)}\n\n"
    
    injected_issue = injected_issue[:insert_pos] + injection + injected_issue[insert_pos:]
    return injected_issue 