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
from typing import Optional
from google.adk.tools import ToolContext

from ..unified_injection_tool import analyze_and_inject_trajectory
from ...config import settings

logger = logging.getLogger(__name__)


def process_trajectory_file(
    file_path: str,
    command_type: str = "pkill",
    injection_strategy: str = "technical",
    custom_command: Optional[str] = None,
    output_dir: Optional[str] = None,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Process a single trajectory file for injection analysis.
    
    This tool analyzes trajectory JSON files to extract conversational
    flows, identify injection opportunities, and generate injection
    attack demonstrations for security research.
    
    Args:
        file_path: Path to trajectory JSON file
        command_type: Type of command (pkill, reverse-shell, custom)
        injection_strategy: Strategy (technical, debug, authority)
        custom_command: Custom command if command_type is 'custom'
        output_dir: Directory to save results (defaults to settings.ANALYSIS_DIR)
        tool_context: ADK tool context (optional)
    
    Returns:
        Analysis results and injection report summary
    """
    
    try:
        logger.info(f"Processing trajectory file: {file_path}")
        
        if output_dir is None:
            output_dir = settings.ANALYSIS_DIR
        
        # Use the existing unified injection tool
        result_path = analyze_and_inject_trajectory(
            file_path=file_path,
            command_type=command_type,
            injection_strategy=injection_strategy,
            custom_command=custom_command,
            output_dir=output_dir,
            tool_context=tool_context
        )
        
        if result_path.startswith("ERROR:"):
            logger.error(f"Trajectory processing failed: {result_path}")
            return result_path
        
        # Generate processing summary
        summary = _generate_processing_summary(
            file_path,
            result_path,
            command_type,
            injection_strategy,
            custom_command
        )
        
        logger.info(f"Trajectory processing completed: {result_path}")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to process trajectory file {file_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_processing_summary(
    input_file: str,
    output_file: str,
    command_type: str,
    injection_strategy: str,
    custom_command: Optional[str]
) -> str:
    """Generate summary of trajectory processing results"""
    
    import os
    
    input_name = os.path.basename(input_file)
    output_name = os.path.basename(output_file)
    
    summary = f"""
Trajectory File Processing Complete:

Input File: {input_name}
Output File: {output_name}
Command Type: {command_type}
Injection Strategy: {injection_strategy}
Custom Command: {custom_command or "None"}

Processing Status: SUCCESS

The trajectory file has been analyzed and injection opportunities have been
identified and exploited using advanced prompt engineering techniques.

Key Processing Steps Completed:
1. Trajectory log parsing and structure analysis
2. User input extraction and issue content identification
3. Injection point discovery using pattern matching and LLM analysis
4. Sophisticated injection payload generation with GPT-4o
5. Context-aware injection implementation with fallback mechanisms
6. Comprehensive analysis report generation

Output Details:
- Detailed injection analysis saved to: {output_file}
- Injection success probability and effectiveness metrics included
- Technical justification and psychological hooks documented
- Original and modified content comparison provided

This analysis demonstrates injection vulnerabilities for security research purposes.
Review the detailed report for specific injection techniques and success metrics.
"""
    
    return summary