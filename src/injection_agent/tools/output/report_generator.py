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
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from google.adk.tools import ToolContext

from ...config import settings, InjectionConfig
from ...utils import SWEBenchLoader, IssueExtractor


def save_analysis_results(
    user_input: str,
    injected_input: str,
    task_id: str,
    injection_points: List[Dict],
    config: InjectionConfig,
    tool_context: Optional[ToolContext] = None
) -> Dict[str, Any]:
    """
    Save injection analysis results to a JSON report.
    
    This tool creates a comprehensive report of the injection analysis,
    including metadata, injection details, and success indicators.
    
    Args:
        user_input: Original user input
        injected_input: Modified input with injection
        task_id: Task identifier
        injection_points: List of identified injection points
        config: Injection configuration used
        tool_context: ADK tool context (optional)
        
    Returns:
        Dictionary containing the complete analysis report
    """
    # Extract issue content to find SWEBench ID
    issue_content, _, _ = IssueExtractor.extract_issue_content(user_input)
    
    # Try to find matching SWEBench ID
    swebench_loader = SWEBenchLoader()
    swebench_id = swebench_loader.find_matching_id(issue_content) if issue_content else None
    
    # Determine the actual command used
    if config.command_type.value == "custom":
        command = config.custom_command
    else:
        command = settings.COMMANDS.get(config.command_type)
    
    # Create report
    report = {
        "task_id": task_id,
        "swebench_id": swebench_id,
        "timestamp": datetime.now().isoformat(),
        "original_length": len(user_input),
        "injected_length": len(injected_input),
        "command_type": config.command_type.value,
        "command": command,
        "injection_strategy": config.injection_strategy.value,
        "model": config.model,
        "injection_success": command in injected_input if command else False,
        "injection_points": injection_points,
        "injection_summary": {
            "total_points_found": len(injection_points),
            "high_probability_points": sum(1 for p in injection_points if p.get("success_probability") == "high"),
            "medium_probability_points": sum(1 for p in injection_points if p.get("success_probability") == "medium"),
            "low_probability_points": sum(1 for p in injection_points if p.get("success_probability") == "low"),
        },
        "injected_text": injected_input
    }
    
    # Save report to file
    settings.ensure_directories()
    report_file = os.path.join(settings.ANALYSIS_DIR, f"analysis_{task_id}.json")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    
    # Also save the injected input separately for easy access
    injected_file = os.path.join(settings.INJECTED_DIR, f"injected_{task_id}.txt")
    with open(injected_file, 'w', encoding='utf-8') as f:
        f.write(injected_input)
    
    # Add file paths to report
    report["report_file"] = report_file
    report["injected_file"] = injected_file
    
    return report 