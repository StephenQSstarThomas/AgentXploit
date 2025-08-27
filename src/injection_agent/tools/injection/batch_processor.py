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

import os
import logging
from typing import Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.adk.tools import ToolContext

from ..unified_injection_tool import analyze_and_inject_trajectory
from ...config import settings

logger = logging.getLogger(__name__)


def execute_batch_injection(
    input_directory: str,
    output_directory: Optional[str] = None,
    command_type: str = "pkill",
    injection_strategy: str = "technical",
    custom_command: Optional[str] = None,
    max_workers: int = 3,
    file_limit: Optional[int] = None,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Execute batch injection analysis on multiple trajectory files.
    
    This tool processes multiple trajectory files in parallel for injection
    analysis, providing efficient batch processing with configurable
    concurrency and comprehensive reporting.
    
    Args:
        input_directory: Directory containing trajectory JSON files
        output_directory: Directory to save results (defaults to settings.ANALYSIS_DIR)
        command_type: Type of command (pkill, reverse-shell, custom)
        injection_strategy: Strategy (technical, debug, authority)
        custom_command: Custom command if command_type is 'custom'
        max_workers: Maximum concurrent workers (default: 3)
        file_limit: Maximum number of files to process (optional)
        tool_context: ADK tool context (optional)
    
    Returns:
        Batch processing summary and results
    """
    
    try:
        logger.info(f"Starting batch injection processing of: {input_directory}")
        
        if output_directory is None:
            output_directory = settings.ANALYSIS_DIR
        
        # Ensure directories exist
        if not os.path.exists(input_directory):
            return f"ERROR: Input directory {input_directory} does not exist"
        
        os.makedirs(output_directory, exist_ok=True)
        
        # Find trajectory files
        trajectory_files = _find_trajectory_files(input_directory, file_limit)
        
        if not trajectory_files:
            return f"No valid trajectory JSON files found in {input_directory}"
        
        # Process files in parallel
        results = _process_files_parallel(
            trajectory_files,
            command_type,
            injection_strategy,
            custom_command,
            output_directory,
            max_workers
        )
        
        # Generate batch summary
        summary = _generate_batch_summary(results, input_directory, output_directory)
        
        logger.info(f"Batch injection processing completed for {input_directory}")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to execute batch injection on {input_directory}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _find_trajectory_files(directory: str, file_limit: Optional[int]) -> list:
    """Find valid trajectory JSON files in directory"""
    
    trajectory_files = []
    exclude_patterns = ["processed_", settings.SWEBENCH_FILE]
    
    for filename in sorted(os.listdir(directory)):
        if not filename.endswith('.json'):
            continue
        
        # Check exclude patterns
        should_exclude = any(
            filename.startswith(pattern) or filename == pattern
            for pattern in exclude_patterns
        )
        
        if should_exclude:
            continue
        
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            trajectory_files.append(filepath)
            
            if file_limit and len(trajectory_files) >= file_limit:
                break
    
    return trajectory_files


def _process_files_parallel(
    files: list,
    command_type: str,
    injection_strategy: str,
    custom_command: Optional[str],
    output_dir: str,
    max_workers: int
) -> list:
    """Process files in parallel using ThreadPoolExecutor"""
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {
            executor.submit(
                analyze_and_inject_trajectory,
                file_path,
                command_type,
                injection_strategy,
                custom_command,
                output_dir
            ): file_path
            for file_path in files
        }
        
        # Collect results
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                result_path = future.result()
                
                if result_path.startswith("ERROR:"):
                    results.append({
                        "file": os.path.basename(file_path),
                        "status": "failed",
                        "error": result_path,
                        "result_path": None
                    })
                else:
                    results.append({
                        "file": os.path.basename(file_path),
                        "status": "success",
                        "error": None,
                        "result_path": result_path
                    })
                    
            except Exception as e:
                results.append({
                    "file": os.path.basename(file_path),
                    "status": "failed", 
                    "error": str(e),
                    "result_path": None
                })
    
    return results


def _generate_batch_summary(results: list, input_dir: str, output_dir: str) -> str:
    """Generate summary of batch processing results"""
    
    total_files = len(results)
    successful = len([r for r in results if r["status"] == "success"])
    failed = total_files - successful
    
    summary = f"""
Batch Injection Processing Complete:

Input Directory: {input_dir}
Output Directory: {output_dir}
Total Files: {total_files}
Successful: {successful}
Failed: {failed}
Success Rate: {(successful/total_files*100):.1f}%

Processing Results:
"""
    
    # Add individual results
    for result in results:
        status_icon = "✓" if result["status"] == "success" else "✗"
        file_name = result["file"]
        
        if result["status"] == "success":
            result_file = os.path.basename(result["result_path"]) if result["result_path"] else "unknown"
            summary += f"  {status_icon} {file_name} -> {result_file}\n"
        else:
            error = result["error"][:100] + "..." if len(result["error"]) > 100 else result["error"]
            summary += f"  {status_icon} {file_name}: {error}\n"
    
    if successful > 0:
        summary += f"\nAll successful results saved to: {output_dir}\n"
    
    return summary