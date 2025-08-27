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
from typing import List, Dict, Any, Optional
from google.adk.tools import ToolContext

from ...config import settings

logger = logging.getLogger(__name__)


def batch_process_trajectories(
    directory: str = None,
    file_pattern: str = "*.json",
    exclude_patterns: List[str] = None,
    tool_context: Optional[ToolContext] = None
) -> List[Dict[str, Any]]:
    """
    Batch process multiple trajectory JSON files.
    
    This tool identifies and prepares multiple trajectory files for
    injection analysis. It filters out special files and returns a
    list of valid files for processing.
    
    Args:
        directory: Directory containing trajectory files (defaults to settings.TRAJECTORIES_DIR)
        file_pattern: Pattern for matching files (default: "*.json")
        exclude_patterns: List of patterns to exclude (e.g., ["processed_*", "SWEBenchlite.json"])
        tool_context: ADK tool context (optional)
        
    Returns:
        List of dictionaries containing:
        - filepath: Full path to the file
        - filename: Base filename
        - task_id: Extracted task ID
        - size: File size in bytes
    """
    if directory is None:
        directory = settings.TRAJECTORIES_DIR
    
    if exclude_patterns is None:
        exclude_patterns = ["processed_*", settings.SWEBENCH_FILE]
    
    if not os.path.exists(directory):
        logger.error(f"Directory not found: {directory}")
        return []
    
    files_to_process = []
    
    # List all files in directory
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        
        # Skip if not a file
        if not os.path.isfile(filepath):
            continue
        
        # Check if file matches pattern
        if file_pattern == "*.json" and not filename.endswith('.json'):
            continue
        
        # Check exclude patterns
        should_exclude = False
        for pattern in exclude_patterns:
            if pattern.endswith('*'):
                # Prefix matching
                if filename.startswith(pattern[:-1]):
                    should_exclude = True
                    break
            elif pattern.startswith('*'):
                # Suffix matching
                if filename.endswith(pattern[1:]):
                    should_exclude = True
                    break
            else:
                # Exact matching
                if filename == pattern:
                    should_exclude = True
                    break
        
        if should_exclude:
            continue
        
        # Extract task ID from filename
        task_id = os.path.splitext(filename)[0]
        
        # Get file info
        file_info = {
            "filepath": filepath,
            "filename": filename,
            "task_id": task_id,
            "size": os.path.getsize(filepath)
        }
        
        files_to_process.append(file_info)
    
    # Sort by filename for consistent processing order
    files_to_process.sort(key=lambda x: x["filename"])
    
    logger.info(f"Found {len(files_to_process)} files to process in {directory}")
    
    return files_to_process 