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

"""
Unified Path Resolver for AgentXploit
Provides consistent path construction logic across decision engine and analysis agent
"""

import os
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)


class PathResolver:
    """Unified path resolution for consistent path construction across the codebase"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.current_context = {}  # Stores current directory context for path resolution
    
    def set_current_context(self, explored_path: Optional[str] = None, current_file_path: Optional[str] = None) -> None:
        """Set current directory context for path resolution"""
        self.current_context = {
            "explored_path": explored_path,
            "current_file_path": current_file_path,
            "current_directory": self._determine_current_directory(explored_path, current_file_path)
        }
        logger.debug(f"[PATH_RESOLVER] Context updated: {self.current_context}")
    
    def _determine_current_directory(self, explored_path: Optional[str], current_file_path: Optional[str]) -> str:
        """Determine the current working directory for path resolution"""
        if explored_path and explored_path != ".":
            # We are exploring a specific directory
            return explored_path
        elif current_file_path:
            # We are analyzing a file, use its parent directory
            return str(Path(current_file_path).parent) if "/" in current_file_path else "."
        else:
            # Default to repository root
            return "."
    
    def resolve_target_path(self, target_path: str, target_type: str = "file") -> Tuple[str, bool, str]:
        """
        Resolve target path based on current context
        
        Args:
            target_path: The relative target path (e.g., "bedrock.py", "subfolder")
            target_type: Type of target ("file" or "directory")
            
        Returns:
            Tuple of (resolved_path, is_valid, reason)
        """
        if not target_path or not target_path.strip():
            return "", False, "Empty target path"
        
        target_path = target_path.strip()
        current_dir = self.current_context.get("current_directory", ".")
        
        logger.debug(f"[PATH_RESOLVER] Resolving '{target_path}' (type: {target_type})")
        logger.debug(f"[PATH_RESOLVER] Current directory: '{current_dir}'")
        
        # Step 1: Construct the full path
        if os.path.isabs(target_path):
            # Absolute path - validate it's within repo
            resolved_path = target_path
            abs_target = Path(target_path).resolve()
            if not str(abs_target).startswith(str(self.repo_path)):
                return resolved_path, False, "Absolute path outside repository"
        elif current_dir and current_dir != ".":
            # We are in a subdirectory, combine paths
            resolved_path = os.path.join(current_dir, target_path)
            logger.debug(f"[PATH_RESOLVER] Combined: '{current_dir}' + '{target_path}' = '{resolved_path}'")
        else:
            # We are at repository root
            resolved_path = target_path
            logger.debug(f"[PATH_RESOLVER] At root, using '{target_path}' directly")
        
        # Step 2: Validate the resolved path
        full_system_path = self.repo_path / resolved_path
        
        if not full_system_path.exists():
            return resolved_path, False, f"Path does not exist: {resolved_path}"
        
        if target_type == "file" and not full_system_path.is_file():
            return resolved_path, False, f"Path is not a file: {resolved_path}"
        
        if target_type == "directory" and not full_system_path.is_dir():
            return resolved_path, False, f"Path is not a directory: {resolved_path}"
        
        logger.debug(f"[PATH_RESOLVER] Successfully resolved: '{target_path}' -> '{resolved_path}'")
        return resolved_path, True, "Valid path"
    
    def resolve_content_follow_up_paths(self, targets: list, current_file_path: str) -> list:
        """
        Resolve paths for content follow-up targets with proper directory context
        
        Args:
            targets: List of target dictionaries with 'path' and 'type'
            current_file_path: Path of the file that triggered the follow-up
            
        Returns:
            List of resolved target dictionaries with updated paths
        """
        # Set context based on the current file being analyzed
        self.set_current_context(current_file_path=current_file_path)
        
        resolved_targets = []
        for target in targets:
            if not isinstance(target, dict) or "path" not in target:
                continue
                
            original_path = target["path"]
            target_type = target.get("type", "file")
            
            resolved_path, is_valid, reason = self.resolve_target_path(original_path, target_type)
            
            if is_valid:
                # Create a new target with resolved path
                resolved_target = target.copy()
                resolved_target["path"] = resolved_path
                resolved_target["original_path"] = original_path
                resolved_targets.append(resolved_target)
                logger.info(f"[PATH_RESOLVER] Content follow-up: '{original_path}' -> '{resolved_path}'")
            else:
                logger.warning(f"[PATH_RESOLVER] Invalid content follow-up: '{original_path}' ({reason})")
        
        return resolved_targets
    
    def resolve_exploration_paths(self, targets: list, explored_path: str) -> list:
        """
        Resolve paths for exploration targets with proper directory context
        
        Args:
            targets: List of target dictionaries with 'path' and 'type'
            explored_path: Current directory being explored
            
        Returns:
            List of resolved target dictionaries with updated paths
        """
        # Set context based on the directory being explored
        self.set_current_context(explored_path=explored_path)
        
        resolved_targets = []
        for target in targets:
            if not isinstance(target, dict) or "path" not in target:
                continue
                
            original_path = target["path"]
            target_type = target.get("type", "file")
            
            resolved_path, is_valid, reason = self.resolve_target_path(original_path, target_type)
            
            if is_valid:
                # Create a new target with resolved path
                resolved_target = target.copy()
                resolved_target["path"] = resolved_path
                resolved_target["original_path"] = original_path
                resolved_targets.append(resolved_target)
                logger.info(f"[PATH_RESOLVER] Exploration: '{original_path}' -> '{resolved_path}'")
            else:
                logger.warning(f"[PATH_RESOLVER] Invalid exploration: '{original_path}' ({reason})")
        
        return resolved_targets
    
    def get_current_context(self) -> Dict[str, Any]:
        """Get current path resolution context for debugging"""
        return self.current_context.copy()
