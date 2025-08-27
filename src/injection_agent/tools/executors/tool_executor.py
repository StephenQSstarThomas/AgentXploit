"""
Tool executor base class for unified tool execution interface.
Handles execution of different task types with standardized results.
"""

import os
import time
from typing import Dict, Any, Optional
from ..core.task import Task, TaskType, TaskStatus


class ToolExecutor:
    """Unified interface for executing analysis tools based on task type"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = os.path.abspath(repo_path)
    
    def execute(self, task: Task) -> Dict[str, Any]:
        """
        Execute a task and return standardized result
        
        Args:
            task: Task to execute
            
        Returns:
            Dictionary with execution result in standard format:
            {
                "success": bool,
                "task_id": str, 
                "task_type": str,
                "target": str,
                "duration": float,
                "result": Dict[str, Any] or None,
                "error": str or None
            }
        """
        start_time = time.time()
        task.set_running()
        
        result_template = {
            "success": False,
            "task_id": task.task_id,
            "task_type": task.type.value,
            "target": task.target,
            "duration": 0.0,
            "result": None,
            "error": None
        }
        
        try:
            if task.type == TaskType.EXPLORE:
                result_data = self._execute_list_directory(task.target)
            elif task.type == TaskType.READ:
                result_data = self._execute_read_file(task.target)
            else:
                raise NotImplementedError(f"Task type {task.type.value} not supported yet")
            
            duration = time.time() - start_time
            result_template.update({
                "success": True,
                "duration": duration,
                "result": result_data
            })
            
            task.set_completed(result_template)
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            result_template.update({
                "success": False,
                "duration": duration,
                "error": error_msg
            })
            
            task.set_failed(error_msg)
        
        return result_template
    
    def _execute_list_directory(self, directory_path: str) -> Dict[str, Any]:
        """Execute directory listing operation"""
        full_path = os.path.join(self.repo_path, directory_path.lstrip('/'))
        
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not os.path.isdir(full_path):
            raise NotADirectoryError(f"Path is not a directory: {directory_path}")
        
        try:
            entries = os.listdir(full_path)
            files = []
            directories = []
            
            for entry in entries:
                entry_path = os.path.join(full_path, entry)
                if os.path.isfile(entry_path):
                    files.append(entry)
                elif os.path.isdir(entry_path):
                    directories.append(entry)
            
            return {
                "path": directory_path,
                "files": sorted(files),
                "directories": sorted(directories),
                "total_entries": len(entries)
            }
            
        except PermissionError:
            raise PermissionError(f"Permission denied accessing directory: {directory_path}")
    
    def _execute_read_file(self, file_path: str) -> Dict[str, Any]:
        """Execute file reading operation"""
        full_path = os.path.join(self.repo_path, file_path.lstrip('/'))
        
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not os.path.isfile(full_path):
            raise IsADirectoryError(f"Path is not a file: {file_path}")
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return {
                "path": file_path,
                "content": content,
                "size": len(content),
                "lines": content.count('\n') + 1 if content else 0,
                "encoding": "utf-8"
            }
            
        except UnicodeDecodeError:
            # Try with latin-1 encoding as fallback
            with open(full_path, 'r', encoding='latin-1') as f:
                content = f.read()
            
            return {
                "path": file_path,
                "content": content,
                "size": len(content),
                "lines": content.count('\n') + 1 if content else 0,
                "encoding": "latin-1"
            }
        except PermissionError:
            raise PermissionError(f"Permission denied reading file: {file_path}")
    
    def can_execute(self, task_type: TaskType) -> bool:
        """Check if this executor can handle the given task type"""
        return task_type in [TaskType.EXPLORE, TaskType.READ]