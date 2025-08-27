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
Analysis tools for intelligent static analysis - mimicking Cursor's toolset
"""

import os
import re
import json
import fnmatch
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AnalysisTools:
    """Collection of analysis tools similar to Cursor's capabilities"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.tool_call_log = []
    
    def log_tool_call(self, tool_name: str, params: Dict[str, Any], result: Any):
        """Log each tool call for structured logging"""
        log_entry = {
            "tool": tool_name,
            "parameters": params,
            "result_summary": self._summarize_result(result),
            "timestamp": self._get_timestamp()
        }
        self.tool_call_log.append(log_entry)
        logger.info(f"Tool Call: {tool_name} with {params}")
    
    def list_directory(self, path: str = ".", max_items: int = 50) -> Dict[str, Any]:
        """
        Tool: List directory contents
        Similar to Cursor's file explorer functionality
        """
        try:
            target_path = self.repo_path / path if path != "." else self.repo_path
            
            items = []
            directories = []
            files = []
            
            for item in sorted(target_path.iterdir()):
                if item.name.startswith('.'):
                    continue
                    
                item_info = {
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "path": str(item.relative_to(self.repo_path))
                }
                
                if item.is_file():
                    item_info.update({
                        "size": item.stat().st_size,
                        "extension": item.suffix,
                        "size_readable": self._format_size(item.stat().st_size)
                    })
                    files.append(item_info)
                else:
                    directories.append(item_info)
                
                items.append(item_info)
                
                if len(items) >= max_items:
                    break
            
            result = {
                "path": path,
                "total_items": len(items),
                "directories": directories,
                "files": files,
                "items": items
            }
            
            self.log_tool_call("list_directory", {"path": path}, result)
            return result
            
        except Exception as e:
            error_result = {"error": str(e), "path": path}
            self.log_tool_call("list_directory", {"path": path}, error_result)
            return error_result
    
    def read_file(self, file_path: str, start_line: Optional[int] = None, end_line: Optional[int] = None, max_lines: int = 100) -> Dict[str, Any]:
        """
        Tool: Read file contents with line numbers
        Similar to Cursor's file reading with line ranges
        """
        try:
            target_file = self.repo_path / file_path
            
            if not target_file.exists():
                error_result = {"error": "File not found", "file_path": file_path}
                self.log_tool_call("read_file", {"file_path": file_path}, error_result)
                return error_result
            
            with open(target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            total_lines = len(lines)
            
            # Handle None values for start_line
            if start_line is None:
                start_line = 1
            
            start_idx = max(0, start_line - 1)  # Convert to 0-based
            if end_line is not None:
                end_idx = min(total_lines, end_line)
            else:
                end_idx = min(total_lines, start_idx + max_lines)
            
            selected_lines = lines[start_idx:end_idx]
            
            result = {
                "file_path": file_path,
                "total_lines": total_lines,
                "start_line": start_line,
                "end_line": start_idx + len(selected_lines),
                "lines_read": len(selected_lines),
                "content": ''.join(selected_lines),
                "numbered_content": self._add_line_numbers(selected_lines, start_line)
            }
            
            self.log_tool_call("read_file", {
                "file_path": file_path, 
                "start_line": start_line, 
                "end_line": end_line
            }, result)
            
            return result
            
        except Exception as e:
            error_result = {"error": str(e), "file_path": file_path}
            self.log_tool_call("read_file", {"file_path": file_path}, error_result)
            return error_result
    
    def grep_search(self, pattern: str, file_pattern: str = "*", max_results: int = 20) -> Dict[str, Any]:
        """
        Tool: Search for patterns in files
        Similar to Cursor's global search functionality
        """
        try:
            matches = []
            files_searched = 0
            
            for root, dirs, files in os.walk(self.repo_path):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if not fnmatch.fnmatch(file, file_pattern):
                        continue
                    
                    file_path = Path(root) / file
                    relative_path = file_path.relative_to(self.repo_path)
                    files_searched += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            for line_num, line in enumerate(f, 1):
                                if re.search(pattern, line, re.IGNORECASE):
                                    matches.append({
                                        "file": str(relative_path),
                                        "line": line_num,
                                        "content": line.strip(),
                                        "match": re.search(pattern, line, re.IGNORECASE).group()
                                    })
                                    
                                    if len(matches) >= max_results:
                                        break
                        
                        if len(matches) >= max_results:
                            break
                            
                    except Exception:
                        continue
                
                if len(matches) >= max_results:
                    break
            
            result = {
                "pattern": pattern,
                "file_pattern": file_pattern,
                "matches": matches,
                "total_matches": len(matches),
                "files_searched": files_searched
            }
            
            self.log_tool_call("grep_search", {
                "pattern": pattern, 
                "file_pattern": file_pattern
            }, result)
            
            return result
            
        except Exception as e:
            error_result = {"error": str(e), "pattern": pattern}
            self.log_tool_call("grep_search", {"pattern": pattern}, error_result)
            return error_result
    
    def search_files(self, filename_pattern: str, max_results: int = 10) -> Dict[str, Any]:
        """
        Tool: Search for files by name pattern
        Similar to Cursor's file search functionality
        """
        try:
            matches = []
            
            for root, dirs, files in os.walk(self.repo_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                
                for file in files:
                    if fnmatch.fnmatch(file, filename_pattern):
                        file_path = Path(root) / file
                        relative_path = file_path.relative_to(self.repo_path)
                        
                        matches.append({
                            "name": file,
                            "path": str(relative_path),
                            "directory": str(relative_path.parent),
                            "size": file_path.stat().st_size,
                            "extension": file_path.suffix
                        })
                        
                        if len(matches) >= max_results:
                            break
                
                if len(matches) >= max_results:
                    break
            
            result = {
                "filename_pattern": filename_pattern,
                "matches": matches,
                "total_found": len(matches)
            }
            
            self.log_tool_call("search_files", {"filename_pattern": filename_pattern}, result)
            return result
            
        except Exception as e:
            error_result = {"error": str(e), "filename_pattern": filename_pattern}
            self.log_tool_call("search_files", {"filename_pattern": filename_pattern}, error_result)
            return error_result
    
    def analyze_file_structure(self, file_path: str) -> Dict[str, Any]:
        """
        Tool: Analyze file structure (functions, classes, imports)
        Similar to Cursor's code outline functionality
        """
        try:
            target_file = self.repo_path / file_path
            
            if not target_file.exists():
                error_result = {"error": "File not found", "file_path": file_path}
                self.log_tool_call("analyze_file_structure", {"file_path": file_path}, error_result)
                return error_result
            
            with open(target_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract structure elements
            imports = re.findall(r'^(?:from|import)\s+([^\s#]+)', content, re.MULTILINE)
            classes = re.findall(r'^class\s+(\w+)', content, re.MULTILINE)
            functions = re.findall(r'^def\s+(\w+)', content, re.MULTILINE)
            
            # Find main patterns
            has_main = bool(re.search(r'if __name__ == ["\']__main__["\']', content))
            has_async = bool(re.search(r'async def', content))
            
            result = {
                "file_path": file_path,
                "imports": imports,
                "classes": classes,
                "functions": functions,
                "has_main": has_main,
                "has_async": has_async,
                "total_lines": len(content.splitlines()),
                "structure_summary": {
                    "imports_count": len(imports),
                    "classes_count": len(classes),
                    "functions_count": len(functions)
                }
            }
            
            self.log_tool_call("analyze_file_structure", {"file_path": file_path}, result)
            return result
            
        except Exception as e:
            error_result = {"error": str(e), "file_path": file_path}
            self.log_tool_call("analyze_file_structure", {"file_path": file_path}, error_result)
            return error_result
    
    def get_execution_log(self) -> List[Dict[str, Any]]:
        """Get the complete execution log of all tool calls"""
        return self.tool_call_log
    
    # Helper methods
    def _summarize_result(self, result: Any) -> str:
        """Create a brief summary of the result for logging"""
        if isinstance(result, dict):
            if "error" in result:
                return f"Error: {result['error']}"
            elif "total_items" in result:
                return f"Found {result['total_items']} items"
            elif "total_matches" in result:
                return f"Found {result['total_matches']} matches"
            elif "total_found" in result:
                return f"Found {result['total_found']} files"
            elif "total_lines" in result:
                return f"Read {result.get('lines_read', 0)} lines from {result['total_lines']} total"
        return str(type(result).__name__)
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f}GB"
    
    def _add_line_numbers(self, lines: List[str], start_line: int) -> str:
        """Add line numbers to content"""
        numbered_lines = []
        for i, line in enumerate(lines):
            line_num = start_line + i
            numbered_lines.append(f"{line_num:4d}→{line.rstrip()}")
        return '\n'.join(numbered_lines)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for logging"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]