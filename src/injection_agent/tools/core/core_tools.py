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
Core analysis tools - streamlined version without logging overhead
"""

import os
import re
import fnmatch
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path


class CoreTools:
    """Streamlined analysis tools for repository exploration"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
    
    def list_directory(self, path: str = ".", max_items: int = 50, include_structure: bool = False) -> Dict[str, Any]:
        """List directory contents"""
        try:
            target_path = self.repo_path / path if path != "." else self.repo_path
            
            items = []
            for item in sorted(target_path.iterdir()):
                if item.name.startswith('.'):
                    continue
                    
                item_info = {
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "path": str(item.relative_to(self.repo_path))
                }
                
                if item.is_file():
                    item_info["size"] = item.stat().st_size
                    item_info["extension"] = item.suffix
                
                items.append(item_info)
                
                if len(items) >= max_items:
                    break
            
            result = {
                "path": path,
                "items": items,
                "total": len(items),
                "files": [item["name"] for item in items if item["type"] == "file"],
                "directories": [item["name"] for item in items if item["type"] == "directory"]
            }
            
            # Add structure info if requested
            if include_structure:
                result["tree_structure"] = self.get_tree_structure(max_depth=2, show_files=True)
            
            return result
            
        except Exception as e:
            return {"error": str(e), "path": path}
    
    def read_file(self, file_path: str, start_line: Optional[int] = None, 
                  end_line: Optional[int] = None, max_lines: int = 100) -> Dict[str, Any]:
        """Read file contents with optional line range"""
        try:
            target_file = self.repo_path / file_path
            
            if not target_file.exists():
                return {"error": "File not found", "file_path": file_path}
            
            with open(target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            total_lines = len(lines)
            start_idx = max(0, (start_line or 1) - 1)
            end_idx = min(total_lines, end_line or (start_idx + max_lines))
            
            selected_lines = lines[start_idx:end_idx]
            
            return {
                "file_path": file_path,
                "content": ''.join(selected_lines),
                "total_lines": total_lines,
                "lines_read": len(selected_lines)
            }
            
        except Exception as e:
            return {"error": str(e), "file_path": file_path}
    
    def grep_search(self, pattern: str, file_pattern: str = "*", 
                    max_results: int = 20) -> Dict[str, Any]:
        """Search for patterns in files"""
        try:
            matches = []
            files_searched = 0
            
            for root, dirs, files in os.walk(self.repo_path):
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
                                        "content": line.strip()
                                    })
                                    
                                    if len(matches) >= max_results:
                                        break
                        
                        if len(matches) >= max_results:
                            break
                            
                    except Exception:
                        continue
                
                if len(matches) >= max_results:
                    break
            
            return {
                "pattern": pattern,
                "matches": matches,
                "total": len(matches),
                "files_searched": files_searched
            }
            
        except Exception as e:
            return {"error": str(e), "pattern": pattern}
    
    def get_tree_structure(self, max_depth: int = 3, show_files: bool = True) -> Dict[str, Any]:
        """Get tree structure using tree command if available, fallback to custom implementation"""
        try:
            # Try using system tree command first
            tree_output = self._get_system_tree(max_depth, show_files)
            if tree_output:
                return {
                    "method": "system_tree",
                    "tree_output": tree_output,
                    "max_depth": max_depth,
                    "show_files": show_files
                }
            
            # Fallback to custom tree implementation
            tree_data = self._build_custom_tree("", max_depth, show_files)
            tree_string = self._format_tree_string(tree_data)
            
            return {
                "method": "custom_tree",
                "tree_output": tree_string,
                "tree_data": tree_data,
                "max_depth": max_depth,
                "show_files": show_files
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def _get_system_tree(self, max_depth: int, show_files: bool) -> Optional[str]:
        """Try to use system tree command"""
        try:
            cmd = ["tree", "-L", str(max_depth)]
            if not show_files:
                cmd.append("-d")  # directories only
            cmd.extend(["-a", "--charset", "ascii"])  # show hidden, use ascii chars
            cmd.append(str(self.repo_path))
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout
            return None
            
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return None
    
    def _build_custom_tree(self, path: str, max_depth: int, show_files: bool, current_depth: int = 0) -> Dict[str, Any]:
        """Build custom tree structure recursively"""
        if current_depth >= max_depth:
            return {}
        
        target_path = self.repo_path / path if path else self.repo_path
        tree_node = {
            "name": target_path.name or ".",
            "type": "directory",
            "children": []
        }
        
        try:
            items = sorted(target_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            
            for item in items:
                if item.name.startswith('.') and item.name not in ['.env', '.gitignore', '.github']:
                    continue
                    
                if item.is_dir():
                    # Skip common non-code directories
                    if item.name in ['__pycache__', '.git', 'node_modules', '.vscode', '.idea']:
                        continue
                    
                    child_path = str(item.relative_to(self.repo_path))
                    child_node = self._build_custom_tree(child_path, max_depth, show_files, current_depth + 1)
                    child_node["name"] = item.name
                    child_node["type"] = "directory"
                    tree_node["children"].append(child_node)
                    
                elif show_files:
                    # Only include certain file types
                    if item.suffix in ['.py', '.toml', '.yaml', '.yml', '.json', '.md', '.txt', '.env', '.cfg']:
                        file_node = {
                            "name": item.name,
                            "type": "file",
                            "size": item.stat().st_size,
                            "extension": item.suffix
                        }
                        tree_node["children"].append(file_node)
            
        except PermissionError:
            tree_node["error"] = "Permission denied"
        except Exception as e:
            tree_node["error"] = str(e)
        
        return tree_node
    
    def _format_tree_string(self, tree_data: Dict[str, Any], prefix: str = "", is_last: bool = True) -> str:
        """Format tree data as string representation"""
        if not tree_data or "name" not in tree_data:
            return ""
        
        output = ""
        name = tree_data["name"]
        
        if tree_data["type"] == "directory":
            name = f"{name}/"
        elif tree_data["type"] == "file" and "size" in tree_data:
            size_str = self._format_size(tree_data["size"])
            name = f"{name} ({size_str})"
        
        connector = "+-- " if is_last else "|-- "
        output += f"{prefix}{connector}{name}\n"
        
        children = tree_data.get("children", [])
        for i, child in enumerate(children):
            is_child_last = i == len(children) - 1
            child_prefix = prefix + ("    " if is_last else "|   ")
            output += self._format_tree_string(child, child_prefix, is_child_last)
        
        return output
    
    def _format_size(self, size: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.0f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"
    
    def get_project_structure_summary(self) -> Dict[str, Any]:
        """Get comprehensive project structure summary"""
        try:
            summary = {
                "repo_path": str(self.repo_path),
                "total_files": 0,
                "total_directories": 0,
                "file_types": {},
                "directories_by_depth": {},
                "largest_files": [],
                "structure_analysis": {}
            }
            
            large_files = []
            
            for root, dirs, files in os.walk(self.repo_path):
                # Filter out hidden and irrelevant directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['__pycache__', 'node_modules']]
                
                depth = root.replace(str(self.repo_path), '').count(os.sep)
                summary["directories_by_depth"][depth] = summary["directories_by_depth"].get(depth, 0) + 1
                summary["total_directories"] += 1
                
                for file in files:
                    if file.startswith('.'):
                        continue
                        
                    file_path = os.path.join(root, file)
                    ext = Path(file).suffix or "no_extension"
                    
                    summary["file_types"][ext] = summary["file_types"].get(ext, 0) + 1
                    summary["total_files"] += 1
                    
                    # Track large files
                    try:
                        size = os.path.getsize(file_path)
                        if size > 10000:  # Files larger than 10KB
                            rel_path = os.path.relpath(file_path, self.repo_path)
                            large_files.append({
                                "path": rel_path,
                                "size": size,
                                "size_str": self._format_size(size)
                            })
                    except OSError:
                        continue
            
            # Keep only top 10 largest files
            summary["largest_files"] = sorted(large_files, key=lambda x: x["size"], reverse=True)[:10]
            
            # Analyze project structure patterns
            summary["structure_analysis"] = self._analyze_project_patterns(summary)
            
            return summary
            
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_project_patterns(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze project structure to determine patterns and type"""
        file_types = summary.get("file_types", {})
        
        analysis = {
            "project_type": "unknown",
            "frameworks": [],
            "has_tests": False,
            "has_docs": False,
            "has_config": False
        }
        
        # Determine project type
        if ".py" in file_types:
            analysis["project_type"] = "python"
            if ".toml" in file_types or file_types.get(".py", 0) > 5:
                analysis["project_type"] = "python_package"
        elif ".js" in file_types:
            analysis["project_type"] = "javascript"
        elif ".java" in file_types:
            analysis["project_type"] = "java"
        elif ".rs" in file_types:
            analysis["project_type"] = "rust"
        
        # Detect common patterns
        if ".md" in file_types:
            analysis["has_docs"] = True
        if any(ext in file_types for ext in [".toml", ".yaml", ".yml", ".json", ".cfg"]):
            analysis["has_config"] = True
        
        # Estimate complexity
        total_code_files = sum(count for ext, count in file_types.items() 
                             if ext in [".py", ".js", ".java", ".rs", ".cpp", ".c", ".go"])
        if total_code_files < 5:
            analysis["complexity"] = "simple"
        elif total_code_files < 20:
            analysis["complexity"] = "moderate"
        else:
            analysis["complexity"] = "complex"
        
        return analysis