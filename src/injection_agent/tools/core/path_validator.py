"""
Simplified path validation and normalization utilities
Focuses on core path operations without rule-based validation
"""

import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class PathValidator:
    """Simplified path validation focusing on core operations only"""
    
    def __init__(self, repo_path: str = None):
        self.repo_path = Path(repo_path).resolve() if repo_path else None
        self.current_absolute_path = str(self.repo_path) if self.repo_path else os.getcwd()
    
    def normalize_path(self, target: str) -> str:
        """
        Normalize path for consistent handling across the system
        Returns absolute path with consistent separators
        """
        try:
            # Clean input
            target = str(target).strip().replace('\\', '/')
            
            if self.repo_path:
                if Path(target).is_absolute():
                    abs_path = Path(target).resolve()
                else:
                    abs_path = (self.repo_path / target).resolve()
                return str(abs_path).replace('\\', '/')
            else:
                return str(Path(target).resolve()).replace('\\', '/')
                
        except Exception:
            # Fallback to basic normalization
            return str(target).replace('\\', '/')
    
    def get_current_absolute_path(self) -> str:
        """Get current absolute path for reference"""
        return self.current_absolute_path
    
    def update_current_path(self, new_path: str) -> None:
        """Update current working path"""
        self.current_absolute_path = self.normalize_path(new_path)
    
    def basic_path_exists_check(self, path: str) -> bool:
        """Basic existence check without rule-based validation"""
        try:
            normalized = self.normalize_path(path)
            return os.path.exists(normalized)
        except:
            return False
    
    def is_directory(self, path: str) -> bool:
        """Check if path is a directory"""
        try:
            normalized = self.normalize_path(path)
            return os.path.isdir(normalized)
        except:
            return False
    
    def is_file(self, path: str) -> bool:
        """Check if path is a file"""
        try:
            normalized = self.normalize_path(path)
            return os.path.isfile(normalized)
        except:
            return False
    
    def get_path_depth(self, path: str) -> int:
        """Get path depth for LLM reference"""
        try:
            normalized = self.normalize_path(path)
            return len(Path(normalized).parts)
        except:
            return 0
    
    def get_path_info(self, path: str) -> Dict:
        """Get basic path information for LLM decision making"""
        normalized = self.normalize_path(path)
        return {
            'normalized_path': normalized,
            'exists': self.basic_path_exists_check(path),
            'is_directory': self.is_directory(path),
            'is_file': self.is_file(path),
            'depth': self.get_path_depth(path),
            'relative_from_repo': os.path.relpath(normalized, self.current_absolute_path) if self.current_absolute_path else normalized
        }
        
    def validate_target(self, path: str, action_type: str) -> Tuple[bool, str]:
        """Simple path validation for targets based on existence and basic type checks
        Returns (is_valid, reason)"""
        try:
            normalized = self.normalize_path(path)
            
            # Skip validation for actual system/hidden paths, but allow relative paths like ./openhands
            if (path.startswith('.') and len(path) > 1 and path[1] in ['/', '\\']) or \
               path in ['node_modules', '__pycache__', '.git', 'build', 'dist'] or \
               (path.startswith('.') and path.count('/') == 0 and path.count('\\') == 0 and len(path) <= 2):
                # Allow paths like "./openhands" but skip paths like ".", "..", ".gitignore"
                if path.startswith('./') or path.startswith('.\\'):
                    pass  # Allow these paths
                else:
                    return False, f"Skipping system/hidden path: {path}"
            
            # Enforce different validation based on action type
            if action_type in ['analyze_file', 'read_file']:
                if self.is_file(path):
                    return True, "Valid file"
                elif self.is_directory(path):
                    return False, f"Cannot analyze directory as file: {path}"
                elif not self.basic_path_exists_check(path):
                    return False, f"File does not exist: {path}"
            elif action_type in ['explore_directory', 'explore']:
                if self.is_directory(path):
                    return True, "Valid directory"
                elif self.is_file(path):
                    return False, f"Cannot explore file as directory: {path}"
                elif not self.basic_path_exists_check(path):
                    return False, f"Directory does not exist: {path}"
            
            return True, "Path is valid"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def get_path_category(self, path: str) -> str:
        """Simplified path categorization for LLM context
        Returns a simple category string based on file extension or path pattern"""
        if not path:
            return "unknown"
            
        normalized = self.normalize_path(path)
        
        # Basic file extension categorization
        if self.is_file(normalized):
            if normalized.endswith(('.py', '.pyc')):
                return "python_source"
            elif normalized.endswith(('.js', '.ts', '.jsx', '.tsx')):
                return "javascript_source"
            elif normalized.endswith(('.java', '.class', '.jar')):
                return "java_source"
            elif normalized.endswith(('.c', '.cpp', '.h', '.hpp')):
                return "c_cpp_source"
            elif normalized.endswith(('.go')):
                return "golang_source"
            elif normalized.endswith(('.sh', '.bash')):
                return "shell_script"
            elif normalized.endswith(('.json', '.yaml', '.yml', '.toml')):
                return "config_file"
            elif normalized.endswith(('.md', '.txt', '.rst')):
                return "documentation"
            else:
                return "general_file"
        
        # Basic directory pattern categorization
        if self.is_directory(normalized):
            path_lower = normalized.lower()
            if 'test' in path_lower:
                return "test_directory"
            elif any(name in path_lower for name in ['src', 'source', 'lib', 'pkg']):
                return "source_directory"
            elif any(name in path_lower for name in ['config', 'conf', 'settings']):
                return "config_directory"
            elif any(name in path_lower for name in ['doc', 'docs', 'documentation']):
                return "documentation_directory"
            else:
                return "general_directory"
                
        return "unknown"
    
