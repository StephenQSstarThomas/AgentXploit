"""
Unified analysis context manager

Provides a simple context management class to replace the existing knowledge_base dictionary.
Manages analysis state including explored directories and analyzed files.
"""

from typing import List, Set, Dict, Any


class AnalysisContext:
    """Analysis context manager for tracking global analysis state"""
    
    def __init__(self):
        self._explored_directories: Set[str] = set()
        self._analyzed_files: Set[str] = set()
        self._additional_data: Dict[str, Any] = {}
    
    def add_explored_directory(self, directory_path: str) -> None:
        self._explored_directories.add(directory_path)
    
    def add_analyzed_file(self, file_path: str) -> None:
        self._analyzed_files.add(file_path)
    
    def get_explored_directories(self) -> List[str]:
        return sorted(list(self._explored_directories))
    
    def get_analyzed_files(self) -> List[str]:
        return sorted(list(self._analyzed_files))
    
    def is_directory_explored(self, directory_path: str) -> bool:
        return directory_path in self._explored_directories
    
    def is_file_analyzed(self, file_path: str) -> bool:
        return file_path in self._analyzed_files
    
    def set_data(self, key: str, value: Any) -> None:
        self._additional_data[key] = value
    
    def get_data(self, key: str, default: Any = None) -> Any:
        return self._additional_data.get(key, default)
    
    def clear(self) -> None:
        """Reset all analysis state"""
        self._explored_directories.clear()
        self._analyzed_files.clear()
        self._additional_data.clear()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get context summary with counts and lists of explored/analyzed items"""
        return {
            "explored_directories_count": len(self._explored_directories),
            "analyzed_files_count": len(self._analyzed_files),
            "explored_directories": self.get_explored_directories(),
            "analyzed_files": self.get_analyzed_files(),
            "additional_data_keys": list(self._additional_data.keys())
        }
