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
Security scanner for detecting dangerous patterns in code
"""

import re
from typing import List, Tuple


# Dangerous patterns to detect
DANGEROUS_PATTERNS = [
    ("exec", "high"),
    ("eval", "high"), 
    ("subprocess", "medium"),
    ("os.system", "high"),
    ("os.popen", "medium"),
    ("shell=True", "medium"),
    ("pickle.loads", "high"),
    ("yaml.load", "medium"),
    ("marshal.loads", "high"),
    ("input.*exec", "high"),
    ("getattr.*exec", "high")
]


def scan_file(content: str) -> List[Tuple[str, int, str]]:
    """
    Scan file content for dangerous patterns
    
    Args:
        content: File content to scan
        
    Returns:
        List of (pattern, line_num, risk_level) tuples
    """
    findings = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for pattern, risk_level in DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append((pattern, line_num, risk_level))
    
    return findings


def scan_directory(tools, directory: str = ".") -> dict:
    """
    Scan directory for security issues
    
    Args:
        tools: CoreTools instance for file operations
        directory: Directory to scan
        
    Returns:
        Security scan results
    """
    results = {
        "high_risk": [],
        "medium_risk": [],
        "total_files": 0,
        "total_issues": 0
    }
    
    # Get directory listing
    dir_result = tools.list_directory(directory)
    if "error" in dir_result:
        return {"error": dir_result["error"]}
    
    # Scan Python files
    for item in dir_result["items"]:
        if item["type"] == "file" and item["path"].endswith(".py"):
            results["total_files"] += 1
            
            # Read file content
            file_result = tools.read_file(item["path"])
            if "error" not in file_result:
                findings = scan_file(file_result["content"])
                
                for pattern, line_num, risk_level in findings:
                    issue = {
                        "file": item["path"],
                        "pattern": pattern,
                        "line": line_num,
                        "risk": risk_level
                    }
                    
                    if risk_level == "high":
                        results["high_risk"].append(issue)
                    else:
                        results["medium_risk"].append(issue)
                    
                    results["total_issues"] += 1
    
    return results