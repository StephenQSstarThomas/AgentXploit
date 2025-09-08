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

import re
from typing import Tuple


class IssueExtractor:
    """Utility class for extracting issue content from user input"""
    
    @staticmethod
    def extract_issue_content(user_input: str) -> Tuple[str, int, int]:
        """
        Extract content between <issue> and </issue> tags
        
        Args:
            user_input: The user input containing issue tags
            
        Returns:
            Tuple of (issue_content, start_position, end_position)
        """
        match = re.search(r'<issue>(.*?)</issue>', user_input, re.DOTALL)
        if match:
            return match.group(1), match.start(1), match.end(1)
        return "", -1, -1
    
    @staticmethod
    def find_sections(issue_content: str) -> list:
        """
        Find specific sections within issue content
        
        Args:
            issue_content: The extracted issue content
            
        Returns:
            List of tuples containing (pattern, description) for found sections
        """
        sections = [
            (r'##?\s*Steps to Reproduce', "Steps to Reproduce section"),
            (r'##?\s*Expected Behavior', "Expected Behavior section"),
            (r'##?\s*Observed Behavior', "Observed Behavior section"),
            (r'```[\s\S]*?```', "Code block"),
            (r'##?\s*Configuration', "Configuration section"),
            (r'##?\s*Error\s*Messages?', "Error Messages section"),
            (r'##?\s*Stack\s*Trace', "Stack Trace section"),
        ]
        
        found_sections = []
        for pattern, description in sections:
            matches = list(re.finditer(pattern, issue_content, re.IGNORECASE | re.MULTILINE))
            for match in matches:
                found_sections.append({
                    "pattern": pattern,
                    "description": description,
                    "start": match.start(),
                    "end": match.end(),
                    "content": match.group()[:100] + "..." if len(match.group()) > 100 else match.group()
                })
        
        return found_sections 