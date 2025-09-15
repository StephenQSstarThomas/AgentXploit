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

import json
import os
from typing import List, Dict, Optional
from ..config import settings


class SWEBenchLoader:
    """Utility class for loading and searching SWEBench data"""
    
    def __init__(self):
        self.data = self._load_data()
    
    def _load_data(self) -> List[Dict]:
        """Load SWEBenchlite.json data"""
        swebench_path = os.path.join(settings.TRAJECTORIES_DIR, settings.SWEBENCH_FILE)
        if os.path.exists(swebench_path):
            with open(swebench_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    
    def find_matching_id(self, issue_content: str) -> Optional[str]:
        """Find matching ID in SWEBenchlite.json based on problem statement"""
        if not issue_content:
            return None
            
        for entry in self.data:
            problem_statement = entry.get('problem_statement', '')
            if problem_statement and issue_content.startswith(problem_statement[:100]):
                return entry.get('instance_id')
        
        return None 