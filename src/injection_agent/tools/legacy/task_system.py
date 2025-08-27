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
Simplified task system for analysis workflow management
"""

import heapq
from dataclasses import dataclass
from typing import Dict, List, Optional, Any


@dataclass
class Task:
    """Simple task definition"""
    type: str  # "explore", "read", "analyze"
    target: str
    priority: int = 0
    result: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if not hasattr(self, 'task_id'):
            import uuid
            self.task_id = str(uuid.uuid4())[:8]


class TaskQueue:
    """Simple priority queue for analysis tasks"""
    
    def __init__(self):
        self._heap = []
        self._counter = 0
        
    def add_task(self, task_type: str, target: str, priority: int = 0) -> Task:
        """Add a new task to the queue"""
        task = Task(type=task_type, target=target, priority=priority)
        heapq.heappush(self._heap, (-priority, self._counter, task))
        self._counter += 1
        return task
    
    def get_next(self) -> Optional[Task]:
        """Get the next highest priority task"""
        if self._heap:
            _, _, task = heapq.heappop(self._heap)
            return task
        return None
    
    def size(self) -> int:
        """Get number of pending tasks"""
        return len(self._heap)
    
    def clear(self) -> None:
        """Clear all tasks"""
        self._heap.clear()
        self._counter = 0