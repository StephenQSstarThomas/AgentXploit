"""
Priority task queue for managing analysis tasks.
Implements a simple priority queue with task lifecycle management.
"""

import heapq
from typing import Dict, List, Optional
from .task import Task, TaskStatus


class TaskQueue:
    """Priority queue for analysis tasks, ordered by priority (higher = first)"""
    
    def __init__(self):
        self._heap: List[tuple] = []  # (negative_priority, counter, task)
        self._tasks: Dict[str, Task] = {}  # task_id -> Task
        self._counter = 0  # For stable sorting when priorities are equal
    
    def add_task(self, task: Task) -> None:
        """Add a task to the queue"""
        if task.task_id in self._tasks:
            return  # Task already exists
        
        self._tasks[task.task_id] = task
        # Use negative priority for max-heap behavior (higher priority first)
        heapq.heappush(self._heap, (-task.priority, self._counter, task))
        self._counter += 1
    
    def get_next(self) -> Optional[Task]:
        """Get the next highest priority pending task"""
        while self._heap:
            _, _, task = heapq.heappop(self._heap)
            
            # Check if task still exists and is pending
            if task.task_id in self._tasks and task.is_pending():
                return task
        
        return None
    
    def complete_task(self, task_id: str, result: Dict) -> bool:
        """Mark a task as completed with result"""
        if task_id not in self._tasks:
            return False
        
        task = self._tasks[task_id]
        task.set_completed(result)
        return True
    
    def fail_task(self, task_id: str, error_message: str) -> bool:
        """Mark a task as failed with error message"""
        if task_id not in self._tasks:
            return False
        
        task = self._tasks[task_id]
        task.set_failed(error_message)
        return True
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a specific task by ID"""
        return self._tasks.get(task_id)
    
    def get_pending_tasks(self) -> List[Task]:
        """Get all pending tasks sorted by priority"""
        pending = [task for task in self._tasks.values() if task.is_pending()]
        return sorted(pending, key=lambda t: -t.priority)  # Higher priority first
    
    def get_completed_tasks(self) -> List[Task]:
        """Get all completed tasks"""
        return [task for task in self._tasks.values() if task.is_completed()]
    
    def get_failed_tasks(self) -> List[Task]:
        """Get all failed tasks"""
        return [task for task in self._tasks.values() if task.is_failed()]
    
    def size(self) -> int:
        """Get total number of tasks in queue"""
        return len(self._tasks)
    
    def pending_count(self) -> int:
        """Get number of pending tasks"""
        return len([t for t in self._tasks.values() if t.is_pending()])
    
    def clear(self) -> None:
        """Remove all tasks from queue"""
        self._heap.clear()
        self._tasks.clear()
        self._counter = 0
    
    def get_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        stats = {"pending": 0, "running": 0, "completed": 0, "failed": 0}
        for task in self._tasks.values():
            if task.is_pending():
                stats["pending"] += 1
            elif task.is_running():
                stats["running"] += 1
            elif task.is_completed():
                stats["completed"] += 1
            elif task.is_failed():
                stats["failed"] += 1
        return stats