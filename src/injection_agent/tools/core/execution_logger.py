"""
Execution logger for tracking task executions.
Replaces multiple log lists with a unified logging system.
"""

import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .task import Task


@dataclass
class ExecutionLog:
    """Single execution log entry"""
    task_id: str
    task_type: str
    target: str
    duration: float
    success: bool
    timestamp: float
    result_summary: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "target": self.target,
            "duration": self.duration,
            "success": self.success,
            "timestamp": self.timestamp,
            "result_summary": self.result_summary,
            "error_message": self.error_message
        }


class ExecutionLogger:
    """Unified execution logging system"""
    
    def __init__(self):
        self._logs: List[ExecutionLog] = []
    
    def log_execution(self, task: Task, result: Dict[str, Any], duration: float) -> None:
        """Record a task execution"""
        success = result.get("success", False)
        error_message = result.get("error") if not success else None
        
        # Create result summary
        result_summary = None
        if success and result.get("result"):
            task_result = result["result"]
            if task.type.value == "explore":
                files_count = len(task_result.get("files", []))
                dirs_count = len(task_result.get("directories", []))
                result_summary = f"{files_count} files, {dirs_count} directories"
            elif task.type.value == "read":
                lines = task_result.get("lines", 0)
                size = task_result.get("size", 0)
                result_summary = f"{lines} lines, {size} chars"
            else:
                result_summary = "completed"
        
        log_entry = ExecutionLog(
            task_id=task.task_id,
            task_type=task.type.value,
            target=task.target,
            duration=duration,
            success=success,
            timestamp=time.time(),
            result_summary=result_summary,
            error_message=error_message
        )
        
        self._logs.append(log_entry)
    
    def get_recent_logs(self, n: int = 10) -> List[ExecutionLog]:
        """Get the most recent n log entries"""
        return self._logs[-n:] if n > 0 else self._logs
    
    def get_summary(self) -> Dict[str, Any]:
        """Get execution statistics summary"""
        if not self._logs:
            return {
                "total_executions": 0,
                "successful_executions": 0,
                "failed_executions": 0,
                "success_rate": 0.0,
                "average_duration": 0.0,
                "task_type_counts": {}
            }
        
        successful = sum(1 for log in self._logs if log.success)
        failed = len(self._logs) - successful
        total_duration = sum(log.duration for log in self._logs)
        
        # Count by task type
        task_type_counts = {}
        for log in self._logs:
            task_type_counts[log.task_type] = task_type_counts.get(log.task_type, 0) + 1
        
        return {
            "total_executions": len(self._logs),
            "successful_executions": successful,
            "failed_executions": failed,
            "success_rate": successful / len(self._logs) if self._logs else 0.0,
            "average_duration": total_duration / len(self._logs) if self._logs else 0.0,
            "task_type_counts": task_type_counts
        }
    
    def get_logs_by_type(self, task_type: str) -> List[ExecutionLog]:
        """Get all logs for a specific task type"""
        return [log for log in self._logs if log.task_type == task_type]
    
    def get_failed_logs(self) -> List[ExecutionLog]:
        """Get all failed execution logs"""
        return [log for log in self._logs if not log.success]
    
    def clear(self) -> None:
        """Clear all execution logs"""
        self._logs.clear()
    
    def get_logs_count(self) -> int:
        """Get total number of logs"""
        return len(self._logs)