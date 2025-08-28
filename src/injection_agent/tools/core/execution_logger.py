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
    """Simplified execution log entry with trace logging"""
    step: int
    action: str
    target: str
    result: str
    extra_actions: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "step": self.step,
            "action": self.action,
            "target": self.target,
            "result": self.result
        }
        if self.extra_actions:
            data["extra_actions"] = self.extra_actions
        return data


class ExecutionLogger:
    """Simplified execution logging system"""

    def __init__(self):
        self._logs: List[ExecutionLog] = []
        self._step_counter = 0

    def log_execution(self, task: Task, result: Dict[str, Any], step: int,
                     extra_actions: Optional[List[Dict[str, Any]]] = None) -> None:
        """Record a task execution with trace logging format"""
        success = result.get("success", False)

        # Create simple result description
        if success:
            if task.type.value == "explore":
                task_result = result.get("result", {})
                files_count = len(task_result.get("files", []))
                dirs_count = len(task_result.get("directories", []))
                result_desc = f"Found {files_count} files, {dirs_count} directories"
            elif task.type.value == "read":
                task_result = result.get("result", {})
                # Try different possible line count fields
                lines = task_result.get("total_lines", task_result.get("lines_read", task_result.get("lines", 0)))
                result_desc = f"Read {lines} lines"
            else:
                result_desc = "Completed"
        else:
            error_msg = result.get("error", "Unknown error")
            result_desc = f"Failed: {error_msg}"

        log_entry = ExecutionLog(
            step=step,
            action=task.type.value.upper(),
            target=task.target,
            result=result_desc,
            extra_actions=extra_actions
        )

        self._logs.append(log_entry)
    
    def get_recent_logs(self, n: int = 10) -> List[ExecutionLog]:
        """Get the most recent n log entries"""
        return self._logs[-n:] if n > 0 else self._logs
    
    def get_summary(self) -> Dict[str, Any]:
        """Get simplified execution statistics summary"""
        if not self._logs:
            return {"total_executions": 0}

        return {
            "total_executions": len(self._logs),
            "latest_step": max((log.step for log in self._logs), default=0)
        }

    def get_trace_logs(self) -> List[Dict[str, Any]]:
        """Get all execution logs in trace format"""
        return [log.to_dict() for log in self._logs]
    
    def get_logs_by_action(self, action: str) -> List[ExecutionLog]:
        """Get all logs for a specific action type"""
        return [log for log in self._logs if log.action == action]

    def get_failed_logs(self) -> List[ExecutionLog]:
        """Get all failed execution logs"""
        return [log for log in self._logs if "Failed" in log.result]
    
    def clear(self) -> None:
        """Clear all execution logs"""
        self._logs.clear()
    
    def get_logs_count(self) -> int:
        """Get total number of logs"""
        return len(self._logs)