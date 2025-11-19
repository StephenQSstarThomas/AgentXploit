"""
Status checker tool - provides comprehensive analysis status and readiness checks.

This tool helps the agent understand its current state and decide whether to continue
analyzing or move to report generation. It prevents premature termination by providing
clear readiness metrics and recommendations.
"""
import logging
import json
import os
from typing import Optional, Any, Dict, List

logger = logging.getLogger(__name__)

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any

from .incremental_writer import _get_incremental_json_path, _load_or_create_incremental_json
from .todo_manager import TodoTracker


def check_status(
    include_recent_events: int = 5,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Check comprehensive analysis status and readiness.

    Use this tool to understand:
    - How many tools have been analyzed
    - Current todo progress
    - Recent activity (trace events)
    - Whether analysis is ready for report generation
    - What to do next

    This tool is crucial for preventing premature termination. Always call it
    before deciding to stop or when you want to verify progress.

    Args:
        include_recent_events: Number of recent trace events to include (default: 5, max: 20)
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: Comprehensive status with fields:
            - success (bool): Whether status was retrieved successfully
            - message (str): Summary message
            - session (dict): Session info (session_id, agent_name, timestamps, duration)
            - progress (dict): Progress metrics (tools counts, completion percentage)
            - current_state (dict): Current todos status and active task
            - recent_activity (list): Last N events from analysis trace
            - environment (dict): Environment detection status
            - readiness (dict): Readiness checks and recommendation
            - paths (dict): File paths (incremental_json, report_path)

    Example usage:
        # Check status before deciding whether to continue
        status = check_status(include_recent_events=10)

        if status["readiness"]["recommendation"] == "ready_for_report":
            write_report()
        else:
            # Continue with next tool analysis
            ...
    """
    try:
        # Validate include_recent_events parameter
        include_recent_events = max(1, min(include_recent_events, 20))

        # Get incremental JSON path
        json_path = _get_incremental_json_path(tool_context)

        # Get agent name from context
        agent_name = None
        if tool_context is not None:
            agent_name = tool_context.state.get("agent_name")

        # Load incremental JSON data
        if not os.path.exists(json_path):
            return {
                "success": False,
                "message": "No analysis session found. Call start_analysis_session() first.",
                "readiness": {
                    "recommendation": "start_session"
                }
            }

        data = _load_or_create_incremental_json(json_path, agent_name)

        # === SESSION INFO ===
        session_info = {
            "session_id": data.get("session_id", "unknown"),
            "agent_name": data.get("agent_name", "unknown"),
            "analysis_start": data.get("analysis_start"),
            "last_updated": data.get("last_updated"),
            "duration_seconds": _calculate_duration(
                data.get("analysis_start"),
                data.get("last_updated")
            )
        }

        # === PROGRESS METRICS ===
        tools_list = data.get("tools", [])

        # Count fully analyzed tools (have all 3 components)
        tools_fully_analyzed = sum(
            1 for tool in tools_list
            if all(k in tool for k in ["tool_info", "dataflow", "vulnerabilities"])
        )

        # Count tools with vulnerabilities
        tools_with_vulns = sum(
            1 for tool in tools_list
            if tool.get("vulnerabilities", {}).get("has_vulnerabilities", False)
        )

        # Calculate completion percentage
        tools_discovered = len(tools_list)
        completion_percentage = 0.0
        if tools_discovered > 0:
            completion_percentage = (tools_fully_analyzed / max(5, tools_discovered)) * 100

        progress = {
            "tools_discovered": tools_discovered,
            "tools_analyzed": tools_fully_analyzed,
            "tools_with_vulnerabilities": tools_with_vulns,
            "analysis_status": data.get("analysis_status", "in_progress"),
            "completion_percentage": round(completion_percentage, 1)
        }

        # === CURRENT STATE (TODOS) ===
        todos_data = data.get("todos", [])
        todos_total = len(todos_data)
        todos_pending = sum(1 for t in todos_data if t.get("status") == "pending")
        todos_in_progress = sum(1 for t in todos_data if t.get("status") == "in_progress")
        todos_completed = sum(1 for t in todos_data if t.get("status") == "completed")

        # Find current task (first in_progress todo)
        current_task = "None"
        for todo in todos_data:
            if todo.get("status") == "in_progress":
                current_task = todo.get("content", "Unknown task")
                break

        current_state = {
            "todos_total": todos_total,
            "todos_pending": todos_pending,
            "todos_in_progress": todos_in_progress,
            "todos_completed": todos_completed,
            "current_task": current_task
        }

        # === RECENT ACTIVITY ===
        analysis_log = data.get("analysis_log", [])
        recent_activity = analysis_log[-include_recent_events:] if analysis_log else []

        # === ENVIRONMENT STATUS ===
        env_data = data.get("environment", {})
        environment = {
            "framework_detected": env_data.get("framework") is not None,
            "framework": env_data.get("framework"),
            "docker_required": env_data.get("docker_required"),
            "dependencies_count": len(env_data.get("dependencies", [])),
            "config_files_count": len(env_data.get("config_files", []))
        }

        # === READINESS CHECKS ===

        # Check if write_report was called
        write_report_called = any(
            event.get("event") == "report_generated"
            for event in analysis_log
        )

        # Minimum tools threshold (at least 5 tools should be fully analyzed)
        minimum_tools_met = tools_fully_analyzed >= 5

        # All todos completed
        all_todos_completed = (todos_total > 0) and (todos_completed == todos_total)

        # Can generate report
        can_generate_report = minimum_tools_met and not write_report_called

        # Determine recommendation
        if write_report_called:
            recommendation = "analysis_complete"
            recommendation_msg = "Analysis complete! Report has been generated."
        elif can_generate_report and all_todos_completed:
            recommendation = "ready_for_report"
            recommendation_msg = f"Ready to generate report! {tools_fully_analyzed} tools analyzed and all todos completed."
        elif tools_discovered == 0:
            recommendation = "start_exploration"
            recommendation_msg = "No tools discovered yet. Start by exploring the codebase with list_directory and read_code."
        elif tools_fully_analyzed < 5:
            recommendation = "continue_analysis"
            recommendation_msg = f"Continue analyzing tools. Progress: {tools_fully_analyzed}/5 minimum tools analyzed."
        elif not all_todos_completed:
            recommendation = "complete_todos"
            recommendation_msg = f"Complete pending todos before generating report. {todos_pending} pending, {todos_in_progress} in progress."
        else:
            recommendation = "ready_for_report"
            recommendation_msg = f"Ready to generate report! {tools_fully_analyzed} tools analyzed."

        readiness = {
            "can_generate_report": can_generate_report,
            "minimum_tools_analyzed": minimum_tools_met,
            "all_todos_completed": all_todos_completed,
            "write_report_called": write_report_called,
            "recommendation": recommendation,
            "recommendation_message": recommendation_msg
        }

        # === PATHS ===
        paths = {
            "incremental_json": json_path,
            "report_path": None  # Will be set after report generation
        }

        # Build summary message
        summary_lines = [
            f"Analysis Status: {progress['analysis_status']}",
            f"Tools: {tools_fully_analyzed} analyzed / {tools_discovered} discovered ({completion_percentage:.1f}% complete)",
            f"Todos: {todos_completed}/{todos_total} completed",
            f"Recommendation: {recommendation_msg}"
        ]
        message = " | ".join(summary_lines)

        logger.info(f"Status check: {message}")

        return {
            "success": True,
            "message": message,
            "session": session_info,
            "progress": progress,
            "current_state": current_state,
            "recent_activity": recent_activity,
            "environment": environment,
            "readiness": readiness,
            "paths": paths
        }

    except Exception as e:
        logger.error(f"Status check error: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error checking status: {str(e)}",
            "readiness": {
                "recommendation": "error",
                "recommendation_message": "Failed to check status. See error message."
            }
        }


def _calculate_duration(start_time: Optional[str], end_time: Optional[str]) -> int:
    """
    Calculate duration in seconds between two timestamps.

    Args:
        start_time: Start timestamp (format: "YYYY-MM-DD HH:MM:SS")
        end_time: End timestamp (format: "YYYY-MM-DD HH:MM:SS")

    Returns:
        int: Duration in seconds, or 0 if timestamps are invalid
    """
    if not start_time or not end_time:
        return 0

    try:
        from datetime import datetime
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        duration = (end_dt - start_dt).total_seconds()
        return int(duration)
    except Exception:
        return 0


__all__ = ["check_status"]
