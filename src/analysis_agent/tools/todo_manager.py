"""
Todo tracking tool for analysis agent - mimics Claude Code's TodoWrite functionality.
Implemented as a Google ADK custom tool.
"""
import logging
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

# State key for storing todos in tool context
TODOS_STATE_KEY = "analysis:todos"

# Try to import ToolContext, but make it optional
try:
    from google.adk.tools import ToolContext
except ImportError:
    # Create a dummy ToolContext type for type hints
    ToolContext = Any  # type: ignore


def todo_write(
    todos: List[Dict[str, str]],
    tool_context: Optional[ToolContext] = None
) -> dict:
    """Track and update analysis progress using a todo list.

    This tool mimics Claude Code's TodoWrite functionality for tracking multi-step
    analysis tasks. Call this tool to update the entire todo list.

    Args:
        todos: Complete list of todos. Each todo must have:
            - content: Task description (imperative form, e.g., "Analyze authentication flow")
            - status: One of "pending", "in_progress", or "completed"
            - activeForm: Present continuous form (e.g., "Analyzing authentication flow")
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "total_tasks": int,
            "pending": int,
            "in_progress": int,
            "completed": int,
            "current_todos": List[dict],
            "message": str
        }

    Example usage:
        todo_write(todos=[
            {
                "content": "Read target agent configuration files",
                "status": "completed",
                "activeForm": "Reading configuration files"
            },
            {
                "content": "Identify tool definitions and data flows",
                "status": "in_progress",
                "activeForm": "Identifying tool definitions"
            },
            {
                "content": "Map agent architecture and vulnerabilities",
                "status": "pending",
                "activeForm": "Mapping agent architecture"
            }
        ])

    Best practices:
    - Create todos for complex multi-step analysis (3+ distinct actions)
    - Update status to "in_progress" when starting a task
    - Mark as "completed" immediately after finishing
    - Only ONE task should be "in_progress" at a time
    - Use clear, specific task descriptions
    """
    try:
        # Validate input
        if not isinstance(todos, list):
            return {
                "success": False,
                "total_tasks": 0,
                "pending": 0,
                "in_progress": 0,
                "completed": 0,
                "current_todos": [],
                "message": "Error: todos must be a list"
            }

        # Validate each todo
        valid_statuses = {"pending", "in_progress", "completed"}
        for i, todo in enumerate(todos):
            if not isinstance(todo, dict):
                return {
                    "success": False,
                    "total_tasks": 0,
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "current_todos": [],
                    "message": f"Error: todo {i} is not a dictionary"
                }

            # Check required fields
            if not all(k in todo for k in ["content", "status", "activeForm"]):
                return {
                    "success": False,
                    "total_tasks": 0,
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "current_todos": [],
                    "message": f"Error: todo {i} missing required fields (content, status, activeForm)"
                }

            # Validate status
            if todo["status"] not in valid_statuses:
                return {
                    "success": False,
                    "total_tasks": 0,
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "current_todos": [],
                    "message": f"Error: todo {i} has invalid status '{todo['status']}'. Must be one of: {valid_statuses}"
                }

        # Store in tool context state if available
        if tool_context is not None:
            tool_context.state[TODOS_STATE_KEY] = todos

        # Calculate statistics
        total_tasks = len(todos)
        pending = sum(1 for t in todos if t["status"] == "pending")
        in_progress = sum(1 for t in todos if t["status"] == "in_progress")
        completed = sum(1 for t in todos if t["status"] == "completed")

        # Log the update
        logger.info(f"Todo list updated: {total_tasks} total, {completed} completed, {in_progress} in progress, {pending} pending")

        # Build friendly message
        if total_tasks == 0:
            message = "Todo list cleared"
        elif completed == total_tasks:
            message = f"All {total_tasks} tasks completed!"
        else:
            message = f"Tracking {total_tasks} tasks: {completed} completed, {in_progress} in progress, {pending} pending"

        return {
            "success": True,
            "total_tasks": total_tasks,
            "pending": pending,
            "in_progress": in_progress,
            "completed": completed,
            "current_todos": todos,
            "message": message
        }

    except Exception as e:
        logger.error(f"Todo write error: {e}", exc_info=True)
        return {
            "success": False,
            "total_tasks": 0,
            "pending": 0,
            "in_progress": 0,
            "completed": 0,
            "current_todos": [],
            "message": f"Error: {str(e)}"
        }


def todo_read(tool_context: Optional[ToolContext] = None) -> dict:
    """Read current todo list without modifying it.

    Args:
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: Current todos with statistics
    """
    try:
        # Retrieve from tool context state
        todos = []
        if tool_context is not None:
            todos = tool_context.state.get(TODOS_STATE_KEY, [])

        # Calculate statistics
        total_tasks = len(todos)
        pending = sum(1 for t in todos if t["status"] == "pending")
        in_progress = sum(1 for t in todos if t["status"] == "in_progress")
        completed = sum(1 for t in todos if t["status"] == "completed")

        return {
            "success": True,
            "total_tasks": total_tasks,
            "pending": pending,
            "in_progress": in_progress,
            "completed": completed,
            "current_todos": todos,
            "message": f"Found {total_tasks} todos" if total_tasks > 0 else "No todos yet"
        }

    except Exception as e:
        logger.error(f"Todo read error: {e}", exc_info=True)
        return {
            "success": False,
            "total_tasks": 0,
            "pending": 0,
            "in_progress": 0,
            "completed": 0,
            "current_todos": [],
            "message": f"Error: {str(e)}"
        }


__all__ = ["todo_write", "todo_read"]
