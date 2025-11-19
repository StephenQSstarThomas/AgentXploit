"""
Todo tracking tool for analysis agent - mimics Claude Code's TodoWrite functionality.
Implemented as a Google ADK custom tool with auto-tracking capabilities.
"""
import logging
import re
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)

# State key for storing todos in tool context
TODOS_STATE_KEY = "analysis:todos"
TRACKER_STATE_KEY = "analysis:todo_tracker"

# Try to import ToolContext, but make it optional
try:
    from google.adk.tools import ToolContext
except ImportError:
    # Create a dummy ToolContext type for type hints
    ToolContext = Any  # type: ignore


@dataclass
class Todo:
    """Todo item with auto-tracking support."""
    content: str
    status: str  # pending, in_progress, completed
    activeForm: str
    id: Optional[str] = None  # Auto-generated unique ID
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    tool_pattern: Optional[str] = None  # Regex pattern to match tool calls
    auto_track: bool = True  # Enable auto-tracking for this todo

    def __post_init__(self):
        if self.id is None:
            # Generate ID from content
            self.id = re.sub(r'[^a-z0-9]+', '_', self.content.lower())[:50]
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.updated_at is None:
            self.updated_at = self.created_at

    def to_dict(self) -> dict:
        """Convert to dictionary for tool response."""
        return {
            "content": self.content,
            "status": self.status,
            "activeForm": self.activeForm,
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

    def update_status(self, new_status: str):
        """Update todo status."""
        if new_status in ["pending", "in_progress", "completed"]:
            old_status = self.status
            self.status = new_status
            self.updated_at = datetime.now().isoformat()
            # Log status change
            if old_status != new_status:
                logger.info(f"Todo '{self.content}' status changed: {old_status} → {new_status}")


class TodoTracker:
    """Auto-tracking system for todos based on tool calls."""

    def __init__(self):
        self.todos: Dict[str, Todo] = {}
        self.tool_todo_map: Dict[str, str] = {}  # tool_pattern -> todo_id

    @classmethod
    def from_state(cls, tool_context: Optional[ToolContext]) -> Optional['TodoTracker']:
        """Reconstruct TodoTracker from serialized state.

        Args:
            tool_context: ADK tool context containing state

        Returns:
            TodoTracker instance or None if no state found
        """
        if tool_context is None:
            return None

        todos_list = tool_context.state.get(TODOS_STATE_KEY, [])
        tool_map = tool_context.state.get(TRACKER_STATE_KEY + "_map", {})

        if not todos_list:
            return None

        # Reconstruct tracker from stored data
        tracker = cls()
        tracker.tool_todo_map = dict(tool_map)

        # Reconstruct Todo objects from dictionaries
        for todo_dict in todos_list:
            todo = Todo(
                content=todo_dict["content"],
                status=todo_dict["status"],
                activeForm=todo_dict["activeForm"],
                id=todo_dict.get("id"),
                created_at=todo_dict.get("created_at"),
                updated_at=todo_dict.get("updated_at")
            )
            tracker.todos[todo.id] = todo

        return tracker

    def save_to_state(self, tool_context: Optional[ToolContext]):
        """Save tracker state to tool context (serializable format).

        Args:
            tool_context: ADK tool context to save state to
        """
        if tool_context is not None:
            tool_context.state[TODOS_STATE_KEY] = self.get_todos_list()
            tool_context.state[TRACKER_STATE_KEY + "_map"] = dict(self.tool_todo_map)

    def add_todo(self, todo: Todo):
        """Add a new todo to tracking system."""
        self.todos[todo.id] = todo
        if todo.tool_pattern and todo.auto_track:
            self.tool_todo_map[todo.tool_pattern] = todo.id

    def update_todo(self, todo_id: str, status: str) -> bool:
        """Update todo status by ID."""
        if todo_id in self.todos:
            old_status = self.todos[todo_id].status
            self.todos[todo_id].update_status(status)
            logger.info(f"Todo '{todo_id}' manually updated: {old_status} → {status}")
            return True
        logger.warning(f"Attempted to update non-existent todo: {todo_id}")
        return False

    def mark_in_progress_by_tool(self, tool_name: str) -> Optional[str]:
        """Auto-mark todo as in_progress when tool is called."""
        for pattern, todo_id in self.tool_todo_map.items():
            if re.search(pattern, tool_name, re.IGNORECASE):
                todo = self.todos.get(todo_id)
                if todo and todo.status == "pending":
                    todo.update_status("in_progress")
                    logger.info(f"Auto-marked todo '{todo.content}' as in_progress (tool: {tool_name})")
                    return todo_id
        return None

    def mark_completed_by_tool(self, tool_name: str) -> Optional[str]:
        """Auto-mark todo as completed when tool finishes successfully."""
        for pattern, todo_id in self.tool_todo_map.items():
            if re.search(pattern, tool_name, re.IGNORECASE):
                todo = self.todos.get(todo_id)
                if todo and todo.status == "in_progress":
                    todo.update_status("completed")
                    logger.info(f"Auto-marked todo '{todo.content}' as completed (tool: {tool_name})")
                    return todo_id
        return None

    def get_todos_list(self) -> List[dict]:
        """Get list of todos as dictionaries."""
        return [todo.to_dict() for todo in self.todos.values()]

    def get_stats(self) -> dict:
        """Get todo statistics."""
        todos = list(self.todos.values())
        return {
            "total": len(todos),
            "pending": sum(1 for t in todos if t.status == "pending"),
            "in_progress": sum(1 for t in todos if t.status == "in_progress"),
            "completed": sum(1 for t in todos if t.status == "completed")
        }


def todo_write(
    todos: List[Dict[str, str]],
    tool_context: Optional[ToolContext] = None
) -> dict:
    """Track and update analysis progress using a todo list with auto-tracking support.

    This tool mimics Claude Code's TodoWrite functionality for tracking multi-step
    analysis tasks. Call this tool to update the entire todo list.

    Args:
        todos: Complete list of todos. Each todo must have:
            - content: Task description (imperative form, e.g., "Analyze authentication flow")
            - status: One of "pending", "in_progress", or "completed"
            - activeForm: Present continuous form (e.g., "Analyzing authentication flow")
            - tool_pattern (optional): Regex pattern to auto-match tool calls (e.g., "read_code|search_code")
            - auto_track (optional): Enable auto-tracking (default: True)
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "total_tasks": int,
            "pending": int,
            "in_progress": int,
            "completed": int,
            "current_todos": List[dict],
            "auto_tracking_enabled": bool,
            "message": str
        }

    Example usage with auto-tracking:
        todo_write(todos=[
            {
                "content": "Read target agent configuration files",
                "status": "pending",
                "activeForm": "Reading configuration files",
                "tool_pattern": "read_code",  # Auto-track read_code calls
                "auto_track": True
            },
            {
                "content": "Search for tool definitions",
                "status": "pending",
                "activeForm": "Searching for tool definitions",
                "tool_pattern": "search_code",  # Auto-track search_code calls
            }
        ])

    Best practices:
    - Use tool_pattern to enable auto-tracking for specific todos
    - Pattern will auto-mark todo as "in_progress" when tool is called
    - Pattern will auto-mark todo as "completed" when tool succeeds
    - Only ONE task should be "in_progress" at a time
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
                "auto_tracking_enabled": False,
                "message": "Error: todos must be a list"
            }

        # Validate and convert todos to Todo objects
        valid_statuses = {"pending", "in_progress", "completed"}
        tracker = TodoTracker()

        for i, todo_dict in enumerate(todos):
            if not isinstance(todo_dict, dict):
                return {
                    "success": False,
                    "total_tasks": 0,
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "current_todos": [],
                    "auto_tracking_enabled": False,
                    "message": f"Error: todo {i} is not a dictionary"
                }

            # Check required fields
            if not all(k in todo_dict for k in ["content", "status", "activeForm"]):
                return {
                    "success": False,
                    "total_tasks": 0,
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "current_todos": [],
                    "auto_tracking_enabled": False,
                    "message": f"Error: todo {i} missing required fields (content, status, activeForm)"
                }

            # Validate status
            if todo_dict["status"] not in valid_statuses:
                return {
                    "success": False,
                    "total_tasks": 0,
                    "pending": 0,
                    "in_progress": 0,
                    "completed": 0,
                    "current_todos": [],
                    "auto_tracking_enabled": False,
                    "message": f"Error: todo {i} has invalid status '{todo_dict['status']}'. Must be one of: {valid_statuses}"
                }

            # Create Todo object
            todo = Todo(
                content=todo_dict["content"],
                status=todo_dict["status"],
                activeForm=todo_dict["activeForm"],
                id=todo_dict.get("id"),
                tool_pattern=todo_dict.get("tool_pattern"),
                auto_track=todo_dict.get("auto_track", True)
            )
            tracker.add_todo(todo)

        # Save tracker state to tool context (serializable format only)
        tracker.save_to_state(tool_context)

        # Get statistics
        stats = tracker.get_stats()

        # Log the update
        logger.info(f"Todo list updated: {stats['total']} total, {stats['completed']} completed, {stats['in_progress']} in progress, {stats['pending']} pending")

        # Check if auto-tracking is enabled
        auto_tracking_enabled = any(t.auto_track and t.tool_pattern for t in tracker.todos.values())

        # Sync todos to incremental JSON
        try:
            from .incremental_writer import sync_todos_to_json
            sync_todos_to_json(tracker.get_todos_list(), tool_context)
            logger.info("Synced todos to incremental JSON")
        except Exception as e:
            logger.warning(f"Failed to sync todos to incremental JSON: {e}")

        # Build friendly message
        if stats['total'] == 0:
            message = "Todo list cleared"
        elif stats['completed'] == stats['total']:
            message = f"All {stats['total']} tasks completed!"
        else:
            tracking_msg = " (auto-tracking enabled)" if auto_tracking_enabled else ""
            message = f"Tracking {stats['total']} tasks: {stats['completed']} completed, {stats['in_progress']} in progress, {stats['pending']} pending{tracking_msg}"

        return {
            "success": True,
            "total_tasks": stats['total'],
            "pending": stats['pending'],
            "in_progress": stats['in_progress'],
            "completed": stats['completed'],
            "current_todos": tracker.get_todos_list(),
            "auto_tracking_enabled": auto_tracking_enabled,
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
            "auto_tracking_enabled": False,
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
        # Retrieve tracker from tool context state
        tracker = TodoTracker.from_state(tool_context)

        if tracker is None:
            # Fallback to legacy todos format
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
                "auto_tracking_enabled": False,
                "message": f"Found {total_tasks} todos" if total_tasks > 0 else "No todos yet"
            }

        # Use tracker
        stats = tracker.get_stats()
        auto_tracking_enabled = any(t.auto_track and t.tool_pattern for t in tracker.todos.values())

        return {
            "success": True,
            "total_tasks": stats['total'],
            "pending": stats['pending'],
            "in_progress": stats['in_progress'],
            "completed": stats['completed'],
            "current_todos": tracker.get_todos_list(),
            "auto_tracking_enabled": auto_tracking_enabled,
            "message": f"Found {stats['total']} todos" if stats['total'] > 0 else "No todos yet"
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
            "auto_tracking_enabled": False,
            "message": f"Error: {str(e)}"
        }


def todo_update(
    todo_id: str,
    status: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """Update a single todo's status by ID (incremental update).

    Args:
        todo_id: ID of the todo to update
        status: New status ("pending", "in_progress", or "completed")
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: Update result with current todos
    """
    try:
        tracker = TodoTracker.from_state(tool_context)

        if tracker is None:
            return {
                "success": False,
                "message": "No todo tracker found. Use todo_write first to initialize todos."
            }

        if status not in ["pending", "in_progress", "completed"]:
            return {
                "success": False,
                "message": f"Invalid status '{status}'. Must be pending, in_progress, or completed."
            }

        # Get old status for logging
        old_status = tracker.todos.get(todo_id).status if todo_id in tracker.todos else None

        success = tracker.update_todo(todo_id, status)
        if not success:
            logger.warning(f"Failed to update todo '{todo_id}': not found")
            return {
                "success": False,
                "message": f"Todo with ID '{todo_id}' not found"
            }

        # Save updated state
        tracker.save_to_state(tool_context)

        stats = tracker.get_stats()
        logger.info(f"Todo '{todo_id}' updated: {old_status} → {status} | Stats: {stats['completed']}/{stats['total']} completed")

        return {
            "success": True,
            "updated_id": todo_id,
            "new_status": status,
            "stats": stats,
            "current_todos": tracker.get_todos_list(),
            "message": f"Todo updated to '{status}'"
        }

    except Exception as e:
        logger.error(f"Todo update error: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }


def todo_add(
    content: str,
    activeForm: str,
    tool_pattern: Optional[str] = None,
    auto_track: bool = True,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """Add a new todo to the list (incremental add).

    Args:
        content: Task description (imperative form)
        activeForm: Present continuous form
        tool_pattern: Optional regex pattern to auto-match tool calls
        auto_track: Enable auto-tracking (default: True)
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: Add result with current todos
    """
    try:
        tracker = TodoTracker.from_state(tool_context)

        if tracker is None:
            # Initialize new tracker
            tracker = TodoTracker()

        # Create new todo
        new_todo = Todo(
            content=content,
            status="pending",
            activeForm=activeForm,
            tool_pattern=tool_pattern,
            auto_track=auto_track
        )
        tracker.add_todo(new_todo)

        # Save updated state
        tracker.save_to_state(tool_context)

        stats = tracker.get_stats()
        logger.info(f"New todo added: '{content}' (ID: {new_todo.id}) | Stats: {stats['completed']}/{stats['total']} total")

        return {
            "success": True,
            "added_id": new_todo.id,
            "stats": stats,
            "current_todos": tracker.get_todos_list(),
            "message": f"New todo added: {content}"
        }

    except Exception as e:
        logger.error(f"Todo add error: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }


def todo_complete(
    todo_id: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """Mark a todo as completed (convenience function).

    Args:
        todo_id: ID of the todo to complete
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: Completion result
    """
    return todo_update(todo_id, "completed", tool_context)


def on_tool_call(tool_name: str, tool_context: Optional[ToolContext] = None) -> Optional[str]:
    """Hook function called when any tool is invoked (auto-tracking).

    This function should be called before tool execution to auto-mark
    todos as "in_progress" based on tool_pattern matching.

    Args:
        tool_name: Name of the tool being called
        tool_context: ADK tool context

    Returns:
        Optional[str]: ID of the todo that was auto-marked as in_progress
    """
    try:
        if tool_context is None:
            return None

        tracker = TodoTracker.from_state(tool_context)
        if tracker is None:
            return None

        # Auto-mark matching todo as in_progress
        todo_id = tracker.mark_in_progress_by_tool(tool_name)
        if todo_id:
            # Save updated state
            tracker.save_to_state(tool_context)

        return todo_id

    except Exception as e:
        logger.error(f"Tool call hook error: {e}", exc_info=True)
        return None


def on_tool_success(tool_name: str, tool_context: Optional[ToolContext] = None) -> Optional[str]:
    """Hook function called when a tool completes successfully (auto-tracking).

    This function should be called after successful tool execution to auto-mark
    todos as "completed" based on tool_pattern matching.

    Args:
        tool_name: Name of the tool that completed
        tool_context: ADK tool context

    Returns:
        Optional[str]: ID of the todo that was auto-marked as completed
    """
    try:
        if tool_context is None:
            return None

        tracker = TodoTracker.from_state(tool_context)
        if tracker is None:
            return None

        # Auto-mark matching todo as completed
        todo_id = tracker.mark_completed_by_tool(tool_name)
        if todo_id:
            # Save updated state
            tracker.save_to_state(tool_context)

        return todo_id

    except Exception as e:
        logger.error(f"Tool success hook error: {e}", exc_info=True)
        return None


__all__ = [
    "todo_write",
    "todo_read",
    "todo_update",
    "todo_add",
    "todo_complete",
    "on_tool_call",
    "on_tool_success",
    "TodoTracker",
    "Todo"
]
