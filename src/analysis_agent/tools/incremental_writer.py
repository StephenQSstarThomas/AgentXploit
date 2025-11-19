"""
Incremental analysis writer - saves tool analysis results progressively.

This module provides tools for incrementally writing analysis results to a JSON file
as tools are discovered and analyzed, rather than waiting until the end.
"""
import logging
import json
import os
import time
from typing import Optional, Any, Dict, List

logger = logging.getLogger(__name__)

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any


def _get_incremental_json_path(tool_context: Optional[ToolContext] = None) -> str:
    """
    Get the path to the incremental JSON file for the current session.

    Args:
        tool_context: ADK tool context (auto-injected)

    Returns:
        str: Path to incremental JSON file
    """
    if tool_context is not None:
        # Check if path is already stored in context
        stored_path = tool_context.state.get("incremental_json_path")
        if stored_path:
            return stored_path

    # Default path if no context
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(script_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    agent_name = tool_context.state.get("agent_name", "unknown") if tool_context else "unknown"
    filename = f"incremental_analysis_{agent_name}_{timestamp}.json"
    path = os.path.join(reports_dir, filename)

    # Store in context for reuse
    if tool_context is not None:
        tool_context.state["incremental_json_path"] = path

    return path


def _load_or_create_incremental_json(path: str, agent_name: str = None) -> dict:
    """
    Load existing incremental JSON or create new one.

    Args:
        path: Path to JSON file
        agent_name: Name of agent being analyzed

    Returns:
        dict: Incremental analysis data
    """
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    # Create new structure
    return {
        "session_id": None,
        "agent_name": agent_name or "unknown",
        "analysis_start": time.strftime("%Y-%m-%d %H:%M:%S"),
        "analysis_status": "in_progress",
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tools": [],
        "environment": {
            "docker_required": None,
            "dependencies": [],
            "config_files": [],
            "framework": None,
            "entry_points": []
        },
        "todos": [],
        "analysis_log": []
    }


def _save_incremental_json(path: str, data: dict):
    """
    Save incremental JSON data to file.

    Args:
        path: Path to JSON file
        data: Data to save
    """
    data["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved incremental analysis to: {path}")


def save_tool_analysis(
    tool_name: str,
    tool_info: dict,
    dataflow: dict,
    vulnerabilities: dict,
    position: Optional[str] = None,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Save a single tool's analysis results to the incremental JSON file.

    This function should be called immediately after completing the 3-round analysis
    of a tool (extract_tool_info → extract_dataflow → extract_vulnerabilities).

    Args:
        tool_name: Name of the analyzed tool
        tool_info: Results from extract_tool_info (Round 1)
        dataflow: Results from extract_dataflow (Round 2)
        vulnerabilities: Results from extract_vulnerabilities (Round 3)
        position: Code location (e.g., "file.py:function_name")
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "message": str,
            "tools_count": int,
            "json_path": str
        }
    """
    try:
        # Get incremental JSON path
        json_path = _get_incremental_json_path(tool_context)

        # Get agent name from context
        agent_name = None
        if tool_context is not None:
            agent_name = tool_context.state.get("agent_name")

        # Load existing data
        data = _load_or_create_incremental_json(json_path, agent_name)

        # Update session_id if available
        if tool_context is not None:
            session_id = tool_context.state.get("analysis_session_id")
            if session_id and not data["session_id"]:
                data["session_id"] = session_id

        # Create tool entry
        tool_entry = {
            "tool_name": tool_name,
            "position": position or tool_info.get("position", "unknown"),
            "discovered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool_info": tool_info,
            "dataflow": dataflow,
            "vulnerabilities": vulnerabilities
        }

        # Check if tool already exists (avoid duplicates)
        existing_tool = next((t for t in data["tools"] if t["tool_name"] == tool_name), None)
        if existing_tool:
            logger.warning(f"Tool {tool_name} already exists in incremental JSON, updating...")
            data["tools"].remove(existing_tool)

        # Append tool
        data["tools"].append(tool_entry)

        # Add log entry
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": "tool_analyzed",
            "details": {
                "tool_name": tool_name,
                "position": position,
                "has_vulnerabilities": vulnerabilities.get("has_vulnerabilities", False),
                "overall_risk": vulnerabilities.get("overall_risk", "unknown")
            }
        }
        data["analysis_log"].append(log_entry)

        # Save
        _save_incremental_json(json_path, data)

        logger.info(f"Saved analysis for tool: {tool_name}")
        logger.info(f"Total tools analyzed: {len(data['tools'])}")

        # Record todo snapshot if todos have changed
        _record_todo_snapshot_if_changed(tool_context)

        return {
            "success": True,
            "message": f"Successfully saved analysis for '{tool_name}'. Total tools: {len(data['tools'])}",
            "tools_count": len(data["tools"]),
            "json_path": json_path
        }

    except Exception as e:
        logger.error(f"Failed to save tool analysis: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error saving tool analysis: {str(e)}",
            "tools_count": 0,
            "json_path": None
        }


def log_analysis_event(
    event_type: str,
    details: dict,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Log an analysis event to the incremental JSON file.

    Use this to record key events during the analysis process, such as:
    - tool_discovered
    - environment_detected
    - framework_identified
    - directory_explored
    - analysis_completed

    Args:
        event_type: Type of event (tool_discovered, environment_detected, etc.)
        details: Event details (dict with relevant information)
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "message": str
        }
    """
    try:
        json_path = _get_incremental_json_path(tool_context)
        agent_name = tool_context.state.get("agent_name") if tool_context else None
        data = _load_or_create_incremental_json(json_path, agent_name)

        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": event_type,
            "details": details
        }

        data["analysis_log"].append(log_entry)
        _save_incremental_json(json_path, data)

        # Record todo snapshot if todos have changed
        _record_todo_snapshot_if_changed(tool_context)

        logger.info(f"Logged event: {event_type}")
        return {
            "success": True,
            "message": f"Event '{event_type}' logged successfully"
        }

    except Exception as e:
        logger.error(f"Failed to log event: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error logging event: {str(e)}"
        }


def save_environment_info(
    docker_required: Optional[bool] = None,
    framework: Optional[str] = None,
    dependencies: Optional[List[str]] = None,
    config_files: Optional[List[str]] = None,
    entry_points: Optional[List[str]] = None,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Save environment information to the incremental JSON file.

    Call this when you discover important environment details about the target agent.

    Args:
        docker_required: Whether Docker is required
        framework: Agent framework being used (LangChain, AutoGPT, etc.)
        dependencies: List of dependencies (packages, libraries)
        config_files: List of configuration files found
        entry_points: List of entry point files
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "message": str
        }
    """
    try:
        json_path = _get_incremental_json_path(tool_context)
        agent_name = tool_context.state.get("agent_name") if tool_context else None
        data = _load_or_create_incremental_json(json_path, agent_name)

        # Update environment info
        env = data["environment"]
        if docker_required is not None:
            env["docker_required"] = docker_required
        if framework:
            env["framework"] = framework
        if dependencies:
            env["dependencies"].extend(dependencies)
            env["dependencies"] = list(set(env["dependencies"]))  # Remove duplicates
        if config_files:
            env["config_files"].extend(config_files)
            env["config_files"] = list(set(env["config_files"]))
        if entry_points:
            env["entry_points"].extend(entry_points)
            env["entry_points"] = list(set(env["entry_points"]))

        _save_incremental_json(json_path, data)

        # Log event
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event": "environment_info_updated",
            "details": {
                "docker_required": docker_required,
                "framework": framework,
                "dependencies_count": len(env["dependencies"]),
                "config_files_count": len(env["config_files"])
            }
        }
        data["analysis_log"].append(log_entry)
        _save_incremental_json(json_path, data)

        # Record todo snapshot if todos have changed
        _record_todo_snapshot_if_changed(tool_context)

        logger.info("Updated environment information")
        return {
            "success": True,
            "message": "Environment information updated successfully"
        }

    except Exception as e:
        logger.error(f"Failed to save environment info: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error saving environment info: {str(e)}"
        }


def sync_todos_to_json(
    todos: List[dict],
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Sync todo list to the incremental JSON file.

    This is called automatically by todo_manager when todos are updated.

    Args:
        todos: List of todos with id, content, status, etc.
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "message": str
        }
    """
    try:
        json_path = _get_incremental_json_path(tool_context)
        agent_name = tool_context.state.get("agent_name") if tool_context else None
        data = _load_or_create_incremental_json(json_path, agent_name)

        # Update todos
        data["todos"] = todos
        _save_incremental_json(json_path, data)

        # Record todo snapshot after sync (always record, as todos have definitely changed)
        _record_todo_snapshot_if_changed(tool_context)

        logger.info(f"Synced {len(todos)} todos to incremental JSON")
        return {
            "success": True,
            "message": f"Synced {len(todos)} todos successfully"
        }

    except Exception as e:
        logger.error(f"Failed to sync todos: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error syncing todos: {str(e)}"
        }


def get_incremental_analysis_summary(
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Get a summary of the current incremental analysis.

    Returns:
        dict: Summary with tools_count, status, etc.
    """
    try:
        json_path = _get_incremental_json_path(tool_context)

        if not os.path.exists(json_path):
            return {
                "success": False,
                "message": "No incremental analysis found",
                "tools_count": 0
            }

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return {
            "success": True,
            "message": "Analysis summary retrieved",
            "agent_name": data.get("agent_name"),
            "tools_count": len(data.get("tools", [])),
            "analysis_status": data.get("analysis_status"),
            "analysis_start": data.get("analysis_start"),
            "last_updated": data.get("last_updated"),
            "json_path": json_path
        }

    except Exception as e:
        logger.error(f"Failed to get summary: {e}", exc_info=True)
        return {
            "success": False,
            "message": f"Error: {str(e)}",
            "tools_count": 0
        }


def _record_todo_snapshot_if_changed(
    tool_context: Optional[ToolContext] = None
) -> bool:
    """
    Record a todo snapshot to the trace if todos have changed since last snapshot.

    This function compares the current todos with the last recorded snapshot
    and adds a new todo_snapshot event if there are changes.

    Args:
        tool_context: ADK tool context (auto-injected)

    Returns:
        bool: True if snapshot was recorded, False otherwise
    """
    try:
        if tool_context is None:
            return False

        # Get current todos from tool context
        from .todo_manager import TODOS_STATE_KEY
        current_todos = tool_context.state.get(TODOS_STATE_KEY, [])

        # Get incremental JSON path
        json_path = _get_incremental_json_path(tool_context)
        if not os.path.exists(json_path):
            return False

        agent_name = tool_context.state.get("agent_name")
        data = _load_or_create_incremental_json(json_path, agent_name)

        # Find last todo_snapshot in analysis_log
        last_snapshot_todos = None
        for event in reversed(data.get("analysis_log", [])):
            if event.get("event") == "todo_snapshot":
                last_snapshot_todos = event.get("details", {}).get("todos", [])
                break

        # Compare current todos with last snapshot
        # Serialize for comparison (using json to normalize)
        import json as json_module
        current_serialized = json_module.dumps(current_todos, sort_keys=True)
        last_serialized = json_module.dumps(last_snapshot_todos, sort_keys=True) if last_snapshot_todos is not None else None

        # If todos have changed, record new snapshot
        if current_serialized != last_serialized:
            # Calculate statistics
            todos_total = len(current_todos)
            todos_pending = sum(1 for t in current_todos if t.get("status") == "pending")
            todos_in_progress = sum(1 for t in current_todos if t.get("status") == "in_progress")
            todos_completed = sum(1 for t in current_todos if t.get("status") == "completed")

            # Create snapshot event
            snapshot_event = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event": "todo_snapshot",
                "details": {
                    "todos": current_todos,
                    "stats": {
                        "total": todos_total,
                        "pending": todos_pending,
                        "in_progress": todos_in_progress,
                        "completed": todos_completed
                    }
                }
            }

            # Append to analysis log
            data["analysis_log"].append(snapshot_event)
            _save_incremental_json(json_path, data)

            logger.info(f"Todo snapshot recorded: {todos_completed}/{todos_total} completed")
            return True

        return False

    except Exception as e:
        logger.error(f"Failed to record todo snapshot: {e}", exc_info=True)
        return False


__all__ = [
    "save_tool_analysis",
    "log_analysis_event",
    "save_environment_info",
    "sync_todos_to_json",
    "get_incremental_analysis_summary"
]
