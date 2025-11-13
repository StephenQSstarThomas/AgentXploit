"""
Session management for multi-tool analysis workflows.

This module provides session tracking to ensure that tools analyzed during
the same session are written to the same report file.
"""
import logging
import os
import uuid
import time
from typing import Optional, Any, Dict

logger = logging.getLogger(__name__)

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any


# Global session storage (in-memory for now)
_sessions: Dict[str, Dict[str, Any]] = {}


def start_analysis_session(
    agent_name: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Start a new analysis session for an agent.

    This creates a unique session ID and initializes the incremental JSON file
    for tracking analysis progress.

    Args:
        agent_name: Name of the agent being analyzed
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "session_id": str,
            "agent_name": str,
            "incremental_json_path": str,
            "message": str
        }
    """
    session_id = str(uuid.uuid4())
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    # Initialize incremental JSON file path
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(script_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    incremental_json_filename = f"incremental_analysis_{agent_name}_{timestamp}.json"
    incremental_json_path = os.path.join(reports_dir, incremental_json_filename)

    session_data = {
        "session_id": session_id,
        "agent_name": agent_name,
        "start_time": timestamp,
        "tools_analyzed": [],
        "incremental_json_path": incremental_json_path,
        "active": True
    }

    # Store in global registry
    _sessions[session_id] = session_data

    # Store in tool context if available
    if tool_context is not None:
        tool_context.state["analysis_session_id"] = session_id
        tool_context.state["agent_name"] = agent_name
        tool_context.state["session_start_time"] = timestamp
        tool_context.state["incremental_json_path"] = incremental_json_path

    logger.info(f"Started analysis session: {session_id}")
    logger.info(f"Agent: {agent_name}")
    logger.info(f"Incremental JSON: {incremental_json_path}")

    return {
        "success": True,
        "session_id": session_id,
        "agent_name": agent_name,
        "timestamp": timestamp,
        "incremental_json_path": incremental_json_path,
        "message": f"Session started for agent: {agent_name}. Analysis will be saved to: {os.path.basename(incremental_json_path)}"
    }


def get_session(
    session_id: str,
    tool_context: Optional[ToolContext] = None
) -> Optional[dict]:
    """
    Get session data for a given session ID.

    Args:
        session_id: The session ID to look up
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: Session data, or None if not found
    """
    # First check tool context
    if tool_context is not None:
        ctx_session_id = tool_context.state.get("analysis_session_id")
        if ctx_session_id == session_id:
            return {
                "session_id": ctx_session_id,
                "agent_name": tool_context.state.get("agent_name"),
                "start_time": tool_context.state.get("session_start_time"),
                "report_path": tool_context.state.get("session_report_path"),
                "active": True
            }

    # Fall back to global registry
    return _sessions.get(session_id)


def update_session_report_path(
    session_id: str,
    report_path: str,
    tool_context: Optional[ToolContext] = None
) -> bool:
    """
    Update the report path for a session.

    Args:
        session_id: The session ID
        report_path: Path to the report file
        tool_context: ADK tool context (auto-injected)

    Returns:
        bool: True if successful, False otherwise
    """
    if session_id in _sessions:
        _sessions[session_id]["report_path"] = report_path

    if tool_context is not None:
        tool_context.state["session_report_path"] = report_path

    logger.info(f"Updated session {session_id} report path: {report_path}")
    return True


def add_tool_to_session(
    session_id: str,
    tool_name: str,
    tool_context: Optional[ToolContext] = None
) -> bool:
    """
    Record that a tool has been analyzed in this session.

    Args:
        session_id: The session ID
        tool_name: Name of the tool analyzed
        tool_context: ADK tool context (auto-injected)

    Returns:
        bool: True if successful, False otherwise
    """
    if session_id in _sessions:
        if tool_name not in _sessions[session_id]["tools_analyzed"]:
            _sessions[session_id]["tools_analyzed"].append(tool_name)
            logger.info(f"Added tool '{tool_name}' to session {session_id}")
            return True

    return False


def end_analysis_session(
    session_id: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    End an analysis session.

    This marks the session as complete and returns summary information.

    Args:
        session_id: The session ID to end
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "session_id": str,
            "tools_count": int,
            "report_path": str,
            "message": str
        }
    """
    session = get_session(session_id, tool_context)

    if session is None:
        return {
            "success": False,
            "session_id": session_id,
            "tools_count": 0,
            "report_path": "",
            "message": f"Session not found: {session_id}"
        }

    # Mark as inactive
    if session_id in _sessions:
        _sessions[session_id]["active"] = False

    # Clear from tool context
    if tool_context is not None:
        tool_context.state.pop("analysis_session_id", None)
        tool_context.state.pop("session_report_path", None)

    tools_count = len(session.get("tools_analyzed", []))
    report_path = session.get("report_path", "")

    logger.info(f"Ended analysis session: {session_id}")
    logger.info(f"Tools analyzed: {tools_count}")
    logger.info(f"Report: {report_path}")

    return {
        "success": True,
        "session_id": session_id,
        "agent_name": session.get("agent_name", ""),
        "tools_count": tools_count,
        "report_path": report_path,
        "message": f"Session ended. Analyzed {tools_count} tool(s)."
    }


def get_current_session(
    tool_context: Optional[ToolContext] = None
) -> Optional[str]:
    """
    Get the current active session ID from tool context.

    Args:
        tool_context: ADK tool context (auto-injected)

    Returns:
        str: Session ID if active session exists, None otherwise
    """
    if tool_context is not None:
        return tool_context.state.get("analysis_session_id")
    return None


__all__ = [
    "start_analysis_session",
    "get_session",
    "update_session_report_path",
    "add_tool_to_session",
    "end_analysis_session",
    "get_current_session"
]
