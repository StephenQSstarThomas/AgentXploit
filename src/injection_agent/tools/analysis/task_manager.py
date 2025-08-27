"""
Task manager integrated with new AnalysisContextManager system.
Provides task management capabilities for agents using the context-aware approach.
"""

import logging
from typing import Optional, Dict, Any, List
from google.adk.tools import ToolContext

from ..planners.analysis_context_manager import AnalysisContextManager

logger = logging.getLogger(__name__)


def manage_analysis_tasks(
    repo_path: str,
    max_tasks: int = 50,
    priority_focus: str = "security",
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Manage and coordinate analysis tasks using the new context-driven approach.
    
    This tool integrates with AnalysisContextManager to provide task management
    capabilities for agents, allowing them to track progress, manage todos,
    and coordinate analysis workflow.
    
    Args:
        repo_path: Path to repository to analyze
        max_tasks: Maximum number of tasks to track
        priority_focus: Focus area for analysis ("security", "architecture")
        tool_context: ADK tool context (optional)
    
    Returns:
        Task management summary and current status
    """
    
    try:
        logger.info(f"Managing analysis tasks for: {repo_path}")
        
        # Initialize context manager
        context_manager = AnalysisContextManager(repo_path)
        
        # Get current project overview
        overview = context_manager.get_project_overview()
        
        # Get analysis history
        history = context_manager.get_analysis_history(limit=10)
        
        # Get current todos
        current_todos = context_manager.get_current_todos()
        
        # Get security summary
        security_summary = context_manager.get_security_summary()
        
        # Get next priority suggestions
        suggestions = context_manager.suggest_next_priorities()
        
        # Generate comprehensive task management summary
        summary = f"""ANALYSIS TASK MANAGEMENT - {repo_path}

PROJECT OVERVIEW:
- Project Type: {overview['project_type']}
- Total Files: {overview['total_files']}
- Analysis Progress: {overview['analysis_progress']['files_analyzed']} files analyzed

CURRENT TASK STATUS:
- Active Todos: {len(current_todos)}
- Security Findings: {security_summary['total_findings']}
- High Risk Files: {security_summary['high_risk_count']}

RECENT ANALYSIS ACTIVITY:
"""
        
        if history:
            for entry in history[:5]:
                timestamp = entry['timestamp'][:16]  # Just date and time
                if entry['type'] == 'structure_discovery':
                    summary += f"  [{timestamp}] Discovered {entry['path']} - {entry.get('files_found', 0)} files\n"
                elif entry['type'] == 'file_analysis':
                    summary += f"  [{timestamp}] Analyzed {entry['file']} - Risk: {entry.get('risk_level', 'unknown')}\n"
        else:
            summary += "  No recent activity\n"
        
        summary += "\nCURRENT TODOS:\n"
        if current_todos:
            for todo in current_todos[:5]:  # Show top 5
                status = todo['status'].upper()
                priority = todo['priority'].upper()
                summary += f"  [{priority}] {status}: {todo['description']}\n"
        else:
            summary += "  No active todos\n"
        
        summary += "\nSUGGESTED NEXT PRIORITIES:\n"
        if suggestions:
            for i, suggestion in enumerate(suggestions, 1):
                summary += f"  {i}. {suggestion}\n"
        else:
            summary += "  Continue current analysis or explore new directories\n"
        
        if security_summary['high_risk_count'] > 0:
            summary += f"\nSECURITY ALERTS:\n"
            summary += f"  {security_summary['high_risk_count']} high-risk files identified\n"
            for file in security_summary['high_risk_files'][:3]:
                summary += f"  - {file}\n"
        
        summary += f"\nFocus Area: {priority_focus.upper()}"
        summary += f"\nMax Tasks Tracked: {max_tasks}"
        
        logger.info(f"Task management completed for {repo_path}")
        return summary
        
    except Exception as e:
        error_msg = f"Task management failed for {repo_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def create_analysis_todo(
    repo_path: str,
    description: str,
    priority: str = "medium",
    context: str = "",
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Create a new analysis todo using the context manager.
    
    Args:
        repo_path: Repository path
        description: Todo description
        priority: Priority level (low, medium, high)
        context: Additional context information
        tool_context: ADK tool context (optional)
    
    Returns:
        Status message with todo ID
    """
    
    try:
        context_manager = AnalysisContextManager(repo_path)
        todo_id = context_manager.add_todo(description, priority, context)
        return f"Created analysis todo: {todo_id} - {description} (Priority: {priority})"
        
    except Exception as e:
        error_msg = f"Failed to create todo: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def update_analysis_progress(
    repo_path: str,
    file_path: str,
    analysis_results: Dict[str, Any],
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Update analysis progress with new results.
    
    Args:
        repo_path: Repository path
        file_path: File that was analyzed
        analysis_results: Analysis results dictionary
        tool_context: ADK tool context (optional)
    
    Returns:
        Status message
    """
    
    try:
        context_manager = AnalysisContextManager(repo_path)
        context_manager.add_analysis_result(file_path, analysis_results)
        return f"Updated analysis progress for {file_path}"
        
    except Exception as e:
        error_msg = f"Failed to update progress: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def get_analysis_status(
    repo_path: str,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Get current analysis status and progress summary.
    
    Args:
        repo_path: Repository path
        tool_context: ADK tool context (optional)
    
    Returns:
        Analysis status summary
    """
    
    try:
        context_manager = AnalysisContextManager(repo_path)
        
        overview = context_manager.get_project_overview()
        security = context_manager.get_security_summary()
        todos = context_manager.get_current_todos()
        
        status = f"""ANALYSIS STATUS - {repo_path}

Progress Summary:
- Files Analyzed: {overview['analysis_progress']['files_analyzed']}
- Security Findings: {security['total_findings']} ({security['high_risk_count']} high risk)
- Active Todos: {len(todos)}

Current Focus Areas:
"""
        
        if todos:
            high_priority = [t for t in todos if t['priority'] == 'high']
            if high_priority:
                status += "  High Priority Tasks:\n"
                for todo in high_priority[:3]:
                    status += f"    - {todo['description']}\n"
        
        if security['high_risk_count'] > 0:
            status += f"  Security Concerns: {security['high_risk_count']} files need attention\n"
        
        return status
        
    except Exception as e:
        error_msg = f"Failed to get analysis status: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"