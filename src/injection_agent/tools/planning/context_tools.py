"""
Context tools for agents to access analysis history, manage todos,
and make informed decisions about what to analyze next.
"""

import json
from typing import Optional, Dict, Any, List
from google.adk.tools import ToolContext

from .analysis_context_manager import AnalysisContextManager

# Global context manager instance (initialized per analysis session)
_context_manager = None


def initialize_analysis_context(repo_path: str, tool_context: Optional[ToolContext] = None) -> str:
    """Initialize analysis context for a repository"""
    global _context_manager
    _context_manager = AnalysisContextManager(repo_path)
    return f"Analysis context initialized for repository: {repo_path}"


def get_project_overview(tool_context: Optional[ToolContext] = None) -> str:
    """Get comprehensive project overview and analysis status"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    overview = _context_manager.get_project_overview()
    
    summary = f"""PROJECT OVERVIEW - {overview['repo_path']}

Project Type: {overview['project_type']}
Total Files: {overview['total_files']}, Directories: {overview['total_directories']}

File Types:
"""
    
    for ext, count in sorted(overview['file_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
        summary += f"  {ext or 'no extension'}: {count} files\n"
    
    summary += f"""
Key Components:
- Entry Points: {', '.join(overview['entry_points'][:5]) if overview['entry_points'] else 'None identified'}
- Config Files: {', '.join(overview['config_files'][:5]) if overview['config_files'] else 'None found'}  
- Security Files: {', '.join(overview['security_relevant_files'][:5]) if overview['security_relevant_files'] else 'None found'}

Analysis Progress:
- Files Analyzed: {overview['analysis_progress']['files_analyzed']}
- Security Findings: {overview['analysis_progress']['security_findings']}
- Pending Todos: {overview['analysis_progress']['pending_todos']}
- Completed Todos: {overview['analysis_progress']['completed_todos']}

Last Updated: {overview['last_updated']}"""
    
    return summary


def get_analysis_history(limit: int = 10, tool_context: Optional[ToolContext] = None) -> str:
    """Get recent analysis history and discoveries"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    history = _context_manager.get_analysis_history(limit)
    
    if not history:
        return "No analysis history available yet."
    
    summary = f"RECENT ANALYSIS HISTORY (Last {len(history)} actions):\n\n"
    
    for entry in history:
        timestamp = entry['timestamp'][:19]  # Remove microseconds
        if entry['type'] == 'structure_discovery':
            summary += f"[{timestamp}] DISCOVERED: {entry['path']} - {entry['files_found']} files, {entry['dirs_found']} dirs\n"
        elif entry['type'] == 'file_analysis':
            summary += f"[{timestamp}] ANALYZED: {entry['file']} - Risk: {entry['risk_level']}\n"
        else:
            summary += f"[{timestamp}] {entry['type'].upper()}: {json.dumps(entry, default=str)[:100]}\n"
    
    return summary


def get_security_summary(tool_context: Optional[ToolContext] = None) -> str:
    """Get security findings summary"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    security = _context_manager.get_security_summary()
    
    summary = f"""SECURITY ANALYSIS SUMMARY

Total Findings: {security['total_findings']}
- High Risk: {security['high_risk_count']} files
- Medium Risk: {security['medium_risk_count']} files

High Risk Files:
"""
    
    if security['high_risk_files']:
        for file in security['high_risk_files']:
            summary += f"  - {file}\n"
    else:
        summary += "  None identified\n"
    
    if security['recent_findings']:
        summary += "\nRecent Findings:\n"
        for finding in security['recent_findings']:
            summary += f"  [{finding['risk_level'].upper()}] {finding['file']}: {', '.join(finding['findings'][:2])}\n"
    
    return summary


def add_analysis_todo(description: str, priority: str = "medium", context: str = "", tool_context: Optional[ToolContext] = None) -> str:
    """Add a new analysis todo (agents can use this to track their own work)"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    if priority not in ["low", "medium", "high"]:
        priority = "medium"
    
    todo_id = _context_manager.add_todo(description, priority, context)
    return f"Added todo '{description}' with ID: {todo_id} (Priority: {priority})"


def update_todo_status(todo_id: str, status: str, notes: str = "", tool_context: Optional[ToolContext] = None) -> str:
    """Update status of an analysis todo"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    if status not in ["pending", "in_progress", "completed", "cancelled"]:
        return f"ERROR: Invalid status '{status}'. Use: pending, in_progress, completed, cancelled"
    
    success = _context_manager.update_todo_status(todo_id, status, notes)
    if success:
        return f"Updated todo {todo_id} status to: {status}"
    else:
        return f"ERROR: Todo {todo_id} not found"


def get_current_todos(tool_context: Optional[ToolContext] = None) -> str:
    """Get current analysis todos and their status"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    todos = _context_manager.get_current_todos()
    
    if not todos:
        return "No current todos."
    
    summary = f"CURRENT ANALYSIS TODOS ({len(todos)} active):\n\n"
    
    # Group by status
    by_status = {}
    for todo in todos:
        status = todo['status']
        if status not in by_status:
            by_status[status] = []
        by_status[status].append(todo)
    
    for status in ['in_progress', 'pending']:
        if status in by_status:
            summary += f"{status.upper().replace('_', ' ')}:\n"
            for todo in by_status[status]:
                priority_icon = {"high": "[!]", "medium": "[=]", "low": "[-]"}
                icon = priority_icon.get(todo['priority'], '[=]')
                summary += f"  {icon} {todo['id']}: {todo['description']}\n"
                if todo.get('context'):
                    summary += f"      Context: {todo['context']}\n"
            summary += "\n"
    
    return summary


def get_next_suggestions(tool_context: Optional[ToolContext] = None) -> str:
    """Get AI suggestions for what to analyze next based on current discoveries"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    suggestions = _context_manager.suggest_next_priorities()
    
    if not suggestions:
        return "No specific suggestions available. Consider exploring more directories or analyzing key files."
    
    summary = "SUGGESTED NEXT PRIORITIES:\n\n"
    for i, suggestion in enumerate(suggestions, 1):
        summary += f"{i}. {suggestion}\n"
    
    return summary


def record_analysis_result(file_path: str, security_risk: str = "low", key_findings: Optional[List[str]] = None, additional_data: Optional[Dict[str, Any]] = None, tool_context: Optional[ToolContext] = None) -> str:
    """Record analysis results for a file (agents can use this to track their findings)"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"
    
    if security_risk not in ["low", "medium", "high"]:
        security_risk = "low"
    
    analysis_data = {
        "security_risk": security_risk,
        "key_findings": key_findings or [],
    }
    
    if additional_data:
        analysis_data.update(additional_data)
    
    _context_manager.add_analysis_result(file_path, analysis_data)
    return f"Recorded analysis for {file_path} - Risk: {security_risk}, Findings: {len(key_findings or [])}"


def record_directory_structure(path: str, files: List[str], directories: List[str], additional_info: Optional[Dict[str, Any]] = None, tool_context: Optional[ToolContext] = None) -> str:
    """Record discovered directory structure (agents can use this when exploring directories)"""
    if not _context_manager:
        return "ERROR: Analysis context not initialized"

    structure_data = {
        "files": files,
        "directories": directories
    }

    if additional_info:
        structure_data.update(additional_info)

    _context_manager.update_project_structure(path, structure_data)
    return f"Recorded structure for {path} - {len(files)} files, {len(directories)} directories"


