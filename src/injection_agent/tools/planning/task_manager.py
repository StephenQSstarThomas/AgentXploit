"""
Task manager integrated with new AnalysisContextManager system.
Provides task management capabilities for agents using the context-aware approach.
"""

import logging
from typing import Optional, Dict, Any, List
from google.adk.tools import ToolContext

from .analysis_context_manager import AnalysisContextManager

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


def create_comprehensive_analysis_plan(
    repo_path: str,
    analysis_type: str = "security",
    max_depth: int = 3,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Create a comprehensive analysis plan based on repository context and intelligent prioritization.

    Args:
        repo_path: Repository path to analyze
        analysis_type: Type of analysis (security, architecture, comprehensive)
        max_depth: Maximum analysis depth
        tool_context: ADK tool context (optional)

    Returns:
        Comprehensive analysis plan with prioritized tasks
    """

    try:
        logger.info(f"Creating comprehensive analysis plan for: {repo_path}")

        # Initialize context manager
        context_manager = AnalysisContextManager(repo_path)

        # Get comprehensive context
        overview = context_manager.get_project_overview()
        security_summary = context_manager.get_security_summary()
        suggestions = context_manager.suggest_next_priorities()
        history = context_manager.get_analysis_history(limit=20)

        # Create detailed analysis plan
        plan = f"""COMPREHENSIVE ANALYSIS PLAN - {repo_path}
{'='*60}

REPOSITORY OVERVIEW:
- Project Type: {overview['project_type']}
- Total Files: {overview['total_files']}
- Entry Points: {len(overview['entry_points'])}
- Config Files: {len(overview['config_files'])}
- Security-Relevant Files: {len(overview['security_relevant_files'])}

CURRENT ANALYSIS STATE:
- Files Analyzed: {overview['analysis_progress']['files_analyzed']}
- Security Findings: {security_summary['total_findings']} ({security_summary['high_risk_count']} high risk)
- Active Todos: {len([t for t in context_manager.analysis_todos if t['status'] in ['pending', 'in_progress']])}

PRIORITIZED ANALYSIS PHASES:
{'='*40}

PHASE 1 - HIGH PRIORITY SECURITY ANALYSIS:
"""

        # Phase 1: High-risk security files
        high_risk_files = security_summary.get('high_risk_files', [])
        if high_risk_files:
            plan += "1. Critical Security Files Analysis:\n"
            for i, file in enumerate(high_risk_files[:5], 1):
                plan += f"   {i}. {file} - IMMEDIATE SECURITY REVIEW REQUIRED\n"

        # Phase 2: Entry points
        unanalyzed_entry_points = []
        analyzed_files = [a["file_path"] for a in context_manager.completed_analysis]
        for entry_point in overview['entry_points']:
            if entry_point not in analyzed_files:
                unanalyzed_entry_points.append(entry_point)

        if unanalyzed_entry_points:
            plan += "\n2. Entry Points Analysis:\n"
            for i, entry_point in enumerate(unanalyzed_entry_points[:5], 1):
                plan += f"   {i}. {entry_point} - ARCHITECTURAL ENTRY POINT\n"

        # Phase 3: Configuration files
        unanalyzed_configs = []
        for config_file in overview['config_files']:
            if config_file not in analyzed_files:
                unanalyzed_configs.append(config_file)

        if unanalyzed_configs:
            plan += "\n3. Configuration Analysis:\n"
            for i, config_file in enumerate(unanalyzed_configs[:5], 1):
                plan += f"   {i}. {config_file} - CONFIGURATION SECURITY REVIEW\n"

        # Phase 4: Security-relevant files
        unanalyzed_security = []
        for security_file in overview['security_relevant_files']:
            if security_file not in analyzed_files:
                unanalyzed_security.append(security_file)

        if unanalyzed_security:
            plan += "\n4. Security-Relevant Files:\n"
            for i, security_file in enumerate(unanalyzed_security[:5], 1):
                plan += f"   {i}. {security_file} - SECURITY COMPONENT ANALYSIS\n"

        # Phase 5: AI suggestions
        if suggestions:
            plan += "\n5. Intelligent Suggestions:\n"
            for i, suggestion in enumerate(suggestions[:5], 1):
                plan += f"   {i}. {suggestion}\n"

        # Analysis strategy
        plan += f"""
{'='*40}
ANALYSIS STRATEGY:
{'='*40}

Recommended Approach for {analysis_type.upper()} Analysis:

1. **Depth**: {'Deep analysis' if max_depth > 2 else 'Focused analysis'} (max_depth={max_depth})
2. **Priority**: {'Security-first' if analysis_type == 'security' else 'Architecture-first' if analysis_type == 'architecture' else 'Comprehensive'}
3. **Scope**: {len(high_risk_files) + len(unanalyzed_entry_points) + len(unanalyzed_configs)} high-priority items identified

EXECUTION RECOMMENDATIONS:
- Start with Phase 1 (High Priority Security) if security findings exist
- Use intelligent task generation based on discoveries
- Update analysis progress regularly for context awareness
- Create follow-up todos for interesting findings

This plan was generated based on repository structure analysis and {len(history)} historical analysis actions.
"""

        logger.info(f"Comprehensive analysis plan created for {repo_path}")
        return plan

    except Exception as e:
        error_msg = f"Failed to create comprehensive analysis plan: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"