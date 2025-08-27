import logging
from typing import Optional, Dict, Any
from google.adk.tools import ToolContext

from ...config import settings

logger = logging.getLogger(__name__)


def analyze_repository_static(
    repo_path: str,
    max_files_to_read: int = 200,
    analysis_mode: str = "intelligent",
    output_dir: Optional[str] = None,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Perform comprehensive static analysis of a repository.
    
    This tool analyzes repository structure, identifies key components,
    maps architectural patterns, and generates detailed reports suitable
    for security research and vulnerability assessment.
    
    Args:
        repo_path: Path to the target repository
        max_files_to_read: Maximum number of files to analyze (default: 20)
        analysis_mode: Analysis approach - "intelligent" for iterative or "simple" for batch
        output_dir: Optional directory to save results (defaults to settings.ANALYSIS_DIR)
        tool_context: ADK tool context (optional)
    
    Returns:
        Path to the generated analysis report or error message
    """
    
    try:
        logger.info(f"Starting static analysis of repository: {repo_path}")
        
        # Use the smart analyzer directly
        focus = "security"  # Always focus on security for injection analysis
        
        # Perform the analysis using our modular system
        from ..smart_analyzer import Analyzer
        analyzer = Analyzer(repo_path)
        analysis_result = analyzer.analyze(max_steps=max_files_to_read, save_results=True, focus=focus)
        
        if "error" in analysis_result:
            error_msg = f"Static analysis failed: {analysis_result['error']}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        # Generate summary for the caller
        analysis_summary = _generate_analysis_summary(analysis_result)
        
        logger.info(f"Static analysis completed successfully for {repo_path}")
        return analysis_summary
        
    except Exception as e:
        error_msg = f"Failed to perform static analysis of {repo_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_analysis_summary(analysis_result: Dict[str, Any]) -> str:
    """Generate a concise summary of analysis results"""
    
    analysis_info = analysis_result.get("analysis_info", {})
    execution_summary = analysis_result.get("execution_summary", {})
    structure = analysis_result.get("discovered_structure", {})
    security = analysis_result.get("security_analysis", {})
    
    # Extract key metrics
    repo_path = analysis_info.get("repository_path", "unknown")
    steps_completed = execution_summary.get("steps_completed", 0)
    total_files = structure.get("total_files", 0)
    total_directories = structure.get("total_directories", 0)
    security_findings = security.get("total_security_findings", 0)
    high_risk_files = len(security.get("high_risk_files", []))
    
    summary = f"""
Repository Static Analysis Complete:

Repository: {repo_path}
Analysis Steps: {steps_completed}
Files Analyzed: {total_files}
Directories Explored: {total_directories}
Security Findings: {security_findings}
High Risk Files: {high_risk_files}

Key Security Findings:
"""
    
    # Add high-risk files
    if security.get("high_risk_files"):
        summary += "\nHigh Risk Files:\n"
        for file_path in security["high_risk_files"][:5]:  # Top 5
            summary += f"  - {file_path}\n"
    
    # Add security findings summary
    aggregate_findings = security.get("aggregate_findings", [])
    if aggregate_findings:
        summary += f"\nTop Security Concerns:\n"
        for finding in aggregate_findings[:3]:  # Top 3
            finding_type = finding.get("type", "Unknown")
            severity = finding.get("severity", "Unknown")
            summary += f"  - {finding_type} (Severity: {severity})\n"
    
    # Add architectural insights
    insights = analysis_result.get("architectural_insights", {})
    key_components = insights.get("key_components", [])
    if key_components:
        summary += f"\nKey Components Identified:\n"
        for component in key_components[:3]:  # Top 3
            summary += f"  - {component}\n"
    
    # Add analysis metadata for reference
    summary += f"\nDetailed results saved to analysis directory."
    
    return summary