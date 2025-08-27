import logging
from typing import Optional, Dict, Any
from google.adk.tools import ToolContext

from ..analyzers.call_chain_tracer import CallChainTracer

logger = logging.getLogger(__name__)


def analyze_call_graph(
    repo_path: str,
    max_depth: int = 5,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Analyze call graph and function relationships in a repository.
    
    This tool maps function call relationships, traces execution paths,
    identifies critical control flow points, and analyzes inter-module
    dependencies for security assessment.
    
    Args:
        repo_path: Path to repository to analyze
        max_depth: Maximum call depth to trace (default: 5)
        tool_context: ADK tool context (optional)
    
    Returns:
        Call graph analysis summary
    """
    
    try:
        logger.info(f"Starting call graph analysis of: {repo_path}")
        
        # Initialize call chain tracer
        tracer = CallChainTracer()
        
        # Perform call graph analysis
        call_graph_results = tracer.trace_call_chains(
            repo_path, 
            [],  # No specific entry points
            max_depth
        )
        
        if "error" in call_graph_results:
            error_msg = f"Call graph analysis failed: {call_graph_results['error']}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        # Generate call graph summary
        summary = _generate_call_graph_summary(call_graph_results, repo_path)
        
        logger.info(f"Call graph analysis completed for {repo_path}")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to analyze call graph of {repo_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_call_graph_summary(results: Dict[str, Any], repo_path: str) -> str:
    """Generate summary of call graph analysis"""
    
    total_functions = len(results.get("functions", []))
    call_chains = results.get("call_chains", [])
    critical_paths = results.get("critical_paths", [])
    entry_points = results.get("entry_points", [])
    
    summary = f"""
Call Graph Analysis Results:

Repository: {repo_path}
Total Functions: {total_functions}
Call Chains: {len(call_chains)}
Critical Paths: {len(critical_paths)}
Entry Points: {len(entry_points)}

Key Entry Points:
"""
    
    for entry in entry_points[:5]:  # Top 5
        func_name = entry.get("function", "Unknown")
        file_path = entry.get("file", "Unknown")
        summary += f"  - {func_name} in {file_path}\n"
    
    if critical_paths:
        summary += "\nCritical Execution Paths:\n"
        for path in critical_paths[:3]:  # Top 3
            path_desc = path.get("description", "Unknown path")
            risk_level = path.get("risk_level", "Unknown")
            summary += f"  - {path_desc} (Risk: {risk_level})\n"
    
    return summary