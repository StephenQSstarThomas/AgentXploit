"""
Report generation tool for creating security analysis reports in JSON format.
"""
import logging
import json
import os
import time
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any


def write_report(
    agent_name: str,
    agent_framework: str,
    agent_entry_point: str,
    tools: List[Dict[str, Any]],
    dataflows: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    environment: Dict[str, Any],
    additional_notes: Optional[List[str]] = None,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """Generate security analysis report for target agent.

    Args:
        agent_name: Name of the analyzed agent
        agent_framework: Framework used by agent
        agent_entry_point: Main entry file path
        tools: List of tool definitions. Each should contain:
            - name: Tool name
            - type: Tool category (file_execution, bash_command, web_browsing, etc.)
            - description: What the tool does
            - position: Where tool is defined (file:function)
            - parameters: Input parameters
        dataflows: List of data flow paths. Each should contain:
            - source: Origin of data
            - destination: Where data goes
            - transformations: Processing steps
            - sanitization: Whether sanitization is applied
        vulnerabilities: List of identified vulnerabilities. Each should contain:
            - tool_name: Name of vulnerable tool
            - position: Location in code
            - vulnerabilities: List of vulnerability descriptions
            - injection_vectors: List of attack vectors
            - threat_model: List of threat types
        environment: Environment information:
            - requires_docker: bool
            - dependencies: List of required packages
            - runtime: Runtime environment
        additional_notes: Optional additional observations
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "report_path": str,
            "message": str
        }
    """
    try:
        # Build report structure
        report_data = {
            "agent_name": agent_name,
            "framework": agent_framework,
            "entry_point": agent_entry_point,
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tools": tools,
            "dataflows": dataflows,
            "vulnerabilities": vulnerabilities,
            "environment": environment,
            "additional_notes": additional_notes or []
        }

        # Save report to file
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        reports_dir = os.path.join(script_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_filename = f"security_analysis_{agent_name}_{timestamp}.json"
        report_path = os.path.join(reports_dir, report_filename)

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        # Store in context if available
        if tool_context is not None:
            tool_context.state["analysis:final_report"] = report_data

        logger.info(f"Report saved: {report_path}")

        return {
            "success": True,
            "report_path": report_path,
            "message": f"Report generated: {len(tools)} tools, {len(dataflows)} dataflows, {len(vulnerabilities)} vulnerabilities"
        }

    except Exception as e:
        logger.error(f"Report error: {e}")
        return {
            "success": False,
            "report_path": "",
            "message": f"Error: {str(e)}"
        }


__all__ = ["write_report"]
