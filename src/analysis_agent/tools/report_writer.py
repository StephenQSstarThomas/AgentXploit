"""
Final report generation tool - consolidates incremental analysis into final report.

This module provides the write_report function which reads the incremental JSON
(created by incremental_writer) and generates a final, comprehensive security report.
"""
import logging
import json
import os
import time
from typing import Optional, Any

logger = logging.getLogger(__name__)

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any


def write_report(
    incremental_json_path: Optional[str] = None,
    agent_name: Optional[str] = None,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    Generate final comprehensive security analysis report.

    This function reads the incremental analysis JSON file (created during the
    analysis session by save_tool_analysis calls) and generates a final,
    formatted security report.

    **Call this MANUALLY at the end** after analyzing all tools.

    Args:
        incremental_json_path: Path to the incremental JSON file
                               If not provided, will use path from tool_context
        agent_name: Name of the analyzed agent (for filename)
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "success": bool,
            "report_path": str,
            "final_report_path": str,
            "message": str,
            "summary": {
                "tools_count": int,
                "vulnerabilities_count": int,
                "critical_risks": int,
                ...
            }
        }
    """
    try:
        # Determine incremental JSON path
        if incremental_json_path is None:
            if tool_context is not None:
                incremental_json_path = tool_context.state.get("incremental_json_path")

        if not incremental_json_path or not os.path.exists(incremental_json_path):
            return {
                "success": False,
                "report_path": "",
                "message": "Error: No incremental analysis JSON found. Run analysis first with save_tool_analysis."
            }

        # Load incremental analysis
        with open(incremental_json_path, 'r', encoding='utf-8') as f:
            incremental_data = json.load(f)

        logger.info(f"Loading incremental analysis from: {incremental_json_path}")

        # Extract agent name
        if agent_name is None:
            agent_name = incremental_data.get("agent_name", "unknown")

        # Build final report structure
        tools = incremental_data.get("tools", [])
        environment = incremental_data.get("environment", {})

        # Create simple list of all discovered tools (just names and positions)
        all_tools_list = [
            {
                "tool_name": tool.get("tool_name"),
                "position": tool.get("position")
            }
            for tool in tools
        ]

        # Filter tools with security issues
        vulnerable_tools = []
        vulnerability_summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for tool in tools:
            tool_vulns = tool.get("vulnerabilities", {})
            if tool_vulns.get("has_vulnerabilities", False):
                # Count vulnerabilities by severity
                for vuln in tool_vulns.get("vulnerabilities", []):
                    severity = vuln.get("severity", "low").lower()
                    if severity in vulnerability_summary:
                        vulnerability_summary[severity] += 1

                # Add full tool analysis for vulnerable tools only
                vulnerable_tools.append({
                    "tool_name": tool.get("tool_name"),
                    "position": tool.get("position"),
                    "description": tool.get("tool_info", {}).get("description", ""),
                    "functionality": tool.get("tool_info", {}).get("functionality", ""),
                    "dataflow": {
                        "sources": tool.get("dataflow", {}).get("data_sources", []),
                        "destinations": tool.get("dataflow", {}).get("data_destinations", []),
                        "sensitive_flows": tool.get("dataflow", {}).get("sensitive_flows", [])
                    },
                    "vulnerabilities": tool_vulns.get("vulnerabilities", []),
                    "injection_vectors": tool_vulns.get("injection_vectors", []),
                    "threat_model": tool_vulns.get("threat_model", []),
                    "overall_risk": tool_vulns.get("overall_risk", "low"),
                    "risk_summary": tool_vulns.get("risk_summary", "")
                })

        # Calculate total vulnerabilities count
        total_vulnerabilities = sum(vulnerability_summary.values())

        # Calculate overall risk level
        if vulnerability_summary["critical"] > 0:
            overall_risk = "critical"
        elif vulnerability_summary["high"] > 0:
            overall_risk = "high"
        elif vulnerability_summary["medium"] > 0:
            overall_risk = "medium"
        elif total_vulnerabilities > 0:
            overall_risk = "low"
        else:
            overall_risk = "none"

        # Extract critical findings from vulnerable tools
        critical_findings = []
        for tool in vulnerable_tools:
            for vuln in tool.get("vulnerabilities", []):
                if vuln.get("severity", "").lower() == "critical":
                    critical_findings.append({
                        "tool_name": tool.get("tool_name"),
                        "vulnerability": vuln.get("name", ""),
                        "description": vuln.get("description", ""),
                        "impact": vuln.get("impact", "")
                    })

        # Create final report with simplified structure
        final_report = {
            "report_metadata": {
                "report_type": "final_security_analysis",
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "analysis_duration": f"{incremental_data.get('analysis_start')} to {incremental_data.get('last_updated')}",
                "session_id": incremental_data.get("session_id"),
                "incremental_source": os.path.basename(incremental_json_path)
            },

            "executive_summary": {
                "tools_discovered": len(tools),
                "tools_with_vulnerabilities": len(vulnerable_tools),
                "total_vulnerabilities": total_vulnerabilities,
                "overall_risk_level": overall_risk,
                "vulnerability_breakdown": vulnerability_summary,
                "critical_findings": critical_findings[:5]  # Top 5 critical
            },

            "all_tools_discovered": all_tools_list,

            "environment": {
                "agent_name": agent_name,
                "framework": environment.get("framework", "unknown"),
                "docker_required": environment.get("docker_required"),
                "dependencies": environment.get("dependencies", []),
                "config_files": environment.get("config_files", []),
                "entry_points": environment.get("entry_points", [])
            },

            "tools_with_security_issues": vulnerable_tools,

            "analysis_process": {
                "todos_tracked": incremental_data.get("todos", []),
                "analysis_log": incremental_data.get("analysis_log", [])
            }
        }

        # Save final report
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        reports_dir = os.path.join(script_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        final_report_filename = f"FINAL_security_analysis_{agent_name}_{timestamp}.json"
        final_report_path = os.path.join(reports_dir, final_report_filename)

        with open(final_report_path, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)

        logger.info(f"Final report generated: {final_report_path}")

        # Prepare summary
        summary = {
            "tools_count": len(tools),
            "tools_with_vulnerabilities": len(vulnerable_tools),
            "vulnerabilities_count": total_vulnerabilities,
            "critical_risks": vulnerability_summary["critical"],
            "high_risks": vulnerability_summary["high"],
            "medium_risks": vulnerability_summary["medium"],
            "low_risks": vulnerability_summary["low"],
            "overall_risk": overall_risk
        }

        return {
            "success": True,
            "report_path": incremental_json_path,
            "final_report_path": final_report_path,
            "message": f"Final report generated successfully. Analyzed {len(tools)} tools, found {len(vulnerable_tools)} tools with {total_vulnerabilities} vulnerabilities.",
            "summary": summary
        }

    except Exception as e:
        logger.error(f"Failed to generate final report: {e}", exc_info=True)
        return {
            "success": False,
            "report_path": "",
            "final_report_path": "",
            "message": f"Error generating final report: {str(e)}"
        }


__all__ = ["write_report"]
