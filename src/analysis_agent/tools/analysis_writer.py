"""
Analysis writer - manages incremental analysis JSON file.

This module provides tools for creating and writing analysis results to a JSON file.
All write_* functions support overwriting/updating existing data.

Functions:
- create_analysis_json() - Create new analysis JSON file with basic structure
- write_tool_info() - Write/update tool information analysis
- write_dataflow() - Write/update data flow analysis
- write_vulnerabilities() - Write/update security vulnerability analysis
- write_environment() - Write/update environment information
- write_dependencies() - Write/update dependency information
"""
import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_json(json_path: str) -> dict:
    """Load JSON file."""
    with open(json_path, encoding='utf-8') as f:
        return json.load(f)


def _save_json(json_path: str, data: dict) -> None:
    """Save JSON file."""
    data["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _get_or_create_tool(data: dict, tool_name: str) -> dict:
    """Get existing tool entry or create a new one."""
    tool_entry = next((t for t in data["tools"] if t.get("tool_name") == tool_name), None)
    if tool_entry is None:
        tool_entry = {
            "tool_name": tool_name,
            "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        data["tools"].append(tool_entry)
    return tool_entry


def create_analysis_json(json_path: str) -> dict:
    """Create a new analysis JSON file with basic structure.

    This must be called first before any write_* functions.
    Creates the JSON file at the specified absolute path.

    Args:
        json_path: Absolute path where the JSON file will be created

    Returns:
        dict: {"success": bool, "error": str or None}
    """
    try:
        path = Path(json_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "json_path": json_path,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "in_progress",
            "environment": {},
            "dependencies": [],
            "tools": []
        }

        _save_json(json_path, data)
        logger.info(f"Created analysis JSON: {json_path}")
        return {"success": True, "error": None}

    except Exception as e:
        logger.error(f"Failed to create analysis JSON: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def write_tool_info(json_path: str, tool_name: str, tool_info: dict) -> dict:
    """Write or update tool information analysis to the JSON file.

    Supports overwriting: if tool already exists, its tool_info will be replaced.
    Creates tool entry if it doesn't exist.

    Expected tool_info structure:
    {
        "tool_name": "name of the tool",
        "position": "file path and function name",
        "description": "One-sentence clear description",
        "functionality": "Detailed explanation of what this tool does",
        "parameters": [
            {"name": "param_name", "type": "param_type", "purpose": "usage"}
        ],
        "return_type": "What type is returned",
        "return_description": "What the return value represents"
    }

    Args:
        json_path: Absolute path to the analysis JSON file
        tool_name: Name of the tool being analyzed
        tool_info: Tool information dict (overwrites existing if present)

    Returns:
        dict: {"success": bool, "error": str or None}
    """
    try:
        data = _load_json(json_path)
        tool_entry = _get_or_create_tool(data, tool_name)
        tool_entry["tool_info"] = tool_info
        _save_json(json_path, data)
        logger.info(f"Wrote tool_info for: {tool_name}")
        return {"success": True, "error": None}
    except Exception as e:
        logger.error(f"Failed to write tool_info: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def write_dataflow(json_path: str, tool_name: str, dataflow: dict) -> dict:
    """Write or update data flow analysis to the JSON file.

    Supports overwriting: if tool already has dataflow, it will be replaced.
    Creates tool entry if it doesn't exist.

    Expected dataflow structure:
    {
        "tool_name": "name of the tool",
        "position": "file path and function name",
        "data_sources": ["user_input", "web_content", "file_read", "database",
                         "llm_output", "api_response", "external_input", "document"],
        "data_destinations": ["llm_prompt", "file_write", "bash_command", "api_call",
                              "database_write", "user_output", "network_write"],
        "data_transformations": ["sanitization", "encoding", "parsing", "concatenation"],
        "flow_description": "Complete description of data flow",
        "sensitive_flows": [
            {"from": "source", "to": "destination",
             "risk_level": "high|medium|low", "reason": "Why sensitive"}
        ]
    }

    Args:
        json_path: Absolute path to the analysis JSON file
        tool_name: Name of the tool being analyzed
        dataflow: Data flow dict (overwrites existing if present)

    Returns:
        dict: {"success": bool, "error": str or None}
    """
    try:
        data = _load_json(json_path)
        tool_entry = _get_or_create_tool(data, tool_name)
        tool_entry["dataflow"] = dataflow
        _save_json(json_path, data)
        logger.info(f"Wrote dataflow for: {tool_name}")
        return {"success": True, "error": None}
    except Exception as e:
        logger.error(f"Failed to write dataflow: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def write_vulnerabilities(json_path: str, tool_name: str, vulnerabilities: dict) -> dict:
    """Write or update security vulnerability analysis to the JSON file.

    Supports overwriting: if tool already has vulnerabilities, it will be replaced.
    Creates tool entry if it doesn't exist.

    Expected vulnerabilities structure:
    {
        "has_vulnerabilities": true/false,
        "vulnerabilities": [
            {
                "type": "path_traversal|command_injection|prompt_injection|
                        indirect_prompt_injection|data_exfiltration|unauthorized_access",
                "severity": "critical|high|medium|low",
                "description": "Clear description of the vulnerability",
                "attack_scenario": "Step-by-step attack scenario",
                "end_to_end_impact": ["Concrete impact 1", "Concrete impact 2"],
                "evidence": "Code patterns or dataflow proving vulnerability",
                "mitigation": "Suggested fix or mitigation"
            }
        ],
        "injection_vectors": [
            {"type": "vector_type", "source": "data_source", "destination": "data_dest",
             "severity": "critical|high|medium|low", "exploitability": "easy|medium|hard"}
        ],
        "threat_model": ["threat1", "threat2"],
        "overall_risk": "critical|high|medium|low",
        "risk_summary": "Summary of overall security posture"
    }

    Args:
        json_path: Absolute path to the analysis JSON file
        tool_name: Name of the tool being analyzed
        vulnerabilities: Vulnerability dict (overwrites existing if present)

    Returns:
        dict: {"success": bool, "error": str or None}
    """
    try:
        data = _load_json(json_path)
        tool_entry = _get_or_create_tool(data, tool_name)
        tool_entry["vulnerabilities"] = vulnerabilities
        _save_json(json_path, data)
        logger.info(f"Wrote vulnerabilities for: {tool_name}")
        return {"success": True, "error": None}
    except Exception as e:
        logger.error(f"Failed to write vulnerabilities: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def write_environment(json_path: str, environment: dict) -> dict:
    """Write or update environment information to the JSON file.

    Supports overwriting: existing environment data will be replaced.

    Expected environment structure:
    {
        "framework": "Agent framework name (e.g., LangChain, AutoGPT, OpenHands)",
        "docker_required": true/false,
        "entry_points": ["main.py", "agent.py"],
        "config_files": ["config.yaml", ".env"]
    }

    Args:
        json_path: Absolute path to the analysis JSON file
        environment: Environment dict (overwrites existing if present)

    Returns:
        dict: {"success": bool, "error": str or None}
    """
    try:
        data = _load_json(json_path)
        data["environment"] = environment
        _save_json(json_path, data)
        logger.info("Wrote environment info")
        return {"success": True, "error": None}
    except Exception as e:
        logger.error(f"Failed to write environment: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def write_dependencies(json_path: str, dependencies: list[str]) -> dict:
    """Write or update dependency information to the JSON file.

    Supports overwriting: existing dependencies list will be replaced.

    Args:
        json_path: Absolute path to the analysis JSON file
        dependencies: List of dependency names (overwrites existing if present)
                      e.g., ["langchain", "openai", "requests"]

    Returns:
        dict: {"success": bool, "error": str or None}
    """
    try:
        data = _load_json(json_path)
        data["dependencies"] = dependencies
        _save_json(json_path, data)
        logger.info(f"Wrote {len(dependencies)} dependencies")
        return {"success": True, "error": None}
    except Exception as e:
        logger.error(f"Failed to write dependencies: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def write_final_report(json_path: str) -> dict:
    """Generate final security analysis report. ONLY call when analysis is complete.

    This function should be called ONLY when you have finished analyzing all tools
    and are ready to finalize the report. It reads the analysis JSON and generates
    a summary with vulnerability overview.

    The function will:
    1. Mark analysis status as "completed"
    2. Generate vulnerability summary (counts by severity)
    3. Calculate overall risk level
    4. Save the final report

    Args:
        json_path: Absolute path to the analysis JSON file

    Returns:
        dict: {
            "success": bool,
            "error": str or None,
            "report_path": str,
            "summary": {
                "tools_analyzed": int,
                "tools_with_vulnerabilities": int,
                "vulnerability_counts": {"critical": N, "high": N, "medium": N, "low": N},
                "overall_risk": "critical|high|medium|low|none"
            }
        }
    """
    try:
        data = _load_json(json_path)

        # Mark as completed
        data["status"] = "completed"

        # Count tools and vulnerabilities
        tools = data.get("tools", [])
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        tools_with_vulns = 0

        for tool in tools:
            tool_vulns = tool.get("vulnerabilities", {})
            if tool_vulns.get("has_vulnerabilities", False):
                tools_with_vulns += 1
                for vuln in tool_vulns.get("vulnerabilities", []):
                    severity = vuln.get("severity", "low").lower()
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1

        # Determine overall risk
        if vuln_counts["critical"] > 0:
            overall_risk = "critical"
        elif vuln_counts["high"] > 0:
            overall_risk = "high"
        elif vuln_counts["medium"] > 0:
            overall_risk = "medium"
        elif sum(vuln_counts.values()) > 0:
            overall_risk = "low"
        else:
            overall_risk = "none"

        # Build summary
        summary = {
            "tools_analyzed": len(tools),
            "tools_with_vulnerabilities": tools_with_vulns,
            "vulnerability_counts": vuln_counts,
            "overall_risk": overall_risk
        }

        # Add summary to data
        data["final_summary"] = summary

        _save_json(json_path, data)
        logger.info(f"Final report written: {json_path}")

        return {
            "success": True,
            "error": None,
            "report_path": json_path,
            "summary": summary
        }

    except Exception as e:
        logger.error(f"Failed to write final report: {e}", exc_info=True)
        return {"success": False, "error": str(e), "report_path": "", "summary": {}}


__all__ = [
    "create_analysis_json",
    "write_tool_info",
    "write_dataflow",
    "write_vulnerabilities",
    "write_environment",
    "write_dependencies",
    "write_final_report"
]
