# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from typing import Optional, Dict, Any
from google.adk.tools import ToolContext

from ..core import CoreTools
from ..injection_specific.security_scanner import scan_directory

logger = logging.getLogger(__name__)


def scan_directory_security(
    directory_path: str,
    max_files: int = 50,
    scan_depth: int = 3,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Perform comprehensive security scanning of a directory.
    
    This tool scans directories for security vulnerabilities, identifies
    potential injection points, assesses file-level risks, and generates
    security assessment reports.
    
    Args:
        directory_path: Path to directory to scan
        max_files: Maximum number of files to scan (default: 50)
        scan_depth: Maximum directory depth to scan (default: 3)
        tool_context: ADK tool context (optional)
    
    Returns:
        Security scan summary and findings
    """
    
    try:
        logger.info(f"Starting security scan of directory: {directory_path}")
        
        # Initialize core tools for the directory
        tools = CoreTools(directory_path)
        
        # Perform the security scan using existing scanner
        scan_results = scan_directory(tools)
        
        if "error" in scan_results:
            error_msg = f"Security scan failed: {scan_results['error']}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        # Generate security summary
        security_summary = _generate_security_summary(scan_results, directory_path)
        
        logger.info(f"Security scan completed for {directory_path}")
        return security_summary
        
    except Exception as e:
        error_msg = f"Failed to perform security scan of {directory_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_security_summary(scan_results: Dict[str, Any], directory_path: str) -> str:
    """Generate a concise summary of security scan results"""
    
    # Extract security metrics
    total_files = scan_results.get("total_files_scanned", 0)
    vulnerabilities = scan_results.get("vulnerabilities_found", [])
    risk_levels = scan_results.get("risk_assessment", {})
    injection_points = scan_results.get("potential_injection_points", [])
    
    # Count vulnerabilities by severity
    high_severity = len([v for v in vulnerabilities if v.get("severity") == "HIGH"])
    medium_severity = len([v for v in vulnerabilities if v.get("severity") == "MEDIUM"])
    low_severity = len([v for v in vulnerabilities if v.get("severity") == "LOW"])
    
    summary = f"""
Security Scan Results:

Directory: {directory_path}
Files Scanned: {total_files}
Total Vulnerabilities: {len(vulnerabilities)}

Severity Breakdown:
  High:   {high_severity}
  Medium: {medium_severity}
  Low:    {low_severity}

Potential Injection Points: {len(injection_points)}
"""
    
    # Add top vulnerabilities
    if vulnerabilities:
        summary += "\nTop Security Vulnerabilities:\n"
        for vuln in vulnerabilities[:5]:  # Top 5
            vuln_type = vuln.get("type", "Unknown")
            severity = vuln.get("severity", "Unknown")
            file_path = vuln.get("file", "Unknown")
            summary += f"  - {vuln_type} ({severity}) in {file_path}\n"
    
    # Add injection points if found
    if injection_points:
        summary += "\nPotential Injection Points:\n"
        for point in injection_points[:3]:  # Top 3
            location = point.get("location", "Unknown")
            risk = point.get("risk_level", "Unknown")
            summary += f"  - {location} (Risk: {risk})\n"
    
    # Add overall risk assessment
    overall_risk = risk_levels.get("overall_risk", "UNKNOWN")
    risk_score = risk_levels.get("risk_score", 0)
    summary += f"\nOverall Risk Level: {overall_risk} (Score: {risk_score}/10)\n"
    
    # Add recommendations
    recommendations = scan_results.get("recommendations", [])
    if recommendations:
        summary += "\nSecurity Recommendations:\n"
        for rec in recommendations[:3]:  # Top 3
            summary += f"  - {rec}\n"
    
    return summary