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

from ..analyzers.dataflow_tracker import DataflowTracker

logger = logging.getLogger(__name__)


def track_dataflow(
    repo_path: str,
    max_paths: int = 10,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Track data flow through the repository to identify potential vulnerabilities.
    
    This tool traces data movement through the system, identifies data
    transformation points, maps input/output relationships, and finds
    potential data leakage or injection points.
    
    Args:
        repo_path: Path to repository to analyze
        max_paths: Maximum number of data flow paths to analyze
        tool_context: ADK tool context (optional)
    
    Returns:
        Data flow analysis summary
    """
    
    try:
        logger.info(f"Starting data flow analysis of: {repo_path}")
        
        # Initialize dataflow tracker
        tracker = DataflowTracker()
        
        # Set default patterns
        source_patterns = ["input", "request", "user", "param", "arg"]
        sink_patterns = ["execute", "eval", "system", "command", "subprocess"]
        
        # Perform dataflow analysis
        dataflow_results = tracker.track_data_flows(
            repo_path,
            source_patterns,
            sink_patterns,
            max_paths
        )
        
        if "error" in dataflow_results:
            error_msg = f"Data flow analysis failed: {dataflow_results['error']}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        # Generate dataflow summary
        summary = _generate_dataflow_summary(dataflow_results, repo_path)
        
        logger.info(f"Data flow analysis completed for {repo_path}")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to analyze data flow of {repo_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_dataflow_summary(results: Dict[str, Any], repo_path: str) -> str:
    """Generate summary of data flow analysis"""
    
    data_flows = results.get("data_flows", [])
    sources = results.get("sources", [])
    sinks = results.get("sinks", [])
    vulnerable_paths = results.get("vulnerable_paths", [])
    
    summary = f"""
Data Flow Analysis Results:

Repository: {repo_path}
Data Sources: {len(sources)}
Data Sinks: {len(sinks)}
Data Flow Paths: {len(data_flows)}
Vulnerable Paths: {len(vulnerable_paths)}

Key Data Sources:
"""
    
    for source in sources[:5]:  # Top 5
        source_type = source.get("type", "Unknown")
        location = source.get("location", "Unknown")
        summary += f"  - {source_type} in {location}\n"
    
    if vulnerable_paths:
        summary += "\nVulnerable Data Flow Paths:\n"
        for path in vulnerable_paths[:3]:  # Top 3
            path_desc = path.get("description", "Unknown path")
            risk_level = path.get("risk_level", "Unknown")
            summary += f"  - {path_desc} (Risk: {risk_level})\n"
    
    return summary