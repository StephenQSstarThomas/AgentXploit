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

from ..analyzers.pattern_detector import PatternDetector

logger = logging.getLogger(__name__)


def detect_patterns(
    repo_path: str,
    confidence_threshold: float = 0.7,
    max_patterns: int = 20,
    tool_context: Optional[ToolContext] = None
) -> str:
    """
    Detect security and vulnerability patterns in repository code.
    
    This tool identifies common vulnerability patterns, anti-patterns,
    configuration issues, and security-relevant code patterns that
    may indicate potential attack surfaces.
    
    Args:
        repo_path: Path to repository to analyze
        confidence_threshold: Minimum confidence for pattern detection (0.0-1.0)
        max_patterns: Maximum number of patterns to report
        tool_context: ADK tool context (optional)
    
    Returns:
        Pattern detection summary
    """
    
    try:
        logger.info(f"Starting pattern detection analysis of: {repo_path}")
        
        # Initialize pattern detector
        detector = PatternDetector()
        
        # Set default pattern types
        pattern_types = ["injection", "auth", "crypto", "file_access", "network"]
        
        # Perform pattern detection
        pattern_results = detector.detect_security_patterns(
            repo_path,
            pattern_types,
            confidence_threshold,
            max_patterns
        )
        
        if "error" in pattern_results:
            error_msg = f"Pattern detection failed: {pattern_results['error']}"
            logger.error(error_msg)
            return f"ERROR: {error_msg}"
        
        # Generate pattern summary
        summary = _generate_pattern_summary(pattern_results, repo_path)
        
        logger.info(f"Pattern detection completed for {repo_path}")
        return summary
        
    except Exception as e:
        error_msg = f"Failed to detect patterns in {repo_path}: {str(e)}"
        logger.error(error_msg)
        return f"ERROR: {error_msg}"


def _generate_pattern_summary(results: Dict[str, Any], repo_path: str) -> str:
    """Generate summary of pattern detection results"""
    
    patterns = results.get("patterns", [])
    pattern_types = results.get("pattern_types_found", [])
    high_confidence = [p for p in patterns if p.get("confidence", 0) >= 0.8]
    
    summary = f"""
Security Pattern Detection Results:

Repository: {repo_path}
Total Patterns Found: {len(patterns)}
High Confidence Patterns: {len(high_confidence)}
Pattern Types: {', '.join(pattern_types)}

High Confidence Security Patterns:
"""
    
    for pattern in high_confidence[:5]:  # Top 5
        pattern_type = pattern.get("type", "Unknown")
        description = pattern.get("description", "Unknown pattern")
        confidence = pattern.get("confidence", 0)
        location = pattern.get("location", "Unknown")
        summary += f"  - {pattern_type}: {description} (Confidence: {confidence:.2f}) in {location}\n"
    
    # Add pattern type breakdown
    if pattern_types:
        summary += "\nPattern Type Breakdown:\n"
        type_counts = {}
        for pattern in patterns:
            ptype = pattern.get("type", "Unknown")
            type_counts[ptype] = type_counts.get(ptype, 0) + 1
        
        for ptype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            summary += f"  - {ptype}: {count} patterns\n"
    
    return summary