"""
Security analyzer coordinator for comprehensive security analysis.
Orchestrates pattern detection, dataflow analysis, and risk assessment.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from .pattern_detector import PatternDetector, DetectedPattern, InputPoint
from .dataflow_tracker import DataflowTracker, DataFlow


@dataclass
class SecurityFinding:
    """Represents a security finding with risk assessment"""
    finding_id: str
    finding_type: str  # "dangerous_pattern", "data_flow", "input_point"
    severity: str  # "high", "medium", "low"
    file_path: str
    line_number: int
    description: str
    details: Dict[str, Any]
    risk_score: int  # 0-100
    recommendation: str


class SecurityAnalyzer:
    """Coordinates security-focused analysis of code files"""
    
    def __init__(self):
        self.pattern_detector = PatternDetector()
        self.dataflow_tracker = DataflowTracker()
        self.finding_counter = 0
    
    def analyze_file_security(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis of a file.
        
        Args:
            file_path: Path to the file being analyzed
            content: File content to analyze
            
        Returns:
            Structured security analysis results
        """
        # Reset finding counter for this file
        self.finding_counter = 0
        
        # Pattern detection
        dangerous_patterns = self.pattern_detector.detect_dangerous_patterns(content)
        input_points = self.pattern_detector.detect_input_points(content)
        safety_analysis = self.pattern_detector.analyze_code_safety(content)
        
        # Dataflow analysis
        data_flows = self.dataflow_tracker.find_data_flows(content)
        injection_risks = self.dataflow_tracker.find_potential_injections(content)
        
        # Generate security findings
        findings = self._generate_security_findings(
            file_path, dangerous_patterns, input_points, data_flows, injection_risks
        )
        
        # Calculate overall risk assessment
        risk_assessment = self._calculate_risk_assessment(findings, safety_analysis)
        
        return {
            "file_path": file_path,
            "analysis_timestamp": self._get_timestamp(),
            "risk_assessment": risk_assessment,
            "findings": findings,
            "patterns": {
                "dangerous_patterns": dangerous_patterns,
                "input_points": input_points,
                "safety_analysis": safety_analysis
            },
            "dataflow": {
                "data_flows": data_flows,
                "injection_risks": injection_risks,
                "dataflow_summary": self.dataflow_tracker.get_dataflow_summary(content)
            },
            "summary": self._generate_security_summary(findings, risk_assessment),
            "recommendations": self._generate_recommendations(findings)
        }
    
    def _generate_security_findings(
        self, 
        file_path: str,
        dangerous_patterns: List[DetectedPattern],
        input_points: List[InputPoint],
        data_flows: List[DataFlow],
        injection_risks: List[Dict[str, Any]]
    ) -> List[SecurityFinding]:
        """Generate structured security findings"""
        findings = []
        
        # Process dangerous patterns
        for pattern in dangerous_patterns:
            finding = SecurityFinding(
                finding_id=self._next_finding_id(),
                finding_type="dangerous_pattern",
                severity=pattern.severity,
                file_path=file_path,
                line_number=pattern.line_number,
                description=pattern.description,
                details={
                    "pattern_type": pattern.pattern_type,
                    "matched_text": pattern.matched_text,
                    "context": pattern.context
                },
                risk_score=self.score_injection_risk(pattern.pattern_type, pattern.context, pattern.severity),
                recommendation=self._get_pattern_recommendation(pattern.pattern_type)
            )
            findings.append(finding)
        
        # Process injection risks (high priority findings)
        for risk in injection_risks:
            if risk["severity"] == "HIGH":
                finding = SecurityFinding(
                    finding_id=self._next_finding_id(),
                    finding_type="injection_vulnerability",
                    severity="high",
                    file_path=file_path,
                    line_number=risk["sink_line"],
                    description=f"Potential injection: {risk['description']}",
                    details={
                        "vulnerability_type": risk["type"],
                        "variable": risk["variable"],
                        "source_line": risk["source_line"],
                        "sink_line": risk["sink_line"],
                        "dataflow": risk["flow"]
                    },
                    risk_score=85,  # High risk score for injection vulnerabilities
                    recommendation="Validate and sanitize input before use in dangerous operations"
                )
                findings.append(finding)
        
        # Process significant input points (only if they connect to dangerous patterns)
        risky_inputs = self._identify_risky_input_points(input_points, dangerous_patterns)
        for input_point in risky_inputs:
            finding = SecurityFinding(
                finding_id=self._next_finding_id(),
                finding_type="risky_input_point",
                severity="medium",
                file_path=file_path,
                line_number=input_point.line_number,
                description=f"Input point that may feed dangerous operations: {input_point.description}",
                details={
                    "input_type": input_point.input_type,
                    "variable_name": input_point.variable_name,
                    "context": input_point.context
                },
                risk_score=60,
                recommendation="Implement input validation and sanitization"
            )
            findings.append(finding)
        
        return sorted(findings, key=lambda f: (f.severity == "high", f.risk_score), reverse=True)
    
    def score_injection_risk(self, pattern_type: str, context: str, severity: str = "medium") -> int:
        """
        Score injection risk for a pattern based on type and context.
        
        Args:
            pattern_type: Type of dangerous pattern detected
            context: Code context where pattern was found
            severity: Base severity level
            
        Returns:
            Risk score from 0-100
        """
        base_score = {
            "high": 70,
            "medium": 40,
            "low": 20
        }.get(severity, 40)
        
        # Pattern-specific scoring
        pattern_multipliers = {
            "exec": 1.3,
            "eval": 1.3,
            "os_system": 1.2,
            "subprocess_call": 1.1,
            "sql_execute": 1.2,
            "compile": 1.1
        }
        
        multiplier = pattern_multipliers.get(pattern_type, 1.0)
        score = int(base_score * multiplier)
        
        # Context-based adjustments
        context_lower = context.lower()
        
        # Higher score if user input is nearby
        input_indicators = ["input(", "request.", "argv", "stdin", "raw_input("]
        if any(indicator in context_lower for indicator in input_indicators):
            score += 20
        
        # Higher score if in web/API context
        web_indicators = ["request", "response", "http", "api", "route", "view"]
        if any(indicator in context_lower for indicator in web_indicators):
            score += 15
        
        # Lower score if input appears to be hardcoded
        hardcode_indicators = ["'", '"', "constant", "config"]
        if any(indicator in context_lower for indicator in hardcode_indicators):
            score -= 25
        
        # Lower score if there are validation keywords nearby
        validation_indicators = ["validate", "sanitize", "escape", "check", "verify"]
        if any(indicator in context_lower for indicator in validation_indicators):
            score -= 20
        
        return max(10, min(100, score))
    
    def _identify_risky_input_points(
        self, 
        input_points: List[InputPoint], 
        dangerous_patterns: List[DetectedPattern]
    ) -> List[InputPoint]:
        """Identify input points that may feed into dangerous operations"""
        if not dangerous_patterns:
            return []
        
        # For simplicity, return input points that are within 10 lines of dangerous patterns
        risky_inputs = []
        dangerous_lines = {p.line_number for p in dangerous_patterns}
        
        for input_point in input_points:
            # Check if input is near a dangerous pattern
            if any(abs(input_point.line_number - dl) <= 10 for dl in dangerous_lines):
                risky_inputs.append(input_point)
        
        return risky_inputs
    
    def _calculate_risk_assessment(
        self, 
        findings: List[SecurityFinding], 
        safety_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate overall risk assessment for the file"""
        if not findings:
            return {
                "overall_risk": "LOW",
                "risk_score": safety_analysis.get("risk_score", 0),
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0
            }
        
        # Count findings by severity
        high_findings = sum(1 for f in findings if f.severity == "high")
        medium_findings = sum(1 for f in findings if f.severity == "medium")
        low_findings = sum(1 for f in findings if f.severity == "low")
        
        # Calculate overall risk
        total_risk_score = sum(f.risk_score for f in findings) // len(findings) if findings else 0
        
        if high_findings > 0 or total_risk_score >= 70:
            overall_risk = "HIGH"
        elif medium_findings > 0 or total_risk_score >= 40:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            "overall_risk": overall_risk,
            "risk_score": max(total_risk_score, safety_analysis.get("risk_score", 0)),
            "critical_findings": 0,  # Reserved for future use
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "low_findings": low_findings,
            "total_findings": len(findings)
        }
    
    def _generate_security_summary(
        self, 
        findings: List[SecurityFinding], 
        risk_assessment: Dict[str, Any]
    ) -> str:
        """Generate a human-readable security summary"""
        risk_level = risk_assessment["overall_risk"]
        risk_score = risk_assessment["risk_score"]
        
        summary = f"Security Risk: {risk_level} (Score: {risk_score}/100)"
        
        if risk_assessment["high_findings"] > 0:
            summary += f"\n- {risk_assessment['high_findings']} high-risk finding(s)"
        
        if risk_assessment["medium_findings"] > 0:
            summary += f"\n- {risk_assessment['medium_findings']} medium-risk finding(s)"
        
        # Highlight specific critical issues
        injection_findings = [f for f in findings if f.finding_type == "injection_vulnerability"]
        if injection_findings:
            summary += f"\n- ⚠️  {len(injection_findings)} potential injection vulnerability(ies)"
        
        return summary
    
    def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = set()
        
        for finding in findings:
            if finding.severity in ["high", "medium"]:
                recommendations.add(finding.recommendation)
        
        # Add general recommendations based on finding types
        finding_types = {f.finding_type for f in findings}
        
        if "dangerous_pattern" in finding_types:
            recommendations.add("Review all dynamic code execution patterns for necessity and safety")
        
        if "injection_vulnerability" in finding_types:
            recommendations.add("Implement comprehensive input validation and output encoding")
        
        if "risky_input_point" in finding_types:
            recommendations.add("Audit all user input handling for proper sanitization")
        
        return sorted(list(recommendations))
    
    def _get_pattern_recommendation(self, pattern_type: str) -> str:
        """Get specific recommendation for a pattern type"""
        recommendations = {
            "exec": "Avoid using exec(). Use safer alternatives or validate input thoroughly",
            "eval": "Avoid using eval(). Use ast.literal_eval() for safe evaluation",
            "os_system": "Use subprocess module with proper argument handling",
            "subprocess_call": "Validate command arguments and avoid shell=True when possible",
            "sql_execute": "Use parameterized queries to prevent SQL injection",
            "compile": "Validate source code before compilation",
            "importlib": "Validate module names before dynamic import",
            "socket": "Implement proper network security measures"
        }
        return recommendations.get(pattern_type, "Review this pattern for security implications")
    
    def _next_finding_id(self) -> str:
        """Generate next finding ID"""
        self.finding_counter += 1
        return f"SEC-{self.finding_counter:03d}"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        import datetime
        return datetime.datetime.now().isoformat()
    
    def batch_analyze_files(self, files: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze multiple files and provide aggregate results.
        
        Args:
            files: Dictionary mapping file paths to file contents
            
        Returns:
            Aggregate security analysis results
        """
        results = {}
        all_findings = []
        
        for file_path, content in files.items():
            file_result = self.analyze_file_security(file_path, content)
            results[file_path] = file_result
            all_findings.extend(file_result["findings"])
        
        # Generate aggregate statistics
        aggregate_stats = self._calculate_aggregate_stats(all_findings, results)
        
        return {
            "files_analyzed": len(files),
            "individual_results": results,
            "aggregate_findings": all_findings,
            "aggregate_stats": aggregate_stats,
            "summary": self._generate_aggregate_summary(aggregate_stats)
        }
    
    def _calculate_aggregate_stats(self, all_findings: List[SecurityFinding], results: Dict) -> Dict[str, Any]:
        """Calculate aggregate statistics across all analyzed files"""
        high_risk_files = sum(1 for r in results.values() if r["risk_assessment"]["overall_risk"] == "HIGH")
        medium_risk_files = sum(1 for r in results.values() if r["risk_assessment"]["overall_risk"] == "MEDIUM")
        low_risk_files = sum(1 for r in results.values() if r["risk_assessment"]["overall_risk"] == "LOW")
        
        return {
            "total_findings": len(all_findings),
            "high_risk_files": high_risk_files,
            "medium_risk_files": medium_risk_files,
            "low_risk_files": low_risk_files,
            "findings_by_severity": {
                "high": sum(1 for f in all_findings if f.severity == "high"),
                "medium": sum(1 for f in all_findings if f.severity == "medium"),
                "low": sum(1 for f in all_findings if f.severity == "low")
            }
        }
    
    def _generate_aggregate_summary(self, stats: Dict[str, Any]) -> str:
        """Generate summary for multiple file analysis"""
        summary = f"Analyzed {stats['high_risk_files'] + stats['medium_risk_files'] + stats['low_risk_files']} files"
        
        if stats['high_risk_files'] > 0:
            summary += f", {stats['high_risk_files']} HIGH risk"
        if stats['medium_risk_files'] > 0:
            summary += f", {stats['medium_risk_files']} MEDIUM risk"
        
        summary += f"\nTotal findings: {stats['total_findings']}"
        
        return summary