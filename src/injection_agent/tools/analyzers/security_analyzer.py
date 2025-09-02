"""
Security analyzer using LLM for comprehensive security analysis.
Provides intelligent security assessment and vulnerability detection.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import os
import re

# Import LLMClient at module level
from ..smart_analyzer import LLMClient


@dataclass
class SecurityFinding:
    """Represents a security finding with risk assessment"""
    finding_id: str
    finding_type: str  # "injection_risk", "authentication_issue", "data_exposure", "configuration_risk"
    severity: str  # "high", "medium", "low", "info"
    file_path: str
    line_number: int
    description: str
    details: Dict[str, Any]
    risk_score: int  # 0-100
    recommendation: str
    code_snippet: str


class SecurityAnalyzer:
    """LLM-powered security analysis of code files"""
    
    def __init__(self):
        self.finding_counter = 0
        self._setup_llm()

    def _setup_llm(self):
        """Setup LLM for security analysis"""
        if not os.environ.get("OPENAI_API_KEY"):
            try:
                from ...config import settings
                api_key = settings.get_openai_api_key()
                os.environ["OPENAI_API_KEY"] = api_key
            except Exception:
                pass
    
    def analyze_file_security(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Perform LLM-powered comprehensive security analysis of a file.

        Args:
            file_path: Path to the file being analyzed
            content: File content to analyze

        Returns:
            Structured security analysis results
        """
        # Reset finding counter for this file
        self.finding_counter = 0

        # Perform LLM-based security analysis
        llm_analysis = self._analyze_with_llm(file_path, content)

        # Extract findings from LLM analysis
        findings = self._extract_findings_from_llm(file_path, content, llm_analysis)

        # Perform additional pattern-based analysis as fallback/supplement
        pattern_findings = self._analyze_patterns_basic(content)

        # Combine findings
        all_findings = findings + pattern_findings

        # Calculate overall risk assessment
        risk_assessment = self._calculate_risk_assessment(all_findings)

        # For LOW risk files, provide minimal output using LLM helper
        if risk_assessment["overall_risk"] == "LOW":
            # Use LLM helper to generate proper summary for LOW risk files
            llm_helper = self._get_llm_helper()
            llm_result = llm_helper.analyze_code_snippet(content, file_path)

            # Create minimal risk assessment
            minimal_risk_assessment = {
                "overall_risk": "LOW",
                "risk_score": 0
            }

            # Use LLM-generated summary, fallback to simple message if LLM fails
            if "analysis" in llm_result:
                summary = llm_result["analysis"]
            else:
                summary = "文件分析完成，未发现显著安全风险"

            return {
                "file_path": file_path,
                "analysis_timestamp": self._get_timestamp(),
                "risk_assessment": minimal_risk_assessment,
                "summary": summary,
                "llm_analysis": llm_result
            }

        return {
            "file_path": file_path,
            "analysis_timestamp": self._get_timestamp(),
            "risk_assessment": risk_assessment,
            "findings": all_findings,
            "llm_analysis": llm_analysis,
            "pattern_analysis": pattern_findings,
            "summary": self._generate_security_summary(all_findings, risk_assessment),
            "recommendations": self._generate_recommendations(all_findings)
        }
    
    def _analyze_with_llm(self, file_path: str, content: str) -> Dict[str, Any]:
        """Use LLM to perform comprehensive security analysis"""
        # Use centralized LLM client for security analysis
        lines = content.split('\n')
        file_extension = file_path.split('.')[-1] if '.' in file_path else 'unknown'

        # Check if this is likely a LOW risk file based on content analysis
        is_likely_low_risk = self._is_likely_low_risk(content, file_path)

        if is_likely_low_risk:
            # For LOW risk files, only extract function information
            prompt = f"""Analyze this {file_extension} file and extract function/class information:

File: {file_path}
Lines: {len(lines)}

Content:
{content[:1500]}...

Please provide:
1. List all functions/classes with their purposes
2. Overall security assessment

Format as JSON:
{{
    "overall_risk": "LOW",
    "risk_score": 0,
    "findings": [],
    "functions": [
        {{
            "name": "function_name",
            "purpose": "Brief description of what this function does"
        }}
    ],
    "summary": "Functions identified and no significant security issues detected"
}}"""
        else:
            # For potentially risky files, perform comprehensive analysis
            prompt = f"""Perform a comprehensive security analysis of this {file_extension} file:

File: {file_path}
Lines: {len(lines)}

Content:
{content[:2000]}...  # Limit content for LLM

Please analyze for:
1. Security vulnerabilities (injection, XSS, authentication issues)
2. Data exposure risks
3. Configuration problems
4. Code quality and security best practices
5. Potential attack vectors

Format your response as JSON with this structure:
{{
    "overall_risk": "HIGH|MEDIUM|LOW",
    "risk_score": 0-100,
    "findings": [
        {{
            "type": "vulnerability_type",
            "severity": "high|medium|low",
            "line": 123,
            "description": "description of issue",
            "code_snippet": "relevant code",
            "recommendation": "how to fix"
        }}
    ],
    "summary": "Brief security assessment summary"
}}"""

        # Use centralized LLM client
        result_text = LLMClient.call_llm(
            model=LLMClient.get_model(),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200 if not is_likely_low_risk else 800,  # Smaller for low risk
            temperature=0.1,
            timeout=30 if not is_likely_low_risk else 20,  # Faster for low risk
            max_retries=3 if not is_likely_low_risk else 2
        )

        if result_text:
            # Try to parse JSON response
            try:
                import json
                parsed_result = json.loads(result_text)

                # Handle function information for LOW risk files
                if is_likely_low_risk and "functions" in parsed_result:
                    parsed_result["summary"] = self._format_function_summary(parsed_result.get("functions", []))
                elif isinstance(parsed_result.get("summary"), dict):
                    # New structured format for high/medium risk
                    summary_data = parsed_result["summary"]
                    parsed_result["summary"] = self._format_structured_summary(summary_data)

                return parsed_result
            except:
                # If JSON parsing fails, return structured response
                return {
                    "overall_risk": "MEDIUM" if not is_likely_low_risk else "LOW",
                    "risk_score": 50 if not is_likely_low_risk else 0,
                    "findings": [],
                    "summary": result_text[:500],
                    "llm_raw_response": result_text
                }
        else:
            return {
                "overall_risk": "UNKNOWN",
                "risk_score": 0,
                "findings": [],
                "summary": "LLM analysis failed - no response received",
                "error": "LLM call failed"
            }

    def _extract_findings_from_llm(self, file_path: str, content: str, llm_analysis: Dict) -> List[SecurityFinding]:
        """Extract security findings from LLM analysis with enhanced LLM-driven decision making"""
        findings = []
        
        llm_findings = llm_analysis.get("findings", [])

        for finding_data in llm_findings:
            # LLM-driven decision: Let LLM determine the finding type based on content
            finding_type = self._classify_finding_with_llm(finding_data, content)

            # LLM-driven decision: Let LLM determine severity with more context
            severity = self._assess_severity_with_llm(finding_data, content, file_path)

            # LLM-driven decision: Let LLM determine risk score with context
            risk_score = self._calculate_llm_driven_risk_score(finding_data, severity, content)

            finding = SecurityFinding(
                finding_id=self._next_finding_id(),
                finding_type=finding_type,
                severity=severity,
                file_path=file_path,
                line_number=finding_data.get("line", 1),
                description=finding_data.get("description", "Security issue detected"),
                details={
                    "llm_analysis": llm_analysis.get("summary", ""),
                    "detection_method": "llm_analysis",
                    "llm_risk_assessment": f"LLM-determined risk score: {risk_score}",
                    "content_context": self._extract_content_context(content, finding_data.get("line", 1))
                },
                risk_score=risk_score,
                recommendation=self._generate_llm_recommendation(finding_data, content),
                code_snippet=finding_data.get("code_snippet", "")
            )
            findings.append(finding)
        
        return findings

    def _classify_finding_with_llm(self, finding_data: Dict, content: str) -> str:
        """Use LLM to classify the finding type based on content context"""
        prompt = f"""Classify this security finding based on the code context:

Finding: {finding_data.get('description', '')}
Code snippet: {finding_data.get('code_snippet', '')}

Classify as one of: injection_risk, authentication_issue, data_exposure, configuration_risk, code_quality, other

Respond with just the classification:"""

        response_text = LLMClient.call_llm(
            model=LLMClient.get_model(),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=50,
            temperature=0.1,
            timeout=15,
            max_retries=2
        )

        if response_text:
            classification = response_text.strip().lower()
            # Map to valid finding types
            valid_types = ["injection_risk", "authentication_issue", "data_exposure", "configuration_risk", "code_quality"]
            if classification in valid_types:
                return classification

        return finding_data.get("type", "general_security_issue")

    def _assess_severity_with_llm(self, finding_data: Dict, content: str, file_path: str) -> str:
        """Use LLM to assess severity with full context"""
        prompt = f"""Assess the severity of this security finding considering:

File: {file_path}
Finding: {finding_data.get('description', '')}
Context: {content[:500]}...

Rate severity as: critical, high, medium, low, info

Consider:
- Potential impact on the system
- Ease of exploitation
- Data sensitivity
- System criticality

Respond with just the severity level:"""

        response_text = LLMClient.call_llm(
            model=LLMClient.get_model(),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=20,
            temperature=0.1,
            timeout=15,
            max_retries=2
        )

        if response_text:
            severity = response_text.strip().lower()
            # Normalize severity
            if severity in ["critical"]:
                return "high"
            elif severity in ["high", "medium", "low", "info"]:
                return severity

        return finding_data.get("severity", "medium")

    def _calculate_llm_driven_risk_score(self, finding_data: Dict, severity: str, content: str) -> int:
        """Use LLM to calculate risk score with context"""
        prompt = f"""Calculate a risk score (0-100) for this security finding:

Severity: {severity}
Description: {finding_data.get('description', '')}
Code context: {content[:300]}...

Consider:
- Technical complexity of exploitation
- Potential data exposure
- System impact
- Likelihood of occurrence
- Current mitigations in the code

Respond with just the numeric score:"""

        response_text = LLMClient.call_llm(
            model=LLMClient.get_model(),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=10,
            temperature=0.1,
            timeout=15,
            max_retries=2
        )

        if response_text:
            # Extract numeric score
            import re
            numbers = re.findall(r'\d+', response_text)
            if numbers:
                score = int(numbers[0])
                return max(0, min(100, score))

        return self._calculate_risk_score_from_severity(severity)

    def _generate_llm_recommendation(self, finding_data: Dict, content: str) -> str:
        """Use LLM to generate specific recommendations"""
        prompt = f"""Generate a specific, actionable recommendation for this security finding:

Finding: {finding_data.get('description', '')}
Code context: {content[:300]}...

Provide a concrete, implementable solution.
Keep it brief but specific:"""

        response_text = LLMClient.call_llm(
            model=LLMClient.get_model(),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=100,
            temperature=0.2,
            timeout=15,
            max_retries=2
        )

        if response_text and len(response_text) > 10:
            return response_text

        return finding_data.get("recommendation", "Review and address this security concern")

    def _extract_content_context(self, content: str, line_number: int) -> str:
        """Extract relevant content context around the finding"""
        lines = content.split('\n')
        start = max(0, line_number - 3)
        end = min(len(lines), line_number + 3)

        context_lines = []
        for i in range(start, end):
            marker = ">>> " if i + 1 == line_number else "    "
            context_lines.append(f"{marker}{i + 1:4d}: {lines[i]}")

        return "\n".join(context_lines)

    def _is_likely_low_risk(self, content: str, file_path: str) -> bool:
        """Determine if a file is likely to be LOW risk based on content analysis"""
        # Quick content analysis to determine if this is likely a low-risk file
        content_lower = content.lower()

        # Check for risky patterns
        risky_patterns = [
            'api[_-]?key', 'password', 'secret', 'token', 'auth',
            'eval', 'exec', 'system', 'subprocess', 'shell',
            'sql', 'query', 'database', 'inject',
            'config', 'settings', 'env', 'credential'
        ]

        risky_count = 0
        for pattern in risky_patterns:
            if re.search(pattern, content_lower):
                risky_count += 1

        # If file has very few risky patterns and is not a config file, likely low risk
        file_extension = file_path.split('.')[-1] if '.' in file_path else ''
        config_files = ['config', 'settings', 'env', 'toml', 'yaml', 'yml', 'json']

        if file_extension in config_files:
            return False  # Config files are potentially risky

        # Consider low risk if very few risky patterns found
        return risky_count <= 2

    def _format_structured_summary(self, summary_data: Dict) -> str:
        """Format structured summary data into readable text"""
        if not isinstance(summary_data, dict):
            return str(summary_data)

        file_purpose = summary_data.get("file_purpose", "Unknown purpose")
        security_issue_location = summary_data.get("security_issue_location", "No specific location")
        issue_explanation = summary_data.get("issue_explanation", "No detailed explanation available")

        # Format the structured summary
        formatted_summary = f"""file function:{file_purpose}
        security issue location:{security_issue_location}
        issue description:{issue_explanation}"""

        return formatted_summary





    def _analyze_patterns_basic(self, content: str) -> List[SecurityFinding]:
        """Perform basic pattern-based security analysis as supplement"""
        findings = []

        # Common dangerous patterns
        dangerous_patterns = [
            (r"eval\s*\(", "HIGH", "Use of eval() function"),
            (r"exec\s*\(", "HIGH", "Use of exec() function"),
            (r"os\.system\s*\(", "HIGH", "Use of os.system()"),
            (r"subprocess\.(call|Popen|run)\s*\(", "MEDIUM", "Subprocess execution"),
            (r"SQLAlchemy.*text\s*\(", "HIGH", "SQL injection via SQLAlchemy text"),
            (r"cursor\.execute\s*\([^,)]*\+\s*[^,)]*\)", "HIGH", "Potential SQL injection"),
            (r"innerHTML\s*=.*\+", "HIGH", "Potential XSS via innerHTML"),
            (r"document\.write\s*\(.*\+.*\)", "HIGH", "Potential XSS via document.write"),
            (r"password\s*=\s*['\"][^'\"]{0,10}['\"]", "MEDIUM", "Weak or empty password"),
            (r"secret[_-]?key\s*=\s*['\"][^'\"]*['\"]", "HIGH", "Hardcoded secret key"),
            (r"api[_-]?key\s*=\s*['\"][^'\"]*['\"]", "HIGH", "Hardcoded API key"),
        ]

        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            for pattern, severity, description in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = SecurityFinding(
                        finding_id=self._next_finding_id(),
                        finding_type="pattern_based",
                        severity=severity.lower(),
                        file_path="",  # Will be filled by caller
                        line_number=i,
                        description=description,
                        details={
                            "pattern": pattern,
                            "matched_line": line.strip(),
                            "detection_method": "regex_pattern"
                        },
                        risk_score=self._calculate_risk_score_from_severity(severity.lower()),
                        recommendation=self._get_recommendation_for_pattern(pattern),
                        code_snippet=line.strip()
                    )
                    findings.append(finding)

        return findings

    def _calculate_risk_score_from_severity(self, severity: str) -> int:
        """Convert severity string to risk score"""
        severity_map = {
            "high": 80,
            "medium": 50,
            "low": 25,
            "info": 10
        }
        return severity_map.get(severity.lower(), 25)
    
    def _get_recommendation_for_pattern(self, pattern: str) -> str:
        """Get specific recommendation for a security pattern"""
        recommendations = {
            r"eval\s*\(": "Avoid using eval(). Use ast.literal_eval() for safe evaluation",
            r"exec\s*\(": "Avoid using exec(). Use safer alternatives or validate input thoroughly",
            r"os\.system\s*\(": "Use subprocess module with proper argument handling",
            r"subprocess\.(call|Popen|run)\s*\(": "Validate command arguments and avoid shell=True when possible",
            r"SQLAlchemy.*text\s*\(": "Use parameterized queries to prevent SQL injection",
            r"cursor\.execute\s*\([^,)]*\+\s*[^,)]*\)": "Use parameterized queries to prevent SQL injection",
            r"innerHTML\s*=.*\+": "Use textContent or innerText, or properly escape HTML",
            r"document\.write\s*\(.*\+.*\)": "Avoid document.write with user input. Use DOM manipulation instead",
            r"password\s*=\s*['\"][^'\"]{0,10}['\"]": "Use strong passwords and never hardcode them",
            r"secret[_-]?key\s*=\s*['\"][^'\"]*['\"]": "Move secrets to environment variables or secure config",
            r"api[_-]?key\s*=\s*['\"][^'\"]*['\"]": "Store API keys securely, never in source code"
        }

        for pattern_key, recommendation in recommendations.items():
            if re.search(pattern_key, pattern):
                return recommendation

        return "Review this pattern for security implications"
    
    def _calculate_risk_assessment(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Calculate overall risk assessment for the file"""
        if not findings:
            return {
                "overall_risk": "LOW",
                "risk_score": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0
            }

        # Count findings by severity
        high_findings = sum(1 for f in findings if f.severity == "high")
        medium_findings = sum(1 for f in findings if f.severity == "medium")
        low_findings = sum(1 for f in findings if f.severity == "low")

        # Calculate overall risk with adjusted thresholds for cleaner output
        total_risk_score = sum(f.risk_score for f in findings) // len(findings) if findings else 0

        if high_findings > 0:
            overall_risk = "HIGH"
        elif medium_findings > 0:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"  # Only low severity findings = LOW risk

        return {
            "overall_risk": overall_risk,
            "risk_score": total_risk_score if overall_risk != "LOW" else 0,  # Don't show score for LOW risk
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

        # For LOW risk files, provide minimal summary
        if risk_level == "LOW":
            total_findings = risk_assessment["total_findings"]
            if total_findings == 0:
                return "Security Risk: LOW - No security issues found"
            else:
                return f"Security Risk: LOW - {total_findings} minor finding(s), no immediate action required"

        # For MEDIUM and HIGH risk files, provide detailed summary
        risk_score = risk_assessment["risk_score"]
        summary = f"Security Risk: {risk_level} (Score: {risk_score}/100)"

        if risk_assessment["high_findings"] > 0:
            summary += f"\n- {risk_assessment['high_findings']} high-risk finding(s)"

        if risk_assessment["medium_findings"] > 0:
            summary += f"\n- {risk_assessment['medium_findings']} medium-risk finding(s)"

        # Highlight specific critical issues
        injection_findings = [f for f in findings if "injection" in f.finding_type.lower()]
        if injection_findings:
            summary += f"\n- WARNING: {len(injection_findings)} potential injection vulnerability(ies)"

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

    def _get_llm_helper(self):
        """Get LLM helper instance for code analysis"""
        from ..code_analysis.llm_decider import LLMHelper
        return LLMHelper()
    
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