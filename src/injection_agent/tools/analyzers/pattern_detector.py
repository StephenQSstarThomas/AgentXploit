"""
Pattern detector for identifying dangerous code patterns and input points.
Detects security-relevant patterns in Python code.
"""

import re
import ast
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass


@dataclass
class DetectedPattern:
    """Represents a detected code pattern"""
    pattern_type: str
    line_number: int
    context: str
    severity: str  # "high", "medium", "low"
    description: str
    matched_text: str


@dataclass  
class InputPoint:
    """Represents a detected input point"""
    input_type: str
    line_number: int
    variable_name: str
    context: str
    description: str


class PatternDetector:
    """Detects dangerous patterns and input points in Python code"""
    
    def __init__(self):
        # Dangerous function patterns
        self.dangerous_patterns = {
            # Code execution
            'exec': {
                'pattern': r'\bexec\s*\(',
                'severity': 'high',
                'description': 'Dynamic code execution with exec()'
            },
            'eval': {
                'pattern': r'\beval\s*\(',
                'severity': 'high', 
                'description': 'Dynamic code evaluation with eval()'
            },
            'compile': {
                'pattern': r'\bcompile\s*\(',
                'severity': 'medium',
                'description': 'Code compilation with compile()'
            },
            
            # System commands
            'os_system': {
                'pattern': r'\bos\.system\s*\(',
                'severity': 'high',
                'description': 'System command execution with os.system()'
            },
            'subprocess_call': {
                'pattern': r'\bsubprocess\.(call|run|Popen|check_call|check_output)\s*\(',
                'severity': 'high',
                'description': 'Process execution with subprocess'
            },
            'popen': {
                'pattern': r'\bos\.popen\s*\(',
                'severity': 'high',
                'description': 'Process execution with os.popen()'
            },
            
            # Dynamic imports
            'importlib': {
                'pattern': r'\bimportlib\.import_module\s*\(',
                'severity': 'medium',
                'description': 'Dynamic module import'
            },
            'builtin_import': {
                'pattern': r'\b__import__\s*\(',
                'severity': 'medium',
                'description': 'Dynamic import with __import__()'
            },
            
            # File operations
            'open_write': {
                'pattern': r'\bopen\s*\([^)]*[\'"][wa][\'"]',
                'severity': 'medium',
                'description': 'File writing operation'
            },
            
            # Network operations
            'socket': {
                'pattern': r'\bsocket\.(socket|create_connection)\s*\(',
                'severity': 'medium',
                'description': 'Network socket operation'
            },
            
            # SQL-like patterns
            'sql_execute': {
                'pattern': r'\.(execute|executemany|query)\s*\(',
                'severity': 'medium',
                'description': 'Database query execution'
            }
        }
        
        # Input point patterns
        self.input_patterns = {
            # Web input
            'request_body': {
                'pattern': r'\brequest\.(body|data|form|json|args|values)',
                'type': 'web_input',
                'description': 'Web request input'
            },
            'request_get': {
                'pattern': r'\brequest\.GET\[',
                'type': 'web_input',
                'description': 'HTTP GET parameter'
            },
            'request_post': {
                'pattern': r'\brequest\.POST\[',
                'type': 'web_input',
                'description': 'HTTP POST parameter'
            },
            
            # Command line input
            'sys_argv': {
                'pattern': r'\bsys\.argv',
                'type': 'command_line',
                'description': 'Command line arguments'
            },
            'argparse': {
                'pattern': r'\.add_argument\(',
                'type': 'command_line',
                'description': 'Command line argument parsing'
            },
            
            # Standard input
            'input_builtin': {
                'pattern': r'\binput\s*\(',
                'type': 'stdin',
                'description': 'Standard input'
            },
            'raw_input': {
                'pattern': r'\braw_input\s*\(',
                'type': 'stdin',
                'description': 'Raw input (Python 2)'
            },
            'stdin_read': {
                'pattern': r'\bsys\.stdin\.(read|readline)',
                'type': 'stdin',
                'description': 'Standard input reading'
            },
            
            # File input
            'file_read': {
                'pattern': r'\bopen\s*\([^)]*[\'"]r[\'"]',
                'type': 'file_input',
                'description': 'File reading operation'
            },
            
            # Environment variables
            'env_var': {
                'pattern': r'\bos\.environ\[',
                'type': 'environment',
                'description': 'Environment variable access'
            },
            'getenv': {
                'pattern': r'\bos\.getenv\s*\(',
                'type': 'environment',
                'description': 'Environment variable retrieval'
            }
        }
    
    def detect_dangerous_patterns(self, code: str) -> List[DetectedPattern]:
        """
        Detect dangerous code execution patterns in the given code.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of detected dangerous patterns
        """
        patterns = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            
            # Check each dangerous pattern
            for pattern_name, pattern_info in self.dangerous_patterns.items():
                regex = pattern_info['pattern']
                matches = re.finditer(regex, line, re.IGNORECASE)
                
                for match in matches:
                    # Get surrounding context (±1 line)
                    context_lines = []
                    for ctx_line_num in range(max(0, line_num-2), min(len(lines), line_num+1)):
                        context_lines.append(f"{ctx_line_num+1}: {lines[ctx_line_num]}")
                    
                    pattern = DetectedPattern(
                        pattern_type=pattern_name,
                        line_number=line_num,
                        context='\n'.join(context_lines),
                        severity=pattern_info['severity'],
                        description=pattern_info['description'],
                        matched_text=match.group()
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def detect_input_points(self, code: str) -> List[InputPoint]:
        """
        Detect user input points in the given code.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of detected input points
        """
        input_points = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            
            # Check each input pattern
            for pattern_name, pattern_info in self.input_patterns.items():
                regex = pattern_info['pattern']
                matches = re.finditer(regex, line, re.IGNORECASE)
                
                for match in matches:
                    # Try to extract variable name
                    variable_name = self._extract_variable_name(line, match.start())
                    
                    # Get surrounding context
                    context_lines = []
                    for ctx_line_num in range(max(0, line_num-2), min(len(lines), line_num+1)):
                        context_lines.append(f"{ctx_line_num+1}: {lines[ctx_line_num]}")
                    
                    input_point = InputPoint(
                        input_type=pattern_info['type'],
                        line_number=line_num,
                        variable_name=variable_name or "unknown",
                        context='\n'.join(context_lines),
                        description=pattern_info['description']
                    )
                    input_points.append(input_point)
        
        return input_points
    
    def _extract_variable_name(self, line: str, match_start: int) -> Optional[str]:
        """Extract variable name from assignment statement"""
        # Look for assignment pattern before the match
        before_match = line[:match_start].strip()
        
        # Simple pattern matching for variable assignment
        assignment_match = re.search(r'(\w+)\s*=\s*$', before_match)
        if assignment_match:
            return assignment_match.group(1)
        
        # Check if it's part of a larger expression
        # Look for variable names in common patterns
        var_patterns = [
            r'(\w+)\s*=.*',  # Direct assignment
            r'for\s+(\w+)\s+in.*',  # Loop variable
            r'with.*as\s+(\w+).*'  # Context manager
        ]
        
        for pattern in var_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return None
    
    def analyze_code_safety(self, code: str) -> Dict[str, Any]:
        """
        Perform comprehensive safety analysis of code.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            Dictionary with safety analysis results
        """
        dangerous_patterns = self.detect_dangerous_patterns(code)
        input_points = self.detect_input_points(code)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(dangerous_patterns, input_points)
        
        # Group patterns by severity
        patterns_by_severity = {"high": [], "medium": [], "low": []}
        for pattern in dangerous_patterns:
            patterns_by_severity[pattern.severity].append(pattern)
        
        # Group input points by type
        inputs_by_type = {}
        for input_point in input_points:
            if input_point.input_type not in inputs_by_type:
                inputs_by_type[input_point.input_type] = []
            inputs_by_type[input_point.input_type].append(input_point)
        
        return {
            "risk_score": risk_score,
            "total_dangerous_patterns": len(dangerous_patterns),
            "total_input_points": len(input_points),
            "dangerous_patterns": dangerous_patterns,
            "input_points": input_points,
            "patterns_by_severity": patterns_by_severity,
            "inputs_by_type": inputs_by_type,
            "has_high_risk": len(patterns_by_severity["high"]) > 0,
            "has_user_input": len(input_points) > 0,
            "potential_injection_risk": len(patterns_by_severity["high"]) > 0 and len(input_points) > 0
        }
    
    def _calculate_risk_score(self, patterns: List[DetectedPattern], inputs: List[InputPoint]) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Add score for dangerous patterns
        for pattern in patterns:
            if pattern.severity == "high":
                score += 30
            elif pattern.severity == "medium":
                score += 15
            else:
                score += 5
        
        # Add score for input points
        score += len(inputs) * 5
        
        # Multiply if both dangerous patterns and inputs are present
        if patterns and inputs:
            score = int(score * 1.5)
        
        return min(100, score)
    
    def get_security_summary(self, code: str) -> str:
        """Get a brief security summary of the code"""
        analysis = self.analyze_code_safety(code)
        
        risk_score = analysis["risk_score"]
        high_patterns = len(analysis["patterns_by_severity"]["high"])
        input_points = analysis["total_input_points"]
        
        if risk_score >= 70:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        summary = f"Security Risk: {risk_level} (Score: {risk_score}/100)"
        
        if high_patterns > 0:
            summary += f"\n- {high_patterns} high-risk pattern(s) detected"
        
        if input_points > 0:
            summary += f"\n- {input_points} user input point(s) found"
        
        if analysis["potential_injection_risk"]:
            summary += "\n- ⚠️  Potential injection vulnerability detected"
        
        return summary