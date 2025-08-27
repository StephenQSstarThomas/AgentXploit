"""
Simple dataflow tracker for tracing variables from input to usage.
Tracks variable assignments and usage patterns for security analysis.
"""

import re
import ast
from typing import List, Dict, Any, Tuple, Optional, Set
from dataclasses import dataclass


@dataclass
class VariableUsage:
    """Represents a variable usage in code"""
    line_number: int
    usage_type: str  # "assignment", "read", "function_call", "dangerous_call"
    context: str
    variable_name: str
    expression: str


@dataclass
class DataFlow:
    """Represents a data flow from source to sink"""
    variable_name: str
    source_line: int
    source_type: str  # "input", "file", "network", etc.
    sink_line: int
    sink_type: str  # "exec", "system", "sql", etc.
    flow_path: List[VariableUsage]


class DataflowTracker:
    """Simple dataflow analysis for tracking variables from input to dangerous usage"""
    
    def __init__(self):
        # Input source patterns
        self.input_sources = {
            'user_input': [r'\binput\s*\(', r'\braw_input\s*\('],
            'web_input': [r'\brequest\.(body|data|form|json|args|values)', r'\brequest\.(GET|POST)\['],
            'file_input': [r'\.read\s*\(', r'\.readline\s*\('],
            'env_input': [r'\bos\.environ\[', r'\bos\.getenv\s*\('],
            'argv_input': [r'\bsys\.argv']
        }
        
        # Dangerous sink patterns
        self.dangerous_sinks = {
            'exec': [r'\bexec\s*\(', r'\beval\s*\('],
            'system': [r'\bos\.system\s*\(', r'\bsubprocess\.(call|run|Popen)', r'\bos\.popen\s*\('],
            'sql': [r'\.(execute|executemany|query)\s*\('],
            'file_write': [r'\bopen\s*\([^)]*[\'"][wa][\'"]'],
            'import': [r'\bimportlib\.import_module\s*\(', r'\b__import__\s*\(']
        }
    
    def track_variable(self, code: str, var_name: str) -> List[VariableUsage]:
        """
        Track all usages of a specific variable in the code.
        
        Args:
            code: Python source code to analyze
            var_name: Variable name to track
            
        Returns:
            List of variable usages sorted by line number
        """
        usages = []
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            
            # Check if variable is used in this line
            if self._variable_used_in_line(var_name, line):
                usage_type = self._determine_usage_type(var_name, line)
                
                usage = VariableUsage(
                    line_number=line_num,
                    usage_type=usage_type,
                    context=line.strip(),
                    variable_name=var_name,
                    expression=self._extract_expression(var_name, line)
                )
                usages.append(usage)
        
        return sorted(usages, key=lambda u: u.line_number)
    
    def find_data_flows(self, code: str) -> List[DataFlow]:
        """
        Find data flows from input sources to dangerous sinks.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of detected data flows
        """
        flows = []
        lines = code.split('\n')
        
        # Step 1: Find all variable assignments from input sources
        input_vars = self._find_input_variables(lines)
        
        # Step 2: For each input variable, track its flow to dangerous sinks
        for var_name, source_info in input_vars.items():
            usages = self.track_variable(code, var_name)
            
            # Find dangerous usages
            dangerous_usages = [u for u in usages if u.usage_type == "dangerous_call"]
            
            for dangerous_usage in dangerous_usages:
                # Create dataflow
                flow = DataFlow(
                    variable_name=var_name,
                    source_line=source_info['line'],
                    source_type=source_info['type'],
                    sink_line=dangerous_usage.line_number,
                    sink_type=self._identify_sink_type(dangerous_usage.context),
                    flow_path=usages
                )
                flows.append(flow)
        
        return flows
    
    def _find_input_variables(self, lines: List[str]) -> Dict[str, Dict[str, Any]]:
        """Find variables assigned from input sources"""
        input_vars = {}
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            
            # Look for assignment statements with input sources
            assignment_match = re.match(r'\s*(\w+)\s*=\s*(.+)', line)
            if assignment_match:
                var_name = assignment_match.group(1)
                expression = assignment_match.group(2)
                
                # Check if the expression contains an input source
                source_type = self._identify_input_source(expression)
                if source_type:
                    input_vars[var_name] = {
                        'line': line_num,
                        'type': source_type,
                        'expression': expression
                    }
        
        return input_vars
    
    def _identify_input_source(self, expression: str) -> Optional[str]:
        """Identify if expression contains an input source"""
        for source_type, patterns in self.input_sources.items():
            for pattern in patterns:
                if re.search(pattern, expression, re.IGNORECASE):
                    return source_type
        return None
    
    def _identify_sink_type(self, context: str) -> str:
        """Identify the type of dangerous sink"""
        for sink_type, patterns in self.dangerous_sinks.items():
            for pattern in patterns:
                if re.search(pattern, context, re.IGNORECASE):
                    return sink_type
        return "unknown"
    
    def _variable_used_in_line(self, var_name: str, line: str) -> bool:
        """Check if variable is used in the given line"""
        # Use word boundaries to avoid partial matches
        pattern = r'\b' + re.escape(var_name) + r'\b'
        return bool(re.search(pattern, line))
    
    def _determine_usage_type(self, var_name: str, line: str) -> str:
        """Determine how the variable is being used"""
        # Check for assignment
        if re.match(r'\s*' + re.escape(var_name) + r'\s*=', line):
            return "assignment"
        
        # Check for dangerous calls
        for sink_type, patterns in self.dangerous_sinks.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if variable is used in this dangerous call
                    if self._variable_used_in_line(var_name, line):
                        return "dangerous_call"
        
        # Check for function calls
        if re.search(r'\b' + re.escape(var_name) + r'\s*\(', line):
            return "function_call"
        
        # Default to read usage
        return "read"
    
    def _extract_expression(self, var_name: str, line: str) -> str:
        """Extract the expression containing the variable"""
        # For now, return the whole line trimmed
        # Could be enhanced to extract just the relevant expression
        return line.strip()
    
    def analyze_variable_flow(self, code: str, var_name: str) -> Dict[str, Any]:
        """
        Comprehensive analysis of a variable's data flow.
        
        Args:
            code: Python source code to analyze
            var_name: Variable name to analyze
            
        Returns:
            Dictionary with flow analysis results
        """
        usages = self.track_variable(code, var_name)
        
        if not usages:
            return {
                "variable_name": var_name,
                "found": False,
                "usages": [],
                "risk_assessment": "Not found"
            }
        
        # Categorize usages
        assignments = [u for u in usages if u.usage_type == "assignment"]
        reads = [u for u in usages if u.usage_type == "read"]
        dangerous_calls = [u for u in usages if u.usage_type == "dangerous_call"]
        function_calls = [u for u in usages if u.usage_type == "function_call"]
        
        # Assess risk
        risk_level = "LOW"
        risk_details = []
        
        if dangerous_calls:
            risk_level = "HIGH"
            risk_details.append(f"{len(dangerous_calls)} dangerous call(s)")
        elif function_calls:
            risk_level = "MEDIUM"
            risk_details.append(f"{len(function_calls)} function call(s)")
        
        # Check if variable comes from user input
        first_assignment = assignments[0] if assignments else None
        is_user_input = False
        if first_assignment:
            is_user_input = bool(self._identify_input_source(first_assignment.expression))
            if is_user_input:
                risk_details.append("originates from user input")
        
        return {
            "variable_name": var_name,
            "found": True,
            "total_usages": len(usages),
            "usages": usages,
            "assignments": assignments,
            "reads": reads,
            "dangerous_calls": dangerous_calls,
            "function_calls": function_calls,
            "risk_level": risk_level,
            "risk_details": risk_details,
            "is_user_input": is_user_input,
            "flow_summary": self._create_flow_summary(usages)
        }
    
    def _create_flow_summary(self, usages: List[VariableUsage]) -> str:
        """Create a human-readable flow summary"""
        if not usages:
            return "No usages found"
        
        summary_parts = []
        for usage in usages:
            summary_parts.append(f"Line {usage.line_number}: {usage.usage_type}")
        
        return " → ".join(summary_parts)
    
    def find_potential_injections(self, code: str) -> List[Dict[str, Any]]:
        """
        Find potential injection vulnerabilities by analyzing data flows.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            List of potential injection vulnerabilities
        """
        flows = self.find_data_flows(code)
        vulnerabilities = []
        
        for flow in flows:
            # High risk: user input flowing to dangerous sinks
            if flow.source_type in ['user_input', 'web_input', 'argv_input']:
                severity = "HIGH"
            elif flow.source_type in ['file_input', 'env_input']:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            vulnerability = {
                "type": f"{flow.source_type}_to_{flow.sink_type}",
                "severity": severity,
                "variable": flow.variable_name,
                "source_line": flow.source_line,
                "sink_line": flow.sink_line,
                "description": f"Data flows from {flow.source_type} to {flow.sink_type}",
                "flow": flow
            }
            vulnerabilities.append(vulnerability)
        
        return sorted(vulnerabilities, key=lambda v: (v["severity"] == "HIGH", v["source_line"]))
    
    def get_dataflow_summary(self, code: str) -> str:
        """Get a brief summary of dataflow analysis results"""
        flows = self.find_data_flows(code)
        vulnerabilities = self.find_potential_injections(code)
        
        if not flows:
            return "No data flows from input sources to dangerous sinks detected."
        
        high_risk = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
        medium_risk = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
        
        summary = f"Found {len(flows)} data flow(s)"
        if high_risk > 0:
            summary += f" ({high_risk} HIGH risk)"
        if medium_risk > 0:
            summary += f" ({medium_risk} MEDIUM risk)"
        
        return summary