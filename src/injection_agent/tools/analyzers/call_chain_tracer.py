"""
Call chain tracer for tracking function calls and dependencies.
Analyzes function call relationships and identifies call paths.
"""

import re
import ast
from typing import List, Dict, Any, Set, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FunctionCall:
    """Represents a function call in the code"""
    caller_function: str
    called_function: str
    line_number: int
    call_context: str
    call_type: str  # "direct", "method", "imported"


@dataclass
class CallChain:
    """Represents a chain of function calls"""
    start_function: str
    end_function: str
    chain_path: List[FunctionCall]
    chain_length: int
    risk_level: str


class CallChainTracer:
    """Traces function call relationships and dependencies"""
    
    def __init__(self):
        self.function_definitions = {}  # function_name -> line_number
        self.function_calls = []  # List of FunctionCall objects
        self.call_graph = {}  # caller -> [callees]
        self.reverse_call_graph = {}  # callee -> [callers]
    
    def trace_function_calls(self, code: str, target_function: str = None) -> List[FunctionCall]:
        """
        Trace function calls in the given code.
        
        Args:
            code: Python source code to analyze
            target_function: Specific function to trace (optional)
            
        Returns:
            List of function calls found
        """
        self._reset_state()
        self._parse_code(code)
        
        if target_function:
            return [call for call in self.function_calls if call.called_function == target_function]
        
        return self.function_calls
    
    def find_call_chains(self, code: str, start_function: str, max_depth: int = 5) -> List[CallChain]:
        """
        Find call chains starting from a specific function.
        
        Args:
            code: Python source code to analyze
            start_function: Function to start tracing from
            max_depth: Maximum chain depth to explore
            
        Returns:
            List of call chains found
        """
        self._reset_state()
        self._parse_code(code)
        self._build_call_graph()
        
        chains = []
        visited = set()
        
        def explore_chain(current_func: str, current_path: List[str], depth: int):
            if depth > max_depth or current_func in visited:
                return
            
            visited.add(current_func)
            
            # Get functions called by current function
            callees = self.call_graph.get(current_func, [])
            
            if not callees:
                # End of chain - create CallChain object
                if len(current_path) > 1:
                    chain_calls = self._build_chain_calls(current_path)
                    if chain_calls:
                        chain = CallChain(
                            start_function=current_path[0],
                            end_function=current_path[-1],
                            chain_path=chain_calls,
                            chain_length=len(current_path),
                            risk_level=self._assess_chain_risk(chain_calls)
                        )
                        chains.append(chain)
            else:
                # Continue exploring
                for callee in callees:
                    explore_chain(callee, current_path + [callee], depth + 1)
            
            visited.remove(current_func)
        
        explore_chain(start_function, [start_function], 0)
        return chains
    
    def find_callers_of_function(self, code: str, target_function: str) -> List[FunctionCall]:
        """
        Find all functions that call a specific target function.
        
        Args:
            code: Python source code to analyze
            target_function: Function to find callers for
            
        Returns:
            List of function calls that call the target function
        """
        calls = self.trace_function_calls(code)
        return [call for call in calls if call.called_function == target_function]
    
    def analyze_function_dependencies(self, code: str) -> Dict[str, Any]:
        """
        Analyze function dependencies and call patterns.
        
        Args:
            code: Python source code to analyze
            
        Returns:
            Dictionary with dependency analysis results
        """
        self._reset_state()
        self._parse_code(code)
        self._build_call_graph()
        
        # Find functions with no callers (entry points)
        all_callees = set()
        for callees in self.call_graph.values():
            all_callees.update(callees)
        
        entry_points = [func for func in self.function_definitions.keys() 
                       if func not in all_callees]
        
        # Find functions with no callees (leaf functions)
        leaf_functions = [func for func, callees in self.call_graph.items() 
                         if not callees]
        
        # Find highly connected functions (called by many others)
        call_counts = {}
        for call in self.function_calls:
            call_counts[call.called_function] = call_counts.get(call.called_function, 0) + 1
        
        highly_connected = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_functions": len(self.function_definitions),
            "total_calls": len(self.function_calls),
            "entry_points": entry_points,
            "leaf_functions": leaf_functions,
            "highly_connected_functions": highly_connected,
            "call_graph": self.call_graph,
            "function_definitions": self.function_definitions,
            "call_statistics": {
                "functions_with_calls": len([f for f in self.call_graph.values() if f]),
                "functions_without_calls": len([f for f in self.call_graph.values() if not f]),
                "average_calls_per_function": len(self.function_calls) / max(1, len(self.function_definitions))
            }
        }
    
    def _reset_state(self):
        """Reset internal state for new analysis"""
        self.function_definitions.clear()
        self.function_calls.clear()
        self.call_graph.clear()
        self.reverse_call_graph.clear()
    
    def _parse_code(self, code: str):
        """Parse code to extract function definitions and calls"""
        try:
            tree = ast.parse(code)
            self._extract_ast_info(tree)
        except SyntaxError:
            # Fallback to regex-based parsing if AST parsing fails
            self._extract_regex_info(code)
    
    def _extract_ast_info(self, tree: ast.AST):
        """Extract function info using AST parsing"""
        class FunctionVisitor(ast.NodeVisitor):
            def __init__(self, tracer):
                self.tracer = tracer
                self.current_function = None
            
            def visit_FunctionDef(self, node):
                # Record function definition
                self.tracer.function_definitions[node.name] = node.lineno
                
                # Visit function body with current function context
                old_function = self.current_function
                self.current_function = node.name
                self.generic_visit(node)
                self.current_function = old_function
            
            def visit_Call(self, node):
                if self.current_function:
                    # Extract function name from call
                    func_name = self._get_function_name(node)
                    if func_name:
                        call = FunctionCall(
                            caller_function=self.current_function,
                            called_function=func_name,
                            line_number=node.lineno,
                            call_context=f"call to {func_name}",
                            call_type=self._determine_call_type(node)
                        )
                        self.tracer.function_calls.append(call)
                
                self.generic_visit(node)
            
            def _get_function_name(self, node: ast.Call) -> Optional[str]:
                """Extract function name from call node"""
                if isinstance(node.func, ast.Name):
                    return node.func.id
                elif isinstance(node.func, ast.Attribute):
                    return node.func.attr
                return None
            
            def _determine_call_type(self, node: ast.Call) -> str:
                """Determine type of function call"""
                if isinstance(node.func, ast.Name):
                    return "direct"
                elif isinstance(node.func, ast.Attribute):
                    return "method"
                return "unknown"
        
        visitor = FunctionVisitor(self)
        visitor.visit(tree)
    
    def _extract_regex_info(self, code: str):
        """Fallback regex-based parsing"""
        lines = code.split('\n')
        
        # Extract function definitions
        for line_num, line in enumerate(lines, 1):
            # Function definition pattern
            func_def_match = re.match(r'\s*def\s+(\w+)\s*\(', line)
            if func_def_match:
                func_name = func_def_match.group(1)
                self.function_definitions[func_name] = line_num
        
        # Extract function calls
        current_function = None
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Track current function context
            func_def_match = re.match(r'\s*def\s+(\w+)\s*\(', line)
            if func_def_match:
                current_function = func_def_match.group(1)
                continue
            
            if current_function and not stripped.startswith('#') and stripped:
                # Find function calls in the line
                call_matches = re.finditer(r'(\w+)\s*\(', line)
                for match in call_matches:
                    called_func = match.group(1)
                    # Skip keywords and builtins
                    if called_func not in ['if', 'for', 'while', 'with', 'print', 'len', 'str', 'int']:
                        call = FunctionCall(
                            caller_function=current_function,
                            called_function=called_func,
                            line_number=line_num,
                            call_context=line.strip(),
                            call_type="direct"
                        )
                        self.function_calls.append(call)
    
    def _build_call_graph(self):
        """Build call graph from collected function calls"""
        for call in self.function_calls:
            caller = call.caller_function
            callee = call.called_function
            
            if caller not in self.call_graph:
                self.call_graph[caller] = []
            if callee not in self.call_graph[caller]:
                self.call_graph[caller].append(callee)
            
            if callee not in self.reverse_call_graph:
                self.reverse_call_graph[callee] = []
            if caller not in self.reverse_call_graph[callee]:
                self.reverse_call_graph[callee].append(caller)
    
    def _build_chain_calls(self, path: List[str]) -> List[FunctionCall]:
        """Build list of FunctionCall objects for a call chain path"""
        chain_calls = []
        for i in range(len(path) - 1):
            caller = path[i]
            callee = path[i + 1]
            
            # Find the actual function call
            matching_calls = [call for call in self.function_calls 
                            if call.caller_function == caller and call.called_function == callee]
            if matching_calls:
                chain_calls.append(matching_calls[0])
        
        return chain_calls
    
    def _assess_chain_risk(self, chain_calls: List[FunctionCall]) -> str:
        """Assess risk level of a call chain"""
        # Simple risk assessment based on function names
        dangerous_functions = {'exec', 'eval', 'system', 'popen', 'subprocess'}
        
        for call in chain_calls:
            if any(danger in call.called_function.lower() for danger in dangerous_functions):
                return "HIGH"
        
        if len(chain_calls) > 5:
            return "MEDIUM"
        
        return "LOW"
    
    def get_call_summary(self, code: str) -> str:
        """Get a brief summary of function call analysis"""
        analysis = self.analyze_function_dependencies(code)
        
        summary = f"Functions: {analysis['total_functions']}, Calls: {analysis['total_calls']}"
        
        if analysis['entry_points']:
            summary += f", Entry points: {len(analysis['entry_points'])}"
        
        if analysis['highly_connected_functions']:
            top_func = analysis['highly_connected_functions'][0]
            summary += f", Most called: {top_func[0]} ({top_func[1]} times)"
        
        return summary
    
    def find_dangerous_call_paths(self, code: str) -> List[Dict[str, Any]]:
        """Find call paths that lead to dangerous functions"""
        dangerous_functions = ['exec', 'eval', 'os.system', 'subprocess', 'popen']
        dangerous_paths = []
        
        analysis = self.analyze_function_dependencies(code)
        
        for dangerous_func in dangerous_functions:
            callers = [call for call in self.function_calls 
                      if dangerous_func in call.called_function]
            
            for call in callers:
                # Find the path to this dangerous call
                chains = self.find_call_chains(code, call.caller_function, max_depth=3)
                for chain in chains:
                    if any(dangerous_func in c.called_function for c in chain.chain_path):
                        dangerous_paths.append({
                            "dangerous_function": dangerous_func,
                            "entry_point": chain.start_function,
                            "call_chain": chain,
                            "risk_level": "HIGH"
                        })
        
        return dangerous_paths