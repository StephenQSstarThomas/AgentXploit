"""
Dynamic Focus Manager for LLM-driven Analysis Focus Generation
Generates and updates focus dynamically based on discoveries and dataflow patterns
"""

from typing import Dict, List, Any, Optional
import json
from ..tools.core.llm_client import LLMClient


class DynamicFocusManager:
    """Manages dynamic focus generation based on analysis discoveries"""
    
    def __init__(self):
        self.current_focus = "agent tool and dataflow"  # Base focus
        self.focus_history = []
        self.dataflow_patterns = []
        self.tool_chains = []
        
    def generate_initial_focus(self, repo_name: str, initial_files: List[str] = None) -> str:
        """Generate initial focus based on repository structure"""
        context = f"""
Repository: {repo_name}
Initial files: {initial_files[:10] if initial_files else 'Not yet explored'}

Generate a specific analysis focus for finding agent tool implementations and dataflow vulnerabilities.
The focus should be concise (max 5 words) and specific to likely tool/dataflow patterns.
Focus on efficiency - target areas for tool/dataflow discovery.

Examples:
- "LLM tool execution flows"
- "external data processing pipelines"
- "agent action handler chains"
- "API request dataflow paths"

Respond with ONLY the focus phrase, nothing else.
"""
        
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are an expert at identifying agent tool and dataflow patterns in codebases."},
            {"role": "user", "content": context}
        ]
        
        response = LLMClient.call_llm(
            model=model,
            messages=messages,
            max_tokens=50,
            temperature=0.3,
            timeout=15,
            max_retries=2
        )
        
        if response and len(response.strip()) > 0:
            new_focus = response.strip().lower()
            # Ensure it includes core concepts
            if "tool" not in new_focus and "flow" not in new_focus:
                new_focus = f"agent {new_focus} flows"
            self.current_focus = new_focus
        else:
            self.current_focus = "agent tool execution flows"
            
        self.focus_history.append({
            "focus": self.current_focus,
            "reason": "initial",
            "timestamp": self._get_timestamp()
        })
        
        return self.current_focus
    
    def update_focus_from_discoveries(self, discoveries: Dict[str, Any]) -> str:
        """Update focus based on analysis discoveries"""
        # Extract key patterns from discoveries
        tool_patterns = discoveries.get('tool_patterns', [])
        dataflow_patterns = discoveries.get('dataflow_patterns', [])
        high_risk_areas = discoveries.get('high_risk_areas', [])
        recent_findings = discoveries.get('recent_findings', [])
        
        # Build context for LLM
        context = f"""
Current focus: "{self.current_focus}"

DISCOVERY ANALYSIS:
- Tool patterns found: {len(tool_patterns)} total
  {chr(10).join([f"  • {p}" for p in tool_patterns[:3]]) if tool_patterns else "  • No tool patterns discovered yet"}
- Dataflow patterns: {len(dataflow_patterns)} total  
  {chr(10).join([f"  • {p}" for p in dataflow_patterns[:3]]) if dataflow_patterns else "  • No dataflow patterns discovered yet"}
- High-risk areas: {', '.join(high_risk_areas[:3]) if high_risk_areas else 'None identified'}
- Recent findings: {len(recent_findings)} security findings

FOCUS ADAPTATION DECISION:
Based on these concrete discoveries, should we adapt the analysis focus to target areas most likely to reveal MORE dataflow patterns and tool implementations?

CRITICAL: If NO dataflow patterns have been found yet, we need to shift focus to areas more likely to contain:
- Data processing pipelines
- External API integrations  
- File I/O operations
- User input handlers
- Tool execution frameworks

If dataflow patterns ARE being found, focus on expanding that discovery area.

Respond in JSON:
{{
    "should_update": true/false,
    "new_focus": "specific focus phrase",
    "reason": "why this focus will reveal more dataflow patterns"
}}
"""
        
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are an expert at adaptive security analysis focusing on agent tools and dataflows."},
            {"role": "user", "content": context}
        ]
        
        response = LLMClient.call_llm(
            model=model,
            messages=messages,
            max_tokens=200,
            temperature=0.4,
            timeout=20,
            max_retries=2
        )
        
        if response:
            try:
                result = json.loads(response)
                if result.get('should_update', False):
                    new_focus = result.get('new_focus', self.current_focus)
                    reason = result.get('reason', 'discoveries suggest new patterns')
                    
                    # Validate focus contains core concepts
                    if "tool" in new_focus.lower() or "flow" in new_focus.lower() or "agent" in new_focus.lower():
                        self.current_focus = new_focus.lower()
                        self.focus_history.append({
                            "focus": self.current_focus,
                            "reason": reason,
                            "timestamp": self._get_timestamp()
                        })
                        print(f"  [FOCUS_UPDATED] New focus: '{self.current_focus}' - {reason}")
            except:
                pass  # Keep current focus if parsing fails
                
        return self.current_focus
    
    def extract_discoveries_from_context(self, context_manager, security_findings: List[Dict]) -> Dict[str, Any]:
        """Extract discovery patterns from analysis context"""
        discoveries = {
            'tool_patterns': [],
            'dataflow_patterns': [],
            'high_risk_areas': [],
            'recent_findings': security_findings[-10:] if security_findings else []
        }
        
        # Extract patterns from security findings
        for finding in security_findings:
            # Look for agent_analysis section which contains dataflow info
            agent_analysis = finding.get('agent_analysis', {})
            
            # Extract identified tools
            identified_tools = agent_analysis.get('agent_tools', [])
            for tool in identified_tools:
                tool_name = tool.get('tool_name', 'unknown')
                tool_type = tool.get('tool_type', 'unknown')
                file_path = finding.get('file_path', '')
                pattern = f"{file_path}: {tool_name} ({tool_type})"
                discoveries['tool_patterns'].append(pattern)
            
            # Extract dataflow patterns
            dataflow_patterns = agent_analysis.get('dataflow_patterns', [])
            for flow in dataflow_patterns:
                flow_desc = flow.get('description', 'unknown flow')
                data_path = flow.get('data_path', 'unknown path')
                file_path = finding.get('file_path', '')
                pattern = f"{file_path}: {flow_desc} - {data_path}"
                discoveries['dataflow_patterns'].append(pattern)
                
            # Track high-risk areas
            risk_level = finding.get('risk_assessment', {}).get('overall_risk', '').lower()
            if risk_level in ['high', 'medium']:
                discoveries['high_risk_areas'].append(finding.get('file_path', ''))
        
        # Remove duplicates
        discoveries['tool_patterns'] = list(set(discoveries['tool_patterns']))
        discoveries['dataflow_patterns'] = list(set(discoveries['dataflow_patterns']))
        discoveries['high_risk_areas'] = list(set(discoveries['high_risk_areas']))
        
        return discoveries
    
    def get_focus_context(self) -> Dict[str, Any]:
        """Get current focus context for prompts"""
        return {
            'current_focus': self.current_focus,
            'focus_history': self.focus_history[-5:],  # Last 5 focus changes
            'focus_keywords': self._extract_keywords(self.current_focus)
        }
    
    def _extract_keywords(self, focus: str) -> List[str]:
        """Extract key words from focus for search prioritization"""
        # Remove common words
        common_words = {'and', 'the', 'of', 'in', 'for', 'to', 'a', 'an'}
        words = focus.split()
        keywords = [w for w in words if w not in common_words and len(w) > 2]
        
        # Always include core keywords
        core_keywords = ['agent', 'tool', 'dataflow', 'flow', 'execution', 'handler']
        for keyword in core_keywords:
            if keyword in focus and keyword not in keywords:
                keywords.append(keyword)
                
        return keywords
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
