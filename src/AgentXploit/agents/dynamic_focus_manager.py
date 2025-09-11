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

Recent discoveries:
- Tool patterns found: {', '.join(tool_patterns[:5]) if tool_patterns else 'None yet'}
- Dataflow patterns: {', '.join(dataflow_patterns[:5]) if dataflow_patterns else 'None yet'}
- High-risk areas: {', '.join(high_risk_areas[:3]) if high_risk_areas else 'None yet'}
- Recent findings: {len(recent_findings)} findings

Based on these discoveries, should we refine the analysis focus?
If yes, generate a NEW specific focus (max 5 words) that targets the most promising unexplored areas.
If no significant patterns found yet, keep current focus.

CORE REQUIREMENT: Focus must target agent tool implementations and dataflow vulnerabilities.

Respond in JSON:
{{
    "should_update": true/false,
    "new_focus": "specific focus phrase",
    "reason": "why this focus based on discoveries"
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
            # Look for tool-related findings
            if any(keyword in str(finding).lower() for keyword in ['tool', 'executor', 'handler', 'action', 'command']):
                pattern = finding.get('file_path', '') + ": " + finding.get('finding_type', '')
                discoveries['tool_patterns'].append(pattern)
            
            # Look for dataflow findings  
            if any(keyword in str(finding).lower() for keyword in ['flow', 'stream', 'pipeline', 'input', 'output']):
                pattern = finding.get('file_path', '') + ": " + finding.get('finding_type', '')
                discoveries['dataflow_patterns'].append(pattern)
                
            # Track high-risk areas
            if finding.get('severity') in ['high', 'critical']:
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
