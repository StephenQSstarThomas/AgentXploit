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

"""
Improved prompt management for LLM interactions
Focuses on agent injection analysis with intelligent file selection
"""

from typing import Dict, Any, List


class PromptManager:
    """Improved prompt manager focused on agent injection analysis"""
    
    @staticmethod
    def get_exploration_decision_prompt(history_context: str, exploration_context: str = None,
                                      unexplored_areas: List[str] = None, root_unexplored: List[str] = None,
                                      files: List[str] = None, dirs: List[str] = None,
                                      context: Dict = None, focus: str = "security") -> str:
        """Unified exploration decision prompt with smart parameter handling"""
        
        # Handle both calling patterns
        if context is not None:
            # Called with context dict (new style)
            files = context.get('files', [])
            dirs = context.get('directories', [])
            explored_path = context.get('explored_path', '.')
            exploration_context = f"Currently exploring: {explored_path}"
            unexplored_areas = unexplored_areas or []
            root_unexplored = root_unexplored or []
        else:
            # Called with individual parameters (old style)
            files = files or []
            dirs = dirs or []
            unexplored_areas = unexplored_areas or []
            root_unexplored = root_unexplored or []
            exploration_context = exploration_context or "Exploration in progress"
        
        return f"""FOCUS: You are analyzing for AGENT INJECTION vulnerabilities. Prioritize files/directories that could contain LLM interactions, tool execution, or agent workflow logic.

{history_context}

{exploration_context}

AVAILABLE FILES IN CURRENT DIRECTORY:
{chr(10).join([f"- {f}" for f in files[:20]])}

AVAILABLE SUBDIRECTORIES:
{chr(10).join([f"- {d}" for d in dirs[:15]])}

UNEXPLORED ROOT DIRECTORIES:
{chr(10).join([f"- {d}" for d in root_unexplored[:10]])}

AGENT INJECTION ANALYSIS PRIORITY:
1. HIGHEST PRIORITY - Files likely to contain agent/LLM logic:
   - Files with keywords: agent, llm, prompt, tool, executor, runtime, server, api, client, command, workflow, handler
   - Main application files: main.py, app.py, __init__.py
   - Source code files: .py, .js, .ts files

2. HIGH PRIORITY - Directories likely to contain agent components:
   - src/, core/, agents/, tools/, handlers/, api/, server/
   - Avoid: docs/, examples/, tests/, build/, dist/

3. LOWER PRIORITY - Documentation and configuration:
   - README.md, LICENSE, *.md files (analyze only if no higher priority targets)
   - Configuration files: *.toml, *.json, *.yaml

SELECTION STRATEGY:
- Choose up to 3 targets from the available lists above
- Prioritize source code and agent-related files over documentation
- Focus on directories that likely contain core application logic
- Only select files/directories that actually exist in the lists above

Respond in JSON format:
{{
    "analysis_targets": [
        {{
            "type": "file|directory",
            "path": "exact_path_from_available_lists_above",
            "priority": "high|medium|low", 
            "reason": "why important for agent injection analysis"
        }}
    ],
    "strategy_explanation": "focus on agent injection points"
}}"""

    @staticmethod
    def get_content_decision_prompt(history_context: str, context: Dict, focus: str = "security") -> str:
        """Improved content decision prompt with better file filtering"""
        
        file_path = context.get('file_path', '')
        content = context.get('content', '')
        security_result = context.get('security_result', {})
        
        # Extract imports and references from content for intelligent follow-up
        imports_found = []
        if content:
            # Look for Python imports
            import re
            python_imports = re.findall(r'from\s+([a-zA-Z0-9_.]+)\s+import|import\s+([a-zA-Z0-9_.]+)', content)
            for match in python_imports:
                module = match[0] or match[1]
                if module and '.' in module:
                    # Convert module to potential file path
                    file_candidate = module.replace('.', '/') + '.py'
                    imports_found.append(file_candidate)
            
            # Look for file references in configuration
            file_refs = re.findall(r'[\'"]([^\'\"]*\.(?:py|js|ts|json|toml|yaml|yml))[\'"]', content)
            imports_found.extend(file_refs[:3])
        
        # Build analyzed files list from history
        analyzed_files_list = []
        if history_context and "ANALYZED FILES" in history_context:
            lines = history_context.split('\n')
            in_section = False
            for line in lines:
                if 'ANALYZED FILES' in line:
                    in_section = True
                    continue
                elif line.strip().startswith('-') and in_section:
                    file_name = line.strip()[1:].split(':')[0].strip()
                    analyzed_files_list.append(file_name)
                elif line.strip() and not line.startswith('-') and in_section:
                    break

        return f"""You are analyzing file content for agent injection vulnerabilities. Make intelligent follow-up decisions.

CURRENT FILE: {file_path}
SECURITY RISK: {security_result.get('risk_assessment', {}).get('overall_risk', 'UNKNOWN')}

ALREADY ANALYZED FILES (DO NOT suggest these):
{chr(10).join([f"- {f}" for f in analyzed_files_list[-10:]])}

IMPORTS/REFERENCES FOUND IN CURRENT FILE:
{chr(10).join([f"- {imp}" for imp in imports_found[:5]])}

INTELLIGENT FOLLOW-UP STRATEGY:
1. If current file has HIGH/MEDIUM risk → look for related files in same directory
2. If current file imports other modules → analyze those imported files
3. If current file is agent/tool related → look for configuration or handler files
4. Focus on files that could complete the attack chain analysis

FOLLOW-UP RULES:
- Suggest ONLY files that likely exist and are relevant to injection analysis
- Prioritize imported files and same-directory files over random suggestions
- Avoid suggesting documentation files (*.md, LICENSE, etc.)
- Maximum 2 follow-up targets

Respond in JSON format:
{{
    "follow_up_targets": [
        {{"path": "realistic_file_path", "type": "file", "priority": 80, "reason": "imported by current file"}},
        {{"path": "realistic_directory", "type": "directory", "priority": 75, "reason": "likely contains related components"}}
    ],
    "exploration_strategy": "follow imports and related components"
}}"""

    @staticmethod
    def get_context_reassessment_prompt(history_context: str, current_state: Dict,
                                      unexplored_root_dirs: List[str], unexplored_subdirs: List[str],
                                      task_queue_size: int) -> str:
        """Improved context reassessment prompt"""
        return f"""You are making strategic decisions about repository analysis continuation.

{history_context}

CURRENT STATE:
- Files analyzed: {current_state.get('analyzed_files', 0)}
- Directories explored: {current_state.get('explored_dirs', 0)}
- High-risk findings: {current_state.get('high_risk_count', 0)}
- Task queue: {task_queue_size} tasks

UNEXPLORED AREAS:
Root directories: {unexplored_root_dirs[:8]}
Subdirectories: {unexplored_subdirs[:8]}

STRATEGIC PRIORITIES:
1. If high-risk files found → explore related directories first
2. If no high-risk files → focus on core application directories
3. Prioritize: src/, core/, agents/, tools/, handlers/, api/
4. Avoid: docs/, examples/, tests/ unless they contain agent logic

Select the MOST PROMISING unexplored area for agent injection analysis.

Respond in JSON format:
{{
    "next_actions": [
        {{
            "action": "explore_directory",
            "target": "exact_directory_from_unexplored_lists",
            "priority": "high",
            "reason": "likely contains agent components",
            "expected_value": "security"
        }}
    ],
    "strategy_explanation": "focus on core application directories",
    "reasoning": "prioritize areas most likely to contain agent workflow"
}}"""

    @staticmethod
    def get_queue_reassessment_prompt(discoveries_context: str, tasks_context: str) -> str:
        """Improved queue reassessment prompt with realistic expectations"""
        return f"""You are reassessing task priorities based on analysis discoveries.

{discoveries_context}

{tasks_context}

REASSESSMENT STRATEGY:
1. If HIGH/MEDIUM risk files found → increase priority of related files in same directory
2. If agent/tool files analyzed → prioritize configuration and handler files
3. If core application files found → prioritize their dependencies
4. Otherwise → no priority changes needed

REALISTIC EXPECTATIONS:
- Early in analysis: few discoveries, minimal priority changes
- Later in analysis: more discoveries, more targeted priority changes
- Only change priorities when there's clear logical connection

Respond in JSON format:
{{
    "has_relevant_discoveries": true/false,
    "priority_updates": {{
        "exact_task_target": new_priority_number
    }},
    "discovery_based_reasoning": "explain connection to discoveries"
}}

If no clear connections exist, respond:
{{
    "has_relevant_discoveries": false,
    "priority_updates": {{}},
    "discovery_based_reasoning": "No discoveries warrant priority changes"
}}"""

    @staticmethod
    def get_file_priority_prompt(context: str, files: List[str], 
                               security_findings: List[Dict] = None,
                               workflow_analysis: Dict = None) -> str:
        """Improved file priority prompt focused on agent injection"""
        
        # Filter files to focus on agent-relevant ones
        agent_files = []
        other_files = []
        
        for file in files:
            file_lower = file.lower()
            if any(keyword in file_lower for keyword in [
                'agent', 'llm', 'prompt', 'tool', 'executor', 'runtime',
                'server', 'api', 'client', 'command', 'workflow', 'handler'
            ]) or file.endswith(('.py', '.js', '.ts')):
                agent_files.append(file)
            else:
                other_files.append(file)
        
        return f"""You are selecting files for AGENT INJECTION analysis. Focus on files that could contain injection vulnerabilities.

REPOSITORY CONTEXT:
{context}

AGENT-RELEVANT FILES (prioritize these):
{chr(10).join([f"{i+1}. {f}" for i, f in enumerate(agent_files[:15])])}

OTHER FILES (lower priority):
{chr(10).join([f"{i+1}. {f}" for i, f in enumerate(other_files[:10])])}

SELECTION RULES:
1. Prioritize files with agent/LLM/tool keywords in filename
2. Focus on source code files (.py, .js, .ts) over configuration
3. Avoid documentation files unless they contain agent configurations
4. Select maximum 3 files with highest injection potential

Respond in JSON format:
{{
    "priority_files": [
        {{
            "filename": "exact_filename_from_lists_above",
            "priority": "high",
            "reason": "likely contains agent logic or LLM interaction",
            "injection_vector": "prompt_construction|tool_execution|data_flow"
        }}
    ],
    "analysis_strategy": "focus on agent injection vulnerabilities"
}}"""

    @staticmethod
    def get_security_analysis_prompt(file_path: str, content: str, language: str) -> str:
        """Focused security analysis prompt for agent injection"""
        content_sample = content[:1500] + "..." if len(content) > 1500 else content

        return f"""Analyze this code for AGENT INJECTION vulnerabilities in AI agent systems.

FILE: {file_path}
LANGUAGE: {language}

CODE CONTENT:
{content_sample}

FOCUS ON AGENT INJECTION RISKS:

1. LLM PROMPT INJECTION:
   - User input directly inserted into LLM prompts
   - Unsanitized data used in prompt construction
   - Template systems that include external data

2. TOOL EXECUTION INJECTION:
   - User input passed to subprocess/shell commands
   - Tool parameters not properly validated
   - Dynamic tool selection based on user input

3. DATA FLOW INJECTION:
   - External data flowing to agent context
   - File uploads processed by agent
   - API responses incorporated into prompts

IGNORE THESE (not agent injection):
- SQL injection (unless it affects agent prompts)
- XSS (unless it affects agent interface)
- Traditional web vulnerabilities

Respond in JSON format:
{{
    "findings": [
        {{
            "vulnerability_type": "Prompt_Injection|Tool_Execution_Injection|Data_Flow_Injection",
            "severity": "HIGH|MEDIUM|LOW",
            "line_number": 42,
            "description": "specific agent injection vulnerability",
            "injection_vector": "how malicious input reaches LLM/tools",
            "attack_scenario": "concrete exploitation example",
            "remediation": "how to prevent this injection"
        }}
    ],
    "agent_security_assessment": "overall agent injection risk level"
}}"""

    @staticmethod
    def get_focus_aware_reassessment_prompt(current_state: Dict, security_findings: List,
                                          workflow_patterns: Dict, task_queue_info: Dict, 
                                          focus_summary: Dict, primary_focus) -> str:
        """Improved reassessment decision prompt"""
        
        recent_findings = security_findings[-3:] if security_findings else []
        high_risk_count = sum(1 for f in recent_findings if f.get('risk_level') == 'high')
        
        return f"""Make a strategic decision about task queue reassessment.

CURRENT STATE:
- Step: {current_state['step']}
- Files analyzed: {current_state['analyzed_files']}
- Recent high-risk findings: {high_risk_count}
- Pending tasks: {task_queue_info['pending_count']}

REASSESS DECISION CRITERIA:
- Reassess if: new high-risk findings discovered, stuck on low-value files
- Don't reassess if: progressing well, no significant new discoveries

Respond in JSON format:
{{
    "should_reassess": true/false,
    "reasoning": "brief explanation",
    "confidence": "high/medium/low"
}}"""

    @staticmethod
    def get_reassessment_decision_prompt(current_state: Dict, security_findings: List[Dict],
                                       workflow_patterns: Dict, task_queue_info: Dict) -> str:
        """Get prompt for LLM-driven reassessment decision"""
        
        recent_findings = security_findings[-3:] if security_findings else []
        high_risk_count = sum(1 for f in recent_findings if f.get('risk_level') in ['high', 'medium'])
        
        return f"""Make an intelligent reassessment decision based on recent discoveries.

CURRENT STATE:
- Step: {current_state.get('step', 0)}
- Files analyzed: {current_state.get('analyzed_files', 0)}
- Recent high/medium risk findings: {high_risk_count}

REASSESSMENT CRITERIA:
- Reassess if: significant new findings, analysis stuck on low-value files
- Don't reassess if: good progress, no major discoveries

Respond in JSON format:
{{
    "should_reassess": true/false,
    "confidence": "high/medium/low",
    "reasoning": "brief explanation",
    "priority_focus": "what to focus on if reassessing"
}}"""
