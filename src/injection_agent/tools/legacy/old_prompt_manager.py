# Copyright 2025 Google LLC

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Centralized prompt management for LLM interactions
"""


from typing import Dict, Any, List


class PromptManager:
    """Manages all LLM prompts used in the analysis system"""
    
    PRIORITY_LEVELS = {
        95: "CRITICAL - Immediate security concern, likely injection point",
        90: "URGENT - High-value target with security implications",
        85: "HIGH - Important component in security workflow",
        80: "MEDIUM-HIGH - Relevant to focus area with potential impact",
        75: "MEDIUM - Standard analysis target",
        70: "MEDIUM-LOW - Supporting component worth examining",
        65: "LOW - Background analysis, helpful context",
        60: "MINIMAL - Basic fallback exploration",
        50: "DEFAULT - Standard priority"
    }

    @staticmethod
    def get_exploration_decision_prompt(history_context: str, context: Dict, focus: str = "security") -> str:
        """Enhanced exploration decision prompt with few-shot examples and workflow focus"""
        
        files = context.get('files', [])
        dirs = context.get('directories', [])
        explored_path = context.get('explored_path', '.')
        
        return f"""You are analyzing a codebase for {focus} vulnerabilities, specifically focusing on workflow-based injection points.

PRIORITY LEVELS (use exact numbers):
- 95: Critical security files, likely injection points
- 90: Urgent - High-value security targets  
- 85: High - Important workflow components
- 80: Medium-High - Relevant to focus area
- 75: Medium - Standard analysis targets
- 70: Medium-Low - Supporting components
- 65: Low - Background analysis
- 60: Minimal - Basic exploration
- 50: Default priority

WORKFLOW INJECTION ANALYSIS FOCUS:
Look for patterns where user input or external data flows through:
1. LLM prompt construction chains
2. Tool/command execution pipelines  
3. Code generation and evaluation workflows
4. Agent decision-making processes
5. Dynamic configuration loading
6. Inter-service communication channels


{history_context}


CURRENT EXPLORATION: {explored_path}
FILES FOUND: {files[:15]}
DIRECTORIES FOUND: {dirs[:10]}


FEW-SHOT EXAMPLES:


Example 1 - Agent System:
Files: ['agent.py', 'llm_client.py', 'tools.py', 'prompt_builder.py', 'executor.py']
Dirs: ['handlers', 'templates', 'config']
Focus: security


Analysis: In agent systems, injection points are in prompt construction and tool execution
{{
  "analysis_targets": [
    {{"path": "prompt_builder.py", "type": "file", "priority": 95, "reason": "Critical: Handles prompt construction, primary injection vector"}},
    {{"path": "executor.py", "type": "file", "priority": 90, "reason": "Urgent: Executes commands/tools, direct security impact"}},
    {{"path": "agent.py", "type": "file", "priority": 85, "reason": "High: Main agent logic, controls workflow decisions"}},
    {{"path": "handlers", "type": "directory", "priority": 80, "reason": "Medium-High: Contains request/response handling logic"}}
  ],
  "strategy_explanation": "Focus on prompt injection vectors and command execution paths"
}}


Example 2 - Web Service:
Files: ['server.py', 'api.py', 'middleware.py', 'models.py', 'utils.py']  
Dirs: ['auth', 'endpoints', 'static']
Focus: security


Analysis: Web services have injection points in request processing and data validation
{{
  "analysis_targets": [
    {{"path": "middleware.py", "type": "file", "priority": 90, "reason": "Urgent: Processes all requests, filters user input"}},
    {{"path": "auth", "type": "directory", "priority": 85, "reason": "High: Authentication logic, security-critical"}},
    {{"path": "endpoints", "type": "directory", "priority": 80, "reason": "Medium-High: API endpoints, user input processing"}},
    {{"path": "api.py", "type": "file", "priority": 75, "reason": "Medium: Core API logic"}}
  ],
  "strategy_explanation": "Prioritize request pipeline and authentication workflows"
}}


YOUR ANALYSIS:
Analyze the current directory contents focusing on {focus} workflow injection points.
Consider how data flows through the system and where external input could be injected.
Assign priorities based on injection potential and workflow criticality.


Respond in JSON format:
{{
  "analysis_targets": [
    {{"path": "filename", "type": "file|directory", "priority": 50-95, "reason": "specific workflow-based reasoning"}}
  ],
  "strategy_explanation": "workflow-focused explanation of your analysis approach"
}}"""

    @staticmethod  
    def get_content_decision_prompt(history_context: str, context: Dict, focus: str = "security") -> str:
        """Enhanced content analysis decision prompt with workflow injection focus"""
        
        file_path = context.get('file_path', '')
        content_snippet = context.get('content', '')[:2000] + "..." if len(context.get('content', '')) > 2000 else context.get('content', '')
        security_result = context.get('security_result', {})
        
        # Extract analyzed files from history to avoid repetition
        analyzed_files_hint = ""
        if history_context and "ANALYZED FILES" in history_context:
            analyzed_files_hint = "\n\n**IMPORTANT**: The following files have ALREADY been analyzed - DO NOT suggest them again:\n"
            lines = history_context.split('\n')
            in_analyzed_section = False
            for line in lines:
                if 'ANALYZED FILES' in line:
                    in_analyzed_section = True
                    continue
                elif line.strip().startswith('-') and in_analyzed_section:
                    analyzed_files_hint += line + "\n"
                elif line.strip() and not line.startswith('-') and in_analyzed_section:
                    break
        
        return f"""You are analyzing file content for {focus} vulnerabilities, focusing on workflow-based injection points.


PRIORITY LEVELS (use exact numbers):
- 95: Critical injection points found
- 90: Urgent - High-risk security issues
- 85: High - Important workflow vulnerabilities  
- 80: Medium-High - Potential injection vectors
- 75: Medium - Security-relevant code
- 70: Medium-Low - Worth deeper investigation
- 65: Low - Related files for context
- 60: Minimal - Basic follow-up
- 50: Default priority


WORKFLOW INJECTION PATTERNS TO IDENTIFY:
1. User input → LLM prompt construction
2. External data → Command/tool execution  
3. Config values → Code generation/evaluation
4. API inputs → Agent decision workflows
5. File uploads → Dynamic loading/parsing
6. Inter-service calls → Trust boundary violations


{history_context}{analyzed_files_hint}


CURRENT FILE: {file_path}
SECURITY ANALYSIS: {security_result.get('risk_assessment', {}).get('overall_risk', 'UNKNOWN')} risk
FOUND ISSUES: {security_result.get('findings', [])[:3]}


FILE CONTENT PREVIEW:
{content_snippet}


FEW-SHOT EXAMPLES:


Example 1 - Prompt Builder with Injection Risk:
File: prompt_builder.py
Content: "def build_prompt(user_input): return f'Analyze: {{user_input}}' # Direct injection"
Risk: HIGH


Analysis: Direct user input in prompt construction = critical injection vector
{{
  "follow_up_targets": [
    {{"path": "prompt_validator.py", "type": "file", "priority": 95, "reason": "Critical: Need to check if input validation exists"}},
    {{"path": "llm_client.py", "type": "file", "priority": 90, "reason": "Urgent: Check how prompts are sent to LLM"}},
    {{"path": "sanitizers", "type": "directory", "priority": 80, "reason": "Medium-High: Look for sanitization utilities"}}
  ],
  "exploration_strategy": "Trace the complete prompt injection attack surface"
}}


Example 2 - Command Executor:  
File: tool_executor.py
Content: "subprocess.run(user_command, shell=True) # Dangerous command execution"
Risk: HIGH


Analysis: Shell command execution with user input = RCE vulnerability
{{
  "follow_up_targets": [
    {{"path": "command_whitelist.py", "type": "file", "priority": 95, "reason": "Critical: Check if command filtering exists"}},
    {{"path": "security/sandbox.py", "type": "file", "priority": 90, "reason": "Urgent: Look for sandboxing mechanisms"}},
    {{"path": "tools", "type": "directory", "priority": 85, "reason": "High: Examine all available tools for similar issues"}}
  ],
  "exploration_strategy": "Map command execution attack vectors and defenses"
}}


Example 3 - Safe Configuration:
File: config_loader.py  
Content: "config = json.load(config_file) # Safe static loading"
Risk: LOW


Analysis: Static config loading without user input - minimal risk
{{
  "follow_up_targets": [
    {{"path": "config_validator.py", "type": "file", "priority": 70, "reason": "Medium-Low: Check config validation logic"}},
    {{"path": "settings", "type": "directory", "priority": 65, "reason": "Low: Review configuration structure"}}
  ],
  "exploration_strategy": "Verify configuration security and validation patterns"
}}


YOUR ANALYSIS:
Based on the file content and security analysis, identify follow-up targets that help understand the complete injection attack surface.
Focus on workflow connections and data flow paths that could lead to vulnerabilities.


Respond in JSON format:
{{
  "follow_up_targets": [
    {{"path": "filename", "type": "file|directory", "priority": 50-95, "reason": "workflow-based reasoning focusing on injection potential"}}
  ],
  "exploration_strategy": "your workflow-focused exploration approach"
}}"""

    @staticmethod
    def get_file_priority_prompt(context: str, files: List[str],
                               security_findings: List[Dict] = None,
                               workflow_analysis: Dict = None) -> str:
        """Get prompt for file priority assessment focused on agent injection vulnerabilities with existing discoveries"""
        
        # Build findings context from existing discoveries
        findings_context = ""
        if security_findings:
            findings_context = f"""
**EXISTING SECURITY FINDINGS:**
{chr(10).join([f"- {f['file']}: {f['risk_level']} risk - {', '.join(f['findings'][:2])}"
              for f in security_findings[-8:]])}
"""

        # Build workflow context from discovered patterns  
        workflow_context = ""
        if workflow_analysis:
            workflow_context = f"""
**DISCOVERED WORKFLOW PATTERNS:**
- LLM Integration Points: {', '.join(workflow_analysis.get('llm_points', [])[:5])}
- Tool Execution Chains: {', '.join(workflow_analysis.get('tool_chains', [])[:5])}
- Data Flow Paths: {', '.join(workflow_analysis.get('data_flows', [])[:5])}
- Injection Vectors Found: {', '.join(workflow_analysis.get('injection_vectors', [])[:5])}
"""
            
        return f"""You are an AGENT INJECTION SECURITY EXPERT analyzing files for potential injection vulnerabilities in AI agent systems.


REPOSITORY ANALYSIS CONTEXT:
{context}{findings_context}{workflow_context}


**AVAILABLE FILES (choose ONLY from this exact list):**
{chr(10).join(f"{i+1}. {file}" for i, file in enumerate(files))}


**AGENT INJECTION ANALYSIS PRIORITIES:**


**HIGHEST PRIORITY - Direct Injection Risk:**
- Files that handle LLM calls, prompt construction, or message formatting
- Tool definition and execution files
- User input processing and validation
- Agent workflow orchestration and task management
- Context/history management and prompt building


**HIGH PRIORITY - Data Flow Vulnerabilities:**
- Configuration files that control agent behavior or tool access
- CLI entry points and command processing
- File I/O operations that feed data to agents
- Build scripts that could affect agent deployment security
- Environment configuration for agent operation


**MEDIUM PRIORITY - Tool Chain Risks:**
- Tool output processing and sanitization
- Inter-tool communication and data passing
- Agent state management and persistence
- Error handling that might leak sensitive context


**LOW PRIORITY - Supporting Infrastructure:**
- Documentation and static files (unless they contain agent configs)
- Test files (unless they reveal agent vulnerabilities)
- Pure utility functions without LLM/agent interaction


**FOCUS ON INJECTION ATTACK VECTORS:**
- Where can malicious input enter the agent pipeline?
- How is tool output processed before reaching LLM?
- What files control prompt construction or context building?
- Which files manage agent-to-tool and tool-to-LLM data flow?


**INTELLIGENT PRIORITIZATION BASED ON DISCOVERIES:**
- Use existing security findings to identify related files and patterns
- Focus on unexplored files that connect to already discovered injection points
- Prioritize files that could complete the attack chain analysis
- Consider workflow patterns to find missing pieces of the agent pipeline


Select the TOP 3 most valuable files for AGENT INJECTION analysis from the available list.


Respond with JSON:
{{
    "priority_files": [
        {{
            "filename": "exact_filename_from_list",
            "priority": "high|medium|low",
            "reason": "specific injection risk this file could reveal",
            "injection_vector": "data_flow|prompt_construction|tool_execution|context_manipulation",
            "relates_to_findings": "how this connects to existing discoveries"
        }}
    ],
    "analysis_strategy": "focus on agent injection points and data flow vulnerabilities",
    "discovery_driven_reasoning": "how existing findings influenced the prioritization"
}}


**CRITICAL: Only select filenames that EXACTLY match the provided list - NO other files!**"""

    @staticmethod
    def get_context_reassessment_prompt(history_context: str, current_state: dict,
                                      unexplored_root_dirs: list, unexplored_subdirs: list,
                                      task_queue_size: int) -> str:
        """Get prompt for agent injection focused context reassessment"""
        return f"""You are an AGENT INJECTION SECURITY STRATEGIST making intelligent decisions about where to focus analysis next.


**ANALYSIS HISTORY:**
{history_context}


**CURRENT STATE:**
- Files analyzed: {current_state['analyzed_files']}/{current_state['total_files']} ({current_state['coverage']:.1%} coverage)
- Directories explored: {current_state['explored_dirs']}
- High-risk findings: {current_state['high_risk_count']}
- Current task queue: {task_queue_size} tasks


**UNEXPLORED AREAS:**
Root directories: {', '.join(unexplored_root_dirs) if unexplored_root_dirs else 'None'}
Subdirectories: {', '.join(unexplored_subdirs[:5]) if unexplored_subdirs else 'None'}


**AGENT INJECTION ANALYSIS STRATEGY:**


Focus on finding:
1. **LLM Integration Points** - Files handling prompt construction, LLM calls, message formatting
2. **Tool Execution Chains** - How tools pass data to each other and to LLM
3. **User Input Pathways** - Where external input enters the agent system
4. **Agent Configuration** - Settings that control agent behavior and tool access
5. **Context Management** - How agent history/context is built and used


**DECISION CRITERIA:**
- Prioritize directories likely to contain agent components (src, tools, agents, core)
- Avoid purely infrastructure directories unless they control agent deployment
- Focus on unexplored areas with high injection risk potential


Choose the MOST PROMISING unexplored directory for agent injection analysis.


Respond with JSON:
{{
    "next_action": "explore_directory|continue_current_analysis|analysis_complete",
    "target_directory": "exact_directory_name_from_available_list_or_null",
    "reasoning": "why this directory is critical for injection analysis",
    "injection_focus": "what injection vectors you expect to find",
    "priority": "high|medium|low"
}}


**ONLY select directories from the unexplored lists provided above!**"""

    @staticmethod
    def get_security_analysis_prompt(file_path: str, content: str, language: str) -> str:
        """Get prompt for agent injection focused security analysis"""
        content_sample = content[:2000] + "..." if len(content) > 2000 else content


        return f"""You are an AGENT INJECTION SECURITY EXPERT analyzing code for injection vulnerabilities in AI agent systems.


FILE ANALYSIS TARGET:
- File: {file_path}
- Language: {language}
- Content length: {len(content)} characters


CONTENT SAMPLE:
{content_sample}


**AGENT INJECTION VULNERABILITY ANALYSIS:**


**PRIMARY FOCUS - Direct Agent Injection Risks:**


1. **LLM INTERACTION POINTS:**
   - Functions that construct prompts or messages for LLM calls
   - Direct LLM API calls where user input affects prompt content
   - Message formatting or template systems that include external data
   - Context or history building that incorporates untrusted input


2. **TOOL EXECUTION CHAIN VULNERABILITIES:**
   - Tool output processing that feeds directly to LLM without sanitization
   - Inter-tool communication where malicious output can poison next tool input
   - Tool result formatting that could inject malicious content
   - Dynamic tool selection based on LLM or external input


3. **DATA FLOW INJECTION POINTS:**
   - User input processing that flows to agent prompts
   - File content reading that feeds into agent context
   - API responses or external data incorporated into agent prompts
   - Configuration values that affect agent behavior or prompts


4. **WORKFLOW MANIPULATION RISKS:**
   - Agent state management that can be manipulated externally
   - Task queue or workflow systems that accept external input
   - Agent decision-making logic that can be influenced by injection
   - Context persistence that could store malicious instructions


**INJECTION ATTACK VECTORS TO IDENTIFY:**
- Where can malicious input enter the agent pipeline?
- How is external data sanitized before LLM processing?
- What controls exist to prevent prompt injection?
- Can tool outputs manipulate subsequent agent behavior?
- Are there any direct execution paths from LLM output?


Respond with JSON format focusing on injection vulnerabilities:
{{
    "findings": [
        {{
            "vulnerability_type": "Data_Flow_Injection|Tool_Output_Injection|Context_Injection|Workflow_Manipulation|Prompt_Injection",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "line_number": 42,
            "description": "Specific agent injection vulnerability",
            "code_snippet": "relevant code lines",
            "injection_vector": "how malicious input could reach LLM",
            "data_flow": "source -> processing -> llm_input path",
            "attack_scenario": "concrete example of exploitation",
            "remediation": "how to prevent this injection"
        }}
    ],
    "agent_security_assessment": "overall agent injection risk level"
}}


**Focus only on injection vulnerabilities that affect agent/LLM security - ignore traditional application security issues.**"""

    @staticmethod
    def get_exploration_decision_prompt(history_context: str, exploration_context: str,
                                      unexplored_areas: List[str], root_unexplored: List[str],
                                      files: List[str], dirs: List[str]) -> str:
        """Get prompt for exploration decision making"""
        return f"""You are an intelligent security analysis agent making strategic exploration decisions.


{history_context}


{exploration_context}


REPOSITORY EXPLORATION CONTEXT:
- Unexplored subdirectories: {unexplored_areas[:15]}
- Unexplored root directories: {root_unexplored[:10]}


IMPORTANT: You can ONLY select from the following existing items in the CURRENT DIRECTORY:


CURRENT DIRECTORY FILES (available for analysis):
{chr(10).join(f"- {f}" for f in files[:20])}


CURRENT DIRECTORY SUBDIRECTORIES (available for exploration):
{chr(10).join(f"- {d}" for d in dirs[:20])}


HIERARCHICAL DECISION FRAMEWORK:


UNDERSTAND YOUR OPTIONS:
- CURRENT DIRECTORY FILES: {chr(10).join(f"- {f}" for f in files[:20])}
- CURRENT DIRECTORY SUBDIRECTORIES: {chr(10).join(f"- {d}" for d in dirs[:20])}
- UNEXPLORED ROOT DIRECTORIES: {chr(10).join(f"- {d}" for d in root_unexplored[:10])}
- UNEXPLORED SUBDIRECTORIES: {chr(10).join(f"- {d}" for d in unexplored_areas[:10])}


DECISION HIERARCHY (FOLLOW THIS ORDER STRICTLY):


LEVEL 1 - CURRENT DIRECTORY FILES (HIGHEST PRIORITY):
- If CURRENT DIRECTORY contains important files (main.py, __init__.py, config files, security-critical files)
- READ THESE FILES FIRST before any exploration
- This establishes the foundation of what this directory does


LEVEL 2 - CURRENT DIRECTORY SUBDIRECTORIES (SECOND PRIORITY):
- Only if CURRENT DIRECTORY has NO important files to read
- Explore SUBDIRECTORIES WITHIN the current directory
- This allows depth-first exploration of the current scope


LEVEL 3 - UNEXPLORED ROOT DIRECTORIES (THIRD PRIORITY):
- Only if CURRENT DIRECTORY has NO important files AND NO subdirectories
- Look for unexplored directories at ROOT level
- Prefer directories that appear to be core application components


LEVEL 4 - UNEXPLORED SUBDIRECTORIES (FOURTH PRIORITY):
- Only if all above levels are exhausted
- Consider subdirectories in already explored directories
- This is for completing depth exploration


CRITICAL DECISION RULES:
- ALWAYS check LEVEL 1 first - read important current files if available
- ONLY move to LEVEL 2 if LEVEL 1 has nothing important
- ONLY move to LEVEL 3 if both LEVEL 1 and LEVEL 2 are empty
- ONLY use LEVEL 4 as last resort
- NEVER guess paths - only choose from the lists above
- Maximum 3 targets total


Respond with JSON:
{{
    "analysis_targets": [
        {{
            "type": "file|directory",
            "path": "EXACT path from the lists above",
            "priority": "high|medium|low",
            "reason": "why important - be specific"
        }}
    ],
    "exploration_strategy": "read current important files first, then explore",
    "architecture_focus": "focus on current scope before expanding"
}}


SELECTION RULES:
- Maximum 3 targets
- Prioritize files in current directory over exploration
- Only explore if no important files remain in current directory
- Use EXACT paths from the provided lists above."""


    @staticmethod
    def get_context_reassessment_prompt(history_context: str, current_state: Dict,
                                      unexplored_root_dirs: List[str], unexplored_subdirs: List[str],
                                      task_queue_size: int) -> str:
        """Get prompt for context reassessment and strategic planning"""
        return f"""You are an intelligent security analysis agent performing strategic context reassessment.


{history_context}


CURRENT ANALYSIS STATE:
- Task queue size: {task_queue_size}
- Analyzed files: {current_state.get('analyzed_files', 0)}
- Explored directories: {current_state.get('explored_dirs', 0)}
- High-risk files found: {current_state.get('high_risk_count', 0)}
- Total files in repository: {current_state.get('total_files', 0)}
- Analysis coverage: {current_state.get('coverage', 0):.1%}


UNEXPLORED AREAS:
- Root directories: {unexplored_root_dirs[:10]}
- Subdirectories: {unexplored_subdirs[:15]}


STRATEGIC DECISION FRAMEWORK:


PRIORITY HIERARCHY FOR NEXT ACTIONS:


LEVEL 1 - CRITICAL SECURITY ISSUES (HIGHEST PRIORITY):
- If high-risk files exist, focus on related files and dependencies
- Investigate security-critical configurations and authentication files
- Look for patterns that might indicate systemic security issues


LEVEL 2 - DEPTH-FIRST EXPLORATION (SECOND PRIORITY):
- Continue exploring subdirectories of already analyzed directories
- Focus on core application directories (src, app, core, main)
- Prioritize directories likely to contain business logic


LEVEL 3 - BREADTH EXPLORATION (THIRD PRIORITY):
- Explore new root-level directories
- Look for configuration and documentation directories
- Consider utility and supporting directories


LEVEL 4 - COMPLETENESS (FOURTH PRIORITY):
- Fill gaps in analysis coverage
- Analyze remaining files for completeness
- Consider low-priority but potentially revealing files


STRATEGIC RULES:
- Maintain task queue efficiency (aim for 5-15 tasks)
- Prioritize depth over breadth for thorough analysis
- Focus on security-critical paths first
- Avoid redundant exploration
- Consider analysis coverage when making decisions


CRITICAL RESPONSE FORMAT - MUST MATCH EXACTLY:
{{
    "next_actions": [
        {{
            "action": "explore_directory",
            "target": "exact/path/from/unexplored/list",
            "priority": "high",
            "reason": "Contains core application logic",
            "expected_value": "security"
        }},
        {{
            "action": "analyze_file",
            "target": "path/to/specific/file.py",
            "priority": "medium",
            "reason": "Key configuration file",
            "expected_value": "architecture"
        }}
    ],
    "strategy_explanation": "Focus on core application directories first for workflow analysis",
    "focus_areas": ["security", "workflow_analysis", "injection_points"],
    "reasoning": "Prioritizing areas most likely to contain agent workflow and data processing"
}}


CRITICAL INSTRUCTIONS:
1. **action** must be EXACTLY "explore_directory" or "analyze_file"
2. **target** must be EXACT path from unexplored areas listed above
3. **priority** must be "high", "medium", or "low"
4. Maximum 4 actions per reassessment for sustained analysis
5. Focus on directories/files likely to contain:
   - Agent workflow logic
   - Tool integration points
   - Data processing pipelines
   - LLM interaction code
   - Input validation and sanitization
6. Avoid already analyzed paths (see history above)
7. Prioritize depth over breadth for comprehensive analysis"""
    
    @staticmethod
    def get_reassessment_decision_prompt(current_state: Dict, security_findings: List[Dict],
                                       workflow_patterns: Dict, task_queue_info: Dict) -> str:
        """Get prompt for LLM-driven reassessment decision based on comprehensive context"""
        
        # Build findings context
        recent_findings = security_findings[-5:] if security_findings else []
        findings_summary = ""
        if recent_findings:
            findings_summary = f"""
**RECENT SECURITY FINDINGS:**
{chr(10).join([f"- {f['file']}: {f['risk_level']} risk - {', '.join(f['findings'][:2])}"
              for f in recent_findings])}
"""

        # Build workflow context
        workflow_context = ""
        if workflow_patterns:
            workflow_context = f"""
**WORKFLOW PATTERN ANALYSIS:**
- LLM Integration Points: {len(workflow_patterns.get('llm_points', []))} found
- Tool Execution Chains: {len(workflow_patterns.get('tool_chains', []))} found  
- Data Flow Paths: {len(workflow_patterns.get('data_flows', []))} found
- Injection Vectors: {len(workflow_patterns.get('injection_vectors', []))} found
"""


        return f"""You are an AGENT INJECTION ANALYSIS STRATEGIST making intelligent reassessment decisions.


**CURRENT ANALYSIS STATE:**
- Analysis Step: {current_state.get('step', 0)}
- Files Analyzed: {current_state.get('analyzed_files', 0)}
- Pending Tasks: {task_queue_info.get('pending_count', 0)}
- Highest Priority Task: {task_queue_info.get('highest_priority', 0)}
- Steps Since Last Reassessment: {current_state.get('steps_since_last', 0)}
{findings_summary}{workflow_context}


**REASSESSMENT DECISION CRITERIA:**


**SHOULD REASSESS WHEN:**
- New high/medium risk findings discovered that may reveal related attack vectors
- Workflow patterns suggest incomplete analysis of critical injection points
- Current task queue lacks focus on newly discovered vulnerability patterns
- Analysis has drifted from agent injection focus areas
- Recent discoveries suggest priority files were missed in earlier assessments


**SHOULD NOT REASSESS WHEN:**
- No significant new security findings in recent analysis
- Current task queue is well-aligned with discovered patterns
- Recent reassessment was performed (< 5 steps ago) without major new findings
- Analysis is progressing systematically through injection-critical areas


**DECISION FACTORS:**
1. **Discovery Impact**: How significantly do recent findings change our understanding?
2. **Pattern Completion**: Are we missing critical pieces of the attack chain?
3. **Queue Alignment**: Do current tasks align with discovered injection vectors?
4. **Analysis Focus**: Are we staying focused on agent injection vulnerabilities?


Based on the current analysis state and recent discoveries, should the task queue be reassessed?


Respond with JSON:
{{
    "should_reassess": true|false,
    "confidence": "high|medium|low",
    "reasoning": "specific reason based on recent findings and workflow patterns",
    "priority_focus": "what injection areas should be prioritized if reassessing",
    "discovery_impact": "how recent findings influence the decision"
}}


**Make intelligent decisions based on actual discoveries, not arbitrary rules.**"""

    @staticmethod
    def get_queue_reassessment_prompt(discoveries_context: str, tasks_context: str) -> str:
        """Build LLM prompt for discovery-based queue reassessment"""
        return f"""You are performing DISCOVERY-DRIVEN task queue reassessment. Base ALL decisions strictly on actual analysis results provided below.


{discoveries_context}


{tasks_context}


**CRITICAL REQUIREMENT: Only make changes based on ACTUAL DISCOVERIES above. Do NOT guess or assume.**


**DISCOVERY-BASED PRIORITIZATION RULES:**


1. **HIGH-RISK FILE CONNECTIONS**: If HIGH/MEDIUM risk files were found, prioritize:
   - Files in the SAME DIRECTORY as high-risk files
   - Files that IMPORT/REFERENCE the high-risk files  
   - Configuration files that might CONTROL the high-risk components


2. **FILE TYPE PATTERNS**: Based on file types already analyzed:
   - If Python files show risks → prioritize other .py files
   - If config files show risks → prioritize other config files (.toml, .yaml, .json)
   - If specific directories show risks → prioritize unexplored subdirectories


3. **WORKFLOW GAPS**: Only if you can see clear patterns:
   - Missing companion files (e.g., if main.py analyzed, prioritize __init__.py)
   - Missing config files for discovered services
   - Missing test files for high-risk components


**STRICT VALIDATION:**
- ONLY adjust priorities for tasks whose targets are LOGICALLY RELATED to actual discoveries
- DO NOT increase priorities arbitrarily
- DO NOT make changes unless you can explain the connection to actual findings


**RESPONSE FORMAT:**
{{
    "has_relevant_discoveries": true/false,
    "priority_updates": {{
        "exact_task_target": new_priority_number
    }},
    "discovery_based_reasoning": "explain how each change relates to specific discoveries above"
}}


**If no relevant discoveries exist or no logical connections can be made, respond with:**
{{
    "has_relevant_discoveries": false,
    "priority_updates": {{}},
    "discovery_based_reasoning": "No discoveries warrant task priority changes"
}}"""

    @staticmethod
    def get_focus_aware_reassessment_prompt(current_state: Dict, security_findings: List,
                                          workflow_patterns: Dict, task_queue_info: Dict,
                                          focus_summary: Dict, primary_focus) -> str:
        """Build focus-aware prompt for LLM reassessment decision"""
        
        focus_context = ""
        
        if primary_focus:
            focus_context = f"""
**CURRENT ACTIVE FOCUS:**
- Type: {primary_focus.focus_type}
- Target: {primary_focus.target}
- Priority: {primary_focus.priority}
- Investigation Depth: {primary_focus.investigation_depth}
- Pending Leads: {len(primary_focus.leads_to_follow)}
- Key Findings: {len(primary_focus.key_findings)}
- Related Files: {len(primary_focus.related_files)}


**FOCUS LEADS TO PURSUE:**
{chr(10).join([f"- {lead.get('path', lead)}: {lead.get('reason', 'Investigation lead')}" if isinstance(lead, dict) else f"- {lead}" for lead in primary_focus.leads_to_follow[:5]])}
"""
        
        return f"""You are making a STRATEGIC REASSESSMENT decision for deep vulnerability analysis.


**CURRENT ANALYSIS STATE:**
- Step: {current_state['step']}
- Files Analyzed: {current_state['analyzed_files']}
- Steps Since Last Reassessment: {current_state['steps_since_last']}
- Recent Findings: {current_state['recent_findings']}
- Active Investigation Focuses: {current_state['active_focuses']}
- Stagnation Risk: {current_state.get('stagnation_risk', False)}


{focus_context}


**TASK QUEUE STATUS:**
- Pending Tasks: {task_queue_info['pending_count']}
- Highest Priority: {task_queue_info['highest_priority']}
- Focus-Driven Targets Available: {task_queue_info['focus_targets_pending']}


**RECENT SECURITY FINDINGS:**
{chr(10).join([f"- {f.get('file', 'Unknown')}: {f.get('risk_level', 'unknown')} risk" for f in security_findings[-3:]])}


**STRATEGIC DECISION FRAMEWORK:**


You should recommend reassessment (respond "true") if ANY of these apply:
1. **FOCUS PURSUIT**: Active focus has leads that need immediate investigation
2. **DISCOVERY OPPORTUNITY**: Recent findings suggest deeper investigation needed  
3. **ANTI-STAGNATION**: Analysis is stuck on low-value files (configs, documentation)
4. **STRATEGIC SHIFT**: Current approach isn't uncovering meaningful vulnerabilities


You should NOT reassess (respond "false") only if:
- Currently pursuing a productive investigation line
- Recent steps have been uncovering meaningful insights
- No new strategic opportunities identified


**CRITICAL**: Focus on DEPTH over breadth. If we've found something interesting, we should pursue it relentlessly.


Respond EXACTLY in this JSON format:
{{
    "should_reassess": true/false,
    "reasoning": "brief strategic explanation",
    "confidence": "high/medium/low",
    "priority_focus": "what to focus on if reassessing",
    "discovery_impact": "how recent discoveries impact strategy"
}}"""