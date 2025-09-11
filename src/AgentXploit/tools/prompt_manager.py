"""
Improved prompt management for LLM interactions
Focuses on agent injection analysis with intelligent file selection
"""

from typing import Dict, Any, List


class PromptManager:
    """Strict prompt manager for agent injection analysis"""

    @staticmethod
    def get_exploration_decision_prompt(history_context: str,
                                        exploration_context: str = None,
                                        unexplored_areas: List[str] = None,
                                        root_unexplored: List[str] = None,
                                        files: List[str] = None,
                                        dirs: List[str] = None,
                                        context: Dict = None,
                                        focus: str = "security") -> str:
        """Unified exploration decision prompt with strict selection rules"""

        # Handle both calling patterns
        if context is not None:
            files = context.get('files', [])
            dirs = context.get('directories', [])
            explored_path = context.get('explored_path', '.')
            exploration_context = f"Currently exploring: {explored_path}"
            unexplored_areas = unexplored_areas or []
            root_unexplored = root_unexplored or []
        else:
            files = files or []
            dirs = dirs or []
            unexplored_areas = unexplored_areas or []
            root_unexplored = root_unexplored or []
            exploration_context = exploration_context or "Exploration in progress"

        return f"""FOCUS: {focus.upper()} - Analyze AGENT TOOL IMPLEMENTATIONS and DATAFLOW patterns
STRICT RULE: You MUST ONLY select from the AVAILABLE FILES and SUBDIRECTORIES lists below.

AGENT TOOL KEYWORDS TO PRIORITIZE:
- agent, tool, action, executor, handler, processor, runner, client, api
- controller, manager, wrapper, adapter, plugin, extension
- command, operation, task, job, workflow, pipeline

DATAFLOW KEYWORDS TO PRIORITIZE:
- stream, flow, pipe, channel, queue, buffer
- input, output, parse, transform, validate, sanitize
- request, response, send, receive, emit, listen
- read, write, process, handle, execute

AVOID THESE (unless they implement tools):
- README.md, docs/, documentation/, examples/
- tests/, test_, _test.py (unless testing tool implementations)
- config files (unless they define tool configurations)

AVAILABLE FILES IN CURRENT DIRECTORY (SELECT EXACT NAMES ONLY):
{chr(10).join([f"- {f}" for f in files])}

AVAILABLE SUBDIRECTORIES (SELECT EXACT NAMES ONLY):
{chr(10).join([f"- {d}" for d in dirs])}

UNEXPLORED ROOT DIRECTORIES:
{chr(10).join([f"- {d}" for d in root_unexplored])}

{exploration_context}

HISTORY CONTEXT(only for reference):
{history_context}

CRITICAL RULES:
1. Copy-paste EXACT names from the lists above
2. NEVER add '.py' to directory names
3. If it's in SUBDIRECTORIES list, it's a directory, NOT a file
4. Focus on AGENT TOOLS and DATAFLOW for {focus} analysis
5.**BE EFFICIENT**: Choose targets for tool/dataflow analysis - avoid broad exploration

RESPONSE FORMAT (JSON only, using EXACT names from lists):
{{
  "analysis_targets": [
    {{
      "type": "file|directory",
      "path": "EXACT_NAME_FROM_LISTS",
      "priority": "high|medium|low",
      "reason": "contains agent tool implementation|dataflow processing|external data handling"
    }}
  ],
  "strategy_explanation": "focusing on agent tool implementations and dataflow patterns for {focus} analysis"
}}"""


    @staticmethod
    def get_content_decision_prompt(history_context: str, context: Dict, focus: str = "security") -> str:
        """Strict content decision prompt with available-file filtering"""
    
        file_path = context.get('file_path', '')
        content = context.get('content', '')
        security_result = context.get('security_result', {})
        available_files = context.get('available_files', [])
        available_dirs = context.get('available_dirs', [])
    
        # Extract imports and references (only used as hints, not direct selection)
        imports_found = []
        if content:
            import re
            python_imports = re.findall(r'from\s+([a-zA-Z0-9_.]+)\s+import|import\s+([a-zA-Z0-9_.]+)', content)
            for match in python_imports:
                module = match[0] or match[1]
                if module and '.' in module:
                    file_candidate = module.replace('.', '/') + '.py'
                    imports_found.append(file_candidate)
    
            file_refs = re.findall(r'[\'"]([^\'\"]*\.(?:py|js|ts|json|toml|yaml|yml))[\'"]', content)
            imports_found.extend(file_refs)
    
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
    
        return f"""FOCUS: {focus.upper()} - Analyzing file content for AGENT TOOL USE and DATAFLOW vulnerabilities
Make follow-up decisions using STRICT selection rules based on the history context.

CURRENT FILE: {file_path}
SECURITY RISK: {security_result.get('risk_assessment', {}).get('overall_risk', 'UNKNOWN')}

HISTORY CONTEXT:
{history_context}

ALREADY ANALYZED FILES (DO NOT suggest these):
{chr(10).join([f"- {f}" for f in analyzed_files_list])}

IMPORT/REFERENCE HINTS (for prioritization only, do not invent new paths):
{chr(10).join([f"- {imp}" for imp in imports_found])}

AVAILABLE FILES (YOU MUST SELECT FROM THIS LIST ONLY):
{chr(10).join([f"- {f}" for f in available_files])}

AVAILABLE DIRECTORIES (YOU MUST SELECT FROM THIS LIST ONLY):
{chr(10).join([f"- {d}" for d in available_dirs])}

CRITICAL WARNING: DO NOT CREATE FILE NAMES! DO NOT ADD '.py' TO DIRECTORY NAMES!
If you see "serialization" in directories, it's a DIRECTORY, not "serialization.py"!

AGENT TOOL & DATAFLOW FOCUS FOR {focus.upper()} ANALYSIS:
1. PRIORITIZE files/dirs with AGENT TOOLS and DATAFLOW patterns
2. PRIORITIZE dataflow patterns
3. AVOID documentation unless they define tool interfaces
4. AVOID generic files unless they process external data or implement tools
5. ⚡ **BE HIGHLY SELECTIVE**: Focus on files most likely to contain tool implementations or dataflow logic - avoid extensive reading

FOLLOW-UP STRATEGY FOR {focus.upper()}:
1. If current file contains tool definitions -> find files that USE these tools
2. If current file has dataflow patterns -> trace the data path upstream/downstream
3. If current file processes external input -> find validation/sanitization logic
4. Focus on completing tool chains and dataflow analysis
5. Maximum 2 follow-up targets

ABSOLUTE RULES:
- You MUST copy-paste EXACT names from AVAILABLE FILES or AVAILABLE DIRECTORIES
- NEVER invent file names or add extensions to directory names
- If something appears only in AVAILABLE DIRECTORIES, it's a directory, NOT a file

Respond in JSON format:
{{
    "follow_up_targets": [
        {{"path": "EXACT_NAME_FROM_AVAILABLE_LISTS", "type": "file|directory", "priority": "high", "reason": "agent tool or dataflow related"}},
        {{"path": "EXACT_NAME_FROM_AVAILABLE_LISTS", "type": "file|directory", "priority": "medium", "reason": "agent tool or dataflow related"}}
    ],
    "exploration_strategy": "focus on agent tools and dataflow patterns for {focus} analysis, not documentation"
}}"""


    @staticmethod
    def get_context_reassessment_prompt(history_context: str, current_state: Dict,
                                      unexplored_root_dirs: List[str], unexplored_subdirs: List[str],
                                      task_queue_size: int, focus: str = "security") -> str:
        """Improved context reassessment prompt"""
        return f"""FOCUS: {focus.upper()} - Making strategic decisions about repository analysis continuation.

HISTORY CONTEXT:
{history_context}

CURRENT STATE:
- Files analyzed: {current_state.get('analyzed_files', 0)}
- Directories explored: {current_state.get('explored_dirs', 0)}
- High-risk findings: {current_state.get('high_risk_count', 0)}
- Task queue: {task_queue_size} tasks

UNEXPLORED AREAS:
Root directories: {unexplored_root_dirs}
Subdirectories: {unexplored_subdirs}

STRATEGIC PRIORITIES FOR {focus.upper()} ANALYSIS:
1. If files with tool definitions found -> explore directories containing tool implementations or consumers
2. If dataflow patterns identified -> prioritize directories that likely contain related data processing logic
3. Focus on directories suggesting external interaction
4. Prioritize directories that are likely to contain tool chains and dataflow patterns
5. Avoid: documentation directories unless they contain tool configurations or data samples
6. **STRATEGIC FOCUS**: Select areas for tool/dataflow discovery - avoid broad exploration

Select the MOST PROMISING unexplored area for tool chain and dataflow analysis focused on {focus}.

Respond in JSON format:
{{
    "next_actions": [
        {{
            "action": "explore_directory",
            "target": "exact_directory_from_unexplored_lists",
            "priority": "high",
            "reason": "likely contains tool implementations or data processing logic for {focus}",
            "expected_value": "tool_dataflow_analysis"
        }}
    ],
    "strategy_explanation": "focus on tool and data processing directories for {focus} analysis",
    "reasoning": "prioritize areas most likely to contain tool chains and dataflow patterns relevant to {focus}"
}}"""

    @staticmethod
    def get_queue_reassessment_prompt(discoveries_context: str, tasks_context: str) -> str:
        """Improved queue reassessment prompt with realistic expectations"""
        return f"""You are reassessing task priorities based on analysis discoveries.

{discoveries_context}

{tasks_context}

REASSESSMENT STRATEGY:
1. If tool definitions found → increase priority of files that implement or consume these tools
2. If dataflow patterns identified → prioritize upstream sources and downstream processors in the same flow
3. If external data sources discovered → prioritize validation, parsing, and processing files
4. If tool chains partially mapped → prioritize completing the chain analysis
5. Otherwise → minimal priority changes needed

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
    "discovery_based_reasoning": "explain connection to tool/dataflow discoveries"
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
                               workflow_analysis: Dict = None,
                               focus: str = "security") -> str:
        """Improved file priority prompt focused on agent injection"""
        
        # Present ALL files to LLM for intelligent selection - no pre-filtering
        
        return f"""FOCUS: {focus.upper()} - Selecting files for AGENT TOOL IMPLEMENTATION and DATAFLOW analysis.
Your goal is to find actual code that implements tools, processes data, or manages agent workflows for {focus} analysis.

REPOSITORY CONTEXT:
{context}

ALL AVAILABLE FILES (make intelligent selections):
{chr(10).join([f"{i+1}. {f}" for i, f in enumerate(files)])}

CRITICAL SELECTION PRIORITIES FOR {focus.upper()}:
1. **HIGHEST PRIORITY**: Source code files (.py, .js, .ts) that contain:
   - Tool implementations (tool, executor, handler, processor, runner)
   - Agent runtime/engine code (agent, runtime, engine, manager)
   - Data processing pipelines (pipeline, stream, transform, parse)
   - API/service clients (client, api, service, request, response)

2. **STRONGLY AVOID**: 
   - Documentation files UNLESS they contain actual implementations or core information about tools/workflows
   - Configuration files unless they define tools/workflows
   - Test files unless analyzing tool testing

3. **DATAFLOW FOCUS**: Prioritize files likely to show:
   - How external data enters the system
   - How data flows between components  
   - Tool chain implementations
   - Inter-service communication

**EFFICIENCY REQUIREMENT**: Be highly efficient - avoid broad reading patterns. Focus on files most likely to contain actual tool implementations and dataflow logic rather than reading extensively.


Respond in JSON format:
{{
    "priority_files": [
        {{
            "filename": "exact_filename_from_lists_above",
            "priority": "high",
            "reason": "likely contains tool implementation or data processing logic for {focus}",
            "analysis_focus": "tool_definition|data_processing|external_interaction"
        }}
    ],
    "analysis_strategy": "focus on tool chains and dataflow patterns for {focus} analysis"
}}"""

    @staticmethod
    def get_security_analysis_prompt(file_path: str, content: str, language: str) -> str:
        """Focused security analysis prompt for tool use and dataflow analysis"""
        content_sample = content[:1500] + "..." if len(content) > 1500 else content

        return f"""Analyze this code for TOOL USE and DATAFLOW patterns that could lead to injection vulnerabilities.

FILE: {file_path}
LANGUAGE: {language}

CODE CONTENT:
{content_sample}

**PRIMARY ANALYSIS FOCUS - Tool Use and Data Flow:**

1. **TOOL IDENTIFICATION**: What tools/functions does this component provide or use?
   - LLM interaction functions
   - File processing tools  
   - Command execution tools
   - API/web request tools
   - Data processing functions

2. **DATA FLOW MAPPING**: How does data flow through this component?
   - External input sources (user input, files, APIs, etc.)
   - Data processing/transformation steps
   - Output destinations (LLM prompts, tool parameters, files, etc.)
   - Data validation/sanitization points

3. **INJECTION POINT ANALYSIS**: Where in the dataflow could malicious input cause problems?
   - Input sanitization gaps
   - Tool parameter construction
   - LLM prompt building
   - Command execution points

Respond in JSON format:
{{
    "tool_analysis": {{
        "identified_tools": [
            {{
                "tool_name": "specific_tool_or_function_name",
                "tool_type": "llm_interface|file_processor|command_executor|api_client|data_transformer",
                "description": "what this tool does",
                "input_sources": ["where_data_comes_from"],
                "output_destinations": ["where_data_goes_to"]
            }}
        ],
        "dataflow_patterns": [
            {{
                "flow_id": "flow_1",
                "description": "brief description of this data flow",
                "data_path": "source -> processing_step -> destination",
                "external_input": "yes|no - can external users influence this flow",
                "sanitization": "yes|no|partial - is input sanitized",
                "risk_level": "HIGH|MEDIUM|LOW"
            }}
        ]
    }},
    "injection_analysis": {{
        "potential_injection_points": [
            {{
                "location": "line_number_or_function_name",
                "injection_type": "prompt_injection|tool_parameter_injection|command_injection|data_poisoning",
                "severity": "HIGH|MEDIUM|LOW",
                "description": "specific vulnerability description",
                "attack_scenario": "how attacker could exploit this",
                "affected_dataflow": "flow_id from above"
            }}
        ],
        "overall_risk": "HIGH|MEDIUM|LOW"
    }},
    "summary": "Brief summary of tool capabilities and dataflow risks"
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
