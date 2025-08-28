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
Centralized prompt management for LLM interactions
"""

from typing import Dict, Any, List


class PromptManager:
    """Manages all LLM prompts used in the analysis system"""

    @staticmethod
    def get_file_priority_prompt(context: str, files: List[str]) -> str:
        """Get prompt for file priority assessment"""
        return f"""You are a senior code analyst determining which files are most valuable to analyze for understanding system architecture, security vulnerabilities, and core functionality.

REPOSITORY ANALYSIS CONTEXT:
{context}

FILES TO ANALYZE:
{chr(10).join(f"{i+1}. {file}" for i, file in enumerate(files))}

ANALYSIS PRIORITIES:

HIGH PRIORITY FILES (analyze first):
- Core application entry points (main.py, app.py, server.py, __init__.py, cli.py)
- Configuration files (settings, configs, environment files, docker-compose)
- Build and deployment scripts (Makefile, build.sh, setup.py, pyproject.toml)
- Security-critical files (authentication, authorization, security modules)
- Core business logic and architecture files
- Package/module initialization files that define structure

MEDIUM PRIORITY FILES:
- API endpoints, controllers, and routing logic
- Data models, schemas, and database interactions
- Utility modules and helper functions
- Core library implementations
- Test files (reveal usage patterns and security assumptions)
- Infrastructure and deployment configurations

LOW PRIORITY FILES:
- Documentation files (README, CONTRIBUTING, etc.)
- Static assets and resource files  
- Generated or cache files
- License and legal files

ANALYSIS GOALS:
- Understand system architecture and core components
- Identify security vulnerabilities and risk patterns
- Map data flow and application structure
- Discover configuration and deployment issues
- Prioritize files that reveal system design and functionality

Select the TOP 5 most valuable files for security analysis from the list above.

Respond with JSON:
{{
    "priority_files": [
        {{
            "filename": "exact_filename_from_list",
            "priority": "high|medium|low",
            "reason": "why this file is valuable for security analysis",
            "analysis_type": "security_focus|config_review|data_flow|entry_point"
        }}
    ],
    "analysis_strategy": "focus on files that handle sensitive operations or define application structure"
}}

IMPORTANT: Only select filenames that EXACTLY match from the provided list above."""

    @staticmethod
    def get_security_analysis_prompt(file_path: str, content: str, language: str) -> str:
        """Get prompt for security analysis of file content"""
        content_sample = content[:2000] + "..." if len(content) > 2000 else content

        return f"""You are an expert security auditor analyzing code for vulnerabilities. Focus on real security issues, not false positives.

FILE SECURITY ANALYSIS:
- File: {file_path}
- Language: {language}
- Content length: {len(content)} characters

CONTENT SAMPLE:
{content_sample}

SECURITY ANALYSIS REQUIREMENTS:

1. INJECTION VULNERABILITIES:
   - SQL injection (string concatenation in queries)
   - Command injection (shell commands with user input)
   - Code injection (eval, exec usage)
   - Template injection (unsanitized template variables)

2. AUTHENTICATION & AUTHORIZATION:
   - Weak authentication mechanisms
   - Missing authorization checks
   - Insecure password handling
   - Session management issues

3. DATA HANDLING:
   - Hardcoded secrets (API keys, passwords, tokens)
   - Insecure data transmission
   - Improper input validation
   - Sensitive data exposure

4. CONFIGURATION SECURITY:
   - Insecure default configurations
   - Debug mode enabled in production
   - Weak encryption settings

FOCUS AREAS:
- Look for actual security vulnerabilities, not just potential issues
- Identify specific lines or code patterns that are problematic
- Assess the severity and exploitability of each finding
- Provide actionable remediation advice

Respond with JSON format for each security finding:
{{
    "findings": [
        {{
            "vulnerability_type": "SQL_Injection|Command_Injection|Hardcoded_Secret|etc",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "line_number": 42,
            "description": "Specific description of the vulnerability",
            "code_snippet": "relevant code lines",
            "remediation": "How to fix this issue",
            "exploitability": "How easy is this to exploit"
        }}
    ],
    "overall_assessment": "Brief summary of file security posture"
}}

Only report actual security vulnerabilities found in the code."""

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
    def get_content_decision_prompt(history_context: str, content_context: str,
                                  current_dir_files: List[str], current_dir_dirs: List[str],
                                  unexplored_subdirs: List[str],
                                  related_files_recommendations: List[str] = None) -> str:
        """Get prompt for content-based decision making"""
        related_files_context = ""
        if related_files_recommendations:
            related_files_context = f"""

RECOMMENDED RELATED FILES TO CONSIDER:
{chr(10).join(f"- {rec}" for rec in related_files_recommendations[:8])}

These recommendations are based on:
- Import statements and dependencies in the current file
- Referenced configuration files
- Related files in the same directory
- Files that might be relevant for security analysis"""

        return f"""You are an intelligent security analysis agent. Make follow-up decisions based on file analysis and current repository structure.

{history_context}

{content_context}{related_files_context}

CURRENT REPOSITORY CONTEXT:
- Root files: {current_dir_files[:10]}
- Root directories: {current_dir_dirs[:10]}
- Unexplored subdirectories: {unexplored_subdirs[:10]}

IMPORTANT: You can ONLY select from EXISTING items. Based on current analysis, decide what follow-up actions to take.

AVAILABLE ACTIONS (you can ONLY choose these):
1. Files referenced by current file (imports, includes, dependencies) - MUST EXIST
2. Unexplored subdirectories from the repository - MUST EXIST
3. Security-related files in current directory - MUST EXIST
4. Configuration files that might be related - MUST EXIST

FOLLOW-UP DECISION HIERARCHY:

LEVEL 1 - IMPORTED/REFERENCED FILES (HIGHEST PRIORITY):
- If current file IMPORTS or REFERENCES other files
- Read those imported files to understand dependencies
- Consider RECOMMENDED RELATED FILES for deeper analysis
- This helps build complete understanding of the codebase

LEVEL 2 - UNEXPLORED SUBDIRECTORIES (SECOND PRIORITY):
- Only if NO imported files to read
- Explore subdirectories to continue depth-first analysis
- This expands the current scope of analysis

LEVEL 3 - SECURITY-RELATED FILES (THIRD PRIORITY):
- Only if NO imported files AND NO subdirectories to explore
- Look for security configuration or policy files
- This focuses on security aspects of the current directory

LEVEL 4 - OTHER CONFIGURATION FILES (FOURTH PRIORITY):
- Only if all above levels are exhausted
- Consider other configuration files in current directory
- This is for completeness of analysis

CRITICAL FOLLOW-UP RULES:
- ALWAYS prioritize IMPORTED files first (Level 1)
- Consider RECOMMENDED RELATED FILES when making Level 1 decisions
- ONLY move to Level 2 if no imported files exist
- ONLY move to Level 3 if both Level 1 and Level 2 are empty
- ONLY use Level 4 as last resort
- NEVER guess paths - only choose from existing items
- If no valid follow-ups available, return empty targets array
- Maximum 2 targets total

Respond with JSON:
{{
    "follow_up_targets": [
        {{
            "type": "file|directory",
            "path": "EXACT existing path only",
            "priority": "high|medium|low",
            "reason": "why follow up - be specific"
        }}
    ],
    "exploration_strategy": "focus on existing items",
    "security_focus": "what security aspects to investigate further"
}}"""

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

RESPONSE FORMAT:
{{
    "next_actions": [
        {{
            "action": "explore_directory|analyze_file",
            "target": "EXACT path from unexplored areas",
            "priority": "high|medium|low",
            "reason": "strategic justification",
            "expected_value": "security|architecture|completeness"
        }}
    ],
    "strategy_explanation": "overall approach for next phase",
    "focus_areas": ["security", "architecture", "completeness"],
    "coverage_target": "percentage or specific goal"
}}

IMPORTANT:
- Only suggest actions for unexplored areas listed above
- Maximum 3 actions per reassessment
- Focus on strategic value, not random selection"""
