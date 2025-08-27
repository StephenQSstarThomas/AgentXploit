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
Smart Agent Analyzer - LLM-Driven Autonomous Repository Analysis
Inspired by Cursor's architecture, this analyzer gives LLM full autonomy to make decisions,
explore repositories, and conduct comprehensive architectural analysis.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
from google.adk.tools import ToolContext
from litellm import completion
from .analysis_tools import AnalysisTools

logger = logging.getLogger(__name__)


def smart_agent_analyze(
    repo_path: str,
    max_steps: int = 40,
    tool_context: Optional[ToolContext] = None
) -> Dict[str, Any]:
    """
    LLM-Driven Autonomous Repository Analysis
    
    The LLM acts as an autonomous agent with full decision-making power:
    - Decides which directories to explore
    - Chooses which files to read based on discovered content
    - Conducts architectural analysis autonomously
    - Identifies injection points through reasoning
    
    Args:
        repo_path: Path to target repository
        max_steps: Maximum analysis steps
        tool_context: ADK tool context (optional)
        
    Returns:
        Comprehensive analysis with LLM decision log
    """
    
    try:
        repo_path = Path(repo_path).resolve()
        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
        
        logger.info(f"Starting LLM-driven autonomous analysis of: {repo_path}")
        
        # Initialize autonomous analyzer
        analyzer = AutonomousAgentAnalyzer(repo_path, max_steps)
        
        # Let LLM take full control
        result = analyzer.run_autonomous_analysis()
        
        logger.info("LLM-driven autonomous analysis completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error during autonomous analysis: {str(e)}")
        return {
            "error": str(e),
            "decision_log": [],
            "analysis_summary": "Analysis failed due to error",
            "analyzer_version": "6.0.0-autonomous"
        }


class AutonomousAgentAnalyzer:
    """
    Autonomous Agent Analyzer - LLM has full decision-making control
    
    Core Principles:
    1. LLM decides what to explore next
    2. LLM reasons about file importance based on discovered content
    3. LLM conducts architectural analysis autonomously
    4. LLM identifies injection points through reasoning
    5. All decisions are logged with reasoning
    """
    
    def __init__(self, repo_path: Path, max_steps: int):
        self.repo_path = repo_path
        self.max_steps = max_steps
        self.current_step = 0
        
        # Analysis tools available to LLM
        self.tools = AnalysisTools(repo_path)
        
        # LLM's knowledge state
        self.knowledge_base = {
            "discovered_structure": {},      # Discovered directories and files
            "available_files": {},           # All discovered files by directory  
            "analyzed_files": {},            # Files read with content
            "architectural_insights": [],    # LLM's architectural findings
            "injection_points": [],          # LLM's injection point analysis
            "current_understanding": "",     # LLM's current understanding of the codebase
            "exploration_strategy": ""       # LLM's current exploration strategy
        }
        
        # Decision and execution log
        self.decision_log = []
        
        # Operation tracking to prevent repetition
        self.attempted_operations = set()
        self.failed_operations = set()
        self.successful_operations = set()
        
        self._setup_openai_key()
    
    def _setup_openai_key(self):
        """Setup OpenAI API key"""
        if not os.environ.get("OPENAI_API_KEY"):
            try:
                from ...config import Settings
                api_key = getattr(Settings, 'DEFAULT_OPENAI_API_KEY', None)
                if api_key and api_key.startswith('sk-'):
                    os.environ["OPENAI_API_KEY"] = api_key
                    logger.info("OpenAI API key set from configuration")
            except Exception as e:
                logger.debug(f"Could not load API key from settings: {e}")

    def run_autonomous_analysis(self) -> Dict[str, Any]:
        """
        Run LLM-driven autonomous analysis
        
        LLM has full control over:
        - Exploration strategy
        - Tool selection and usage
        - Analysis depth and focus
        - Architectural insights
        - Injection point identification
        """
        
        # Initial briefing to LLM
        self._log_decision_step(
            "INITIALIZATION",
            "Starting autonomous analysis. LLM has full decision-making control.",
            "System initialization complete. Repository path: " + str(self.repo_path),
            {"status": "initialized", "max_steps": self.max_steps}
        )
        
        # Main autonomous exploration loop
        while self.current_step < self.max_steps:
            self.current_step += 1
            
            # Get LLM's next decision
            decision = self._get_llm_autonomous_decision()
            
            if decision.get("action") == "COMPLETE_ANALYSIS":
                self._log_decision_step(
                    "ANALYSIS_COMPLETION",
                    "LLM has decided to complete the analysis",
                    decision.get("reasoning", "Analysis objectives achieved"),
                    {"final_step": self.current_step}
                )
                break
            
            # Execute LLM's decision
            self._execute_llm_decision(decision)
        
        # Generate final report
        return self._generate_autonomous_report()

    def _get_llm_autonomous_decision(self) -> Dict[str, Any]:
        """
        Get LLM's autonomous decision for next action
        
        LLM analyzes current state and decides:
        - What to explore next
        - Which tools to use
        - How to proceed with analysis
        """
        
        # Build comprehensive context for LLM
        context = self._build_llm_context()
        
        # Create autonomous decision prompt
        decision_prompt = f"""You are an expert code analyst with full autonomy to explore and analyze agent repositories. You have complete decision-making control.

REPOSITORY: {self.repo_path.name}
CURRENT STEP: {self.current_step}/{self.max_steps}

CURRENT KNOWLEDGE STATE:
{self._format_knowledge_state()}

OPERATION HISTORY (DO NOT REPEAT):
{self._format_operation_history()}

DISCOVERED FILES AVAILABLE FOR READING:
{self._format_available_files()}

AVAILABLE TOOLS:
- list_directory(path): Explore directory contents (MUST DO FIRST for each new directory)
- read_file(file_path): Read ONLY files that exist in DISCOVERED FILES list above
- grep_search(pattern, file_pattern="*.py"): Search for patterns in discovered files
- search_files(filename_pattern): Find files matching pattern (for discovery only)

YOUR MISSION:
Conduct autonomous repository analysis to understand:
1. Overall architecture and design patterns
2. Core components and their relationships
3. Data flow and execution paths
4. Security vulnerabilities and injection points

THINKING PROCESS:
First, THINK about your current understanding and what you need to discover next.
Consider:
- What gaps exist in your knowledge?
- What would be most valuable to explore next?
- Which files/directories seem most critical?
- What patterns or anomalies have you noticed?

DECISION FORMAT:
{{
  "thinking": "Your detailed reasoning about current state and next steps",
  "action": "list_directory|read_file|grep_search|search_files|COMPLETE_ANALYSIS",
  "reasoning": "Why this action will advance your understanding",
  "parameters": {{"path": "...", "file_path": "...", "pattern": "..."}},
  "expected_outcome": "What you expect to discover",
  "priority": "high|medium|low"
}}

STRICT AUTONOMOUS GUIDELINES:
- SMART EXPLORATION: Use CURRENT KNOWLEDGE STATE to avoid redundant operations
- If a directory is already in DISCOVERED STRUCTURE, DON'T list it again - read its files instead
- NEVER guess file names - ONLY read files from DISCOVERED FILES list
- EFFICIENT WORKFLOW: Explore → Read discovered files → Move to unexplored areas
- YOU decide the exploration strategy based on discovered content
- YOU determine file importance based on actual findings, not naming conventions  
- YOU identify architectural patterns through reasoning
- YOU spot potential injection points through code analysis
- NEVER repeat the same operation twice (check OPERATION HISTORY)
- MAXIMIZE PROGRESS: Prioritize reading unanalyzed files from explored directories

Make your next autonomous decision:"""

        try:
            response = completion(
                model="openai/gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an autonomous code analysis agent with full decision-making authority. Think carefully and make strategic decisions to understand the repository architecture."},
                    {"role": "user", "content": decision_prompt}
                ],
                max_tokens=1000,
                temperature=0.1
            )
            
            decision_text = response.choices[0].message.content.strip()
            
            # Extract JSON decision
            if '{' in decision_text and '}' in decision_text:
                start = decision_text.find('{')
                end = decision_text.rfind('}') + 1
                decision_json = decision_text[start:end]
                
                try:
                    decision = json.loads(decision_json)
                    
                    # Validate decision structure
                    if "action" not in decision:
                        raise ValueError("Missing 'action' in decision")
                    
                    # Check for repetition before accepting decision
                    if self._is_repeated_operation(decision):
                        logger.warning("LLM suggested repeated operation, using fallback")
                        return self._get_fallback_decision()
                    
                    # CRITICAL: Validate read_file operations against discovered files
                    if decision.get("action") == "read_file":
                        if not self._validate_file_access(decision):
                            logger.warning("LLM tried to read undiscovered file, using fallback")
                            return self._get_fallback_decision()
                    
                    # Log LLM's thinking process
                    self._log_decision_step(
                        "LLM_AUTONOMOUS_DECISION",
                        decision.get("thinking", "LLM reasoning not provided"),
                        decision.get("reasoning", "No explicit reasoning"),
                        {
                            "action": decision.get("action"),
                            "priority": decision.get("priority", "medium"),
                            "expected_outcome": decision.get("expected_outcome", "")
                        }
                    )
                    
                    return decision
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse LLM decision JSON: {e}")
                    return self._get_fallback_decision()
            else:
                logger.error("No JSON found in LLM response")
                return self._get_fallback_decision()
                
        except Exception as e:
            logger.error(f"Error getting LLM autonomous decision: {str(e)}")
            return self._get_fallback_decision()

    def _execute_llm_decision(self, decision: Dict[str, Any]):
        """Execute LLM's autonomous decision"""
        
        action = decision.get("action")
        parameters = decision.get("parameters", {})
        reasoning = decision.get("reasoning", "")
        
        try:
            result = None
            
            if action == "list_directory":
                path = parameters.get("path", ".")
                logger.info(f"LLM Decision: Exploring directory '{path}'")
                result = self.tools.list_directory(path)
                
                if result and "error" not in result:
                    # Update knowledge base with discoveries
                    self.knowledge_base["discovered_structure"][path] = result
                    
                    # CRITICAL: Track all discovered files for validation
                    self._update_available_files(path, result)
                    
                    # Let LLM update understanding
                    self._update_llm_understanding_from_discovery(path, result)
                
            elif action == "read_file":
                file_path = parameters.get("file_path")
                start_line = parameters.get("start_line")
                end_line = parameters.get("end_line")
                
                logger.info(f"LLM Decision: Reading file '{file_path}'")
                result = self.tools.read_file(file_path, start_line, end_line)
                
                if result and "error" not in result:
                    # Store file content
                    self.knowledge_base["analyzed_files"][file_path] = result
                    
                    # Let LLM analyze the file content
                    self._conduct_llm_file_analysis(file_path, result)
                
            elif action == "grep_search":
                pattern = parameters.get("pattern")
                file_pattern = parameters.get("file_pattern", "*.py")
                
                logger.info(f"LLM Decision: Searching pattern '{pattern}' in {file_pattern}")
                result = self.tools.grep_search(pattern, file_pattern)
                
                if result and "error" not in result:
                    # Let LLM analyze search results
                    self._conduct_llm_search_analysis(pattern, result)
                
            elif action == "search_files":
                filename_pattern = parameters.get("filename_pattern")
                
                logger.info(f"LLM Decision: Finding files matching '{filename_pattern}'")
                result = self.tools.search_files(filename_pattern)
                
                if result and "error" not in result:
                    # Update knowledge with found files
                    self._update_llm_understanding_from_file_search(filename_pattern, result)
            
            else:
                result = {"error": f"Unknown action: {action}"}
            
            # Track operation success/failure
            operation_sig = self._create_operation_signature(action, parameters)
            success = result and "error" not in result
            
            self.attempted_operations.add(operation_sig)
            if success:
                self.successful_operations.add(operation_sig)
            else:
                self.failed_operations.add(operation_sig)
            
            # Log execution result
            self._log_decision_step(
                "TOOL_EXECUTION",
                f"Executed {action}: {reasoning}",
                self._summarize_execution_result(result),
                {
                    "action": action,
                    "parameters": parameters,
                    "success": success,
                    "operation_signature": operation_sig
                }
            )
            
        except Exception as e:
            error_result = {"error": str(e)}
            self._log_decision_step(
                "EXECUTION_ERROR",
                f"Error executing {action}: {str(e)}",
                "Tool execution failed",
                {"action": action, "error": str(e)}
            )

    def _update_llm_understanding_from_discovery(self, path: str, discovery: Dict[str, Any]):
        """Let LLM update its understanding based on directory discovery"""
        
        prompt = f"""You discovered the following in directory '{path}':

DISCOVERY:
{json.dumps(discovery, indent=2)}

Based on this discovery, update your understanding of the repository architecture.
Focus on:
1. What does this directory structure tell you about the project?
2. Which files/subdirectories seem most important for understanding the architecture?
3. What patterns do you notice?

Provide a brief update to your understanding:"""

        try:
            response = completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.1
            )
            
            understanding_update = response.choices[0].message.content.strip()
            
            # Update knowledge base
            current = self.knowledge_base.get("current_understanding", "")
            self.knowledge_base["current_understanding"] = f"{current}\n\nDiscovery in {path}: {understanding_update}"
            
        except Exception as e:
            logger.warning(f"Failed to update LLM understanding: {e}")

    def _conduct_llm_file_analysis(self, file_path: str, file_content: Dict[str, Any]):
        """Let LLM conduct autonomous file analysis"""
        
        content = file_content.get("content", "")
        if not content or len(content) < 50:
            return
        
        prompt = f"""Analyze this file for architectural insights and potential injection points:

FILE: {file_path}
CONTENT:
```
{content[:3000]}
```

Conduct autonomous analysis focusing on:

1. ARCHITECTURAL ROLE:
   - What is this file's purpose in the overall system?
   - What patterns or frameworks does it use?
   - How does it interact with other components?

2. SECURITY ANALYSIS:
   - Are there any potential injection points?
   - Does it handle user input or external data?
   - Are there dynamic execution or evaluation points?

3. KEY INSIGHTS:
   - What are the most important findings about this file?
   - How does it contribute to your understanding of the system?

Provide your analysis in JSON format:
{{
  "architectural_insights": {{
    "role": "...",
    "patterns": ["..."],
    "dependencies": ["..."],
    "key_functions": ["..."]
  }},
  "security_analysis": {{
    "injection_points": [
      {{
        "type": "...",
        "location": "...",
        "risk_level": "high|medium|low",
        "description": "...",
        "mitigation": "..."
      }}
    ],
    "security_concerns": ["..."]
  }},
  "key_insights": ["..."]
}}"""

        try:
            response = completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1200,
                temperature=0.1
            )
            
            analysis_text = response.choices[0].message.content.strip()
            
            # Extract and store analysis
            if '{' in analysis_text and '}' in analysis_text:
                start = analysis_text.find('{')
                end = analysis_text.rfind('}') + 1
                analysis_json = analysis_text[start:end]
                
                try:
                    analysis = json.loads(analysis_json)
                    
                    # Store architectural insights
                    if "architectural_insights" in analysis:
                        insight = {
                            "file": file_path,
                            "type": "architectural_analysis",
                            "insights": analysis["architectural_insights"],
                            "timestamp": datetime.now().isoformat()
                        }
                        self.knowledge_base["architectural_insights"].append(insight)
                    
                    # Store security analysis
                    if "security_analysis" in analysis and analysis["security_analysis"].get("injection_points"):
                        for point in analysis["security_analysis"]["injection_points"]:
                            point["file"] = file_path
                            point["discovered_by"] = "llm_autonomous_analysis"
                            self.knowledge_base["injection_points"].append(point)
                    
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse LLM analysis for {file_path}")
                    
        except Exception as e:
            logger.warning(f"Failed LLM file analysis for {file_path}: {e}")

    def _conduct_llm_search_analysis(self, pattern: str, search_results: Dict[str, Any]):
        """Let LLM analyze search results for insights"""
        
        if not search_results.get("matches"):
            return
        
        # Limit matches for context
        limited_matches = search_results["matches"][:10]
        
        prompt = f"""Analyze these search results for architectural and security insights:

SEARCH PATTERN: {pattern}
RESULTS:
{json.dumps(limited_matches, indent=2)}

What do these search results tell you about:
1. Architecture patterns in the codebase
2. Potential security vulnerabilities
3. Code organization and design

Provide key insights (2-3 sentences):"""

        try:
            response = completion(
                model="openai/gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=400,
                temperature=0.1
            )
            
            insights = response.choices[0].message.content.strip()
            
            # Store insights
            insight = {
                "type": "search_analysis",
                "pattern": pattern,
                "insights": insights,
                "match_count": len(search_results.get("matches", [])),
                "timestamp": datetime.now().isoformat()
            }
            self.knowledge_base["architectural_insights"].append(insight)
            
        except Exception as e:
            logger.warning(f"Failed LLM search analysis: {e}")

    def _update_llm_understanding_from_file_search(self, pattern: str, search_results: Dict[str, Any]):
        """Update LLM understanding from file search results"""
        
        files_found = search_results.get("files", [])
        if not files_found:
            return
        
        understanding_update = f"File search for '{pattern}' found {len(files_found)} files: {', '.join([f['name'] for f in files_found[:5]])}"
        
        current = self.knowledge_base.get("current_understanding", "")
        self.knowledge_base["current_understanding"] = f"{current}\n{understanding_update}"

    def _build_llm_context(self) -> Dict[str, Any]:
        """Build comprehensive context for LLM decision making"""
        
        return {
            "current_step": self.current_step,
            "max_steps": self.max_steps,
            "discovered_structure": self.knowledge_base["discovered_structure"],
            "analyzed_files": list(self.knowledge_base["analyzed_files"].keys()),
            "architectural_insights_count": len(self.knowledge_base["architectural_insights"]),
            "injection_points_count": len(self.knowledge_base["injection_points"]),
            "current_understanding": self.knowledge_base["current_understanding"],
            "recent_decisions": [log["decision_type"] for log in self.decision_log[-3:]]
        }

    def _format_knowledge_state(self) -> str:
        """Format current knowledge state for LLM"""
        
        lines = []
        
        # Discovered structure with clear status
        structure = self.knowledge_base["discovered_structure"]
        if structure:
            lines.append(f"DISCOVERED STRUCTURE ({len(structure)} locations ALREADY EXPLORED):")
            for path, info in structure.items():
                dirs = len(info.get("directories", []))
                files = len(info.get("files", []))
                lines.append(f"  ✅ {path}/: {dirs} subdirs, {files} files (ALREADY LISTED)")
                
                # Show some subdirectories to guide next exploration
                subdirs = info.get("directories", [])
                if subdirs:
                    subdir_names = [d.get("name", d.get("path", "")) for d in subdirs[:3]]
                    lines.append(f"     Subdirs: {', '.join(subdir_names)}")
        else:
            lines.append("DISCOVERED STRUCTURE: None yet - start with root directory exploration")
        
        # Available vs analyzed files
        total_available = sum(len(files) for files in self.knowledge_base["available_files"].values())
        analyzed = list(self.knowledge_base["analyzed_files"].keys())
        if total_available > 0:
            lines.append(f"\nFILE ANALYSIS STATUS:")
            lines.append(f"  Available files: {total_available}")
            lines.append(f"  Analyzed files: {len(analyzed)}")
            lines.append(f"  Analysis progress: {len(analyzed)}/{total_available}")
            
            if analyzed:
                lines.append(f"  Recently analyzed: {', '.join(analyzed[-3:])}")  # Last 3
        
        # Current understanding
        understanding = self.knowledge_base.get("current_understanding", "")
        if understanding:
            lines.append(f"\nCURRENT UNDERSTANDING:")
            lines.append(f"  {understanding[-500:]}")  # Last 500 chars
        
        # Progress summary
        insights = len(self.knowledge_base["architectural_insights"])
        injection_points = len(self.knowledge_base["injection_points"])
        lines.append(f"\nPROGRESS: {insights} insights, {injection_points} injection points identified")
        
        return "\n".join(lines)

    def _format_operation_history(self) -> str:
        """Format operation history for LLM context"""
        lines = []
        
        if self.failed_operations:
            lines.append("FAILED OPERATIONS (do not repeat):")
            for op in list(self.failed_operations)[-5:]:  # Last 5 failures
                lines.append(f"  ❌ {op}")
        
        if self.successful_operations:
            lines.append("SUCCESSFUL OPERATIONS (already done):")
            for op in list(self.successful_operations)[-3:]:  # Last 3 successes
                lines.append(f"  ✅ {op}")
        
        lines.append(f"Total operations attempted: {len(self.attempted_operations)}")
        
        return "\n".join(lines) if lines else "No operations attempted yet"

    def _format_available_files(self) -> str:
        """Format discovered files for LLM to know what can be read"""
        lines = []
        
        if not self.knowledge_base["available_files"]:
            lines.append("No files discovered yet - must list directories first")
            return "\n".join(lines)
        
        lines.append("FILES AVAILABLE FOR READING (discovered through list_directory):")
        
        for dir_path, files in self.knowledge_base["available_files"].items():
            if files:
                lines.append(f"\nIn directory '{dir_path}':")
                for file_path in files[:10]:  # Show max 10 files per directory
                    status = "✅ ANALYZED" if file_path in self.knowledge_base["analyzed_files"] else "⏳ NOT READ"
                    lines.append(f"  - {file_path} ({status})")
                
                if len(files) > 10:
                    lines.append(f"  ... and {len(files) - 10} more files")
        
        total_files = sum(len(files) for files in self.knowledge_base["available_files"].values())
        analyzed_count = len(self.knowledge_base["analyzed_files"])
        lines.append(f"\nTOTAL: {total_files} discovered files, {analyzed_count} analyzed")
        
        return "\n".join(lines)

    def _update_available_files(self, path: str, discovery_result: Dict[str, Any]):
        """Update the list of available files for reading"""
        files = discovery_result.get("files", [])
        available_in_path = []
        
        for file_info in files:
            file_path = file_info.get("path", file_info.get("name"))
            if file_path:
                available_in_path.append(file_path)
        
        if available_in_path:
            self.knowledge_base["available_files"][path] = available_in_path

    def _validate_file_access(self, decision: Dict[str, Any]) -> bool:
        """Validate that LLM is only trying to read discovered files"""
        if decision.get("action") != "read_file":
            return True
        
        file_path = decision.get("parameters", {}).get("file_path")
        if not file_path:
            return False
        
        # Check if this file was discovered through list_directory
        for dir_path, files in self.knowledge_base["available_files"].items():
            if file_path in files:
                return True
        
        # File not in discovered list
        logger.warning(f"LLM tried to read undiscovered file: {file_path}")
        logger.warning(f"Available files: {self.knowledge_base['available_files']}")
        return False

    def _is_repeated_operation(self, decision: Dict[str, Any]) -> bool:
        """Check if this decision would repeat a previous operation or is unnecessary"""
        action = decision.get("action")
        parameters = decision.get("parameters", {})
        
        operation_sig = self._create_operation_signature(action, parameters)
        
        # Check if already attempted recently
        if operation_sig in self.attempted_operations:
            return True
        
        # CRITICAL: Check if trying to list already explored directory
        if action == "list_directory":
            path = parameters.get("path", ".")
            if path in self.knowledge_base["discovered_structure"]:
                logger.warning(f"LLM tried to re-list already explored directory: {path}")
                return True
        
        return False

    def _create_operation_signature(self, action: str, parameters: Dict[str, Any]) -> str:
        """Create unique signature for operation tracking"""
        if action == "list_directory":
            return f"list_directory:{parameters.get('path', '.')}"
        elif action == "read_file":
            return f"read_file:{parameters.get('file_path', '')}"
        elif action == "grep_search":
            return f"grep_search:{parameters.get('pattern', '')}:{parameters.get('file_pattern', '*.py')}"
        elif action == "search_files":
            return f"search_files:{parameters.get('filename_pattern', '')}"
        else:
            return f"{action}:{str(parameters)}"

    def _get_fallback_decision(self) -> Dict[str, Any]:
        """Provide smart fallback decision prioritizing list-then-read pattern"""
        
        # Step 1: Ensure root directory is explored first
        if "list_directory:." not in self.attempted_operations:
            return {
                "action": "list_directory",
                "reasoning": "Systematic fallback: Start with root directory exploration",
                "parameters": {"path": "."},
                "thinking": "Must explore root directory first to discover files"
            }
        
        # Step 2: Prioritize reading files from already explored directories
        for dir_path, files in self.knowledge_base["available_files"].items():
            for file_path in files:
                file_sig = f"read_file:{file_path}"
                if (file_sig not in self.attempted_operations and 
                    file_path not in self.knowledge_base["analyzed_files"]):
                    return {
                        "action": "read_file",
                        "reasoning": f"Smart fallback: Read discovered file from explored directory",
                        "parameters": {"file_path": file_path},
                        "thinking": f"Utilizing already explored structure - reading {file_path} from {dir_path}"
                    }
        
        # Step 3: Find directories that need listing (only unexplored directories)
        for path_info in self.knowledge_base["discovered_structure"].values():
            for dir_info in path_info.get("directories", []):
                dir_path = dir_info.get("path", dir_info.get("name"))
                # Only list if directory itself hasn't been explored
                if dir_path not in self.knowledge_base["discovered_structure"]:
                    return {
                        "action": "list_directory",
                        "reasoning": f"Smart fallback: Explore new directory {dir_path}",
                        "parameters": {"path": dir_path},
                        "thinking": f"Found unexplored directory: {dir_path}"
                    }
        
        # Step 4: Complete analysis if everything explored
        return {
            "action": "COMPLETE_ANALYSIS",
            "reasoning": "Systematic fallback: All discovered content analyzed",
            "thinking": "No more unexplored directories or unread discovered files"
        }

    def _summarize_execution_result(self, result: Any) -> str:
        """Create brief summary of execution result"""
        
        if not result:
            return "No result"
        
        if isinstance(result, dict):
            if "error" in result:
                return f"Error: {result['error']}"
            elif "total_items" in result:
                return f"Found {result['total_items']} items"
            elif "total_matches" in result:
                return f"Found {result['total_matches']} matches"
            elif "lines_read" in result:
                return f"Read {result['lines_read']} lines"
            elif "total_found" in result:
                return f"Found {result['total_found']} files"
        
        return "Completed successfully"

    def _log_decision_step(self, decision_type: str, thinking: str, reasoning: str, metadata: Dict[str, Any]):
        """Log LLM decision and execution step"""
        
        log_entry = {
            "step": self.current_step,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "decision_type": decision_type,
            "thinking": thinking,
            "reasoning": reasoning,
            "metadata": metadata
        }
        
        self.decision_log.append(log_entry)
        logger.info(f"Step {self.current_step}: {decision_type} - {reasoning}")

    def _generate_autonomous_report(self) -> Dict[str, Any]:
        """Generate comprehensive autonomous analysis report"""
        
        return {
            "analysis_metadata": {
                "repository_path": str(self.repo_path),
                "analysis_type": "llm_autonomous",
                "analyzer_version": "6.0.0-autonomous",
                "total_steps": self.current_step,
                "max_steps": self.max_steps,
                "timestamp": datetime.now().isoformat(),
                "completion_status": "completed" if self.current_step < self.max_steps else "max_steps_reached"
            },
            
            "llm_autonomous_decisions": {
                "total_decisions": len(self.decision_log),
                "decision_log": self.decision_log,
                "exploration_efficiency": self._assess_exploration_efficiency(),
                "decision_quality": self._assess_decision_quality()
            },
            
            "discovered_knowledge": {
                "repository_structure": self.knowledge_base["discovered_structure"],
                "analyzed_files": list(self.knowledge_base["analyzed_files"].keys()),
                "llm_understanding": self.knowledge_base["current_understanding"],
                "discovery_coverage": self._calculate_discovery_coverage()
            },
            
            "architectural_analysis": {
                "total_insights": len(self.knowledge_base["architectural_insights"]),
                "architectural_insights": self.knowledge_base["architectural_insights"],
                "architecture_summary": self._generate_architecture_summary()
            },
            
            "security_analysis": {
                "total_injection_points": len(self.knowledge_base["injection_points"]),
                "injection_points": self.knowledge_base["injection_points"],
                "security_assessment": self._generate_security_assessment()
            },
            
            "tool_usage_log": self.tools.get_execution_log(),
            
            "analysis_quality": {
                "exploration_effectiveness": self._assess_exploration_effectiveness(),
                "insight_generation": self._assess_insight_generation(),
                "overall_quality": self._assess_overall_quality()
            }
        }

    def _assess_exploration_efficiency(self) -> Dict[str, Any]:
        """Assess LLM's exploration efficiency"""
        
        decisions = len(self.decision_log)
        discoveries = len(self.knowledge_base["discovered_structure"])
        files_read = len(self.knowledge_base["analyzed_files"])
        
        efficiency_score = min(100, (discoveries * 10 + files_read * 15) / max(decisions, 1))
        
        return {
            "efficiency_score": round(efficiency_score, 1),
            "total_decisions": decisions,
            "discoveries_made": discoveries,
            "files_analyzed": files_read,
            "assessment": "excellent" if efficiency_score >= 80 else "good" if efficiency_score >= 60 else "needs_improvement"
        }

    def _assess_decision_quality(self) -> Dict[str, Any]:
        """Assess quality of LLM's autonomous decisions"""
        
        total_decisions = len([log for log in self.decision_log if log["decision_type"] == "LLM_AUTONOMOUS_DECISION"])
        successful_executions = len([log for log in self.decision_log if log["decision_type"] == "TOOL_EXECUTION" and log["metadata"].get("success", False)])
        
        quality_score = (successful_executions / max(total_decisions, 1)) * 100
        
        return {
            "quality_score": round(quality_score, 1),
            "autonomous_decisions": total_decisions,
            "successful_executions": successful_executions,
            "assessment": "excellent" if quality_score >= 90 else "good" if quality_score >= 75 else "needs_improvement"
        }

    def _calculate_discovery_coverage(self) -> Dict[str, Any]:
        """Calculate discovery coverage metrics"""
        
        total_dirs = len(self.knowledge_base["discovered_structure"])
        total_files_found = sum(len(info.get("files", [])) for info in self.knowledge_base["discovered_structure"].values())
        files_analyzed = len(self.knowledge_base["analyzed_files"])
        
        return {
            "directories_explored": total_dirs,
            "files_discovered": total_files_found,
            "files_analyzed": files_analyzed,
            "analysis_coverage_percentage": round((files_analyzed / max(total_files_found, 1)) * 100, 1)
        }

    def _generate_architecture_summary(self) -> Dict[str, Any]:
        """Generate LLM-driven architecture summary"""
        
        insights = self.knowledge_base["architectural_insights"]
        if not insights:
            return {"summary": "No architectural insights generated"}
        
        # Analyze insights to generate summary
        patterns = []
        components = []
        
        for insight in insights:
            if insight.get("type") == "architectural_analysis":
                arch_data = insight.get("insights", {})
                patterns.extend(arch_data.get("patterns", []))
                components.extend(arch_data.get("key_functions", []))
        
        return {
            "identified_patterns": list(set(patterns)),
            "key_components": list(set(components)),
            "total_insights": len(insights),
            "llm_understanding": self.knowledge_base.get("current_understanding", "")
        }

    def _generate_security_assessment(self) -> Dict[str, Any]:
        """Generate security assessment from LLM findings"""
        
        injection_points = self.knowledge_base["injection_points"]
        if not injection_points:
            return {"overall_risk": "unknown", "assessment": "No injection points identified"}
        
        # Categorize by risk level
        high_risk = len([p for p in injection_points if p.get("risk_level") == "high"])
        medium_risk = len([p for p in injection_points if p.get("risk_level") == "medium"])
        low_risk = len([p for p in injection_points if p.get("risk_level") == "low"])
        
        # Determine overall risk
        if high_risk > 0:
            overall_risk = "high"
        elif medium_risk > 2:
            overall_risk = "medium"
        elif medium_risk > 0 or low_risk > 3:
            overall_risk = "low"
        else:
            overall_risk = "minimal"
        
        return {
            "overall_risk": overall_risk,
            "risk_distribution": {"high": high_risk, "medium": medium_risk, "low": low_risk},
            "total_injection_points": len(injection_points),
            "assessment": f"Identified {len(injection_points)} potential injection points with {overall_risk} overall risk"
        }

    def _assess_exploration_effectiveness(self) -> str:
        """Assess overall exploration effectiveness"""
        
        structure_coverage = len(self.knowledge_base["discovered_structure"])
        file_analysis = len(self.knowledge_base["analyzed_files"])
        insights_generated = len(self.knowledge_base["architectural_insights"])
        
        score = structure_coverage * 2 + file_analysis * 3 + insights_generated * 5
        
        if score >= 30:
            return "excellent"
        elif score >= 20:
            return "good"
        elif score >= 10:
            return "moderate"
        else:
            return "limited"

    def _assess_insight_generation(self) -> str:
        """Assess LLM's insight generation capability"""
        
        insights = len(self.knowledge_base["architectural_insights"])
        injection_points = len(self.knowledge_base["injection_points"])
        files_analyzed = len(self.knowledge_base["analyzed_files"])
        
        if files_analyzed == 0:
            return "none"
        
        insight_ratio = (insights + injection_points) / files_analyzed
        
        if insight_ratio >= 0.8:
            return "excellent"
        elif insight_ratio >= 0.5:
            return "good"
        elif insight_ratio >= 0.3:
            return "moderate"
        else:
            return "limited"

    def _assess_overall_quality(self) -> str:
        """Assess overall analysis quality"""
        
        exploration = self._assess_exploration_effectiveness()
        insights = self._assess_insight_generation()
        
        quality_map = {"excellent": 4, "good": 3, "moderate": 2, "limited": 1, "none": 0}
        
        avg_score = (quality_map.get(exploration, 0) + quality_map.get(insights, 0)) / 2
        
        if avg_score >= 3.5:
            return "excellent"
        elif avg_score >= 2.5:
            return "good"
        elif avg_score >= 1.5:
            return "moderate"
        else:
            return "limited"