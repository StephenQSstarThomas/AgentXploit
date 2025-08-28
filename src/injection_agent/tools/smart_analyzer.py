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
Streamlined main analyzer - combines all components into efficient analysis system
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import asdict

# CoreTools import removed - using EnhancedFileReader directly
from .core.analysis_context import AnalysisContext
from .core.task import Task, TaskType
from .core.task_queue import TaskQueue
# Use late imports to avoid circular dependencies
from .core.execution_logger import ExecutionLogger
# Import security_analyzer after LLMClient definition to avoid circular import


class LLMClient:
    """Centralized LLM client with robust error handling and retry logic"""

    @staticmethod
    def call_llm(model: str, messages: List[Dict], max_tokens: int = 1000,
                 temperature: float = 0.1, timeout: int = 30, max_retries: int = 3) -> Optional[str]:
        """
        Centralized LLM call with error handling and retry logic

        Args:
            model: LLM model name
            messages: Chat messages
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries

        Returns:
            LLM response text or None if all retries failed
        """
        import time
        from litellm import completion

        for attempt in range(max_retries):
            try:
                response = completion(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=timeout,
                    max_retries=1  # LiteLLM internal retry
                )

                content = response.choices[0].message.content
                if content and len(content.strip()) > 0:
                    return content.strip()

            except KeyboardInterrupt:
                print(f"  LLM call interrupted (attempt {attempt + 1}/{max_retries})")
                if attempt == max_retries - 1:
                    return None
                continue

            except Exception as e:
                error_msg = str(e)
                print(f"  LLM call failed (attempt {attempt + 1}/{max_retries}): {error_msg}")

                if attempt == max_retries - 1:
                    return None
                else:
                    time.sleep(1)  # Wait before retry
                    continue

        return None

    @staticmethod
    def get_model() -> str:
        """Get configured LLM model"""
        try:
            from ..config import settings
            return settings.DEFAULT_MODEL
        except:
            return "gpt-4o"


def serialize_for_json(obj):
    """Convert dataclass objects and other non-serializable objects to dict"""
    if hasattr(obj, '__dataclass_fields__'):  # Check if it's a dataclass
        return asdict(obj)
    elif isinstance(obj, list):
        return [serialize_for_json(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: serialize_for_json(value) for key, value in obj.items()}
    else:
        return obj


class Analyzer:
    """Main analysis coordinator - streamlined and efficient"""
    
    def __init__(self, repo_path: str):
        """Initialize analyzer with streamlined setup"""
        self.repo_path = Path(repo_path).resolve()

        # Initialize core components
        from .core.core_tools import EnhancedFileReader
        self.tools = EnhancedFileReader(repo_path)
        self.context = AnalysisContext()
        self.task_queue = TaskQueue()

        # Initialize context management (late import to avoid circular dependencies)
        from .planning.analysis_context_manager import AnalysisContextManager
        from .planning.context_tools import initialize_analysis_context
        self.context_manager = AnalysisContextManager(str(repo_path))
        initialize_analysis_context(str(repo_path))

        # Initialize supporting components
        self.execution_logger = ExecutionLogger()

        # Initialize security analyzer (late import to avoid circular dependency)
        from .analyzers.security_analyzer import SecurityAnalyzer
        self.security_analyzer = SecurityAnalyzer()

        # Initialize LLM helper for code analysis
        from .code_analysis.llm_decider import LLMHelper
        self.llm = LLMHelper()
        
    def analyze(self, max_steps: int = None, save_results: bool = True, focus: str = "security") -> Dict[str, Any]:
        """
        Autonomous agent-driven analysis using discoveries and context for intelligent decision making
        """

        # Get max_steps from settings if not provided
        if max_steps is None:
            try:
                from ..config import settings
                max_steps = getattr(settings, 'MAX_STEPS', 50)
            except ImportError:
                max_steps = 50

        # Initialize with minimal starting point - just explore the root
        from .core.task import Task, TaskType
        initial_explore = Task(type=TaskType.EXPLORE, target=".", priority=100)
        self.task_queue.add_task(initial_explore)
        
        step = 0
        findings = []
        detailed_findings = []
        security_findings = []

        print("Starting autonomous analysis...")
        print("Agent will use discoveries and context to determine next steps intelligently")
        
        while step < max_steps:
            # Get next task
            task = self.task_queue.get_next()

            # If no tasks in queue, perform autonomous context reassessment
            if not task:
                print(f"\n[STEP {step + 1}/{max_steps}] Autonomous Context Reassessment:")
                print("  Task queue empty - performing autonomous context reassessment...")

                self._autonomous_context_reassessment()

                # Check if new tasks were added
                if self.task_queue.size() == 0:
                    print("  No new tasks generated - analysis complete")
                    break

                # Get the newly added task
                task = self.task_queue.get_next()
                if not task:
                    print("  Still no tasks available - ending analysis")
                    break
                
                        # Enhanced logging of autonomous decisions
            print(f"\n[STEP {step + 1}/{max_steps}] Autonomous Analysis:")
            print(f"  Task: {task.type.value.upper()} → {task.target}")
                
            # Execute task directly
            result = self._execute_task(task)

            # Log execution result
            success = result.get("success", False)
            status = "Success" if success else "Failed"
            print(f"  Status: {status}")

            if result.get("result", {}).get("lines"):
                print(f"  Content: {result['result']['lines']} lines")

            if result.get("duration"):
                print(f"  Duration: {result['duration']:.3f}s")

            # Update task status in queue
            if success:
                self.task_queue.complete_task(task.task_id, result)
            else:
                error_msg = result.get("error", "Unknown error")
                self.task_queue.fail_task(task.task_id, error_msg)

            # Log execution
            self.execution_logger.log_execution(task, result, result.get("duration", 0))
            
            # Process results and make autonomous decisions
            if task.type == TaskType.EXPLORE and result.get("success", False):
                self.context.add_explored_directory(task.target)
                
                # Record discovery in context manager
                if "result" in result and "files" in result["result"]:
                    files = result["result"].get("files", [])
                    dirs = result["result"].get("directories", [])
                    self.context_manager.update_project_structure(task.target, {
                        "files": files,
                        "directories": dirs
                    })
                
                # AUTONOMOUS DECISION MAKING: Use discoveries to determine next actions
                self._make_autonomous_decisions_from_exploration(task.target, files, dirs)
                        
            elif task.type == TaskType.READ and result.get("success", False):
                self.context.add_analyzed_file(task.target)
                file_content = result.get("result", {}).get("content", "")
                
                if file_content:
                    # Perform security analysis
                    security_result = self.security_analyzer.analyze_file_security(task.target, file_content)
                    security_findings.append(security_result)
                    
                    # Store context about findings
                    if security_result["risk_assessment"]["overall_risk"] in ["HIGH", "MEDIUM"]:
                        self.context.set_data(f"security_concern_{task.target}", True)
                    
                    # Record analysis in context manager
                    analysis_data = {
                        "security_risk": security_result["risk_assessment"]["overall_risk"].lower(),
                        "key_findings": security_result.get("findings", []),
                        "lines_of_code": result.get("result", {}).get("lines", 0),
                    }
                    self.context_manager.add_analysis_result(task.target, analysis_data)
                    
                    # Store file analysis for reporting
                    detailed_findings.append({
                        "file": task.target,
                        "content_preview": file_content[:500] + "..." if len(file_content) > 500 else file_content,
                        "lines": result.get("result", {}).get("lines", 0),
                        "security_summary": security_result.get("summary", ""),
                    })
            
                    # AUTONOMOUS DECISION MAKING: Use file content to determine next actions
                    self._make_autonomous_decisions_from_content(task.target, file_content, security_result)
            
            step += 1
        
            # Dynamic context reassessment - let the agent decide when to reassess
            if step % 3 == 0:  # More frequent reassessment for better autonomy
                self._autonomous_context_reassessment()

        # Final autonomous summary
        print("\nAnalysis Complete - Autonomous Summary:")
        print(f"  Steps completed: {step}")
        print(f"  Directories explored: {len(self.context.get_explored_directories())}")
        print(f"  Files analyzed: {len(self.context.get_analyzed_files())}")
        print(f"  Security findings: {sum(len(sr.get('findings', [])) for sr in security_findings)}")
        
        # Get execution statistics
        execution_stats = self.execution_logger.get_summary()
        task_stats = self.task_queue.get_stats()
        
        # Aggregate and organize security findings
        all_security_findings = []
        high_risk_files = []
        medium_risk_files = []

        for sec_result in security_findings:
            findings = sec_result.get("findings", [])
            all_security_findings.extend(findings)
            risk_level = sec_result["risk_assessment"]["overall_risk"]
            if risk_level == "HIGH":
                high_risk_files.append(sec_result["file_path"])
            elif risk_level == "MEDIUM":
                medium_risk_files.append(sec_result["file_path"])

        # Sort findings by risk level
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}
        sorted_security_findings = sorted(security_findings,
            key=lambda x: risk_order.get(x["risk_assessment"]["overall_risk"], 3))

        # Separate findings by severity for summary
        high_risk_findings = [f for f in security_findings if f["risk_assessment"]["overall_risk"] == "HIGH"]
        medium_risk_findings = [f for f in security_findings if f["risk_assessment"]["overall_risk"] == "MEDIUM"]

        # Categorize files by risk level
        low_risk_files = []
        no_risk_files = []

        for finding in detailed_findings:
            risk_level = (finding.get("security_summary", "").split(": ")[-1].split(" ")[0]
                         if "security_summary" in finding else "UNKNOWN")
            file_name = finding["file"]

            if risk_level == "LOW":
                low_risk_files.append(file_name)
            elif risk_level in ["NO_RISK", "UNKNOWN"]:
                no_risk_files.append(file_name)

        # Compile final results with enhanced structure
        final_result = {
            "analysis_info": {
                "repository_path": str(self.repo_path),
                "analysis_timestamp": datetime.now().isoformat(),
                "analyzer_version": "4.0.0-autonomous",
                "focus": focus,
                "analysis_mode": "autonomous_agent_driven"
            },

            "execution_summary": {
                "steps_completed": step,
                "max_steps": max_steps,
                "status": "completed" if step < max_steps else "max_steps_reached",
                "execution_stats": execution_stats,
                "task_stats": task_stats,
                "autonomous_decisions": self.context.get_data("autonomous_decisions", 0)
            },
            "discovered_structure": {
                "explored_directories": self.context.get_explored_directories(),
                "analyzed_files": self.context.get_analyzed_files(),
                "total_directories": len(self.context.get_explored_directories()),
                "total_files": len(self.context.get_analyzed_files()),
                "context_summary": self.context.get_summary()
            },
            "security_analysis": {
                "findings_by_severity": {
                    "high": len(high_risk_findings),
                    "medium": len(medium_risk_findings),
                    "low": len(low_risk_files),
                    "none": len(no_risk_files)
                },
                "high_risk_files": [f["file_path"] for f in high_risk_findings],
                "medium_risk_files": [f["file_path"] for f in medium_risk_findings],
                "low_risk_files": low_risk_files,
                "no_risk_files": no_risk_files,
                "individual_file_results": sorted_security_findings,
                "aggregate_findings": all_security_findings,
                "total_security_findings": len(all_security_findings)
            },
            "analysis_findings": detailed_findings,
            "architectural_insights": self._generate_architectural_insights(detailed_findings),
            "context_manager_state": self.context_manager.export_context()
        }
        
        # Save and return results
        if save_results:
            self._save_analysis_results(final_result)

        return final_result
    

    
    def _get_file_priority(self, file_path: str) -> int:
        """Determine analysis priority for files"""
        path_lower = file_path.lower()
        
        if path_lower.endswith('.py'):
            if 'main' in path_lower or 'agent' in path_lower or 'cli' in path_lower:
                return 90  # High priority for main files
            return 70  # Normal priority for Python files
        elif path_lower.endswith(('.json', '.toml', '.yaml', '.yml')):
            return 60  # Config files
        elif path_lower.endswith('.md'):
            return 30  # Documentation
        elif path_lower.endswith(('.txt', '.log')):
            return 20  # Low priority
        return 0  # Skip other files
    
    def _generate_architectural_insights(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate architectural insights from analysis"""
        insights = {
            "file_types_analyzed": {},
            "key_components": [],
            "potential_entry_points": []
        }
        
        for finding in findings:
            file_ext = Path(finding["file"]).suffix
            insights["file_types_analyzed"][file_ext] = insights["file_types_analyzed"].get(file_ext, 0) + 1
            
            # Identify key components
            if "main" in finding["file"].lower() or "agent" in finding["file"].lower():
                insights["key_components"].append(finding["file"])
            
            # Look for entry points in analysis
            if "entry" in finding.get("analysis", "").lower() or "main" in finding.get("analysis", "").lower():
                insights["potential_entry_points"].append(finding["file"])
        
        return insights
    
    def _save_analysis_results(self, results: Dict[str, Any]) -> None:
        """Save analysis results to the configured analysis directory"""
        print("Attempting to save analysis results...")

        try:
            from ..config import settings

            # Save to configured analysis directory
            repo_name = self.repo_path.name or "unknown_repo"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # Use the configured analysis directory from settings
            analysis_dir = Path(settings.ANALYSIS_DIR)
            print(f"Analysis directory: {analysis_dir.absolute()}")

            analysis_dir.mkdir(exist_ok=True, parents=True)

            filename = f"{repo_name}_static_analysis_{timestamp}.json"
            output_path = analysis_dir / filename

            print(f"Output path: {output_path.absolute()}")

            # Serialize dataclass objects before saving
            serialized_results = serialize_for_json(results)

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serialized_results, f, indent=2, ensure_ascii=False)

            print(f"Analysis results saved to: {output_path}")

        except Exception as e:
            print(f"Warning: Could not save to central directory: {e}")
            print(f"   Error type: {type(e).__name__}")
            import traceback
            print(f"   Traceback: {traceback.format_exc()}")

            # Fallback to current directory
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                repo_name = self.repo_path.name or "unknown_repo"
                fallback_path = Path(f"{repo_name}_analysis_results_{timestamp}.json")
                print(f"Trying fallback location: {fallback_path.absolute()}")

                serialized_results = serialize_for_json(results)
                with open(fallback_path, 'w', encoding='utf-8') as f:
                    json.dump(serialized_results, f, indent=2, ensure_ascii=False)
                print(f"Analysis results saved to fallback location: {fallback_path}")
            except Exception as e2:
                print(f"Failed to save analysis results: {e2}")
                print(f"   Error type: {type(e2).__name__}")
                import traceback
                print(f"   Traceback: {traceback.format_exc()}")

    def _run_targeted_security_analysis(self) -> List[Dict[str, Any]]:
        """Run additional targeted security analysis on high-priority files"""
        targeted_findings = []

        try:
            # Look for high-risk patterns in analyzed files
            for file_path in self.context.get_analyzed_files():
                if file_path.endswith(('.py', '.js', '.ts', '.java')):
                    file_result = self.tools.read_file(file_path)
                    if file_result.get("success") and "content" in file_result.get("result", {}):
                        content = file_result["result"]["content"]

                        # Check for injection vulnerabilities
                        injection_patterns = [
                            r"eval\s*\(", r"exec\s*\(", r"execfile\s*\(",
                            r"subprocess\.(call|Popen|run)", r"os\.system",
                            r"sqlalchemy\.text", r"cursor\.execute.*\+",
                            r"innerHTML.*\+", r"document\.write.*\+"
                        ]

                        for pattern in injection_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                targeted_findings.append({
                                    "file_path": file_path,
                                    "vulnerability_type": "Injection Vulnerability",
                                    "pattern": pattern,
                                    "line_number": content[:match.start()].count('\n') + 1,
                                    "severity": "HIGH",
                                    "description": f"Potential injection vulnerability found with pattern: {pattern}"
                                })

                        # Check for hardcoded secrets
                        secret_patterns = [
                            r"(?i)(api[_-]?key|secret[_-]?key|password|token)[\s]*[=:][\s]*['\"]([^'\"]{10,})['\"]",
                            r"(?i)(bearer|authorization)[\s]*[=:][\s]*['\"]([^'\"]{10,})['\"]",
                            r"(?i)(private[_-]?key|ssh[_-]?key)[\s]*[=:][\s]*['\"]([^'\"]{10,})['\"]"
                        ]

                        for pattern in secret_patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                targeted_findings.append({
                                    "file_path": file_path,
                                    "vulnerability_type": "Hardcoded Secret",
                                    "pattern": pattern,
                                    "line_number": content[:match.start()].count('\n') + 1,
                                    "severity": "CRITICAL",
                                    "description": "Potential hardcoded secret or sensitive information found"
                                })

        except Exception as e:
            print(f"Targeted security analysis failed: {e}")

        return targeted_findings

    def _make_autonomous_decisions_from_exploration(self, explored_path: str, files: List[str], dirs: List[str]) -> None:
        """LLM-driven autonomous decisions based on exploration discoveries with full context"""

        # Get comprehensive analysis history for LLM context
        history_context = self._build_history_context()

        # Build current exploration context
        exploration_context = self._build_exploration_context(explored_path, files, dirs)

        # LLM-driven decision making with full context
        # Get repository structure for better exploration decisions
        try:
            # Find unexplored areas for depth-first exploration
            all_dirs = []
            explored_dirs = list(self.context.get_explored_directories())

            # Get subdirectories of explored directories
            unexplored_areas = []
            for explored_dir in explored_dirs:
                try:
                    dir_path = self.repo_path / explored_dir
                    if dir_path.exists():
                        for subitem in dir_path.iterdir():
                            if subitem.is_dir() and not subitem.name.startswith('.') and not subitem.name.startswith('__'):
                                subdir_path = f"{explored_dir}/{subitem.name}"
                                if subdir_path not in explored_dirs:
                                    unexplored_areas.append(subdir_path)
                except:
                    continue

            # Also look for important top-level directories that haven't been explored
            root_unexplored = []
            for item in (self.repo_path / ".").iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    dir_name = item.name
                    if dir_name not in explored_dirs and dir_name not in ['node_modules', '__pycache__', '.git', 'build', 'dist']:
                        root_unexplored.append(dir_name)

        except Exception:
            unexplored_areas = []
            root_unexplored = []

        decision_prompt = f"""You are an intelligent security analysis agent making strategic exploration decisions.

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
- Use EXACT paths from the provided lists above"""

        # Debug: Check if history context is available
        if history_context and len(history_context.strip()) > 50:
            print(f"  [DEBUG] History context available ({len(history_context)} chars)")
        else:
            print(f"  [DEBUG] History context limited or empty")

        # Use centralized LLM client for robust decision making
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are a senior security analyst making strategic analysis decisions. Use the provided context to make intelligent choices."},
            {"role": "user", "content": decision_prompt}
        ]

        decision_text = LLMClient.call_llm(
            model=model,
            messages=messages,
            max_tokens=1000,
            temperature=0.4,
            timeout=30,
            max_retries=3
        )

        if decision_text:
            decisions = self._parse_llm_decision(decision_text)
            # Validate LLM decisions against available items
            validated_decisions = self._validate_llm_decisions(decisions, files, dirs)
            # Execute validated LLM decisions
            self._execute_llm_decisions(validated_decisions, explored_path)
        else:
            print("  Max retries reached, using fallback")
            # Fallback to simple exploration
            self._simple_fallback_exploration(explored_path, files, dirs)

    def _build_history_context(self) -> str:
        """Build comprehensive analysis history context for LLM to prevent duplicates and invalid paths"""
        try:
            overview = self.context_manager.get_project_overview()
            security_summary = self.context_manager.get_security_summary()
            analyzed_files = list(self.context.get_analyzed_files())
            explored_dirs = list(self.context.get_explored_directories())

            history = f"""
ANALYSIS HISTORY SUMMARY:
- Total analyzed files: {len(analyzed_files)}
- Total explored directories: {len(explored_dirs)}
- Security findings: {security_summary.get('total_findings', 0)}
  - High risk: {security_summary.get('high_risk_count', 0)}
  - Medium risk: {security_summary.get('medium_risk_count', 0)}
  - Low risk: {security_summary.get('low_risk_count', 0)}

EXPLORED DIRECTORIES (DO NOT RE-EXPLORE):
"""

            # List all explored directories to prevent duplicates
            for dir_path in sorted(explored_dirs):
                history += f"- {dir_path}\n"

            history += f"\nANALYZED FILES (DO NOT RE-ANALYZE):\n"

            # List all analyzed files to prevent duplicates
            for file_path in sorted(analyzed_files):
                file_info = self.context_manager.get_analysis_result(file_path)
                risk = file_info.get('security_risk', 'unknown') if file_info else 'unknown'
                history += f"- {file_path}: {risk} risk\n"

            # Add current working directory context
            history += f"\nCURRENT ANALYSIS STATE:\n"
            history += f"- Repository root: {self.repo_path}\n"

            # Add unanalyzed files in recently explored directories
            if explored_dirs:
                history += f"\nFILES AVAILABLE FOR ANALYSIS (in explored directories):\n"
                for explored_dir in explored_dirs[-3:]:  # Last 3 explored dirs
                    try:
                        dir_path = self.repo_path / explored_dir
                        if dir_path.exists():
                            for item in dir_path.iterdir():
                                if item.is_file() and str(item.relative_to(self.repo_path)) not in analyzed_files:
                                    history += f"- {item.relative_to(self.repo_path)}\n"
                    except:
                        continue

            # Add repository structure overview
            try:
                tree_result = self.tools.get_tree_structure(".", max_depth=2)
                if "tree_output" in tree_result and not tree_result.get("error"):
                    tree_lines = tree_result["tree_output"].split('\n')[:15]  # First 15 lines
                    history += f"\nREPOSITORY STRUCTURE OVERVIEW:\n" + "\n".join(tree_lines)
            except Exception:
                pass  # Tree command might not be available

            return history

        except Exception as e:
            return f"Analysis History: Limited context available (error: {e})"

    def _build_exploration_context(self, explored_path: str, files: List[str], dirs: List[str]) -> str:
        """Build current exploration context for LLM"""
        context = f"""
CURRENT EXPLORATION CONTEXT:
- Exploring: {explored_path}
- New files discovered: {len(files)}
- New directories discovered: {len(dirs)}

DISCOVERED FILES:
"""

        for file in files[:20]:  # Limit for context
            file_path = f"{explored_path.rstrip('/')}/{file}"
            context += f"- {file_path}\n"

        if len(files) > 20:
            context += f"- ... and {len(files) - 20} more files\n"

        context += "\nDISCOVERED DIRECTORIES:\n"
        for dir in dirs[:10]:  # Limit for context
            dir_path = f"{explored_path.rstrip('/')}/{dir}"
            context += f"- {dir_path}\n"

        if len(dirs) > 10:
            context += f"- ... and {len(dirs) - 10} more directories\n"

        return context



    def _parse_llm_decision(self, decision_text: str) -> Dict:
        """Parse LLM decision response"""
        try:
            import json
            # Extract JSON from response (LLM might add extra text)
            start = decision_text.find('{')
            end = decision_text.rfind('}') + 1
            if start != -1 and end > start:
                json_text = decision_text[start:end]
                return json.loads(json_text)
            else:
                raise ValueError("No JSON found in response")
        except Exception as e:
            print(f"Failed to parse LLM decision: {e}")
            return {"analysis_targets": [], "strategy_explanation": "parsing_failed"}

    def _validate_llm_decisions(self, decisions: Dict, available_files: List[str], available_dirs: List[str]) -> Dict:
        """Validate LLM decisions against available items to prevent guessing non-existent files"""
        if not decisions or "analysis_targets" not in decisions:
            return {"analysis_targets": [], "strategy_explanation": "no_valid_targets"}

        valid_targets = []
        original_count = len(decisions["analysis_targets"])

        for target in decisions["analysis_targets"]:
            target_path = target.get("path", "")
            target_type = target.get("type", "")

            # Extract filename/directory name from path
            path_parts = target_path.split('/')
            item_name = path_parts[-1] if path_parts else ""

            # Validate based on type
            if target_type == "file":
                # Check if file exists in available files list
                if item_name in available_files:
                    valid_targets.append(target)
                    print(f"  [VALID] File target accepted: {item_name}")
                else:
                    print(f"  [REJECT] File not in available list: {item_name} (available: {available_files[:5]}...)")
            elif target_type == "directory":
                # Check if directory exists in available directories list
                if item_name in available_dirs:
                    valid_targets.append(target)
                    print(f"  [VALID] Directory target accepted: {item_name}")
                else:
                    print(f"  [REJECT] Directory not in available list: {item_name} (available: {available_dirs[:5]}...)")
            else:
                print(f"  [REJECT] Invalid target type: {target_type}")

        validated_decisions = decisions.copy()
        validated_decisions["analysis_targets"] = valid_targets

        print(f"  [VALIDATION] {len(valid_targets)}/{original_count} targets validated")

        return validated_decisions

    def _validate_content_decisions(self, decisions: Dict, available_files: List[str], available_dirs: List[str], unexplored_subdirs: List[str]) -> Dict:
        """Validate content follow-up decisions against available items"""
        if not decisions or "follow_up_targets" not in decisions:
            return {"follow_up_targets": [], "exploration_strategy": "no_valid_targets"}

        valid_targets = []
        original_count = len(decisions["follow_up_targets"])

        for target in decisions["follow_up_targets"]:
            target_path = target.get("path", "")
            target_type = target.get("type", "")

            # Extract filename/directory name from path
            path_parts = target_path.split('/')
            item_name = path_parts[-1] if path_parts else ""

            # Validate based on type
            if target_type == "file":
                # Check if file exists in available files list or unexplored subdirs (for referenced files)
                if item_name in available_files or any(item_name in subdir for subdir in unexplored_subdirs):
                    valid_targets.append(target)
                    print(f"  [VALID] Content follow-up file accepted: {item_name}")
                else:
                    print(f"  [REJECT] Content follow-up file not found: {item_name}")
            elif target_type == "directory":
                # Check if directory exists in available directories or unexplored subdirs
                if item_name in available_dirs or item_name in unexplored_subdirs:
                    valid_targets.append(target)
                    print(f"  [VALID] Content follow-up directory accepted: {item_name}")
                else:
                    print(f"  [REJECT] Content follow-up directory not found: {item_name}")
            else:
                print(f"  [REJECT] Invalid follow-up target type: {target_type}")

        validated_decisions = decisions.copy()
        validated_decisions["follow_up_targets"] = valid_targets

        print(f"  [CONTENT VALIDATION] {len(valid_targets)}/{original_count} follow-up targets validated")

        return validated_decisions

    def _execute_llm_decisions(self, decisions: Dict, explored_path: str) -> None:
        """Execute decisions made by LLM"""
        from .core.task import Task, TaskType

        targets = decisions.get("analysis_targets", [])
        executed_count = 0

        print(f"  Executing LLM decisions: {decisions.get('strategy_explanation', 'No explanation')}")

        for target in targets:
            target_path = target.get("path", "")
            target_type = target.get("type", "")
            priority = target.get("priority", "medium")
            reason = target.get("reason", "")

            # Convert relative paths to absolute
            if not target_path.startswith('/'):
                target_path = f"{explored_path.rstrip('/')}/{target_path}"

            # Skip already analyzed items
            if target_type == "file" and self.context.is_file_analyzed(target_path):
                continue
            elif target_type == "directory" and self.context.is_directory_explored(target_path):
                continue

            # Validate and normalize target path before creating task
            # Handle malformed paths from LLM (e.g., "././openhands/./openhands/core")
            original_path = target_path
            if target_path.startswith('././'):
                target_path = target_path[4:]  # Remove "././" prefix
            elif target_path.startswith('./'):
                target_path = target_path[2:]  # Remove "./" prefix

            # Remove duplicate directory names (e.g., "openhands/openhands/core" -> "openhands/core")
            parts = target_path.split('/')
            if len(parts) > 2:
                # Check for consecutive duplicate directory names
                cleaned_parts = []
                for i, part in enumerate(parts):
                    if i > 0 and part == parts[i-1]:
                        continue  # Skip duplicate
                    cleaned_parts.append(part)
                if len(cleaned_parts) != len(parts):
                    target_path = '/'.join(cleaned_parts)
                    print(f"  [CLEAN] Normalized path: {original_path} -> {target_path}")

            if target_type == "file":
                full_path = self.repo_path / target_path
                if not full_path.exists() or not full_path.is_file():
                    print(f"  [SKIP] File not found: {target_path}")
                    continue

                # Check if file is readable (not binary and not too large)
                try:
                    file_size = full_path.stat().st_size
                    if file_size > 10 * 1024 * 1024:  # 10MB limit
                        print(f"  [SKIP] File too large: {target_path} ({file_size} bytes)")
                        continue

                    # Quick binary check
                    with open(full_path, 'rb') as f:
                        sample = f.read(1024)
                        if b'\x00' in sample[:100]:  # Likely binary
                            print(f"  [SKIP] Binary file: {target_path}")
                            continue
                except Exception as e:
                    print(f"  [SKIP] Cannot access file: {target_path} ({e})")
                    continue

                task = Task(type=TaskType.READ, target=target_path,
                           priority=90 if priority == "high" else 60 if priority == "medium" else 30)
                print(f"  [FILE] Analyzing: {target_path.split('/')[-1]} ({reason})")

            elif target_type == "directory":
                full_path = self.repo_path / target_path
                if not full_path.exists() or not full_path.is_dir():
                    print(f"  [SKIP] Directory not found: {target_path}")
                    continue

                task = Task(type=TaskType.EXPLORE, target=target_path,
                           priority=80 if priority == "high" else 50)
                print(f"  [DIR] Exploring: {target_path.split('/')[-1]} ({reason})")
            else:
                continue

            self.task_queue.add_task(task)
            executed_count += 1

            # Limit to prevent overload
            if executed_count >= 6:
                break

        print(f"  [SUCCESS] Added {executed_count} tasks based on LLM decisions")

    def _simple_fallback_exploration(self, explored_path: str, files: List[str], dirs: List[str]) -> None:
        """Simple fallback exploration when LLM fails"""
        from .core.task import Task, TaskType

        print("  Using simple fallback exploration strategy")

        # Add a few files to analyze
        added_count = 0
        for file in files:
            if added_count >= 3:
                break

            file_path = f"{explored_path.rstrip('/')}/{file}"
            if not self.context.is_file_analyzed(file_path) and not file.startswith('.'):
                task = Task(type=TaskType.READ, target=file_path, priority=50)
                self.task_queue.add_task(task)
                added_count += 1
                print(f"  [FALLBACK] Analyzing: {file}")

        # Add one directory to explore
        for dir_name in dirs:
            if not dir_name.startswith('.') and dir_name not in ['node_modules', '__pycache__', '.git']:
                dir_path = f"{explored_path.rstrip('/')}/{dir_name}"
                if not self.context.is_directory_explored(dir_path):
                    task = Task(type=TaskType.EXPLORE, target=dir_path, priority=50)
                    self.task_queue.add_task(task)
                    print(f"  [FALLBACK] Exploring: {dir_name}")
                    break

    def _make_autonomous_decisions_from_content(self, file_path: str, content: str, security_result: Dict) -> None:
        """LLM-driven autonomous decisions based on file content analysis with full context"""

        # Get analysis history for context
        history_context = self._build_history_context()

        # Build content analysis context
        content_context = self._build_content_context(file_path, content, security_result)

        # Get current repository structure for better decision making
        try:
            current_dir_files = []
            current_dir_dirs = []
            for item in (self.repo_path / ".").iterdir():
                if item.is_file():
                    current_dir_files.append(item.name)
                elif item.is_dir() and not item.name.startswith('.'):
                    current_dir_dirs.append(item.name)

            # Get recently explored directories for deeper exploration
            explored_dirs = list(self.context.get_explored_directories())
            unexplored_subdirs = []
            for explored_dir in explored_dirs:
                try:
                    dir_path = self.repo_path / explored_dir
                    if dir_path.exists():
                        for subitem in dir_path.iterdir():
                            if subitem.is_dir() and not subitem.name.startswith('.') and not subitem.name.startswith('__'):
                                subdir_path = f"{explored_dir}/{subitem.name}"
                                if subdir_path not in explored_dirs:
                                    unexplored_subdirs.append(subdir_path)
                except:
                    continue
        except Exception:
            current_dir_files = []
            current_dir_dirs = []
            unexplored_subdirs = []

        # LLM-driven decision making with repository awareness
        decision_prompt = f"""You are an intelligent security analysis agent. Make follow-up decisions based on file analysis and current repository structure.

{history_context}

{content_context}

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
}}
"""

        # Debug: Check if history context is available for content analysis
        content_history = self._build_history_context()
        if content_history and len(content_history.strip()) > 50:
            print(f"  [DEBUG] Content analysis history available ({len(content_history)} chars)")
        else:
            print(f"  [DEBUG] Content analysis history limited")

        # Use centralized LLM client for content analysis
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are a senior security analyst making strategic follow-up decisions. Use the provided context to make intelligent choices."},
            {"role": "user", "content": decision_prompt}
        ]

        decision_text = LLMClient.call_llm(
            model=model,
            messages=messages,
            max_tokens=800,
            temperature=0.4,
            timeout=25,
            max_retries=2
        )

        if decision_text:
            decisions = self._parse_llm_decision(decision_text)
            # Validate content follow-up decisions
            validated_decisions = self._validate_content_decisions(decisions, current_dir_files, current_dir_dirs, unexplored_subdirs)
            # Execute validated LLM decisions
            self._execute_content_follow_up(validated_decisions, file_path)
        else:
            print("  Max retries reached, using security-based fallback")
            # Simple fallback based on security risk
            if security_result["risk_assessment"]["overall_risk"] in ["HIGH", "CRITICAL"]:
                self._simple_security_followup(file_path, content)

    def _build_content_context(self, file_path: str, content: str, security_result: Dict) -> str:
        """Build content analysis context for LLM"""
        context = f"""CURRENT FILE ANALYSIS:
- File: {file_path}
- Risk Level: {security_result['risk_assessment']['overall_risk']}
- Security Score: {security_result['risk_assessment']['risk_score']}/100
- Findings: {len(security_result.get('findings', []))}

CONTENT PREVIEW (first 500 chars):
{content[:500]}{'...' if len(content) > 500 else ''}

SECURITY SUMMARY:
"""

        # Add security findings
        findings_list = security_result.get('findings', [])
        for finding in findings_list[:3]:  # Limit for context
            severity = getattr(finding, 'severity', 'unknown')
            description = getattr(finding, 'description', 'No description')
            context += f"- {severity.upper()}: {description}\n"

        return context

    def _execute_content_follow_up(self, decisions: Dict, current_file_path: str) -> None:
        """Execute follow-up decisions from content analysis"""
        from .core.task import Task, TaskType

        targets = decisions.get("follow_up_targets", [])
        executed_count = 0

        print(f"  Executing content follow-up: {decisions.get('investigation_strategy', 'No strategy')}")

        for target in targets:
            target_path = target.get("path", "")
            target_type = target.get("type", "")
            priority = target.get("priority", "medium")
            reason = target.get("reason", "")

            # Convert relative paths to absolute if needed
            if not target_path.startswith('/') and not target_path.startswith('./'):
                # Assume it's relative to current file's directory
                current_dir = str(Path(current_file_path).parent)
                target_path = f"{current_dir}/{target_path}"

            # Skip already analyzed items
            if target_type == "file" and self.context.is_file_analyzed(target_path):
                continue
            elif target_type == "directory" and self.context.is_directory_explored(target_path):
                continue

            # Validate and normalize target path before creating task
            # Handle malformed paths from LLM (e.g., "././openhands/./openhands/core")
            if target_path.startswith('././'):
                target_path = target_path[4:]  # Remove "././" prefix
            elif target_path.startswith('./'):
                target_path = target_path[2:]  # Remove "./" prefix

            # Remove duplicate directory names (e.g., "openhands/openhands/core" -> "openhands/core")
            parts = target_path.split('/')
            if len(parts) > 2:
                # Check for consecutive duplicate directory names
                cleaned_parts = []
                for i, part in enumerate(parts):
                    if i > 0 and part == parts[i-1]:
                        continue  # Skip duplicate
                    cleaned_parts.append(part)
                if len(cleaned_parts) != len(parts):
                    target_path = '/'.join(cleaned_parts)
                    print(f"  [CLEAN] Normalized path: {target_path}")

            if target_type == "file":
                full_path = self.repo_path / target_path
                if not full_path.exists() or not full_path.is_file():
                    print(f"  [SKIP] Follow-up file not found: {target_path}")
                    continue

                task = Task(type=TaskType.READ, target=target_path,
                           priority=85 if priority == "high" else 65 if priority == "medium" else 35)
                print(f"  [FOLLOW-UP] Analyzing: {target_path.split('/')[-1]} ({reason})")

            elif target_type == "directory":
                full_path = self.repo_path / target_path
                if not full_path.exists() or not full_path.is_dir():
                    print(f"  [SKIP] Follow-up directory not found: {target_path}")
                    continue

                task = Task(type=TaskType.EXPLORE, target=target_path,
                           priority=75 if priority == "high" else 55)
                print(f"  [FOLLOW-UP] Exploring: {target_path.split('/')[-1]} ({reason})")
            else:
                continue

            self.task_queue.add_task(task)
            executed_count += 1

            # Limit to prevent overload
            if executed_count >= 4:
                break

        print(f"  [SUCCESS] Added {executed_count} follow-up tasks")

    def _simple_security_followup(self, file_path: str, content: str) -> None:
        """Simple fallback for high-risk files"""
        from .core.task import Task, TaskType

        print("  Using simple security follow-up strategy")

        # Look for basic patterns in content
        if 'import ' in content or 'from ' in content:
            related_files = self._find_related_files_from_content(content)
            added_count = 0
            for related_file in related_files[:2]:
                full_path = self.repo_path / related_file.lstrip('/')
                if full_path.exists() and full_path.is_file() and not self.context.is_file_analyzed(str(full_path)):
                    task = Task(type=TaskType.READ, target=str(full_path), priority=80)
                    self.task_queue.add_task(task)
                    added_count += 1
                    print(f"  [SECURITY] Analyzing: {related_file.split('/')[-1]}")

            if added_count > 0:
                print(f"  [SUCCESS] Added {added_count} security-related files for analysis")

    def _autonomous_context_reassessment(self) -> None:
        """Periodically reassess overall context and make strategic decisions"""
        try:
            print("Autonomous Context Reassessment...")

            # Get current state
            overview = self.context_manager.get_project_overview()
            analyzed_files = self.context.get_analyzed_files()
            explored_dirs = list(self.context.get_explored_directories())

            # STRATEGIC DECISION 1: PRIORITY - Find unexplored directories at root level first
            if self.task_queue.size() < 10:
                # Get root directories
                try:
                    root_list = self.tools.list_directory(".")
                    if "result" in root_list:
                        root_dirs = root_list["result"].get("directories", [])
                        unexplored_root = []
                        for dir_name in root_dirs:
                            if (not dir_name.startswith('.') and
                                dir_name not in explored_dirs and
                                dir_name not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                                unexplored_root.append(dir_name)

                        if unexplored_root:
                            # Prioritize core directories
                            priority_dirs = ['src', 'app', 'core', 'main', 'lib', 'openhands', 'containers', 'frontend', 'docs']
                            for priority_dir in priority_dirs:
                                if priority_dir in unexplored_root:
                                    from .core.task import Task, TaskType
                                    explore_task = Task(type=TaskType.EXPLORE, target=priority_dir, priority=70)
                                    self.task_queue.add_task(explore_task)
                                    print(f"  [PRIORITY] Exploring core directory: {priority_dir}")
                                    return  # Exit after adding one priority task

                            # If no priority dirs, take the first unexplored
                            from .core.task import Task, TaskType
                            explore_task = Task(type=TaskType.EXPLORE, target=unexplored_root[0], priority=60)
                            self.task_queue.add_task(explore_task)
                            print(f"  [ROOT] Exploring directory: {unexplored_root[0]}")
                            return  # Exit after adding one task
                except Exception as e:
                    print(f"  Error listing root directory: {e}")

            # STRATEGIC DECISION 2: Find unexplored subdirectories in already explored directories
            if len(explored_dirs) >= 1 and self.task_queue.size() < 15:
                for parent_dir in explored_dirs[-3:]:  # Check last 3 explored dirs
                    try:
                        dir_result = self.tools.list_directory(parent_dir)
                        if "result" in dir_result:
                            subdirs = dir_result["result"].get("directories", [])
                            for subdir in subdirs:
                                if (not subdir.startswith('.') and
                                    subdir not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                                    subdir_path = f"{parent_dir.rstrip('/')}/{subdir}"
                                    if not self.context.is_directory_explored(subdir_path):
                                        from .core.task import Task, TaskType
                                        explore_task = Task(type=TaskType.EXPLORE, target=subdir_path, priority=50)
                                        self.task_queue.add_task(explore_task)
                                        print(f"  [SUBDIR] Exploring subdirectory: {subdir_path}")
                                        return  # Exit after adding one task
                    except Exception as e:
                        print(f"  Error exploring {parent_dir}: {e}")
                        continue

            # STRATEGIC DECISION 3: Focus on high-risk areas if any found
            security_summary = self.context_manager.get_security_summary()
            if security_summary.get('high_risk_count', 0) > 0:
                print(f"  [RISK] Focusing on {security_summary['high_risk_count']} high-risk areas")
                # High-risk focus is already handled in exploration decisions

            # STRATEGIC DECISION 4: Check analysis coverage
            total_files = overview.get('total_files', 0)
            coverage = len(analyzed_files) / max(total_files, 1)
            print(f"  Analysis coverage: {coverage:.1%} ({len(analyzed_files)}/{total_files} files)")

            # Only add exploration if we have very low coverage and no tasks
            if coverage < 0.2 and self.task_queue.size() == 0:
                print("  Very low coverage - will explore more in next cycle")
                # Don't add tasks here, let normal flow handle it

        except Exception as e:
            print(f"Context reassessment failed: {e}")


    def _find_related_files_from_content(self, content: str) -> List[str]:
        """Find files that are imported or referenced in the content"""
        related_files = []

        # Python import patterns
        if 'import ' in content or 'from ' in content:
            import_matches = re.findall(r'(?:import|from)\s+([a-zA-Z0-9_.]+)', content)
            for match in import_matches:
                # Convert module name to potential file path
                file_candidate = match.replace('.', '/') + '.py'
                if '/' in file_candidate:
                    related_files.append(file_candidate)

        # JavaScript/TypeScript import patterns
        js_import_patterns = [
            r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
        ]

        for pattern in js_import_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.endswith(('.js', '.ts', '.json')):
                    related_files.append(match)

        return related_files[:5]  # Limit results

    def _find_referenced_files_from_config(self, content: str) -> List[str]:
        """Find files referenced in configuration files"""
        referenced_files = []

        try:
            # Try to parse as JSON first
            if content.strip().startswith('{'):
                config_data = json.loads(content)
                self._extract_file_paths_from_dict(config_data, referenced_files)
            else:
                # For non-JSON files, use more restrictive pattern matching
                # Only match strings that look like actual file paths
                file_matches = re.findall(r'[\'"]([^\'"]*\.[a-zA-Z]{2,4})[\'"]', content)
                valid_files = []
                for match in file_matches:
                    # Skip version numbers (must contain at least one letter)
                    if not re.search(r'[a-zA-Z]', match):
                        continue
                    # Skip if too short (less than 3 characters before extension)
                    name_part = match.rsplit('.', 1)[0] if '.' in match else match
                    if len(name_part) < 3:
                        continue
                    # Must contain path indicators or be a reasonable filename
                    if ('/' in match or '\\' in match or
                        match.startswith('./') or match.startswith('../') or
                        len(match) >= 5):  # Reasonable minimum length for a filename
                        valid_files.append(match)

                referenced_files.extend(valid_files[:5])
        except:
            # Fallback with even more restrictive pattern
            file_matches = re.findall(r'[\'"]([a-zA-Z0-9_\-]+\.[a-zA-Z]{2,4})[\'"]', content)
            valid_files = []
            for match in file_matches:
                # Additional validation
                if len(match) >= 5 and not match.replace('.', '').replace('_', '').replace('-', '').isdigit():
                    valid_files.append(match)

            referenced_files.extend(valid_files[:5])

        return referenced_files[:3]

    def _extract_file_paths_from_dict(self, data: Dict, file_list: List[str]) -> None:
        """Recursively extract file paths from nested dictionary"""
        for key, value in data.items():
            if isinstance(value, str) and '.' in value:
                extension = value.split('.')[-1]
                # Only consider it a file path if extension is reasonable and value looks like a filename
                if (len(extension) >= 2 and len(extension) <= 4 and extension.isalnum() and
                    len(value) >= 4 and not value.replace('.', '').replace('/', '').replace('\\', '').isdigit()):
                    # Additional validation: must contain letters or be a reasonable file path
                    if (re.search(r'[a-zA-Z]', value) or '/' in value or '\\' in value or
                        value.startswith('./') or value.startswith('../')):
                        file_list.append(value)
            elif isinstance(value, dict):
                self._extract_file_paths_from_dict(value, file_list)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_file_paths_from_dict(item, file_list)

    def _investigate_related_files(self, file_path: str, content: str) -> None:
        """Investigate files related to a high-risk file"""
        from .core.task import Task, TaskType

        # Look for configuration files in the same directory
        directory = '/'.join(file_path.split('/')[:-1])
        if directory:
            try:
                dir_result = self.tools.list_directory(directory)
                if dir_result.get("success"):
                    files = dir_result["result"].get("files", [])
                    config_files = [f for f in files if f.endswith(('.json', '.toml', '.yaml', '.yml', '.py'))]
                    for config_file in config_files[:2]:
                        config_path = f"{directory}/{config_file}"
                        if not self.context.is_file_analyzed(config_path):
                            read_task = Task(type=TaskType.READ, target=config_path, priority=85)
                            self.task_queue.add_task(read_task)
                            print(f"  Investigating related config: {config_file}")
            except Exception as e:
                print(f"Related file investigation failed: {e}")
    
    def _execute_task(self, task) -> Dict[str, Any]:
        """Execute a single task and return standardized result format"""
        import time
        start_time = time.time()

        result_template = {
            "success": False,
            "task_id": task.task_id,
            "task_type": task.type.value,
            "target": task.target,
            "duration": 0.0,
            "result": None,
            "error": None
        }

        try:
            if task.type == TaskType.EXPLORE:
                print(f"    Executing EXPLORE on: {task.target}")
                print(f"    Repo path: {self.repo_path}")
                print(f"    Target path exists: {(self.repo_path / task.target).exists()}")
                print(f"    Target path is dir: {(self.repo_path / task.target).is_dir()}")
                result_data = self.tools.list_directory(task.target)
                print(f"    List directory result: {result_data}")
            elif task.type == TaskType.READ:
                result_data = self.tools.read_file(task.target)
            elif task.type == TaskType.ANALYZE:
                file_result = self.tools.read_file(task.target)
                if "error" not in file_result:
                    try:
                        # Use LLM for code snippet analysis
                        llm_analysis = self.llm.analyze_code_snippet(
                            file_result["content"],
                            task.target
                        )
                        result_data = {
                            "file_info": file_result,
                            "llm_analysis": llm_analysis
                        }
                    except Exception as e:
                        # Fallback to file content if LLM analysis fails
                        result_data = {
                            "file_info": file_result,
                            "llm_error": str(e)
                        }
                else:
                    result_data = file_result
            else:
                raise ValueError(f"Unknown task type: {task.type}")

            duration = time.time() - start_time
            result_template.update({
                "success": "error" not in result_data,
                "duration": duration,
                "result": result_data
            })

            if "error" in result_data:
                result_template["error"] = result_data["error"]

        except Exception as e:
            duration = time.time() - start_time
            result_template.update({
                "success": False,
                "duration": duration,
                "error": str(e)
            })

        return result_template
