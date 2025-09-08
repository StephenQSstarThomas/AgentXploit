import json
import os
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import asdict

from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import FunctionTool

from ..config import settings

# Core analysis components
from ..tools.core.analysis_context import AnalysisContext
from ..tools.core.task import Task, TaskType
from ..tools.core.task_queue import TaskQueue
from ..tools.core.execution_logger import ExecutionLogger
from ..tools.prompt_manager import PromptManager

# Planning and context tools
from ..tools.planning.analysis_context_manager import AnalysisContextManager
from ..tools.planning.context_tools import initialize_analysis_context
from ..tools.planning.decision_engine import DecisionEngine
from .exploration_strategies import ExplorationStrategies
from .focus_tracker import FocusTracker, AnalysisFocus
from .fallback_strategies import FallbackAnalysisStrategies


# Import LLM client from core module
from ..tools.core.llm_client import LLMClient
from ..tools.core.history_compactor import HistoryCompactor


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


class AnalysisAgent:
    """Main analysis coordinator - streamlined and efficient"""
    
    def __init__(self, repo_path: str):
        """Initialize analyzer with streamlined setup"""
        self.repo_path = Path(repo_path).resolve()

        # Initialize core components
        from ..tools.core.core_tools import EnhancedFileReader
        self.tools = EnhancedFileReader(repo_path)
        self.context = AnalysisContext(str(self.repo_path))  # Pass repo path for normalization
        self.task_queue = TaskQueue(str(self.repo_path))  # Pass repo path for target normalization

        # Initialize context management (late import to avoid circular dependencies)
        from ..tools.planning.analysis_context_manager import AnalysisContextManager
        from ..tools.planning.context_tools import initialize_analysis_context
        self.context_manager = AnalysisContextManager(str(repo_path))
        initialize_analysis_context(str(repo_path))

        # Initialize supporting components
        self.execution_logger = ExecutionLogger()
        self.history_compactor = HistoryCompactor(max_context_length=4000)
        self.decision_engine = DecisionEngine(str(repo_path))
        
        # Initialize exploration strategies (after context_manager is ready)
        self.exploration_strategies = None  # Will be initialized after context_manager
        
        # Initialize focus tracker for deep investigation
        self.focus_tracker = FocusTracker()
        
        # Initialize fallback strategies for comprehensive analysis
        self.fallback_strategies = FallbackAnalysisStrategies(
            self.context_manager, self.task_queue, self.context, self.tools
        )

        # Initialize security analyzer (late import to avoid circular dependency)
        from ..tools.analyzers.security_analyzer import SecurityAnalyzer
        self.security_analyzer = SecurityAnalyzer()

        # Initialize LLM helper for code analysis
        from ..tools.code_analysis.llm_decider import LLMHelper
        self.llm = LLMHelper()
        
    def analyze(self, max_steps: Optional[int] = None, save_results: bool = True, focus: str = "security") -> Dict[str, Any]:
        """
        Autonomous agent-driven analysis using discoveries and context for intelligent decision making
        """
        # Initialize analysis parameters and components
        max_steps = self._initialize_analysis_parameters(max_steps)
        self._initialize_analysis_components()
        
        # Initialize analysis state
        analysis_state = self._initialize_analysis_state()
        
        print("Starting autonomous analysis...")
        print("Agent will use discoveries and context to determine next steps intelligently")
        
        # Main analysis loop
        return self._run_analysis_loop(analysis_state, max_steps, save_results, focus)

    def _initialize_analysis_parameters(self, max_steps: Optional[int] = None) -> int:
        """Initialize analysis parameters from settings"""
        if max_steps is None:
            try:
                from ..config import settings
                max_steps = getattr(settings, 'MAX_STEPS', 50)
            except ImportError:
                max_steps = 100
        return max_steps

    def _initialize_analysis_components(self) -> None:
        """Initialize exploration and fallback strategies"""
        if self.exploration_strategies is None:
            self.exploration_strategies = ExplorationStrategies(
                self.tools, self.context, self.context_manager, self.task_queue
            )
            
        self.fallback_strategies = FallbackAnalysisStrategies(
            self.context_manager, self.task_queue, self.context, self.tools
        )

    def _initialize_analysis_state(self) -> Dict:
        """Initialize analysis state variables"""
        # Initialize with minimal starting point - just explore the root
        initial_explore = Task(type=TaskType.EXPLORE, target=".", priority=100)
        self.task_queue.add_task(initial_explore)
        
        return {
            'step': 0,
            'findings': [],
            'detailed_findings': [],
            'security_findings': [],
            'last_reassessment_step': 0
        }

    def _run_analysis_loop(self, analysis_state: Dict, max_steps: int, save_results: bool, focus: str) -> Dict[str, Any]:
        """Main analysis loop with CORE INNOVATION: LLM-driven autonomous decision making and reassessment"""
        consecutive_empty_queue_count = 0  # Track consecutive empty queue attempts
        
        while analysis_state['step'] < max_steps:
            # CORE INNOVATION: LLM-driven intelligent reassessment decision
            should_reassess, reassess_reason = self._llm_should_reassess_decision(
                analysis_state['step'], analysis_state['last_reassessment_step']
            )
            
            # Perform intelligent reassessment if LLM recommends it
            if should_reassess:
                print(f"\n[STEP {analysis_state['step'] + 1}/{max_steps}] LLM Queue Reassessment")
                self._intelligent_queue_reassessment()
                analysis_state['last_reassessment_step'] = analysis_state['step']
            
            # 1. Try to get a task from queue (focus-driven first)
            task = self._get_focus_driven_task() or self.task_queue.get_next()
            
            # 2. If no task available, perform comprehensive task generation
            if not task:
                print(f"\n[STEP {analysis_state['step'] + 1}/{max_steps}] No tasks - performing comprehensive reassessment...")
                
                # First try autonomous context reassessment (core innovation)
                self._autonomous_context_reassessment()
                task = self.task_queue.get_next()
                
                # If still no task, use LLM to generate new targets
                if not task:
                    new_tasks_added = self._llm_generate_new_tasks()
                    if new_tasks_added > 0:
                        print(f"  Generated {new_tasks_added} new tasks")
                        consecutive_empty_queue_count = 0  # Reset counter
                        task = self.task_queue.get_next()
                    else:
                        consecutive_empty_queue_count += 1
                        print(f"  No new tasks generated (attempt {consecutive_empty_queue_count})")
                
                # Only terminate if we've tried multiple times and have done minimum work
                if not task and consecutive_empty_queue_count >= 3 and analysis_state['step'] >= 10:
                    print(f"  Analysis complete - no more discoverable targets after {analysis_state['step']} steps")
                    break
                elif not task:
                    # Skip this step but continue trying
                    analysis_state['step'] += 1
                    continue
            
            # 3. Execute the task
            print(f"\n[STEP {analysis_state['step'] + 1}/{max_steps}] Executing Task:")
            print(f"  Task: {task.type.value.upper()} → {task.target}")
                
            result = self._execute_task(task)

            # 4. Process results and update state
            success = result.get("success", False)
            print(f"  Status: {'Success' if success else 'Failed'}")
            
            if success and result.get("result", {}).get("lines_read"):
                print(f"  Content: {result['result']['lines_read']} lines")

            # Update task status and context
            if success:
                self.task_queue.complete_task(task.task_id, result)
                self._process_successful_task(task, result, analysis_state, focus)
            else:
                error_msg = result.get("error", "Unknown error")
                self.task_queue.fail_task(task.task_id, error_msg)
                print(f"  Error: {error_msg}")

            # Log execution for tracing
            self.execution_logger.log_execution(task, result, analysis_state['step'] + 1)
            analysis_state['step'] += 1

        # Final autonomous summary
        print("\nAnalysis Complete - Autonomous Summary:")
        print(f"  Steps completed: {analysis_state['step']}")
        print(f"  Directories explored: {len(self.context.get_explored_directories())}")
        print(f"  Files analyzed: {len(self.context.get_analyzed_files())}")
        print(f"  Security findings: {sum(len(sr.get('findings', [])) for sr in analysis_state['security_findings'])})")
        
        # Get execution statistics and trace logs
        execution_stats = self.execution_logger.get_summary()
        trace_logs = self.execution_logger.get_trace_logs()
        task_stats = self.task_queue.get_stats()
        
        # Create a unique set of security findings (no duplicates) - simplified using dict comprehension
        unique_security_findings = {
            result["file_path"]: result for result in analysis_state['security_findings']
        }

        # Calculate risk statistics from unique findings
        risk_stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        high_risk_files = []
        medium_risk_files = []

        for sec_result in unique_security_findings.values():
            risk_level = sec_result["risk_assessment"]["overall_risk"]
            risk_stats[risk_level] = risk_stats.get(risk_level, 0) + 1

            if risk_level == "HIGH":
                high_risk_files.append(sec_result["file_path"])
            elif risk_level == "MEDIUM":
                medium_risk_files.append(sec_result["file_path"])

        # Compile final results with simplified structure (no duplicates)
        final_result = {
            "analysis_info": {
                "repository_path": str(self.repo_path),
                "analysis_timestamp": datetime.now().isoformat(),
                "analyzer_version": "4.0.0-autonomous",
                "focus": focus,
                "analysis_mode": "autonomous_agent_driven"
            },

            "execution_summary": {
                "steps_completed": analysis_state['step'],
                "max_steps": max_steps,
                "status": "completed" if analysis_state['step'] < max_steps else "max_steps_reached",
                "execution_stats": execution_stats,
                "task_stats": task_stats,
                "trace_logs": trace_logs,
                "llm_decisions_made": len([log for log in trace_logs if log.get("extra_actions")])
            },

            "discovered_structure": {
                "explored_directories": list(self.context.get_explored_directories()),
                "analyzed_files": list(self.context.get_analyzed_files()),
                "total_directories": len(self.context.get_explored_directories()),
                "total_files": len(self.context.get_analyzed_files())
            },

            "security_analysis": {
                "summary": {
                    "total_files_analyzed": len(unique_security_findings),
                    "risk_distribution": risk_stats,
                    "high_risk_files": high_risk_files,
                    "medium_risk_files": medium_risk_files,
                    "total_findings": sum(len(result.get("findings", [])) for result in unique_security_findings.values())
                },
                "detailed_results": list(unique_security_findings.values())
            }
        }
        
        # Save and return results
        if save_results:
            self._save_analysis_results(final_result)

        return final_result

    def _llm_generate_new_tasks(self) -> int:
        """Simplified LLM-driven task generation when queue is empty"""
        try:
            # Build current analysis context
            analyzed_files = list(self.context.get_analyzed_files())
            explored_dirs = list(self.context.get_explored_directories())
            
            # Get current repository state
            all_files = []
            all_dirs = []
            
            # Collect all discovered but unanalyzed files and unexplored directories
            try:
                for explored_dir in explored_dirs + ["."]:
                    dir_result = self.tools.list_directory(explored_dir)
                    if "error" not in dir_result:
                        dir_files = dir_result.get("files", [])
                        dir_subdirs = dir_result.get("directories", [])
                        
                        for file in dir_files:
                            file_path = f"{explored_dir}/{file}" if explored_dir != "." else file
                            if file_path not in analyzed_files and not file.startswith('.'):
                                all_files.append(file_path)
                        
                        for subdir in dir_subdirs:
                            subdir_path = f"{explored_dir}/{subdir}" if explored_dir != "." else subdir
                            if (subdir_path not in explored_dirs and 
                                not subdir.startswith('.') and 
                                subdir not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                                all_dirs.append(subdir_path)
            except Exception as e:
                print(f"  Error collecting repository state: {e}")
                return 0
            
            # If we have discoverable targets, ask LLM to prioritize them
            if all_files or all_dirs:
                return self._llm_prioritize_targets(all_files[:20], all_dirs[:10])
            else:
                print("  No more discoverable targets in repository")
                return 0
                
        except Exception as e:
            print(f"  Error in LLM task generation: {e}")
            return 0

    def _llm_prioritize_targets(self, available_files: list, available_dirs: list) -> int:
        """Use LLM to prioritize and select targets from available options"""
        try:
            from ..tools.core.llm_client import LLMClient
            
            # Build context for LLM
            analyzed_files = list(self.context.get_analyzed_files())
            security_summary = self.context_manager.get_security_summary()
            
            context = f"""
ANALYSIS PROGRESS:
- Files analyzed: {len(analyzed_files)}
- Security findings: {security_summary.get('total_findings', 0)} 
- High risk files: {security_summary.get('high_risk_count', 0)}

RECENTLY ANALYZED FILES:
{chr(10).join([f"- {f}" for f in analyzed_files[-10:]])}

AVAILABLE TARGETS:
Files to analyze: {available_files[:15]}
Directories to explore: {available_dirs[:10]}
"""

            prompt = f"""You are continuing a security analysis. Select the MOST VALUABLE targets to analyze next.

{context}

SELECTION CRITERIA:
1. Prioritize files that could contain security vulnerabilities
2. Focus on core application logic, configuration, and entry points  
3. Explore directories likely to contain important components
4. Avoid redundant analysis of similar file types

Select up to 5 targets (mix of files and directories) that would provide the most security insight.

Respond in JSON format:
{{
    "selected_targets": [
        {{"type": "file", "path": "exact_path_from_available_list", "priority": 90, "reason": "why important"}},
        {{"type": "directory", "path": "exact_path_from_available_list", "priority": 80, "reason": "why important"}}
    ],
    "strategy": "brief explanation of selection strategy"
}}"""

            model = LLMClient.get_model()
            messages = [
                {"role": "system", "content": "You are a security analyst selecting the most valuable analysis targets."},
                {"role": "user", "content": prompt}
            ]
            
            decision_text = LLMClient.call_llm(
                model=model, messages=messages, max_tokens=800,
                temperature=0.2, timeout=30, max_retries=2
            )
            
            if decision_text:
                # Parse LLM response
                import json
                start_idx = decision_text.find('{')
                end_idx = decision_text.rfind('}') + 1
                if start_idx != -1 and end_idx > start_idx:
                    json_str = decision_text[start_idx:end_idx]
                    decisions = json.loads(json_str)
                    
                    # Add selected targets to task queue
                    from ..tools.core.task import Task, TaskType
                    tasks_added = 0
                    
                    for target_info in decisions.get("selected_targets", []):
                        target_path = target_info.get("path", "")
                        target_type = target_info.get("type", "file")
                        priority = target_info.get("priority", 75)
                        reason = target_info.get("reason", "LLM selection")
                        
                        # Validate target exists in available lists
                        if target_type == "file" and target_path in available_files:
                            task = Task(TaskType.READ, target_path, priority=priority)
                            self.task_queue.add_task(task)
                            tasks_added += 1
                            print(f"    [+] READ {target_path} (priority: {priority}) - {reason}")
                        elif target_type == "directory" and target_path in available_dirs:
                            task = Task(TaskType.EXPLORE, target_path, priority=priority)
                            self.task_queue.add_task(task)
                            tasks_added += 1
                            print(f"    [+] EXPLORE {target_path} (priority: {priority}) - {reason}")
                    
                    if tasks_added > 0:
                        strategy = decisions.get("strategy", "LLM-driven selection")
                        print(f"  Strategy: {strategy}")
                    
                    return tasks_added
            
            return 0
            
        except Exception as e:
            print(f"  Error in LLM prioritization: {e}")
            return 0

    def _process_successful_task(self, task, result, analysis_state, focus):
        """Process successful task execution and generate follow-up tasks"""
        from ..tools.core.task import TaskType
        
        if task.type == TaskType.EXPLORE:
            # Update context and generate follow-up tasks for exploration
            self.context.add_explored_directory(task.target)
            
            result_data = result.get("result", {})
            files = result_data.get("files", [])
            dirs = result_data.get("directories", [])
            
            # Record discovery in context manager
            self.context_manager.update_project_structure(task.target, {
                "files": files, "directories": dirs
            })
            
            # Use decision engine to generate follow-up tasks
            if files or dirs:
                self.decision_engine.make_autonomous_decision(
                    "exploration", self.context_manager, self.task_queue, 
                    self.context.get_analyzed_files(), self.context.get_explored_directories(),
                    explored_path=task.target, files=files, dirs=dirs, focus=focus
                )
                        
        elif task.type == TaskType.READ:
            # Update context and analyze file content
            self.context.add_analyzed_file(task.target)
            file_content = result.get("result", {}).get("content", "")
            
            if file_content:
                # Perform security analysis
                security_result = self.security_analyzer.analyze_file_security(task.target, file_content)
                analysis_state['security_findings'].append(security_result)
                
                # Record analysis results
                risk_level = security_result["risk_assessment"]["overall_risk"]
                if risk_level in ["HIGH", "MEDIUM"]:
                    self.context.set_data(f"security_concern_{task.target}", True)
                    print(f"  Security Risk: {risk_level}")
                
                analysis_data = {
                    "security_risk": risk_level.lower(),
                    "key_findings": security_result.get("findings", []),
                    "lines_of_code": result.get("result", {}).get("lines_read", 0),
                }
                self.context_manager.add_analysis_result(task.target, analysis_data)
                
                # Store for reporting
                analysis_state['detailed_findings'].append({
                    "file": task.target,
                    "content_preview": file_content[:500] + "..." if len(file_content) > 500 else file_content,
                    "lines": result.get("result", {}).get("lines_read", 0),
                    "security_summary": security_result.get("summary", ""),
                })
                
                # Generate follow-up tasks based on content analysis
                self.decision_engine.make_autonomous_decision(
                    "content", self.context_manager, self.task_queue,
                    self.context.get_analyzed_files(), self.context.get_explored_directories(),
                    file_path=task.target, content=file_content, security_result=security_result, focus=focus
                )

    def _assess_file_priorities_with_llm(self, files: List[str], explored_path: str) -> None:
        """Use LLM to assess file priorities and add high-value files to task queue"""
        if not files or len(files) == 0:
            return

        # Build comprehensive context including existing discoveries
        context = self._build_comprehensive_priority_context(explored_path, files)
        
        # Get comprehensive analysis context for intelligent prioritization
        comprehensive_context = self.context_manager.get_comprehensive_analysis_context()
        security_findings = comprehensive_context.get('security_findings', [])
        workflow_analysis = comprehensive_context.get('workflow_analysis', {})

        priority_prompt = PromptManager.get_file_priority_prompt(
            context=context, 
            files=files,
            security_findings=security_findings,
            workflow_analysis=workflow_analysis
        )

        # Use LLM to get priority assessment
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are an expert security analyst selecting the most valuable files for in-depth security analysis."},
            {"role": "user", "content": priority_prompt}
        ]

        priority_text = LLMClient.call_llm(
            model=model,
            messages=messages,
            max_tokens=800,
            temperature=0.3,
            timeout=20,
            max_retries=2
        )

        if priority_text:
            try:
                import json
                start = priority_text.find('{')
                end = priority_text.rfind('}') + 1
                if start != -1 and end > start:
                    json_text = priority_text[start:end]
                    priorities = json.loads(json_text)

                    # Check if all files are low priority
                    priority_files = priorities.get("priority_files", [])[:5]  # Limit to 5 files
                    high_medium_files = [f for f in priority_files if f.get("priority", "low") in ["high", "medium"]]
                    
                    if not high_medium_files:
                        # All files are low priority - suggest exploring subdirectories instead
                        print(f"  [SKIP] All {len(priority_files)} files are low priority")
                        print(f"  [RECOMMENDATION] Consider exploring subdirectories for more valuable content")
                        # Don't add any files, let the system explore deeper
                        return

                    # Add high and medium priority files to task queue
                    from ..tools.core.task import Task, TaskType
                    added_count = 0

                    for file_info in high_medium_files:
                        filename = file_info.get("filename", "")
                        priority = file_info.get("priority", "low")
                        reason = file_info.get("reason", "")

                        if filename in files:
                            # Construct full path
                            file_path = f"{explored_path.rstrip('/')}/{filename}"

                            # Skip if already analyzed
                            if self.context.is_file_analyzed(file_path):
                                continue

                            # Set priority level based on LLM assessment
                            if priority == "high":
                                task_priority = 95  # Very high priority
                            elif priority == "medium":
                                task_priority = 80  # High priority  
                            else:
                                task_priority = 60  # Low priority
                            
                            print(f"    [PRIORITY_ASSIGN] {filename}: {priority} → priority {task_priority}")

                            # Create read task
                            read_task = Task(type=TaskType.READ, target=file_path, priority=task_priority)
                            self.task_queue.add_task(read_task)

                            print(f"  [PRIORITY] Added {priority} priority file: {filename} ({reason})")
                            added_count += 1

                    print(f"  [SUCCESS] Added {added_count} priority files for analysis")

            except Exception as e:
                print(f"  [ERROR] Failed to parse LLM priority assessment: {e}")
                # # Fallback to simple priority selection (COMMENTED OUT FOR TESTING)
                # self.fallback_strategies.fallback_file_priority_selection(files, explored_path)
                print("  LLM priority assessment failed")
        else:
            print("  LLM priority assessment failed")
            # self.fallback_strategies.fallback_file_priority_selection(files, explored_path)

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
        """Run LLM-driven targeted security analysis on high-priority files"""
        targeted_findings = []

        try:
            # Get analyzed files for security analysis
            analyzed_files = self.context.get_analyzed_files()

            # Focus on high-risk files first (limit to prevent token overflow)
            high_risk_files = []
            for file_path in analyzed_files:
                if file_path.endswith(('.py', '.js', '.ts', '.java', '.php')):
                    # Check if this was marked as high risk during initial analysis
                    if self.context.get_data(f"security_concern_{file_path}", False):
                        high_risk_files.append(file_path)

            # If no high-risk files, analyze a sample of recent files
            if not high_risk_files:
                high_risk_files = analyzed_files[-10:]  # Last 10 analyzed files

            # Limit to 5 files for LLM analysis
            analysis_files = high_risk_files[:5]

            print(f"  [SECURITY] Analyzing {len(analysis_files)} files for targeted security issues")

            for file_path in analysis_files:
                try:
                    file_result = self.tools.read_file(file_path)
                    if "error" not in file_result and "content" in file_result:
                        content = file_result["content"]
                        findings = self._analyze_file_security_with_llm(file_path, content)
                        targeted_findings.extend(findings)
                except Exception as e:
                    print(f"  [ERROR] Failed to analyze {file_path}: {e}")
                    continue

        except Exception as e:
            print(f"Targeted security analysis failed: {e}")

        return targeted_findings

    def _analyze_file_security_with_llm(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Use LLM to analyze file content for security vulnerabilities"""
        findings = []

        # Prepare content sample (limit to avoid token limits)
        content_sample = content[:2000] + "..." if len(content) > 2000 else content

        # Build security analysis context
        language = file_path.split('.')[-1] if '.' in file_path else 'unknown'
        security_context = PromptManager.get_security_analysis_prompt(file_path, content_sample, language)

        # Use LLM for security analysis
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are an expert security auditor analyzing code for vulnerabilities. Focus on real security issues, not false positives."},
            {"role": "user", "content": security_context}
        ]

        analysis_text = LLMClient.call_llm(
            model=model,
            messages=messages,
            max_tokens=1200,
            temperature=0.2,
            timeout=30,
            max_retries=2
        )

        if analysis_text:
            try:
                import json
                # Extract JSON from response
                start = analysis_text.find('{')
                end = analysis_text.rfind('}') + 1
                if start != -1 and end > start:
                    json_text = analysis_text[start:end]
                    analysis_result = json.loads(json_text)

                    # Process findings
                    for finding in analysis_result.get("findings", []):
                        finding_dict = {
                            "file_path": file_path,
                            "vulnerability_type": finding.get("vulnerability_type", "Unknown"),
                            "severity": finding.get("severity", "MEDIUM"),
                            "line_number": finding.get("line_number", 0),
                            "description": finding.get("description", "Security issue detected"),
                            "code_snippet": finding.get("code_snippet", ""),
                            "injection_vector": finding.get("injection_vector", "Unknown"),
                            "data_flow": finding.get("data_flow", "Unknown"),
                            "attack_scenario": finding.get("attack_scenario", "Unknown"),
                            "remediation": finding.get("remediation", "Review and fix security issue"),
                            "exploitability": finding.get("exploitability", "Unknown"),
                            "analysis_method": "llm_driven"
                        }
                        findings.append(finding_dict)

                    print(f"  [SECURITY] Found {len(findings)} issues in {file_path.split('/')[-1]}")

            except Exception as e:
                print(f"  [ERROR] Failed to parse LLM security analysis for {file_path}: {e}")
        else:
            print(f"  [ERROR] LLM security analysis failed for {file_path}, no fallback available")

        return findings


    def _make_autonomous_decision(self, decision_type: str, **kwargs) -> None:
        """CORE INNOVATION: Unified LLM-driven autonomous decision making for exploration and content analysis"""
        
        try:
            print(f"  [AUTONOMOUS_DECISION] Making {decision_type} decision...")
            
            # Get comprehensive analysis history for LLM context
            history_context = self._build_history_context()

            # Use decision engine for autonomous decision making (core innovation)
            decision_result = self.decision_engine.make_autonomous_decision(
                decision_type, self.context_manager, self.task_queue, 
                self.context.get_analyzed_files(), self.context.get_explored_directories(),
                focus="security", **kwargs
            )
            
            # Track decision results (core innovation tracking)
            if decision_result and decision_result.get("decisions_made", 0) > 0:
                tasks_added = decision_result.get("tasks_added", 0)
                decision_details = decision_result.get("decision_details", [])
                
                print(f"  [AUTONOMOUS_SUCCESS] Made {decision_result['decisions_made']} decisions, added {tasks_added} tasks")
                
                # Store for trace logging (core innovation)
                current_count = self.context.get_data("autonomous_decisions", 0)
                self.context.set_data("autonomous_decisions", current_count + decision_result["decisions_made"])
                self.context.set_data("last_llm_decisions", decision_details)
                
                # Log decision details
                for detail in decision_details[:3]:  # Show first 3
                    print(f"    → {detail.get('type', 'unknown').upper()}: {detail.get('path', 'unknown')} ({detail.get('reason', 'no reason')})")
            else:
                print(f"  [AUTONOMOUS_INFO] No decisions made for {decision_type}")
                
        except Exception as e:
            print(f"  [AUTONOMOUS_ERROR] Decision making failed: {e}")
            # Continue without autonomous decisions

    # DEPRECATED: Decision context building functions moved to legacy_decision_functions.py

    # DEPRECATED: Build decision prompt functions moved to DecisionEngine

    def _generate_related_files_recommendations(self, file_path: str, content: str) -> List[str]:
        """Generate related files recommendations for LLM decision making"""
        recommendations = []

        try:
            # Get current directory and file info
            current_dir = str(Path(file_path).parent)
            file_extension = Path(file_path).suffix.lower()

            # 1. Extract imports and dependencies
            if file_extension in ['.py', '.js', '.ts', '.java']:
                import_related = self._find_related_files_from_content(content)
                recommendations.extend(import_related)

            # 2. Find configuration files that might be referenced
            config_related = self._find_referenced_files_from_config(content)
            recommendations.extend(config_related)

            # 3. Find related files in the same directory
            try:
                dir_path = self.repo_path / current_dir
                if dir_path.exists():
                    for item in dir_path.iterdir():
                        if item.is_file():
                            item_name = item.name
                            item_path = f"{current_dir}/{item_name}" if current_dir != "." else item_name

                            # Skip already analyzed files
                            if self.context.is_file_analyzed(item_path):
                                continue

                            # Recommend related files based on patterns
                            if any(pattern in item_name.lower() for pattern in [
                                'config', 'settings', 'auth', 'security', 'database', 'db',
                                'model', 'schema', 'api', 'endpoint', 'route', 'controller'
                            ]):
                                recommendations.append(item_path)

                            # Recommend files with similar names or same base name
                            current_base = Path(file_path).stem
                            if Path(item_name).stem == current_base and item_name != Path(file_path).name:
                                recommendations.append(item_path)

            except Exception as e:
                pass  # Continue silently on directory access errors

            # 4. Find potential entry points or main files
            if current_dir != ".":
                try:
                    # Look for main files in the same directory
                    for item in (self.repo_path / current_dir).iterdir():
                        if item.is_file():
                            item_name = item.name.lower()
                            if any(main_file in item_name for main_file in [
                                'main.py', 'app.py', 'server.py', '__init__.py',
                                'index.js', 'app.js', 'server.js'
                            ]):
                                item_path = f"{current_dir}/{item.name}" if current_dir != "." else item.name
                                if not self.context.is_file_analyzed(item_path):
                                    recommendations.append(item_path)
                except Exception as e:
                    pass  # Continue silently on file access errors

            # Remove duplicates and limit results
            recommendations = list(dict.fromkeys(recommendations))  # Remove duplicates while preserving order
            recommendations = [rec for rec in recommendations if rec and not self.context.is_file_analyzed(rec)]
            recommendations = recommendations[:10]  # Limit to 10 recommendations

        except Exception as e:
            print(f"  [ERROR] Failed to generate related files recommendations: {e}")
            recommendations = []

        return recommendations

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

            # Apply auto-compaction if context is too long
            compacted_history = self.history_compactor.compact_if_needed(history)
            return compacted_history

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



    # DEPRECATED FUNCTIONS MOVED TO legacy_decision_functions.py

    # DEPRECATED: _execute_decisions and related functions moved to legacy_decision_functions.py

    def _log_llm_decisions(self, task, result: Dict, success: bool) -> List[Dict]:
        """Helper method to log LLM decisions and generate extra_actions"""
        extra_actions = []
        autonomous_decisions = self.context.get_data("autonomous_decisions", 0)
        
        if task.type == TaskType.EXPLORE and success:
            # Add file priority assessment actions
            files = result.get("result", {}).get("files", [])
            if files:
                extra_actions.append({
                    "action": "PRIORITY_ASSESSMENT",
                    "target": f"{len(files)} files",
                    "result": "LLM analysis completed"
                })
            
            # Add autonomous decision actions
            if autonomous_decisions > 0:
                extra_actions.extend(self._create_decision_actions("AUTONOMOUS_DECISIONS", autonomous_decisions, 5))

        elif task.type == TaskType.READ and result.get("success", False):
            # Add content analysis actions
            extra_actions.append({
                "action": "CONTENT_ANALYSIS",
                "target": task.target,
                "result": "Security analysis completed"
            })
            
            # Add follow-up decision actions
            if autonomous_decisions > 0:
                extra_actions.extend(self._create_decision_actions("CONTENT_FOLLOW_UP", autonomous_decisions, 3))
        
        return extra_actions

    def _create_decision_actions(self, action_type: str, decision_count: int, limit: int) -> List[Dict]:
        """Helper method to create decision action entries"""
        last_decisions = self.context.get_data("last_llm_decisions", [])
        actions = []
        
        if last_decisions:
            decision_details = []
            for decision in last_decisions[:limit]:
                if isinstance(decision, dict):
                    target = decision.get("path", "unknown")
                    decision_action_type = decision.get("type", "unknown")
                    reason = decision.get("reason", "")
                    decision_details.append(f"{decision_action_type}: {target} ({reason})")
            
            if decision_details:
                result_text = f"Decisions: {'; '.join(decision_details)}" if action_type == "AUTONOMOUS_DECISIONS" else f"Follow-ups: {'; '.join(decision_details)}"
                actions.append({
                    "action": action_type,
                    "target": f"{len(last_decisions)} LLM decisions made" if action_type == "AUTONOMOUS_DECISIONS" else f"{len(last_decisions)} follow-up decisions",
                    "result": result_text
                })
            else:
                result_text = "Tasks added to queue" if action_type == "AUTONOMOUS_DECISIONS" else "Follow-up tasks added"
                actions.append({
                    "action": action_type,
                    "target": f"{decision_count} LLM decisions",
                    "result": result_text
                })
        else:
            result_text = "Tasks added to queue" if action_type == "AUTONOMOUS_DECISIONS" else "Follow-up tasks added"
            actions.append({
                "action": action_type,
                "target": f"{decision_count} LLM decisions",
                "result": result_text
            })
        
        return actions

    def _update_decision_context(self, analysis_state: Dict) -> None:
        """Helper method to update context with decision results"""
        decision_result = analysis_state.get('decision_result')
        if decision_result and decision_result.get("decisions_made", 0) > 0:
            # Handle exploration decisions (replace previous)
            if analysis_state.get('decision_type') == 'exploration':
                self.context.set_data("autonomous_decisions", decision_result["decisions_made"])
                self.context.set_data("last_llm_decisions", decision_result.get("decision_details", []))
            # Handle content decisions (append to existing)
            else:
                current_decisions = self.context.get_data("autonomous_decisions", 0)
                self.context.set_data("autonomous_decisions", current_decisions + decision_result["decisions_made"])
                
                current_details = self.context.get_data("last_llm_decisions", [])
                current_details.extend(decision_result.get("decision_details", []))
                self.context.set_data("last_llm_decisions", current_details)
        
        # Clean up temporary data
        analysis_state.pop('decision_result', None)
        analysis_state.pop('decision_type', None)

    def _autonomous_context_reassessment(self) -> None:
        """CORE INNOVATION: LLM-driven strategic context reassessment"""
        try:
            print("  [AUTONOMOUS_REASSESSMENT] Starting strategic context reassessment...")

            # Use decision engine for autonomous context reassessment (core innovation)
            self.decision_engine.autonomous_context_reassessment(
                self.context_manager, self.task_queue, self.context, self.tools
            )
            
            print("  [AUTONOMOUS_REASSESSMENT] Context reassessment completed")

        except Exception as e:
            print(f"  [AUTONOMOUS_REASSESSMENT] Context reassessment failed: {e}")
            # Continue analysis without reassessment

    def _execute_reassessment_decisions(self, decisions: Dict, unexplored_root_dirs: List[str],
                                      unexplored_subdirs: List[str]) -> None:
        """Execute strategic decisions from LLM reassessment"""
        from ..tools.core.task import Task, TaskType

        next_actions = decisions.get("next_actions", [])
        executed_count = 0

        print(f"  [STRATEGY] {decisions.get('strategy_explanation', 'Strategic planning completed')}")

        for action in next_actions:
            action_type = action.get("action", "")
            target = action.get("target", "")
            priority = action.get("priority", "medium")
            reason = action.get("reason", "")

            # Improved target validation with better path resolution
            valid_target = False
            normalized_target = target.strip('/')

            if action_type == "explore_directory":
                # Check against unexplored directories with better path matching
                for unexplored in unexplored_root_dirs + unexplored_subdirs:
                    unexplored_normalized = unexplored.strip('/')
                    if (normalized_target == unexplored_normalized or
                        normalized_target.endswith(unexplored_normalized) or
                        unexplored_normalized.endswith(normalized_target)):
                        valid_target = True
                        target = unexplored  # Use the original path from unexplored list
                        break

                # Additional check: verify directory actually exists and is not explored
                if valid_target:
                    full_path = self.repo_path / target
                    if not full_path.exists() or not full_path.is_dir():
                        valid_target = False
                        print(f"  [SKIP] Directory does not exist: {target}")
                    elif self.context.is_directory_explored(target):
                        valid_target = False
                        print(f"  [SKIP] Directory already explored: {target}")

            elif action_type == "analyze_file":
                # For file analysis, validate that the file exists and hasn't been analyzed
                full_path = self.repo_path / normalized_target
                if full_path.exists() and full_path.is_file():
                    if not self.context.is_file_analyzed(normalized_target):
                        valid_target = True
                        target = normalized_target
                    else:
                        print(f"  [SKIP] File already analyzed: {normalized_target}")
                else:
                    print(f"  [SKIP] File does not exist: {normalized_target}")

            if not valid_target:
                print(f"  [SKIP] Target not valid for execution: {target}")
                continue

            # Create appropriate task with improved error handling
            try:
                if action_type == "explore_directory":
                    task = Task(type=TaskType.EXPLORE, target=target,
                               priority=80 if priority == "high" else 60 if priority == "medium" else 40)
                    print(f"  [EXPLORE] {target} ({reason})")
                elif action_type == "analyze_file":
                    task = Task(type=TaskType.READ, target=target,
                               priority=85 if priority == "high" else 65 if priority == "medium" else 45)
                    print(f"  [ANALYZE] {target} ({reason})")

                self.task_queue.add_task(task)
                executed_count += 1

            except Exception as e:
                print(f"  [ERROR] Failed to create task for {target}: {e}")
                continue

            if executed_count >= 3:  # Respect LLM's limit
                break

        print(f"  [SUCCESS] Added {executed_count} strategic tasks")

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
        from ..tools.core.task import Task, TaskType

        # Look for configuration files in the same directory
        directory = '/'.join(file_path.split('/')[:-1])
        if directory:
            try:
                dir_result = self.tools.list_directory(directory)
                if "error" not in dir_result:
                    files = dir_result.get("files", [])
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
        """Execute a single task and return standardized result format with improved path resolution"""
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
            # Improved path resolution and validation
            target_path = task.target.strip()
            # Handle relative paths correctly
            if target_path.startswith('./'):
                # Remove ./ prefix and resolve relative to repo_path
                clean_path = target_path[2:]
                full_path = self.repo_path / clean_path
            elif target_path.startswith('/'):
                # Absolute path - use as is
                from pathlib import Path
                full_path = Path(target_path)
            else:
                # Relative path - resolve relative to repo_path
                full_path = self.repo_path / target_path

            # Skip execution if target path is obviously invalid (like hardcoded example paths)
            if self._is_invalid_target_path(target_path):
                duration = time.time() - start_time
                result_template.update({
                    "success": False,
                    "duration": duration,
                    "error": f"Invalid target path: {target_path} (appears to be example/placeholder path)"
                })
                return result_template

            if task.type == TaskType.EXPLORE:
                print(f"    Executing EXPLORE on: {target_path}")
                print(f"    Repo path: {self.repo_path}")
                print(f"    Full target path: {full_path}")
                print(f"    Target path exists: {full_path.exists()}")
                print(f"    Target path is dir: {full_path.is_dir() if full_path.exists() else 'N/A'}")

                # Additional validation for exploration
                if not full_path.exists():
                    duration = time.time() - start_time
                    result_template.update({
                        "success": False,
                        "duration": duration,
                        "error": f"Directory not found: {target_path}"
                    })
                    return result_template

                if not full_path.is_dir():
                    duration = time.time() - start_time
                    result_template.update({
                        "success": False,
                        "duration": duration,
                        "error": f"Path is not a directory: {target_path}"
                    })
                    return result_template

                result_data = self.tools.list_directory(target_path)
                print(f"    List directory result: {result_data}")

            elif task.type == TaskType.READ:
                print(f"    Executing READ on: {target_path}")
                print(f"    Full path: {full_path}")

                # Additional validation for file reading
                if not full_path.exists():
                    duration = time.time() - start_time
                    result_template.update({
                        "success": False,
                        "duration": duration,
                        "error": f"File not found: {target_path}"
                    })
                    return result_template

                if not full_path.is_file():
                    duration = time.time() - start_time
                    result_template.update({
                        "success": False,
                        "duration": duration,
                        "error": f"Path is not a file: {target_path}"
                    })
                    return result_template

                # Check file size to avoid reading very large files
                file_size = full_path.stat().st_size
                if file_size > 50 * 1024 * 1024:  # 50MB limit
                    duration = time.time() - start_time
                    result_template.update({
                        "success": False,
                        "duration": duration,
                        "error": f"File too large to read: {target_path} ({file_size} bytes)"
                    })
                    return result_template

                result_data = self.tools.read_file(target_path)

            elif task.type == TaskType.ANALYZE:
                print(f"    Executing ANALYZE on: {target_path}")

                # First check if file exists and is readable
                if not full_path.exists() or not full_path.is_file():
                    duration = time.time() - start_time
                    result_template.update({
                        "success": False,
                        "duration": duration,
                        "error": f"File not found or not readable: {target_path}"
                    })
                    return result_template

                file_result = self.tools.read_file(target_path)
                if "error" not in file_result:
                    try:
                        # Use LLM for code snippet analysis
                        llm_analysis = self.llm.analyze_code_snippet(
                            file_result["content"],
                            target_path
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

    def _is_invalid_target_path(self, target_path: str) -> bool:
        """Check if a target path is obviously invalid (like example/placeholder paths)"""
        invalid_patterns = [
            "path/to/",  # Generic example paths
            "example/",  # Example directories
            "placeholder",  # Placeholder text
            "dummy",  # Dummy files
            "sample",  # Sample files
            "template/file",  # Template paths
            "your/file",  # Generic placeholders
            "some/file",  # Generic placeholders
            "any/file",  # Generic placeholders
        ]

        target_lower = target_path.lower()
        return any(pattern in target_lower for pattern in invalid_patterns)
    
    def _build_comprehensive_priority_context(self, explored_path: str, files: List[str]) -> str:
        """Build comprehensive context including existing discoveries for intelligent priority assessment"""
        
        # Basic repository info
        context = f"""REPOSITORY ANALYSIS CONTEXT:
- Currently exploring: {explored_path}
- Repository root: {self.repo_path.name}
- Total files discovered: {len(files)}

**EXISTING ANALYSIS DISCOVERIES:**
"""
        
        # Add security findings summary
        security_summary = self.context_manager.get_security_summary()
        analyzed_files = list(self.context.get_analyzed_files())
        context += f"""
SECURITY ANALYSIS STATE:
- Files analyzed so far: {len(analyzed_files)}
- Security findings: {security_summary.get('total_findings', 0)} total
  - HIGH risk: {security_summary.get('high_risk_count', 0)} files
  - MEDIUM risk: {security_summary.get('medium_risk_count', 0)} files  
  - LOW risk: {security_summary.get('low_risk_count', 0)} files
"""
        
        # Add high-risk file details if any
        high_risk_details = []
        for file_path in analyzed_files[-10:]:  # Last 10 analyzed files
            analysis_result = self.context_manager.get_analysis_result(file_path)
            if analysis_result and analysis_result.get('security_risk') == 'high':
                findings_count = len(analysis_result.get('key_findings', []))
                high_risk_details.append(f"  - {file_path}: {findings_count} security findings")
        
        if high_risk_details:
            context += f"\nHIGH-RISK FILES DISCOVERED:\n" + "\n".join(high_risk_details)
            context += f"\n→ Consider prioritizing files RELATED to these high-risk findings"
        else:
            context += f"\nNo high-risk files found yet - focus on identifying injection points"
        
        # Add file type patterns discovered
        file_types = {}
        for file_path in analyzed_files:
            ext = file_path.split('.')[-1] if '.' in file_path else 'no_ext'
            file_types[ext] = file_types.get(ext, 0) + 1
        
        if file_types:
            context += f"\n\nFILE TYPES ANALYZED:\n"
            sorted_types = sorted(file_types.items(), key=lambda x: -x[1])
            for ext, count in sorted_types[:5]:
                context += f"  - .{ext}: {count} files analyzed\n"
            context += f"→ Consider similar file types in current directory for consistency"
        
        # Add workflow insights from context
        workflow_insights = self.context.get_data("workflow_insights", [])
        if workflow_insights:
            context += f"\nWORKFLOW PATTERNS DISCOVERED:\n"
            for insight in workflow_insights[-3:]:
                context += f"  - {insight}\n"
            context += f"→ Prioritize files that complete these workflow patterns"
        
        # Add current directory context
        context += f"\n\n**CURRENT DIRECTORY FILES (choose ONLY from this list):**\n"
        for i, file in enumerate(files, 1):
            context += f"{i}. {file}\n"
            
        # Add strategic guidance based on discoveries
        context += f"\n**INTELLIGENT PRIORITIZATION STRATEGY:**\n"
        
        if high_risk_details:
            context += f"- PRIORITIZE files that are likely RELATED to the high-risk files found\n"
            context += f"- Look for configuration, dependency, or import relationships\n"
        
        if len(analyzed_files) < 5:
            context += f"- EARLY STAGE: Focus on core system files (main, config, setup)\n"
        else:
            context += f"- FOLLOW-UP STAGE: Build on existing discoveries and fill knowledge gaps\n"
            
        context += f"- Consider file naming patterns and directory structure\n"
        context += f"- Focus on agent/LLM interaction points based on filename analysis\n"
        
        return context
    
    def _llm_should_reassess_decision(self, current_step: int, last_reassess_step: int) -> tuple[bool, str]:
        """DISCOVERY-DRIVEN LLM reassessment decision - triggers on significant findings"""
        
        try:
            # CRITICAL: Check for new significant findings since last reassessment
            recent_findings = self._get_new_findings_since_step(last_reassess_step)
            
            # IMMEDIATE triggers - don't wait for periodic check
            if self.focus_tracker.should_trigger_reassessment(recent_findings):
                return True, f"DISCOVERY-DRIVEN: Found {len(recent_findings)} significant findings requiring immediate focus"
            
            # Check if current focus needs attention
            primary_focus = self.focus_tracker.get_primary_focus()
            if primary_focus and len(primary_focus.leads_to_follow) > 0:
                return True, f"FOCUS-DRIVEN: Active focus '{primary_focus.target}' has {len(primary_focus.leads_to_follow)} leads to pursue"
            
            # Check if we're stuck analyzing low-value files repeatedly
            recent_files = list(self.context.get_analyzed_files())[-5:] if self.context.get_analyzed_files() else []
            config_file_count = sum(1 for f in recent_files if any(pattern in f.lower() for pattern in ['config', 'toml', 'yml', 'ini']))
            if config_file_count >= 3:
                return True, "ANTI-STAGNATION: Too many config files analyzed - need to diversify focus"
            
            # Get comprehensive analysis context
            comprehensive_context = self.context_manager.get_comprehensive_analysis_context()
            
            # Build current state info
            current_state = {
                'step': current_step,
                'analyzed_files': len(self.context.get_analyzed_files()),
                'steps_since_last': current_step - last_reassess_step,
                'recent_findings': len(recent_findings),
                'active_focuses': len(self.focus_tracker.active_focuses),
                'stagnation_risk': config_file_count >= 2
            }
            
            # Build task queue info
            task_queue_info = {
                'pending_count': self.task_queue.pending_count(),
                'highest_priority': self.task_queue.get_highest_priority(),
                'focus_targets_pending': len(self.focus_tracker.get_next_investigation_targets())
            }
            
            # Get comprehensive data
            security_findings = comprehensive_context.get('security_findings', [])
            workflow_analysis = comprehensive_context.get('workflow_analysis', {})
            
            # Enhanced prompt with focus context
            decision_prompt = PromptManager.get_focus_aware_reassessment_prompt(
                current_state=current_state,
                security_findings=security_findings,
                workflow_patterns=workflow_analysis,
                task_queue_info=task_queue_info,
                focus_summary=self.focus_tracker.get_focus_summary(),
                primary_focus=self.focus_tracker.get_primary_focus()
            )
            
            # Ask LLM for intelligent decision
            model = LLMClient.get_model()
            messages = [
                {"role": "system", "content": "You are an intelligent agent injection analysis strategist making strategic reassessment decisions based on comprehensive security discoveries and workflow patterns."},
                {"role": "user", "content": decision_prompt}
            ]
            
            decision_text = LLMClient.call_llm(
                model=model,
                messages=messages,
                max_tokens=500,
                temperature=0.2,
                timeout=25,
                max_retries=2
            )
            
            if decision_text:
                import json
                start = decision_text.find('{')
                end = decision_text.rfind('}') + 1
                if start != -1 and end > start:
                    decision_data = json.loads(decision_text[start:end])
                    
                    should_reassess = decision_data.get("should_reassess", False)
                    reasoning = decision_data.get("reasoning", "LLM discovery-driven decision")
                    confidence = decision_data.get("confidence", "medium")
                    priority_focus = decision_data.get("priority_focus", "")
                    discovery_impact = decision_data.get("discovery_impact", "")
                    
                    # Simplified LLM decision output
                    if should_reassess:
                        print(f"  [LLM] Queue reassessment needed: {reasoning[:100]}...")
                    
                    return should_reassess, reasoning
        
        except Exception as e:
            pass  # LLM decision failed, use fallback logic
        
        # Minimal fallback if LLM fails
        fallback_should_reassess = (current_step - last_reassess_step >= 6)
        fallback_reason = "LLM decision failed - minimal fallback applied"
        
        return fallback_should_reassess, fallback_reason
    
    def _has_meaningful_discoveries(self) -> bool:
        """Check if we have meaningful discoveries that warrant reassessment"""
        # Must have analyzed at least a few files
        analyzed_count = len(self.context.get_analyzed_files())
        security_summary = self.context_manager.get_security_summary()
        total_findings = security_summary.get('total_findings', 0)
        high_risk_count = security_summary.get('high_risk_count', 0)
        medium_risk_count = security_summary.get('medium_risk_count', 0)
        
        print(f"  [MEANINGFUL_CHECK] Files analyzed: {analyzed_count}, Findings: {total_findings} (H:{high_risk_count}, M:{medium_risk_count})")
        
        # More lenient criteria - either enough files OR security findings
        has_enough_files = analyzed_count >= 2  # Reduced from 3 to 2
        has_security_findings = total_findings > 0 or high_risk_count > 0 or medium_risk_count > 0
        
        # Allow reassessment if we have either condition OR if we've done some analysis
        meaningful = has_enough_files or has_security_findings or analyzed_count >= 1
        
        print(f"  [MEANINGFUL_CHECK] Result: {meaningful} (files≥2: {has_enough_files}, findings: {has_security_findings}, analyzed≥1: {analyzed_count >= 1})")
        return meaningful
    
    def _intelligent_queue_reassessment(self) -> None:
        """CORE INNOVATION: Focus-driven intelligent task queue reassessment with deep investigation capability"""
        try:
            print("  [INTELLIGENT_REASSESS] Starting priority reassessment...")
            
            pending_tasks = self.task_queue.get_pending_tasks()
            if not pending_tasks:
                print("  [INTELLIGENT_REASSESS] No pending tasks to reassess")
                return
            
            # Build comprehensive context for LLM reassessment
            analyzed_files = list(self.context.get_analyzed_files())
            explored_dirs = list(self.context.get_explored_directories())
            current_discoveries = self._build_discoveries_context(analyzed_files, explored_dirs)
            pending_tasks_context = self._build_pending_tasks_context(pending_tasks)
            
            # Create LLM prompt for intelligent reassessment
            reassessment_prompt = PromptManager.get_queue_reassessment_prompt(
                current_discoveries, pending_tasks_context
            )
            
            # Get LLM decision on task prioritization
            model = LLMClient.get_model()
            messages = [
                {"role": "system", "content": "You are an intelligent agent security analyst making strategic task prioritization decisions based on discoveries."},
                {"role": "user", "content": reassessment_prompt}
            ]

            decision_text = LLMClient.call_llm(
                model=model, messages=messages, max_tokens=1000,
                temperature=0.2, timeout=25, max_retries=2
            )

            if decision_text:
                # Parse and apply priority updates (core innovation)
                priority_updates = self._parse_priority_reassessment(decision_text)
                if priority_updates:
                    updated_count = self.task_queue.reassess_priorities(priority_updates)
                    print(f"  [INTELLIGENT_REASSESS] Updated priorities for {updated_count} tasks")
                    
                    # Log the changes
                    for target, new_priority in list(priority_updates.items())[:3]:  # Show first 3
                        print(f"    → {target}: priority → {new_priority}")
                else:
                    print("  [INTELLIGENT_REASSESS] No priority changes recommended")
            else:
                print("  [INTELLIGENT_REASSESS] LLM reassessment failed")
                
        except Exception as e:
            print(f"  [INTELLIGENT_REASSESS] Error during reassessment: {e}")
            # Continue without reassessment
    
    def _build_discoveries_context(self, analyzed_files: List[str], explored_dirs: List[str]) -> str:
        """Build detailed context about actual discoveries for reassessment"""
        discoveries = f"""ACTUAL ANALYSIS DISCOVERIES:

FILES ANALYZED: {len(analyzed_files)} total
DIRECTORIES EXPLORED: {len(explored_dirs)} total

**CONCRETE SECURITY FINDINGS:**
"""
        
        # Get actual security findings from context manager
        security_summary = self.context_manager.get_security_summary()
        high_risk_count = security_summary.get('high_risk_count', 0)
        medium_risk_count = security_summary.get('medium_risk_count', 0)
        
        discoveries += f"""
- HIGH RISK files found: {high_risk_count}
- MEDIUM RISK files found: {medium_risk_count}
- Total security findings: {security_summary.get('total_findings', 0)}

**SPECIFIC HIGH-RISK DISCOVERIES:**
"""
        
        # Get detailed information about high-risk files with actual findings
        high_risk_details = []
        for file_path in analyzed_files[-15:]:  # Check last 15 analyzed files
            if self.context.get_data(f"security_concern_{file_path}", False):
                # Get actual analysis result
                analysis_result = self.context_manager.get_analysis_result(file_path)
                if analysis_result:
                    risk_level = analysis_result.get('security_risk', 'unknown')
                    findings_count = len(analysis_result.get('key_findings', []))
                    high_risk_details.append({
                        'file': file_path,
                        'risk': risk_level,
                        'findings_count': findings_count,
                        'file_type': file_path.split('.')[-1] if '.' in file_path else 'unknown'
                    })
        
        if high_risk_details:
            for detail in high_risk_details[-5:]:  # Show last 5 high-risk files
                discoveries += f"- {detail['file']} ({detail['risk']} risk, {detail['findings_count']} findings, {detail['file_type']} file)\n"
        else:
            discoveries += "- No high-risk files found in recent analysis\n"

        # Add file type distribution for workflow understanding
        file_types = {}
        for file_path in analyzed_files:
            ext = file_path.split('.')[-1] if '.' in file_path else 'no_ext'
            file_types[ext] = file_types.get(ext, 0) + 1
        
        if file_types:
            discoveries += f"\n**FILE TYPES ANALYZED:**\n"
            # Sort by count to show most common file types
            sorted_types = sorted(file_types.items(), key=lambda x: -x[1])
            for ext, count in sorted_types[:8]:  # Show top 8 file types
                discoveries += f"- .{ext}: {count} files\n"

        # Add directory structure insights
        discoveries += f"\n**EXPLORED DIRECTORY STRUCTURE:**\n"
        root_dirs = [d for d in explored_dirs if '/' not in d.strip('./')]
        sub_dirs = [d for d in explored_dirs if '/' in d.strip('./')]
        
        discoveries += f"- Root-level directories: {len(root_dirs)}\n"
        discoveries += f"- Sub-directories explored: {len(sub_dirs)}\n"
        
        if root_dirs:
            discoveries += f"- Root dirs: {', '.join(root_dirs[:5])}\n"
        
        return discoveries
    
    def _build_pending_tasks_context(self, pending_tasks: List) -> str:
        """Build context about pending tasks for reassessment"""
        context = f"""CURRENT TASK QUEUE ({len(pending_tasks)} pending tasks):
"""
        
        # Group by type and priority
        by_type = {}
        for task in pending_tasks:
            task_type = task.type.value
            if task_type not in by_type:
                by_type[task_type] = []
            by_type[task_type].append(task)
        
        for task_type, tasks in by_type.items():
            context += f"\n{task_type.upper()} tasks ({len(tasks)}):\n"
            # Show top 5 highest priority tasks of each type
            sorted_tasks = sorted(tasks, key=lambda t: -t.priority)
            for task in sorted_tasks[:5]:
                context += f"  - {task.target} (priority: {task.priority})\n"
            if len(tasks) > 5:
                context += f"  - ... and {len(tasks) - 5} more tasks\n"
        
        return context
    
    def _parse_priority_reassessment(self, decision_text: str) -> Dict[str, int]:
        """Parse and validate LLM decision for discovery-based priority updates"""
        try:
            import json
            start = decision_text.find('{')
            end = decision_text.rfind('}') + 1
            if start != -1 and end > start:
                json_text = decision_text[start:end]
                decision_data = json.loads(json_text)
                
                # Check if LLM found relevant discoveries
                has_discoveries = decision_data.get("has_relevant_discoveries", False)
                priority_updates = decision_data.get("priority_updates", {})
                reasoning = decision_data.get("discovery_based_reasoning", "")
                
                print(f"  [REASSESS] Has relevant discoveries: {has_discoveries}")
                if reasoning:
                    print(f"  [REASSESS] Reasoning: {reasoning}")
                
                # If no relevant discoveries, don't update anything
                if not has_discoveries:
                    print("  [REASSESS] No relevant discoveries found - no priority changes")
                    return {}
                
                # Validate priority updates are discovery-based
                validated_updates = {}
                pending_tasks = self.task_queue.get_pending_tasks()
                existing_targets = {task.target for task in pending_tasks}
                
                for target, priority in priority_updates.items():
                    # Validate priority range
                    if not isinstance(priority, int) or not (30 <= priority <= 100):
                        print(f"  [REASSESS] Invalid priority {priority} for {target}, skipping")
                        continue
                    
                    # Validate target exists in queue
                    if target not in existing_targets:
                        print(f"  [REASSESS] Target '{target}' not in queue, skipping")
                        continue
                    
                    # Additional validation: ensure priority change is reasonable
                    current_task = next((t for t in pending_tasks if t.target == target), None)
                    if current_task:
                        priority_change = abs(priority - current_task.priority)
                        # Prevent extreme priority changes without strong justification
                        if priority_change > 30:
                            print(f"  [REASSESS] Large priority change ({current_task.priority} -> {priority}) for {target}")
                            # Allow it but log it for monitoring
                    
                    validated_updates[target] = priority
                
                print(f"  [REASSESS] Validated {len(validated_updates)}/{len(priority_updates)} priority updates")
                return validated_updates
                
        except Exception as e:
            print(f"  [REASSESS] Failed to parse LLM reassessment: {e}")
        
        return {}
    
    def _get_new_findings_since_step(self, last_step: int) -> List[Dict]:
        """Get significant findings discovered since the last step"""
        try:
            all_findings = self.context_manager.get_security_summary().get('findings', [])
            
            # Filter for findings from recent steps (rough approximation)
            recent_findings = []
            for finding in all_findings[-10:]:  # Last 10 findings
                if finding.get('risk_level') in ['high', 'medium']:
                    recent_findings.append(finding)
            
            return recent_findings
        except:
            return []
    
    def _get_focus_driven_task(self) -> Optional:
        """Get next task driven by current investigation focus"""
        
        # First priority: focus-driven targets
        focus_targets = self.focus_tracker.get_next_investigation_targets(limit=1)
        if focus_targets:
            target = focus_targets[0]
            from ..tools.core.task import Task, TaskType
            
            task_type = TaskType.READ if target['action'] == 'analyze_file' else TaskType.EXPLORE
            task = Task(
                type=task_type, 
                target=target['path'], 
                priority=target['priority'],
                focus_id=target.get('focus_id'),
                focus_type=target.get('focus_type'),
                focus_driven=True
            )
            
            print(f"  [FOCUS_TASK] {target['action'].upper()} {target['path']} - {target['reason']} (focus: {task.focus_type})")
            return task
        
        return None

    def _update_focus_tracker_with_findings(self, file_path: str, security_result: Dict, file_content: str) -> None:
        """Update focus tracker with new security findings and investigation leads"""
        try:
            findings = security_result.get("findings", [])
            risk_level = security_result["risk_assessment"]["overall_risk"].lower()
            
            # Create or update focus for high and medium risk findings
            if risk_level in ["high", "medium"] and findings:
                # Look for existing focus on this file or create new one
                focus_id = None
                for fid, focus in self.focus_tracker.active_focuses.items():
                    if focus.target == file_path:
                        focus_id = fid
                        break
                
                if focus_id is None:
                    # Create new focus for this file
                    focus_id = self.focus_tracker.create_focus(
                        "vulnerability",
                        file_path,
                        f"{risk_level.upper()} risk findings: {len(findings)} issues",
                        findings
                    )
                
                # Add findings to existing or new focus
                for finding in findings:
                    self.focus_tracker.update_focus(focus_id, finding=finding)
                
                # Extract potential investigation leads from findings and content
                leads = self._extract_investigation_leads(file_path, findings, file_content)
                for lead in leads:
                    self.focus_tracker.update_focus(focus_id, lead=lead)
                    
                print(f"  [FOCUS_UPDATED] {focus_id}: Added {len(findings)} findings, {len(leads)} leads")
            
            # Check for cross-file references that might create secondary focuses
            related_files = self._find_related_files_from_content(file_content)
            if related_files and risk_level in ["high", "medium"]:
                dependency_focus_id = self.focus_tracker.create_focus(
                    "dependency",
                    file_path,
                    f"Dependencies of {risk_level} risk file",
                )
                
                for related_file in related_files[:3]:  # Limit to top 3
                    lead = {
                        'path': related_file,
                        'reason': f'Referenced by {risk_level} risk file {Path(file_path).name}'
                    }
                    self.focus_tracker.update_focus(dependency_focus_id, lead=lead)
        
        except Exception as e:
            print(f"  [ERROR] Failed to update focus tracker: {e}")

    def _extract_investigation_leads(self, file_path: str, findings: List[Dict], content: str) -> List[Dict]:
        """Extract investigation leads from security findings and content"""
        leads = []
        
        try:
            base_dir = str(Path(file_path).parent)
            file_name = Path(file_path).stem
            
            # From findings - look for specific patterns
            for finding in findings:
                description = finding.get('description', '').lower()
                
                # SQL injection patterns suggest database-related files
                if 'sql' in description or 'database' in description:
                    leads.append({
                        'path': f"{base_dir}/models.py",
                        'reason': f'SQL-related finding in {Path(file_path).name}'
                    })
                    leads.append({
                        'path': f"{base_dir}/db",
                        'reason': f'Database configuration check'
                    })
                
                # Authentication issues suggest auth-related files
                if 'auth' in description or 'login' in description or 'password' in description:
                    leads.append({
                        'path': f"{base_dir}/auth.py",
                        'reason': f'Authentication finding in {Path(file_path).name}'
                    })
                    leads.append({
                        'path': f"{base_dir}/security.py",
                        'reason': f'Security configuration check'
                    })
                
                # Configuration issues suggest config files
                if 'config' in description or 'setting' in description:
                    leads.append({
                        'path': f"{base_dir}/config.py",
                        'reason': f'Configuration issue in {Path(file_path).name}'
                    })
            
            # From content - look for imports and references
            if 'import ' in content or 'from ' in content:
                # Look for test files
                leads.append({
                    'path': f"{base_dir}/test_{file_name}.py",
                    'reason': f'Test coverage for {Path(file_path).name}'
                })
                leads.append({
                    'path': f"{base_dir}/{file_name}_test.py",
                    'reason': f'Test coverage for {Path(file_path).name}'
                })
            
        except Exception as e:
            print(f"  [ERROR] Failed to extract leads: {e}")
        
        # Remove duplicates and non-existent paths
        unique_leads = []
        seen_paths = set()
        
        for lead in leads:
            if lead['path'] not in seen_paths:
                seen_paths.add(lead['path'])
                # Basic existence check for files (directories handled later)
                if lead['path'].endswith('.py'):
                    full_path = self.repo_path / lead['path']
                    if full_path.exists():
                        unique_leads.append(lead)
                else:
                    # For directories, add without existence check
                    unique_leads.append(lead)
        
        return unique_leads[:5]  # Limit to top 5 leads





def perform_repository_analysis(repo_path: str, max_steps: Optional[int] = None, save_results: bool = True, focus: str = "security") -> Dict[str, Any]:
    """
    Function tool for performing comprehensive repository analysis
    """
    analyzer = AnalysisAgent(repo_path)
    return analyzer.analyze(max_steps=max_steps, save_results=save_results, focus=focus)


def get_analysis_queue_status(analyzer_instance=None) -> str:
    """
    Function tool to get current task queue status and pending priorities
    """
    if not analyzer_instance:
        return "No active analyzer instance"
    
    stats = analyzer_instance.task_queue.get_stats()
    pending_tasks = analyzer_instance.task_queue.get_pending_tasks()
    
    status = f"""TASK QUEUE STATUS:
- Pending tasks: {stats['pending']}
- Completed tasks: {stats['completed']}
- Failed tasks: {stats['failed']}

TOP PENDING TASKS:"""
    
    for i, task in enumerate(pending_tasks[:5]):
        status += f"\n{i+1}. [{task.priority}] {task.type.value} → {task.target}"
    
    return status


def compact_history_context(history_context: str, max_length: int = 4000) -> str:
    """
    Function tool to compact long history contexts using LLM
    """
    compactor = HistoryCompactor(max_context_length=max_length)
    return compactor.compact_if_needed(history_context)


def make_autonomous_decision(analyzer_instance, decision_type: str, context_data: Dict) -> str:
    """
    Function tool to trigger autonomous decision making
    """
    if not analyzer_instance:
        return "No active analyzer instance"
    
    try:
        if decision_type == "exploration":
            analyzer_instance._make_autonomous_decision(
                "exploration", 
                explored_path=context_data.get('explored_path', '.'),
                files=context_data.get('files', []),
                dirs=context_data.get('dirs', [])
            )
        elif decision_type == "content":
            analyzer_instance._make_autonomous_decision(
                "content",
                file_path=context_data.get('file_path', ''),
                content=context_data.get('content', ''),
                security_result=context_data.get('security_result', {})
            )
        return f"Autonomous decision making triggered for {decision_type}"
    except Exception as e:
        return f"Decision making failed: {e}"


def get_project_overview_direct(repo_path: str) -> str:
    """
    Function tool to get project overview directly from context manager
    """
    try:
        from ..tools.planning.analysis_context_manager import AnalysisContextManager
        manager = AnalysisContextManager(repo_path)
        overview = manager.get_project_overview()
        
        return f"""PROJECT OVERVIEW - {overview['repo_path']}

REPOSITORY STRUCTURE:
- Total files: {overview.get('total_files', 0)}
- Total directories: {overview.get('total_directories', 0)}
- Analysis progress: {overview.get('analysis_progress', '0%')}

SECURITY SUMMARY:
- High risk files: {overview.get('high_risk_count', 0)}
- Medium risk files: {overview.get('medium_risk_count', 0)}
- Total security findings: {overview.get('total_findings', 0)}

RECENT ACTIVITY:
{overview.get('recent_activity', 'No recent activity')}"""
    except Exception as e:
        return f"Failed to get project overview: {e}"


def build_analysis_agent() -> Agent:
    """
    Build the Analysis Agent with repository analysis capabilities.
    
    This agent focuses on static analysis, security scanning, and
    architectural understanding of target repositories.
    """
    
    analysis_agent = Agent(
        model=LiteLlm(model=settings.ANALYSIS_AGENT_MODEL),
        name="analysis_agent",
        instruction="""
You are an expert AI security analysis agent specialized in repository static analysis.
Your role is to perform comprehensive analysis of code repositories to understand
their architecture, identify security patterns, and map potential vulnerabilities.

Your capabilities include:

1. **Autonomous Repository Analysis**:
   - Perform intelligent analysis using context and discoveries
   - Make autonomous decisions about exploration and file analysis
   - Use security findings to drive investigation priorities
   - Generate comprehensive analysis reports

2. **Security Analysis**:
   - Analyze files for security vulnerabilities and injection points
   - Assess risk levels and provide detailed findings
   - Identify high-risk files requiring immediate attention
   - Generate security assessment summaries

3. **Context Management**:
   - Track analysis progress and project understanding
   - Maintain analysis history for intelligent decision making
   - Provide project overview and status information
   - Support adaptive planning based on discoveries

4. **Task Management**:
   - Create and manage analysis tasks with intelligent planning
   - Update analysis progress and track completion
   - Generate comprehensive analysis plans
   - Coordinate analysis workflow with adaptive strategies

CORE ARCHITECTURE & INTELLIGENT DECISION MAKING:
You are built on a sophisticated autonomous analysis architecture with these key innovations:

**Core Architecture Components:**
1. **Priority Task Queue** - Manages analysis tasks by priority with autonomous decision making
2. **History Context Management** - Maintains comprehensive analysis context with auto-compaction
3. **Autonomous Decision Making** - Uses LLM-driven decisions for exploration and content analysis
4. **Context-Aware Planning** - Prevents duplicate work and focuses on high-value targets

**Available Tools:**
1. **perform_repository_analysis()** - Execute comprehensive autonomous repository analysis
2. **get_project_overview_direct()** - Get real-time project structure and security status
3. **compact_history_context()** - Auto-compact long analysis contexts using LLM
4. **initialize_analysis_context()** - Set up analysis context for new repositories
5. **get_security_summary()** - Review current security findings and risk assessment

AUTONOMOUS ANALYSIS WORKFLOW:

1. **Initialization**: The system automatically initializes with a priority queue and context management
2. **Autonomous Exploration**: Uses LLM-driven decisions to explore repositories intelligently
3. **Context-Aware Analysis**: Maintains history to prevent duplicate work and focus on gaps
4. **Priority-Based Task Management**: High-risk findings automatically increase analysis priority
5. **Auto-Compaction**: Long contexts are automatically compacted to maintain LLM effectiveness

CONTEXT-AWARE DECISION MAKING:
- Always check current analysis status before making decisions
- Use project overview and history to avoid redundant analysis
- Prioritize based on security findings and architectural importance
- Create todos for follow-up analysis of interesting discoveries
- Update progress regularly to maintain accurate context

Focus on security vulnerabilities, injection points, and architectural risks.
Be proactive - when you discover something interesting, investigate it thoroughly and create follow-up tasks.
Use the full context and planning toolkit to manage comprehensive, intelligent analysis workflows.
""",
        tools=[
            # Core repository analysis tool  
            FunctionTool(perform_repository_analysis),
            
            # Core architecture tools - direct access to main functionality
            FunctionTool(get_project_overview_direct),
            FunctionTool(compact_history_context),
            
            # Essential context tools (simplified)
            FunctionTool(initialize_analysis_context),
            # Note: Other tools now integrated into agent architecture directly
        ],
    )

    return analysis_agent