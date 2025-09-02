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
from ..tools.planning.task_manager import (
    create_analysis_todo,
    update_analysis_progress,
    get_analysis_status,
    create_comprehensive_analysis_plan
)
from ..tools.planning.context_tools import (
    initialize_analysis_context,
    get_project_overview,
    get_analysis_history,
    get_security_summary,
    update_todo_status,
    get_current_todos,
    get_next_suggestions,
    record_analysis_result,
    record_directory_structure,
)


# Import LLM client from core module
from ..tools.core.llm_client import LLMClient


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
        self.context = AnalysisContext()
        self.task_queue = TaskQueue()

        # Initialize context management (late import to avoid circular dependencies)
        from ..tools.planning.analysis_context_manager import AnalysisContextManager
        from ..tools.planning.context_tools import initialize_analysis_context
        self.context_manager = AnalysisContextManager(str(repo_path))
        initialize_analysis_context(str(repo_path))

        # Initialize supporting components
        self.execution_logger = ExecutionLogger()

        # Initialize security analyzer (late import to avoid circular dependency)
        from ..tools.analyzers.security_analyzer import SecurityAnalyzer
        self.security_analyzer = SecurityAnalyzer()

        # Initialize LLM helper for code analysis
        from ..tools.code_analysis.llm_decider import LLMHelper
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

            if result.get("result", {}).get("lines_read"):
                print(f"  Content: {result['result']['lines_read']} lines")

            if result.get("duration"):
                print(f"  Duration: {result['duration']:.3f}s")

            # Update task status in queue
            if success:
                self.task_queue.complete_task(task.task_id, result)
            else:
                error_msg = result.get("error", "Unknown error")
                self.task_queue.fail_task(task.task_id, error_msg)

            # Log execution with trace format
            extra_actions = []

            # Collect any additional actions taken during this step
            if task.type == TaskType.EXPLORE and result.get("success", False):
                # Add file priority assessment actions
                files = result.get("result", {}).get("files", [])
                if files:
                    extra_actions.append({
                        "action": "PRIORITY_ASSESSMENT",
                        "target": f"{len(files)} files",
                        "result": "LLM analysis completed"
                    })

                # Get detailed autonomous decisions instead of just count
                autonomous_decisions = self.context.get_data("autonomous_decisions", 0)
                if autonomous_decisions > 0:
                    # Get the actual decisions made during this step
                    last_decisions = self.context.get_data("last_llm_decisions", [])
                    if last_decisions:
                        decision_details = []
                        for decision in last_decisions[:5]:  # Limit to first 5 for readability
                            if isinstance(decision, dict):
                                target = decision.get("path", "unknown")
                                action_type = decision.get("type", "unknown")
                                reason = decision.get("reason", "")
                                decision_details.append(f"{action_type}: {target} ({reason})")

                        if decision_details:
                            extra_actions.append({
                                "action": "AUTONOMOUS_DECISIONS",
                                "target": f"{len(last_decisions)} LLM decisions made",
                                "result": f"Decisions: {'; '.join(decision_details)}"
                            })
                        else:
                            extra_actions.append({
                                "action": "AUTONOMOUS_DECISIONS",
                                "target": f"{autonomous_decisions} LLM decisions",
                                "result": "Tasks added to queue"
                            })
                    else:
                        extra_actions.append({
                            "action": "AUTONOMOUS_DECISIONS",
                            "target": f"{autonomous_decisions} LLM decisions",
                            "result": "Tasks added to queue"
                        })

            elif task.type == TaskType.READ and result.get("success", False):
                # Add content analysis actions
                extra_actions.append({
                    "action": "CONTENT_ANALYSIS",
                    "target": task.target,
                    "result": "Security analysis completed"
                })

                # Get detailed follow-up decisions instead of just count
                autonomous_decisions = self.context.get_data("autonomous_decisions", 0)
                if autonomous_decisions > 0:
                    # Get the actual decisions made during this step
                    last_decisions = self.context.get_data("last_llm_decisions", [])
                    if last_decisions:
                        decision_details = []
                        for decision in last_decisions[:3]:  # Limit to first 3 for readability
                            if isinstance(decision, dict):
                                target = decision.get("path", "unknown")
                                action_type = decision.get("type", "unknown")
                                reason = decision.get("reason", "")
                                decision_details.append(f"{action_type}: {target} ({reason})")

                        if decision_details:
                            extra_actions.append({
                                "action": "CONTENT_FOLLOW_UP",
                                "target": f"{len(last_decisions)} follow-up decisions",
                                "result": f"Follow-ups: {'; '.join(decision_details)}"
                            })
                        else:
                            extra_actions.append({
                                "action": "CONTENT_FOLLOW_UP",
                                "target": f"{autonomous_decisions} LLM decisions",
                                "result": "Follow-up tasks added"
                            })
                    else:
                        extra_actions.append({
                            "action": "CONTENT_FOLLOW_UP",
                            "target": f"{autonomous_decisions} LLM decisions",
                            "result": "Follow-up tasks added"
                        })

            self.execution_logger.log_execution(task, result, step + 1, extra_actions if extra_actions else None)
            
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
                
                # LLM-BASED FILE PRIORITY ASSESSMENT: Use LLM to identify valuable files
                self._assess_file_priorities_with_llm(files, task.target)
                
                # AUTONOMOUS DECISION MAKING: Use discoveries to determine next actions
                self._make_autonomous_decision("exploration", explored_path=task.target, files=files, dirs=dirs)
                        
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
                        "lines_of_code": result.get("result", {}).get("lines_read", 0),
                    }
                    self.context_manager.add_analysis_result(task.target, analysis_data)
                    
                    # Store file analysis for reporting
                    detailed_findings.append({
                        "file": task.target,
                        "content_preview": file_content[:500] + "..." if len(file_content) > 500 else file_content,
                        "lines": result.get("result", {}).get("lines_read", 0),
                        "security_summary": security_result.get("summary", ""),
                    })
            
                    # AUTONOMOUS DECISION MAKING: Use file content to determine next actions
                    self._make_autonomous_decision("content", file_path=task.target, content=file_content, security_result=security_result)
            
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
        
        # Get execution statistics and trace logs
        execution_stats = self.execution_logger.get_summary()
        trace_logs = self.execution_logger.get_trace_logs()
        task_stats = self.task_queue.get_stats()
        
        # Create a unique set of security findings (no duplicates)
        unique_security_findings = {}
        for sec_result in security_findings:
            file_path = sec_result["file_path"]
            if file_path not in unique_security_findings:
                unique_security_findings[file_path] = sec_result

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
                "steps_completed": step,
                "max_steps": max_steps,
                "status": "completed" if step < max_steps else "max_steps_reached",
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

    def _assess_file_priorities_with_llm(self, files: List[str], explored_path: str) -> None:
        """Use LLM to assess file priorities and add high-value files to task queue"""
        if not files or len(files) == 0:
            return

        # Limit to 10 files for LLM analysis to avoid token limits
        sample_files = files[:10]

        # Build context about the repository and current exploration
        context = f"""
REPOSITORY ANALYSIS CONTEXT:
- Currently exploring: {explored_path}
- Repository root: {self.repo_path.name}
- Total files discovered: {len(files)}

FILES TO ANALYZE:
"""
        for i, file in enumerate(sample_files, 1):
            context += f"{i}. {file}\n"

        priority_prompt = PromptManager.get_file_priority_prompt(context, sample_files)

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

                        if filename in sample_files:
                            # Construct full path
                            file_path = f"{explored_path.rstrip('/')}/{filename}"

                            # Skip if already analyzed
                            if self.context.is_file_analyzed(file_path):
                                continue

                            # Set priority level
                            task_priority = 90 if priority == "high" else 70

                            # Create read task
                            read_task = Task(type=TaskType.READ, target=file_path, priority=task_priority)
                            self.task_queue.add_task(read_task)

                            print(f"  [PRIORITY] Added {priority} priority file: {filename} ({reason})")
                            added_count += 1

                    print(f"  [SUCCESS] Added {added_count} priority files for analysis")

            except Exception as e:
                print(f"  [ERROR] Failed to parse LLM priority assessment: {e}")
                # Fallback to simple priority selection
                self._fallback_file_priority_selection(sample_files, explored_path)
        else:
            print("  [FALLBACK] LLM priority assessment failed, using simple selection")
            self._fallback_file_priority_selection(sample_files, explored_path)

    def _fallback_file_priority_selection(self, files: List[str], explored_path: str) -> None:
        """Minimal fallback for file selection when LLM completely fails"""
        from ..tools.core.task import Task, TaskType

        if not files:
            return

        added_count = 0
        # Simply take the first few files without any priority logic
        # This ensures the system can continue but doesn't make intelligent decisions
        for file in files[:2]:  # Only take 2 files to be conservative
            file_path = f"{explored_path.rstrip('/')}/{file}"
            if not self.context.is_file_analyzed(file_path):
                read_task = Task(type=TaskType.READ, target=file_path, priority=50)
                self.task_queue.add_task(read_task)
                print(f"  [MINIMAL-FALLBACK] Added file: {file} (LLM unavailable)")
                added_count += 1

        print(f"  [MINIMAL-FALLBACK] Added {added_count} files (no LLM intelligence available)")
    
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
                    if file_result.get("success") and "content" in file_result.get("result", {}):
                        content = file_result["result"]["content"]
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
                            "remediation": finding.get("remediation", "Review and fix security issue"),
                            "exploitability": finding.get("exploitability", "Unknown"),
                            "analysis_method": "llm_driven"
                        }
                        findings.append(finding_dict)

                    print(f"  [SECURITY] Found {len(findings)} issues in {file_path.split('/')[-1]}")

            except Exception as e:
                print(f"  [ERROR] Failed to parse LLM security analysis for {file_path}: {e}")
                # Fallback to simple pattern matching
                findings.extend(self._fallback_security_analysis(file_path, content))
        else:
            print(f"  [FALLBACK] LLM security analysis failed for {file_path}, using pattern matching")
            findings.extend(self._fallback_security_analysis(file_path, content))

        return findings

    def _fallback_security_analysis(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Simple fallback security analysis using pattern matching"""
        findings = []

        # Basic injection patterns
        injection_patterns = [
            (r"eval\s*\(", "Code Injection", "HIGH"),
            (r"exec\s*\(", "Code Injection", "HIGH"),
            (r"os\.system", "Command Injection", "HIGH"),
            (r"subprocess\.(call|Popen|run).*\+", "Command Injection", "HIGH"),
            (r"cursor\.execute.*\+", "SQL Injection", "HIGH"),
            (r"innerHTML.*\+", "XSS Vulnerability", "MEDIUM")
        ]

        # Secret patterns
        secret_patterns = [
            (r"(?i)(api[_-]?key|secret[_-]?key|password|token)[\s]*[=:][\s]*['\"]([^'\"]{10,})['\"]", "Hardcoded Secret", "CRITICAL"),
            (r"(?i)(bearer|authorization)[\s]*[=:][\s]*['\"]([^'\"]{10,})['\"]", "Hardcoded Token", "CRITICAL")
        ]

        for pattern, vuln_type, severity in injection_patterns + secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "file_path": file_path,
                    "vulnerability_type": vuln_type,
                    "severity": severity,
                    "line_number": content[:match.start()].count('\n') + 1,
                    "description": f"Potential {vuln_type.lower()} detected",
                    "analysis_method": "pattern_matching_fallback"
                })

        return findings

    def _make_autonomous_decision(self, decision_type: str, **kwargs) -> None:
        """Unified LLM-driven autonomous decision making for exploration and content analysis"""

        # Get comprehensive analysis history for LLM context
        history_context = self._build_history_context()

        # Build decision-specific context and prompt
        if decision_type == "exploration":
            decision_context = self._build_exploration_decision_context(**kwargs)
            decision_prompt = self._build_exploration_decision_prompt(history_context, decision_context)
            validation_func = self._validate_decisions
            execution_func = self._execute_llm_decisions
            fallback_func = self._simple_fallback_exploration
        elif decision_type == "content":
            decision_context = self._build_content_decision_context(**kwargs)
            decision_prompt = self._build_content_decision_prompt(history_context, decision_context)
            validation_func = self._validate_decisions
            execution_func = self._execute_content_follow_up
            fallback_func = lambda *args: self._simple_security_followup(kwargs.get('file_path', ''), kwargs.get('content', ''))
        else:
            print(f"  [ERROR] Unknown decision type: {decision_type}")
            return

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
            max_tokens=1000 if decision_type == "exploration" else 800,
            temperature=0.4,
            timeout=30 if decision_type == "exploration" else 25,
            max_retries=3 if decision_type == "exploration" else 2
        )

        if decision_text:
            decisions = self._parse_llm_decision(decision_text)

            # Validate decisions based on type and track execution results
            if decision_type == "exploration":
                validated_decisions = validation_func(decisions, kwargs.get('files', []),
                                                     kwargs.get('dirs', []),
                                                     decision_type="exploration")
                tasks_added = execution_func(validated_decisions, kwargs.get('explored_path', ''))
                # Store the count of autonomous decisions and the actual decisions
                current_count = self.context.get_data("autonomous_decisions", 0)
                self.context.set_data("autonomous_decisions", current_count + tasks_added)
                # Store the actual decisions for trace logging
                if validated_decisions and validated_decisions.get("analysis_targets"):
                    self.context.set_data("last_llm_decisions", validated_decisions["analysis_targets"])
            elif decision_type == "content":
                current_dir_files, current_dir_dirs, unexplored_subdirs = self._get_content_decision_data()
                validated_decisions = validation_func(decisions, current_dir_files,
                                                     current_dir_dirs, unexplored_subdirs,
                                                     decision_type="content")
                tasks_added = execution_func(validated_decisions, kwargs.get('file_path', ''))
                # Store the count of autonomous decisions and the actual decisions
                current_count = self.context.get_data("autonomous_decisions", 0)
                self.context.set_data("autonomous_decisions", current_count + tasks_added)
                # Store the actual decisions for trace logging
                if validated_decisions and validated_decisions.get("follow_up_targets"):
                    self.context.set_data("last_llm_decisions", validated_decisions["follow_up_targets"])
        else:
            print(f"  [LLM_ERROR] Max retries reached for {decision_type} decision - skipping autonomous decision making")
            print("  Analysis will continue with current task queue")

    def _build_exploration_decision_context(self, explored_path: str, files: List[str], dirs: List[str]) -> Dict:
        """Build exploration decision context"""
        # Get repository structure for better exploration decisions
        unexplored_areas = []
        root_unexplored = []

        try:
            explored_dirs = list(self.context.get_explored_directories())

            # Get subdirectories of explored directories
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
            for item in (self.repo_path / ".").iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    dir_name = item.name
                    if dir_name not in explored_dirs and dir_name not in ['node_modules', '__pycache__', '.git', 'build', 'dist']:
                        root_unexplored.append(dir_name)

        except Exception:
            pass

        return {
            "explored_path": explored_path,
            "files": files,
            "dirs": dirs,
            "unexplored_areas": unexplored_areas,
            "root_unexplored": root_unexplored
        }

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

    def _build_content_decision_context(self, file_path: str, content: str, security_result: Dict) -> Dict:
        """Build content decision context"""
        content_context = self._build_content_context(file_path, content, security_result)

        # Get current repository structure
        current_dir_files, current_dir_dirs, unexplored_subdirs = self._get_content_decision_data()

        # Generate related files recommendations for LLM context
        related_files_recommendations = self._generate_related_files_recommendations(file_path, content)

        return {
            "file_path": file_path,
            "content_context": content_context,
            "current_dir_files": current_dir_files,
            "current_dir_dirs": current_dir_dirs,
            "unexplored_subdirs": unexplored_subdirs,
            "related_files_recommendations": related_files_recommendations
        }

    def _get_content_decision_data(self) -> tuple:
        """Get data needed for content-based decisions"""
        current_dir_files = []
        current_dir_dirs = []
        unexplored_subdirs = []

        try:
            for item in (self.repo_path / ".").iterdir():
                if item.is_file():
                    current_dir_files.append(item.name)
                elif item.is_dir() and not item.name.startswith('.'):
                    current_dir_dirs.append(item.name)

            # Get recently explored directories for deeper exploration
            explored_dirs = list(self.context.get_explored_directories())
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
            pass

        return current_dir_files, current_dir_dirs, unexplored_subdirs

    def _build_exploration_decision_prompt(self, history_context: str, context: Dict) -> str:
        """Build exploration decision prompt"""
        exploration_context = self._build_exploration_context(context['explored_path'], context['files'], context['dirs'])
        return PromptManager.get_exploration_decision_prompt(
            history_context=history_context,
            exploration_context=exploration_context,
            unexplored_areas=context['unexplored_areas'],
            root_unexplored=context['root_unexplored'],
            files=context['files'],
            dirs=context['dirs']
        )

    def _build_content_decision_prompt(self, history_context: str, context: Dict) -> str:
        """Build content decision prompt"""
        return PromptManager.get_content_decision_prompt(
            history_context=history_context,
            content_context=context['content_context'],
            current_dir_files=context['current_dir_files'],
            current_dir_dirs=context['current_dir_dirs'],
            unexplored_subdirs=context['unexplored_subdirs'],
            related_files_recommendations=context.get('related_files_recommendations')
        )

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
                print(f"  [DEBUG] Error finding directory files: {e}")

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
                    print(f"  [DEBUG] Error finding main files: {e}")

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

    def _validate_decisions(self, decisions: Dict, available_files: List[str] = None,
                          available_dirs: List[str] = None, unexplored_subdirs: List[str] = None,
                          decision_type: str = "exploration") -> Dict:
        """Unified validation for LLM decisions against available items with improved path handling"""
        available_files = available_files or []
        available_dirs = available_dirs or []
        unexplored_subdirs = unexplored_subdirs or []

        # Determine target key based on decision type
        target_key = "analysis_targets" if decision_type == "exploration" else "follow_up_targets"

        if not decisions or target_key not in decisions:
            return {target_key: [], "strategy_explanation": "no_valid_targets"}

        valid_targets = []
        original_count = len(decisions[target_key])

        for target in decisions[target_key]:
            target_path = target.get("path", "")
            target_type = target.get("type", "")

            # Normalize path for better matching
            normalized_path = target_path.strip('/')
            path_parts = normalized_path.split('/')
            item_name = path_parts[-1] if path_parts else ""

            # Validate based on type with improved path matching
            is_valid = False

            if target_type == "file":
                # Check if file exists in available files or can be found in unexplored subdirs
                if item_name in available_files:
                    is_valid = True
                    print(f"  [VALID] {decision_type.title()} file target accepted: {item_name}")
                else:
                    # Check if file might be in an unexplored subdirectory
                    for subdir in unexplored_subdirs:
                        if normalized_path.startswith(subdir) or subdir in normalized_path:
                            is_valid = True
                            print(f"  [VALID] {decision_type.title()} file target in unexplored area: {item_name}")
                            break

                if not is_valid:
                    # Final check: verify file actually exists
                    full_path = self.repo_path / normalized_path
                    if full_path.exists() and full_path.is_file() and not self.context.is_file_analyzed(normalized_path):
                        is_valid = True
                        print(f"  [VALID] {decision_type.title()} file exists and not analyzed: {item_name}")

                if not is_valid:
                    print(f"  [REJECT] {decision_type.title()} file not found or already analyzed: {item_name}")

            elif target_type == "directory":
                # Check if directory exists in available directories or unexplored subdirs
                if item_name in available_dirs:
                    is_valid = True
                    print(f"  [VALID] {decision_type.title()} directory target accepted: {item_name}")
                else:
                    # Check if directory is in unexplored subdirs
                    for subdir in unexplored_subdirs:
                        subdir_normalized = subdir.strip('/')
                        if (item_name == subdir_normalized or
                            normalized_path == subdir_normalized or
                            normalized_path.endswith(subdir_normalized) or
                            subdir_normalized.endswith(normalized_path)):
                            is_valid = True
                            # Use the original path from unexplored list
                            target["path"] = subdir
                            print(f"  [VALID] {decision_type.title()} directory in unexplored areas: {item_name}")
                            break

                if not is_valid:
                    # Final check: verify directory actually exists and is not explored
                    full_path = self.repo_path / normalized_path
                    if full_path.exists() and full_path.is_dir() and not self.context.is_directory_explored(normalized_path):
                        is_valid = True
                        print(f"  [VALID] {decision_type.title()} directory exists and not explored: {item_name}")

                if not is_valid:
                    print(f"  [REJECT] {decision_type.title()} directory not found or already explored: {item_name}")
            else:
                print(f"  [REJECT] Invalid target type: {target_type}")

            if is_valid:
                valid_targets.append(target)

        validated_decisions = decisions.copy()
        validated_decisions[target_key] = valid_targets

        validation_type = "CONTENT" if decision_type == "content" else "EXPLORATION"
        print(f"  [{validation_type} VALIDATION] {len(valid_targets)}/{original_count} targets validated")

        return validated_decisions

    def _execute_llm_decisions(self, decisions: Dict, explored_path: str) -> None:
        """Execute decisions made by LLM"""
        from ..tools.core.task import Task, TaskType

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
                action_desc = f"Analyzing: {target_path.split('/')[-1]} ({reason})"
                print(f"  [FILE] {action_desc}")

            elif target_type == "directory":
                full_path = self.repo_path / target_path
                if not full_path.exists() or not full_path.is_dir():
                    print(f"  [SKIP] Directory not found: {target_path}")
                    continue

                task = Task(type=TaskType.EXPLORE, target=target_path,
                           priority=80 if priority == "high" else 50)
                action_desc = f"Exploring: {target_path.split('/')[-1]} ({reason})"
                print(f"  [DIR] {action_desc}")
            else:
                continue

            self.task_queue.add_task(task)
            executed_count += 1

            # Limit to prevent overload
            if executed_count >= 6:
                break

        print(f"  [SUCCESS] Added {executed_count} tasks based on LLM decisions")
        return executed_count

    def _execute_content_follow_up(self, decisions: Dict, current_file_path: str) -> None:
        """Execute follow-up decisions from content analysis"""
        from ..tools.core.task import Task, TaskType

        targets = decisions.get("follow_up_targets", [])
        executed_count = 0

        print(f"  Executing content follow-up: {decisions.get('exploration_strategy', 'No strategy')}")

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

                # Generate LLM-driven action description
                action_desc = f"LLM-directed analysis of {target_path.split('/')[-1]}"
                if reason:
                    action_desc += f" - {reason}"

                print(f"  [CONTENT-FOLLOW] {action_desc}")

            elif target_type == "directory":
                full_path = self.repo_path / target_path
                if not full_path.exists() or not full_path.is_dir():
                    print(f"  [SKIP] Follow-up directory not found: {target_path}")
                    continue

                task = Task(type=TaskType.EXPLORE, target=target_path,
                           priority=75 if priority == "high" else 55)

                # Generate LLM-driven action description
                action_desc = f"LLM-directed exploration of {target_path.split('/')[-1]}"
                if reason:
                    action_desc += f" - {reason}"

                print(f"  [CONTENT-FOLLOW] {action_desc}")
            else:
                continue

            self.task_queue.add_task(task)
            executed_count += 1

            # Limit to prevent overload
            if executed_count >= 4:
                break

        print(f"  [SUCCESS] Added {executed_count} follow-up tasks")
        return executed_count

    def _simple_fallback_exploration(self, explored_path: str, files: List[str], dirs: List[str]) -> None:
        """Simple fallback exploration when LLM fails"""
        from ..tools.core.task import Task, TaskType

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



    def _simple_security_followup(self, file_path: str, content: str) -> None:
        """Simple fallback for high-risk files"""
        from ..tools.core.task import Task, TaskType

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
        """LLM-driven strategic context reassessment"""
        try:
            print("LLM-Driven Context Reassessment...")

            # Get comprehensive analysis history for LLM context
            history_context = self._build_history_context()

            # Gather current state information
            overview = self.context_manager.get_project_overview()
            analyzed_files = list(self.context.get_analyzed_files())
            explored_dirs = list(self.context.get_explored_directories())
            security_summary = self.context_manager.get_security_summary()

            # Calculate coverage
            total_files = overview.get('total_files', 0)
            coverage = len(analyzed_files) / max(total_files, 1)

            current_state = {
                'analyzed_files': len(analyzed_files),
                'explored_dirs': len(explored_dirs),
                'high_risk_count': security_summary.get('high_risk_count', 0),
                'total_files': total_files,
                'coverage': coverage
            }

            # Find unexplored areas
            unexplored_root_dirs = []
            unexplored_subdirs = []

            try:
                # Get root directories
                root_list = self.tools.list_directory(".")
                if "result" in root_list:
                    root_dirs = root_list["result"].get("directories", [])
                    for dir_name in root_dirs:
                        if (not dir_name.startswith('.') and
                            dir_name not in explored_dirs and
                            dir_name not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                            unexplored_root_dirs.append(dir_name)

                # Get unexplored subdirectories
                for explored_dir in explored_dirs:
                    try:
                        dir_result = self.tools.list_directory(explored_dir)
                        if "result" in dir_result:
                            subdirs = dir_result["result"].get("directories", [])
                            for subdir in subdirs:
                                if (not subdir.startswith('.') and
                                        subdir not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                                    subdir_path = f"{explored_dir.rstrip('/')}/{subdir}"
                                    if not self.context.is_directory_explored(subdir_path):
                                        unexplored_subdirs.append(subdir_path)
                    except:
                        continue
            except Exception as e:
                print(f"  Error gathering unexplored areas: {e}")

            # Use LLM for strategic decision making
            model = LLMClient.get_model()
            reassessment_prompt = PromptManager.get_context_reassessment_prompt(
                history_context=history_context,
                current_state=current_state,
                unexplored_root_dirs=unexplored_root_dirs,
                unexplored_subdirs=unexplored_subdirs,
                task_queue_size=self.task_queue.size()
            )

            messages = [
                {"role": "system", "content": "You are a senior security strategist making intelligent analysis decisions based on current context and strategic goals."},
                {"role": "user", "content": reassessment_prompt}
            ]

            decision_text = LLMClient.call_llm(
                model=model,
                messages=messages,
                max_tokens=1000,
                temperature=0.3,
                timeout=30,
                max_retries=2
            )

            if decision_text:
                try:
                    import json
                    start = decision_text.find('{')
                    end = decision_text.rfind('}') + 1
                    if start != -1 and end > start:
                        json_text = decision_text[start:end]
                        decisions = json.loads(json_text)

                        # Execute LLM-driven strategic decisions
                        self._execute_reassessment_decisions(decisions, unexplored_root_dirs, unexplored_subdirs)
                        print("  [SUCCESS] LLM-driven context reassessment completed")

                except Exception as e:
                    print(f"  [ERROR] Failed to parse LLM reassessment: {e}")
                    # Fallback to minimal exploration if needed
                    if self.task_queue.size() == 0 and unexplored_root_dirs:
                        self._minimal_fallback_exploration(unexplored_root_dirs)
            else:
                print("  [LLM_ERROR] Context reassessment failed, using minimal fallback")
                if self.task_queue.size() == 0 and unexplored_root_dirs:
                    self._minimal_fallback_exploration(unexplored_root_dirs)

        except Exception as e:
            print(f"LLM-driven context reassessment failed: {e}")

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

    def _minimal_fallback_exploration(self, unexplored_root_dirs: List[str]) -> None:
        """Minimal fallback when LLM completely fails - explore first available directory"""
        if not unexplored_root_dirs:
            return

        from ..tools.core.task import Task, TaskType

        # Simply take the first directory without any priority logic
        # This ensures continuation but doesn't make intelligent strategic decisions
        target = unexplored_root_dirs[0]

        task = Task(type=TaskType.EXPLORE, target=target, priority=50)
        self.task_queue.add_task(task)
        print(f"  [MINIMAL-FALLBACK] Exploring directory: {target} (LLM unavailable)")


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
            target_path = task.target.strip('/')
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


def perform_repository_analysis(repo_path: str, max_steps: int = None, save_results: bool = True, focus: str = "security") -> Dict[str, Any]:
    """
    Function tool for performing comprehensive repository analysis
    """
    analyzer = AnalysisAgent(repo_path)
    return analyzer.analyze(max_steps=max_steps, save_results=save_results, focus=focus)


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

INTELLIGENT DECISION MAKING & PLANNING:
You have access to comprehensive context and planning tools that enable autonomous, intelligent analysis:

**Available Tools:**
1. **get_project_overview()** - Understand current project structure and analysis progress
2. **get_analysis_history()** - See what has been discovered recently
3. **get_security_summary()** - Review security findings so far
4. **get_current_todos()** - Check your current analysis tasks
5. **get_analysis_status()** - Get comprehensive analysis status and progress
6. **get_next_suggestions()** - Get AI suggestions for next priorities
7. **create_analysis_todo()** - Create prioritized analysis todos
8. **update_analysis_progress()** - Update progress on completed analysis
9. **create_comprehensive_analysis_plan()** - Generate intelligent analysis plans
10. **perform_repository_analysis()** - Execute comprehensive repository analysis

ANALYSIS WORKFLOW:

1. **Planning**: Use create_comprehensive_analysis_plan() to establish analysis priorities
2. **Context Review**: Call get_project_overview() and get_analysis_history() to understand current state
3. **Execution**: Use perform_repository_analysis() to execute the complete autonomous analysis
4. **Security Focus**: Prioritize analysis based on security findings and risk assessment
5. **Progress Tracking**: Use update_analysis_progress() to maintain analysis state
6. **Iterative Refinement**: Use get_current_todos() for continuous improvement

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

            # Context awareness tools
            FunctionTool(initialize_analysis_context),
            FunctionTool(get_project_overview),
            FunctionTool(get_analysis_history),
            FunctionTool(get_security_summary),
            FunctionTool(get_analysis_status),
            FunctionTool(get_current_todos),
            FunctionTool(get_next_suggestions),

            # Task management tools
            FunctionTool(create_analysis_todo),
            FunctionTool(update_todo_status),
            FunctionTool(update_analysis_progress),
            FunctionTool(record_analysis_result),
            FunctionTool(record_directory_structure),
            FunctionTool(create_comprehensive_analysis_plan),
        ],
    )
    
    return analysis_agent