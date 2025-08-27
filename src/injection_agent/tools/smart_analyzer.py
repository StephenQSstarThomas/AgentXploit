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
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
from dataclasses import asdict

from .core.core_tools import CoreTools
from .core.analysis_context import AnalysisContext
from .core.task import Task, TaskType
from .core.task_queue import TaskQueue
# Use late imports to avoid circular dependencies
from .executors.tool_executor import ToolExecutor
from .core.execution_logger import ExecutionLogger
from .analyzers.security_analyzer import SecurityAnalyzer
from .analyzers.pattern_detector import PatternDetector
from .analyzers.dataflow_tracker import DataflowTracker
from .analyzers.call_chain_tracer import CallChainTracer
from .ai.llm_decider import LLMHelper
from .injection_specific.security_scanner import scan_directory


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
        self.repo_path = Path(repo_path).resolve()
        self.tools = CoreTools(repo_path)
        self.context = AnalysisContext()
        self.task_queue = TaskQueue()
        # Initialize context manager with late import
        from .planners.analysis_context_manager import AnalysisContextManager
        from .analysis.context_tools import initialize_analysis_context
        
        self.context_manager = AnalysisContextManager(str(repo_path))
        initialize_analysis_context(str(repo_path))
        self.tool_executor = ToolExecutor(str(repo_path))
        self.execution_logger = ExecutionLogger()
        self.security_analyzer = SecurityAnalyzer()
        self.pattern_detector = PatternDetector()
        self.dataflow_tracker = DataflowTracker()
        self.call_chain_tracer = CallChainTracer()
        # Agents handle primary analysis decisions, LLM provides supplemental snippet analysis
        self.llm = LLMHelper()
        
    def analyze(self, max_steps: int = 150, save_results: bool = True, focus: str = "security") -> Dict[str, Any]:
        """
        Agent-driven analysis with context management support
        """
        # Record initial repository structure
        initial_structure = self.tools.list_directory("/")
        if initial_structure.get("success"):
            structure_data = initial_structure["result"]
            self.context_manager.update_project_structure("/", structure_data)
        
        # Initialize with basic exploration tasks
        from .core.task import Task, TaskType
        initial_tasks = [
            Task(type=TaskType.EXPLORE, target="/", priority=90),
            Task(type=TaskType.READ, target="/README.md", priority=70),
            Task(type=TaskType.READ, target="/pyproject.toml", priority=75),
        ]
        
        for task in initial_tasks:
            self.task_queue.add_task(task)
        
        step = 0
        findings = []
        detailed_findings = []
        security_findings = []
        
        while step < max_steps and self.task_queue.size() > 0:
            task = self.task_queue.get_next()
            if not task:
                break
                
            # Execute task using our tool executor
            result = self.tool_executor.execute(task)
            
            # Log execution
            self.execution_logger.log_execution(task, result, result.get("duration", 0))
            
            # Process results and generate follow-up tasks
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
                
                # Generate basic follow-up tasks (agents will make more intelligent decisions)
                if "result" in result:
                    files = result["result"].get("files", [])
                    for file in files[:5]:  # Limit initial auto-tasks
                        if file.endswith(".py"):
                            file_path = f"{task.target.rstrip('/')}/{file}"
                            if not self.context.is_file_analyzed(file_path):
                                read_task = Task(
                                    type=TaskType.READ,
                                    target=file_path,
                                    priority=60
                                )
                                self.task_queue.add_task(read_task)
                        
            elif task.type == TaskType.READ and result.get("success", False):
                self.context.add_analyzed_file(task.target)
                file_content = result.get("result", {}).get("content", "")
                
                if file_content:
                    # Perform security analysis
                    security_result = self.security_analyzer.analyze_file_security(task.target, file_content)
                    security_findings.append(security_result)
                    
                    # Store additional context about security findings
                    if security_result["risk_assessment"]["overall_risk"] in ["HIGH", "MEDIUM"]:
                        self.context.set_data(f"security_concern_{task.target}", True)
                    
                    # Supplemental snippet analysis for context (agents do primary analysis)
                    snippet_analysis = {}
                    try:
                        snippet_analysis = self.llm.analyze_code_snippet(file_content, task.target)
                    except Exception as e:
                        print(f"Supplemental snippet analysis failed for {task.target}: {e}")
                    
                    # Record analysis in context manager
                    analysis_data = {
                        "security_risk": security_result["risk_assessment"]["overall_risk"].lower(),
                        "key_findings": security_result.get("findings", []),
                        "lines_of_code": result.get("result", {}).get("lines", 0),
                        "supplemental_analysis": snippet_analysis.get("analysis", "")
                    }
                    self.context_manager.add_analysis_result(task.target, analysis_data)
                    
                    # Store file analysis for reporting
                    detailed_findings.append({
                        "file": task.target,
                        "content_preview": file_content[:500] + "..." if len(file_content) > 500 else file_content,
                        "lines": result.get("result", {}).get("lines", 0),
                        "security_summary": security_result.get("summary", ""),
                        "supplemental_analysis": snippet_analysis.get("analysis", "")
                    })
            
            step += 1
        
        # Run comprehensive security scan
        security_results = scan_directory(self.tools)
        
        # Get execution statistics
        execution_stats = self.execution_logger.get_summary()
        task_stats = self.task_queue.get_stats()
        
        # Aggregate security findings
        all_security_findings = []
        high_risk_files = []
        for sec_result in security_findings:
            all_security_findings.extend(sec_result.get("findings", []))
            if sec_result["risk_assessment"]["overall_risk"] == "HIGH":
                high_risk_files.append(sec_result["file_path"])
        
        # Compile final results
        final_result = {
            "analysis_info": {
                "repository_path": str(self.repo_path),
                "analysis_timestamp": datetime.now().isoformat(),
                "analyzer_version": "3.0.0-modular",
                "focus": focus
            },
            "execution_summary": {
                "steps_completed": step,
                "max_steps": max_steps,
                "status": "completed" if step < max_steps else "max_steps_reached",
                "execution_stats": execution_stats,
                "task_stats": task_stats
            },
            "discovered_structure": {
                "explored_directories": self.context.get_explored_directories(),
                "analyzed_files": self.context.get_analyzed_files(),
                "total_directories": len(self.context.get_explored_directories()),
                "total_files": len(self.context.get_analyzed_files()),
                "context_summary": self.context.get_summary()
            },
            "analysis_findings": detailed_findings,
            "security_analysis": {
                "individual_file_results": security_findings,
                "aggregate_findings": all_security_findings,
                "high_risk_files": high_risk_files,
                "legacy_scan_results": security_results,
                "total_security_findings": len(all_security_findings)
            },
            "architectural_insights": self._generate_architectural_insights(detailed_findings),
            "context_manager_state": self.context_manager.export_context()
        }
        
        # Save results if requested
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
        """Save analysis results to central injection_agent analysis directory"""
        try:
            # Save to central analysis directory
            repo_name = self.repo_path.name or "unknown_repo"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Use central injection_agent analysis directory
            central_analysis_dir = Path("/home/shiqiu/injection_agent/analysis")
            central_analysis_dir.mkdir(exist_ok=True)
            
            filename = f"{repo_name}_static_analysis_{timestamp}.json"
            output_path = central_analysis_dir / filename
            
            # Serialize dataclass objects before saving
            serialized_results = serialize_for_json(results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serialized_results, f, indent=2, ensure_ascii=False)
            
            print(f"Analysis results saved to: {output_path}")
            
        except Exception as e:
            print(f"Warning: Could not save to central directory: {e}")
            # Fallback to current directory
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                repo_name = self.repo_path.name or "unknown_repo"
                fallback_path = Path(f"{repo_name}_analysis_results_{timestamp}.json")
                serialized_results = serialize_for_json(results)
                with open(fallback_path, 'w', encoding='utf-8') as f:
                    json.dump(serialized_results, f, indent=2, ensure_ascii=False)
                print(f"Analysis results saved to fallback location: {fallback_path}")
            except Exception as e2:
                print(f"Failed to save analysis results: {e2}")
    
    def _execute_task(self, task) -> Dict[str, Any]:
        """Execute a single task"""
        if task.type == "explore":
            return self.tools.list_directory(task.target)
        elif task.type == "read":
            return self.tools.read_file(task.target)
        elif task.type == "analyze":
            file_result = self.tools.read_file(task.target)
            if "error" not in file_result:
                return self.llm.analyze_code_snippet(
                    file_result["content"], 
                    task.target
                )
            return file_result
        else:
            return {"error": f"Unknown task type: {task.type}"}


# analyze_repository function removed to prevent circular imports
# Use Analyzer class directly instead