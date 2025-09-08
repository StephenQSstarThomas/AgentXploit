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
Decision engine for autonomous analysis decisions
Moved from analysis_agent.py to planning module for better organization
"""

from typing import Dict, List, Any, Optional
from pathlib import Path
import os
import json

from ..core.llm_client import LLMClient
from ..core.history_compactor import HistoryCompactor
from ..core.path_manager import PathManager
from ..prompt_manager import PromptManager


class DecisionEngine:
    """Handles autonomous decision making for analysis agent"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.history_compactor = HistoryCompactor()
        self.path_manager = PathManager(repo_path)
    
    def make_autonomous_decision(self, decision_type: str, context_manager, task_queue, 
                                analyzed_files: set, explored_dirs: set, focus: str = "security", **kwargs) -> Dict[str, Any]:
        """
        Make autonomous decisions based on analysis context
        Returns decision results for trace logging
        """
        decision_result = {
            "decisions_made": 0,
            "tasks_added": 0,
            "decision_details": []
        }
        
        try:
            # Build comprehensive history context
            history_context = self.build_history_context(context_manager, analyzed_files, explored_dirs)
            
            # Decision logic based on type
            if decision_type == "exploration":
                result = self._handle_exploration_decision(
                    history_context, task_queue, kwargs.get('explored_path'), 
                    kwargs.get('files', []), kwargs.get('dirs', []), focus
                )
                decision_result.update(result)
            elif decision_type == "content":
                result = self._handle_content_decision(
                    history_context, task_queue, kwargs.get('file_path'), 
                    kwargs.get('content'), kwargs.get('security_result', {}), focus
                )
                decision_result.update(result)
                
        except Exception as e:
            print(f"  Decision making failed: {e}")
            
        return decision_result

    def build_history_context(self, context_manager, analyzed_files: set, explored_dirs: set) -> str:
        """
        Build comprehensive analysis history context
        Moved from AnalysisAgent._build_history_context
        """
        try:
            overview = context_manager.get_project_overview()
            security_summary = context_manager.get_security_summary()
            
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
            
            # List explored directories
            for dir_path in sorted(explored_dirs):
                history += f"- {dir_path}\n"
                
            history += f"\nANALYZED FILES (DO NOT RE-ANALYZE):\n"
            
            # List analyzed files with risk levels
            for file_path in sorted(analyzed_files):
                file_info = context_manager.get_analysis_result(file_path)
                risk = file_info.get('security_risk', 'unknown') if file_info else 'unknown'
                history += f"- {file_path}: {risk} risk\n"
                
            history += f"\nCURRENT ANALYSIS STATE:\n"
            history += f"- Repository root: {self.repo_path}\n"
            
            # Add repository structure overview
            try:
                from ..core.core_tools import EnhancedFileReader
                tools = EnhancedFileReader(str(self.repo_path))
                tree_result = tools.get_tree_structure(".", max_depth=2)
                if "tree_output" in tree_result and not tree_result.get("error"):
                    tree_lines = tree_result["tree_output"].split('\n')[:15]
                    history += f"\nREPOSITORY STRUCTURE OVERVIEW:\n" + "\n".join(tree_lines)
            except Exception:
                pass
                
            # Apply auto-compaction if needed
            compacted_history = self.history_compactor.compact_if_needed(history)
            return compacted_history
            
        except Exception as e:
            return f"Analysis History: Limited context available (error: {e})"
    
    def _handle_exploration_decision(self, history_context: str, task_queue, explored_path: str, 
                                   files: List[str], dirs: List[str], focus: str = "security") -> Dict[str, Any]:
        """Handle exploration-based autonomous decisions with enhanced prompts"""
        result = {"decisions_made": 0, "tasks_added": 0, "decision_details": []}
        
        from ..prompt_manager import PromptManager
        
        # Build exploration context with repository information
        # Validate that explored_path is within the current repository
        repo_abs_path = str(Path(self.repo_path).resolve())
        if explored_path and explored_path != "." and not os.path.isabs(explored_path):
            explored_abs_path = str(Path(self.repo_path, explored_path).resolve())
            if not explored_abs_path.startswith(repo_abs_path):
                # Reset to repository root if path is stale
                explored_path = "."
                print(f"  [PATH_FIX] Reset stale explored_path to repository root")
        
        exploration_context = f"Repository: {Path(self.repo_path).name}, Currently exploring: {explored_path}"
        prompt = PromptManager.get_exploration_decision_prompt(
            history_context=history_context,
            exploration_context=exploration_context,
            unexplored_areas=[],  # 暂时为空，可以后续扩展
            root_unexplored=[],   # 暂时为空，可以后续扩展
            files=files,
            dirs=dirs
        )
        
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are an expert code analyzer making autonomous exploration decisions."},
            {"role": "user", "content": prompt}
        ]
        
        decision_text = LLMClient.call_llm(
            model=model, messages=messages, max_tokens=800, 
            temperature=0.1, timeout=30, max_retries=2
        )
        
        if decision_text:
            decisions = self._parse_llm_decision(decision_text)
            validated_decisions = self._validate_decisions(decisions, files, dirs)
            execution_result = self._execute_llm_decisions(validated_decisions, explored_path, task_queue)
            result.update(execution_result)
        
        return result
    
    def _handle_content_decision(self, history_context: str, task_queue, file_path: str, 
                               content: str, security_result: Dict, focus: str = "security") -> Dict[str, Any]:
        """Handle content-based autonomous decisions with enhanced prompts"""
        result = {"decisions_made": 0, "tasks_added": 0, "decision_details": []}
        
        from ..prompt_manager import PromptManager
        
        # Build context with available files from current directory  
        context = self._build_content_decision_context(file_path, content, security_result)
        
        # Get current directory files for strict validation
        current_dir = str(Path(file_path).parent) if "/" in file_path else "."
        try:
            from ..core.core_tools import EnhancedFileReader
            tools = EnhancedFileReader(self.repo_path)
            dir_result = tools.list_directory(current_dir)
            context["available_files"] = dir_result.get("files", [])
            context["available_dirs"] = dir_result.get("directories", [])
        except:
            context["available_files"] = []
            context["available_dirs"] = []
            
        prompt = PromptManager.get_content_decision_prompt(history_context, context, focus)
        
        model = LLMClient.get_model()
        messages = [
            {"role": "system", "content": "You are an expert code analyzer making autonomous content analysis decisions. AVOID suggesting files that have already been analyzed (check history context)."},
            {"role": "user", "content": prompt}
        ]
        
        decision_text = LLMClient.call_llm(
            model=model, messages=messages, max_tokens=600,
            temperature=0.3, timeout=30, max_retries=2  # Increase temperature for more diverse decisions
        )
        
        if decision_text:
            decisions = self._parse_llm_decision(decision_text)
            # Filter out already analyzed files before execution
            decisions = self._filter_already_analyzed_targets(decisions, history_context)
            # Validate against available files like in exploration
            validated_decisions = self._validate_content_decisions(decisions, context["available_files"], context["available_dirs"])
            execution_result = self._execute_content_follow_up(validated_decisions, file_path, task_queue)
            result.update(execution_result)
        
        return result

    def _build_exploration_decision_context(self, explored_path: str, files: List[str], dirs: List[str]) -> Dict:
        """Build context for exploration decisions"""
        return {
            "explored_path": explored_path,
            "files_count": len(files),
            "dirs_count": len(dirs),
            "files": files[:10],  # First 10 files
            "dirs": dirs[:5]      # First 5 directories
        }
    
    def _build_content_decision_context(self, file_path: str, content: str, security_result: Dict) -> Dict:
        """Build context for content decisions"""
        return {
            "file_path": file_path,
            "content": content,
            "security_result": security_result,
            "content_length": len(content),
            "security_risk": security_result.get('risk_level', 'unknown'),
            "key_findings": security_result.get('findings', [])[:3]  # First 3 findings
        }
    
    def _build_exploration_decision_prompt(self, history_context: str, context: Dict) -> str:
        """Build prompt for exploration decisions"""
        return f"""Based on the analysis history and current exploration context, make autonomous decisions about what to analyze next.

{history_context}

CURRENT EXPLORATION CONTEXT:
- Explored Path: {context['explored_path']}
- Files Found: {context['files_count']}
- Directories Found: {context['dirs_count']}

**AVAILABLE FILES (you MUST only choose from this list):**
{chr(10).join([f"- {file}" for file in context['files']])}

**AVAILABLE DIRECTORIES (you MUST only choose from this list):**
{chr(10).join([f"- {dir_name}" for dir_name in context['dirs']])}

DECISION INSTRUCTIONS:
1. **CRITICAL**: You can ONLY select files and directories from the lists above - NO OTHER FILES
2. Choose up to 3 high-priority files for agent workflow and data flow analysis
3. Choose up to 2 directories to explore if they contain agent components
4. Focus on: tool definitions, agent configurations, data processing pipelines, LLM interfaces
5. Prioritize files that handle external input or tool outputs
6. Avoid files/directories already analyzed (see history above)

Respond ONLY in JSON format using EXACT names from the available lists:
{{"read_files": ["exact_filename1", "exact_filename2"], "explore_dirs": ["exact_dirname1", "exact_dirname2"]}}"""

    def _build_content_decision_prompt(self, history_context: str, context: Dict) -> str:
        """Build prompt for content decisions"""
        return f"""Based on the analysis history and current file analysis, make decisions about follow-up analysis.

{history_context}

CURRENT FILE ANALYSIS CONTEXT:
- File: {context['file_path']}
- Security Risk: {context['security_risk']}
- Key Findings: {', '.join(context.get('key_findings', []))}

DECISION INSTRUCTIONS:
1. **IMPORTANT**: Do NOT suggest specific file names - we will explore directories to find related files
2. Instead, suggest directories to explore for related components
3. Focus on agent workflow analysis: data flow, tool chains, LLM interfaces
4. Look for injection points where external data enters the agent pipeline

Respond ONLY in JSON format:
{{"explore_dirs": ["directory_to_explore"], "analysis_focus": ["data_flow", "tool_interfaces", "llm_input_handling"]}}"""

    def _parse_llm_decision(self, decision_text: str) -> Dict:
        """Parse LLM decision from text response"""
        try:
            # Extract JSON from response
            start_idx = decision_text.find('{')
            end_idx = decision_text.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = decision_text[start_idx:end_idx]
                return json.loads(json_str)
            return {}
        except:
            return {}
    
    def _filter_already_analyzed_targets(self, decisions: Dict, history_context: str) -> Dict:
        """Filter out targets that have already been analyzed according to history context"""
        if not history_context:
            return decisions
            
        # Extract already analyzed files from history context
        analyzed_files = set()
        analyzed_dirs = set()
        
        lines = history_context.split('\n')
        in_analyzed_section = False
        in_explored_section = False
        
        for line in lines:
            line = line.strip()
            if 'ANALYZED FILES' in line:
                in_analyzed_section = True
                in_explored_section = False
                continue
            elif 'EXPLORED DIRECTORIES' in line:
                in_explored_section = True
                in_analyzed_section = False
                continue
            elif line.startswith('-') and (in_analyzed_section or in_explored_section):
                # Extract file/directory path
                path_part = line[1:].strip()
                if ':' in path_part:
                    path_part = path_part.split(':')[0].strip()
                if in_analyzed_section:
                    analyzed_files.add(path_part)
                else:
                    analyzed_dirs.add(path_part)
            elif line and not line.startswith('-') and (in_analyzed_section or in_explored_section):
                in_analyzed_section = False
                in_explored_section = False
        
        # Filter follow_up_targets
        filtered_decisions = decisions.copy()
        if 'follow_up_targets' in decisions:
            filtered_targets = []
            for target in decisions['follow_up_targets']:
                if isinstance(target, dict):
                    target_path = target.get('path', '')
                    target_type = target.get('type', 'file')
                    
                    if target_type == 'file' and target_path not in analyzed_files:
                        filtered_targets.append(target)
                    elif target_type == 'directory' and target_path not in analyzed_dirs:
                        filtered_targets.append(target)
                    # Skip if already analyzed
                else:
                    filtered_targets.append(target)  # Keep non-dict targets as-is
            filtered_decisions['follow_up_targets'] = filtered_targets
        
        # Filter explore_dirs (legacy support)
        if 'explore_dirs' in decisions:
            filtered_dirs = [d for d in decisions['explore_dirs'] if d not in analyzed_dirs]
            filtered_decisions['explore_dirs'] = filtered_dirs
            
        return filtered_decisions
    
    def _validate_decisions(self, decisions: Dict, available_files: List[str] = None, 
                          available_dirs: List[str] = None) -> Dict:
        """Validate LLM decisions with improved path matching"""
        validated = {"analysis_targets": [], "strategy_explanation": ""}
        
        # Extract strategy explanation
        validated["strategy_explanation"] = decisions.get("strategy_explanation", "No strategy provided")
        
        # Validate and convert analysis targets
        analysis_targets = decisions.get("analysis_targets", [])
        if isinstance(analysis_targets, list):
            for target in analysis_targets[:6]:  # Limit to 6 targets
                if isinstance(target, dict) and "path" in target:
                    target_path = target["path"]
                    target_type = target.get("type", "file")
                    
                    print(f"  [VALIDATION_DEBUG] Checking {target_type}: '{target_path}'")
                    if target_type == "file":
                        file_match = target_path in available_files if available_files else False
                        print(f"    File match: {file_match} (in {len(available_files) if available_files else 0} available files)")
                    else:
                        dir_match = target_path in available_dirs if available_dirs else False
                        print(f"    Dir match: {dir_match} (in {len(available_dirs) if available_dirs else 0} available dirs)")
                        if not dir_match and available_dirs:
                            print(f"    Available dirs: {available_dirs[:10]}...")
                    
                    # Improved validation with better path matching
                    is_valid = False
                    
                    if target_type == "file" and available_files:
                        # Only allow exact matches - remove fuzzy matching to prevent hallucinated files
                        if target_path in available_files:
                            is_valid = True
                        else:
                            print(f"  [VALIDATION] File '{target_path}' not found in available files: {available_files[:5]}")
                    elif target_type == "directory" and available_dirs:
                        # Only allow exact matches - remove fuzzy matching to prevent hallucinated dirs  
                        if target_path in available_dirs:
                            is_valid = True
                        else:
                            print(f"  [VALIDATION] Directory '{target_path}' not found in available dirs: {available_dirs[:5]}")
                    
                    if is_valid:
                        validated["analysis_targets"].append(target)
                        print(f"  [VALIDATION] Accepted {target_type}: {target_path}")
                    else:
                        print(f"  [VALIDATION] Rejected {target_type}: {target_path} (not in available lists)")
        
        print(f"  [VALIDATION] {len(validated['analysis_targets'])}/{len(analysis_targets)} targets validated")
        return validated

    def _validate_content_decisions(self, decisions: Dict, available_files: List[str] = None, 
                                   available_dirs: List[str] = None) -> Dict:
        """Validate content follow-up decisions against available files"""
        validated = {"follow_up_targets": []}
        
        follow_up_targets = decisions.get("follow_up_targets", [])
        if isinstance(follow_up_targets, list):
            for target in follow_up_targets:
                if isinstance(target, dict) and "path" in target:
                    target_path = target["path"]
                    target_type = target.get("type", "file")
                    
                    print(f"  [CONTENT_VALIDATION] Checking {target_type}: '{target_path}'")
                    
                    # Simple validation like in exploration
                    is_valid = False
                    if target_type == "file" and available_files:
                        if target_path in available_files:
                            is_valid = True
                        else:
                            print(f"  [CONTENT_VALIDATION] File '{target_path}' not in available files: {available_files[:5]}")
                    elif target_type == "directory" and available_dirs:
                        if target_path in available_dirs:
                            is_valid = True
                        else:
                            print(f"  [CONTENT_VALIDATION] Directory '{target_path}' not in available dirs: {available_dirs[:5]}")
                    
                    if is_valid:
                        validated["follow_up_targets"].append(target)
                        print(f"  [CONTENT_VALIDATION] Accepted {target_type}: {target_path}")
                    else:
                        print(f"  [CONTENT_VALIDATION] Rejected {target_type}: {target_path} (not available)")
        
        print(f"  [CONTENT_VALIDATION] {len(validated['follow_up_targets'])}/{len(follow_up_targets)} targets validated")
        return validated
    
    def _execute_llm_decisions(self, decisions: Dict, explored_path: str, task_queue) -> Dict[str, Any]:
        """Execute validated LLM decisions using unified path manager"""
        from ..core.task import Task, TaskType
        
        result = {
            "decisions_made": 0,
            "tasks_added": 0,
            "decision_details": []
        }
        
        # Process analysis targets from validated decisions using path manager
        analysis_targets = decisions.get("analysis_targets", [])
        if analysis_targets:
            # Resolve all paths using the unified path manager
            resolved_targets = self.path_manager.resolve_exploration_paths(analysis_targets, explored_path)
            
            for target in resolved_targets:
                target_path = target.get("path", "")
                original_path = target.get("original_path", target_path)
                target_type = target.get("type", "file")
                priority_level = target.get("priority", "medium")
                reason = target.get("reason", "LLM autonomous decision")
                
                print(f"  [PATH_MANAGER] Resolved {target_type}: '{original_path}' -> '{target_path}'")
                
                # Assign priority directly based on LLM selection
                priority_values = {"high": 90, "medium": 70, "low": 50}
                base_priority = priority_values.get(priority_level, 70)
                # Add a small boost for LLM-selected paths
                priority = min(base_priority + 5, 100)
                
                # Create appropriate task
                if target_type == "file":
                    task = Task(
                        type=TaskType.READ, 
                        target=target_path, 
                        priority=priority,
                        focus_driven=True
                    )
                else:  # directory
                    task = Task(
                        type=TaskType.EXPLORE, 
                        target=target_path, 
                        priority=priority,
                        focus_driven=True
                    )
                
                task_queue.add_task(task)
                result["tasks_added"] += 1
                result["decision_details"].append({
                    "type": target_type,
                    "path": target_path,
                    "original_path": original_path,
                    "priority": priority,
                    "reason": reason
                })
        
        result["decisions_made"] = len(analysis_targets)
        return result
    
    def _execute_content_follow_up(self, decisions: Dict, current_file_path: str, task_queue) -> Dict[str, Any]:
        """Execute content-based follow-up decisions with unified path manager"""
        from ..core.task import Task, TaskType
        
        result = {
            "decisions_made": 0,
            "tasks_added": 0,
            "decision_details": []
        }
        
        # Use path manager to handle content follow-up paths correctly
        follow_up_files = decisions.get("follow_up_targets", [])
        if follow_up_files:
            # Resolve all paths using the unified path manager with current file context
            resolved_targets = self.path_manager.resolve_content_follow_up_paths(follow_up_files, current_file_path)
            
            for target_info in resolved_targets:
                target_path = target_info.get("path", "")
                original_path = target_info.get("original_path", target_path)
                target_type = target_info.get("type", "file")
                reason = target_info.get("reason", "content-based follow-up")
                
                print(f"  [CONTENT_FOLLOW_UP] Resolved {target_type}: '{original_path}' -> '{target_path}'")
                
                # Create task with resolved path
                if target_type == "file":
                    task = Task(TaskType.READ, target_path, priority=87)
                    task_queue.add_task(task)
                    print(f"  [CONTENT_FOLLOW_UP] Added READ task: {target_path}")
                    result["tasks_added"] += 1
                    result["decision_details"].append({
                        "type": "file",
                        "path": target_path,
                        "original_path": original_path,
                        "reason": reason
                    })
                elif target_type == "directory":
                    task = Task(TaskType.EXPLORE, target_path, priority=82)
                    task_queue.add_task(task)
                    print(f"  [CONTENT_FOLLOW_UP] Added EXPLORE task: {target_path}")
                    result["tasks_added"] += 1
                    result["decision_details"].append({
                        "type": "directory",
                        "path": target_path,
                        "original_path": original_path,
                        "reason": reason
                    })
        
        # Legacy support for simple explore_dirs list - also use path manager
        explore_dirs = decisions.get("explore_dirs", [])
        if explore_dirs:
            # Convert to target format and resolve
            legacy_targets = [{"path": dir_name, "type": "directory"} for dir_name in explore_dirs]
            resolved_legacy = self.path_manager.resolve_content_follow_up_paths(legacy_targets, current_file_path)
            
            for target_info in resolved_legacy:
                dir_path = target_info.get("path", "")
                original_path = target_info.get("original_path", dir_path)
                
                task = Task(TaskType.EXPLORE, dir_path, priority=85)  # High priority
                task_queue.add_task(task)
                result["tasks_added"] += 1
                result["decision_details"].append({
                    "type": "explore",
                    "path": dir_path,
                    "original_path": original_path,
                    "reason": "Content analysis - related directory"
                })
        
        result["decisions_made"] = len(follow_up_files) + len(explore_dirs)
        
        if result["decisions_made"] > 0:
            print(f"  [CONTENT-AUTONOMOUS] Added {result['tasks_added']} content follow-up tasks")
        
        return result
    
    def autonomous_context_reassessment(self, context_manager, task_queue, context, tools) -> None:
        """LLM-driven strategic context reassessment - moved from AnalysisAgent"""
        try:
            print("LLM-Driven Context Reassessment...")

            # Get comprehensive analysis history for LLM context
            analyzed_files = set(context.get_analyzed_files())
            explored_dirs = set(context.get_explored_directories())
            history_context = self.build_history_context(context_manager, analyzed_files, explored_dirs)

            # Gather current state information
            overview = context_manager.get_project_overview()
            analyzed_files_list = list(analyzed_files)
            explored_dirs_list = list(explored_dirs)
            security_summary = context_manager.get_security_summary()

            # Calculate coverage
            total_files = overview.get('total_files', 0)
            coverage = len(analyzed_files_list) / max(total_files, 1)

            current_state = {
                'analyzed_files': len(analyzed_files_list),
                'explored_dirs': len(explored_dirs_list),
                'high_risk_count': security_summary.get('high_risk_count', 0),
                'total_files': total_files,
                'coverage': coverage
            }

            # Find unexplored areas
            unexplored_root_dirs = []
            unexplored_subdirs = []

            try:
                # Get root directories
                root_list = tools.list_directory(".")
                if "error" not in root_list:
                    root_dirs = root_list.get("directories", [])
                    for dir_name in root_dirs:
                        if (not dir_name.startswith('.') and
                            dir_name not in explored_dirs and
                            dir_name not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                            unexplored_root_dirs.append(dir_name)

                # Get unexplored subdirectories
                for explored_dir in explored_dirs_list:
                    try:
                        dir_result = tools.list_directory(explored_dir)
                        if "error" not in dir_result:
                            subdirs = dir_result.get("directories", [])
                            for subdir in subdirs:
                                if (not subdir.startswith('.') and
                                        subdir not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                                    subdir_path = f"{explored_dir.rstrip('/')}/{subdir}"
                                    if not context.is_directory_explored(subdir_path):
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
                task_queue_size=task_queue.size()
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
                    start = decision_text.find('{')
                    end = decision_text.rfind('}') + 1
                    if start != -1 and end > start:
                        json_text = decision_text[start:end]
                        decisions = json.loads(json_text)

                        # Execute LLM-driven strategic decisions
                        self._execute_reassessment_decisions(decisions, unexplored_root_dirs, unexplored_subdirs, task_queue)
                        print("  [SUCCESS] LLM-driven context reassessment completed")

                except Exception as e:
                    print(f"  [ERROR] Failed to parse LLM reassessment: {e}")
                    # # Fallback to minimal exploration if needed (COMMENTED OUT FOR TESTING)
                    # if task_queue.size() == 0 and unexplored_root_dirs:
                    #     from ..core.task import Task, TaskType
                    #     task = Task(TaskType.EXPLORE, unexplored_root_dirs[0], priority=5)
                    #     task_queue.add_task(task)
                    print("  LLM reassessment failed")

        except Exception as e:
            print(f"  Context reassessment failed: {e}")

    def _execute_reassessment_decisions(self, decisions: Dict, unexplored_root_dirs: List[str], 
                                      unexplored_subdirs: List[str], task_queue) -> None:
        """Execute strategic reassessment decisions with proper next_actions format support"""
        from ..core.task import Task, TaskType
        
        tasks_added = 0
        
        # Parse new next_actions format with unified validation
        next_actions = decisions.get("next_actions", [])
        if next_actions:
            print(f"  [LLM-DECISION] Processing {len(next_actions)} strategic actions...")
            
            for action_info in next_actions[:4]:  # Limit to 4 actions for sustained analysis
                if not isinstance(action_info, dict):
                    print(f"    [SKIP] Invalid action format: {action_info}")
                    continue
                    
                action = action_info.get("action", "").strip()
                target = action_info.get("target", "").strip()
                priority_str = action_info.get("priority", "medium").strip().lower()
                reason = action_info.get("reason", "LLM strategic decision")
                expected_value = action_info.get("expected_value", "general")
                
                if not target or not action:
                    print(f"    [SKIP] Missing action or target: action='{action}', target='{target}'")
                    continue
                
                # Use unified path validation and resolution
                normalized_target, is_valid, validation_reason = self.path_manager.validate_and_resolve_target(target, action)
                if not is_valid:
                    print(f"    [SKIP] {validation_reason}: {target}")
                    continue
                
                # 使用与LLM priority assessment相同的逻辑
                if priority_str == "high":
                    priority = 95  # Very high priority
                elif priority_str == "medium":
                    priority = 80  # High priority  
                else:
                    priority = 60  # Low priority
                
                # Additional context validation for exploration
                if action == "explore_directory":
                    # Check if target is in unexplored areas or reasonably accessible
                    context_valid = (
                        any(target in area_list for area_list in [unexplored_root_dirs, unexplored_subdirs]) or
                        len(normalized_target.split("/")) <= 4  # Allow reasonable depth
                    )
                    if not context_valid:
                        print(f"    [SKIP] Path not in exploration context: {target}")
                        continue
                
                # Create and add task
                if action == "explore_directory":
                    task = Task(TaskType.EXPLORE, normalized_target, priority=priority)
                    action_display = "EXPLORE"
                elif action == "analyze_file":
                    task = Task(TaskType.READ, normalized_target, priority=priority)
                    action_display = "READ"
                else:
                    print(f"    [SKIP] Unknown action: {action}")
                    continue
                
                task_queue.add_task(task)
                tasks_added += 1
                print(f"    [+] {action_display} {normalized_target} (priority: {priority}) - {reason}")
        
        # Simplified fallback for backward compatibility
        if not next_actions:
            print("  [FALLBACK] Using simplified legacy format...")
            
            # Process any legacy formats through the same validation pipeline
            legacy_actions = []
            
            # Convert legacy explore_directories
            for dir_name in decisions.get("explore_directories", [])[:3]:
                if dir_name in unexplored_root_dirs or dir_name in unexplored_subdirs:
                    legacy_actions.append({
                        "action": "explore_directory",
                        "target": dir_name,
                        "priority": "medium",
                        "reason": "Legacy fallback exploration"
                    })
            
            # Convert legacy read_files
            for file_path in decisions.get("read_files", [])[:3]:
                legacy_actions.append({
                    "action": "analyze_file", 
                    "target": file_path,
                    "priority": "medium",
                    "reason": "Legacy fallback analysis"
                })
                
            # Process through same validation pipeline
            for action_info in legacy_actions:
                target = action_info["target"]
                action = action_info["action"]
                
                normalized_target, is_valid, validation_reason = self.path_manager.validate_and_resolve_target(target, action)
                if is_valid:
                    # 使用与LLM priority assessment相同的逻辑
                    priority_str = action_info["priority"]
                    if priority_str == "high":
                        priority = 95  # Very high priority
                    elif priority_str == "medium":
                        priority = 80  # High priority  
                    else:
                        priority = 60  # Low priority
                    
                    if action == "explore_directory":
                        task = Task(TaskType.EXPLORE, normalized_target, priority=priority)
                        print(f"    [+] EXPLORE {normalized_target} (legacy, priority: {priority})")
                    else:
                        task = Task(TaskType.READ, normalized_target, priority=priority)
                        print(f"    [+] READ {normalized_target} (legacy, priority: {priority})")
                    
                    task_queue.add_task(task)
                    tasks_added += 1
        
        if tasks_added > 0:
            print(f"  [SUCCESS] Added {tasks_added} strategic LLM-driven tasks to queue")
        else:
            print("  [WARNING] No valid tasks extracted from LLM decisions")
            # # Emergency fallback - add at least one exploration task (COMMENTED OUT FOR TESTING)
            # if unexplored_root_dirs:
            #     emergency_target = unexplored_root_dirs[0]
            #     task = Task(TaskType.EXPLORE, emergency_target, priority=60)
            #     task_queue.add_task(task)
            #     print(f"  [EMERGENCY] Added fallback exploration: {emergency_target}")
            print("  No valid LLM decisions extracted")