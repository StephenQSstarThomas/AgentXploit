"""
Exploration strategies for Analysis Agent
Separated from main agent to improve code organization
"""

from typing import Dict, List, Any
from pathlib import Path
import os

class ExplorationStrategies:
    """Helper class for exploration strategies in Analysis Agent"""
    
    def __init__(self, tools, context, context_manager, task_queue):
        self.tools = tools
        self.context = context
        self.context_manager = context_manager
        self.task_queue = task_queue
    
    def get_unexplored_areas(self) -> Dict[str, List[str]]:
        """Get unexplored directories for sustained exploration"""
        explored_dirs = set(self.context.get_explored_directories())
        unexplored_root_dirs = []
        unexplored_subdirs = []
        
        try:
            # Get root directories
            root_list = self.tools.list_directory(".")
            if "error" not in root_list:
                root_dirs = root_list.get("directories", [])
                for dir_name in root_dirs:
                    if (not dir_name.startswith('.') and
                        dir_name not in explored_dirs and
                        dir_name not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                        unexplored_root_dirs.append(dir_name)

            # Get unexplored subdirectories from analyzed directories
            for explored_dir in list(explored_dirs)[:10]:  # Limit to avoid too many
                try:
                    dir_result = self.tools.list_directory(explored_dir)
                    if "error" not in dir_result:
                        subdirs = dir_result.get("directories", [])
                        for subdir in subdirs:
                            if not subdir.startswith('.'):
                                subdir_path = f"{explored_dir.rstrip('/')}/{subdir}"
                                if (not self.context.is_directory_explored(subdir_path) and
                                    subdir not in ['node_modules', '__pycache__', '.git', 'build', 'dist']):
                                    unexplored_subdirs.append(subdir_path)
                except:
                    continue
                    
        except Exception as e:
            print(f"  Error gathering unexplored areas: {e}")
            
        return {
            'root_dirs': unexplored_root_dirs[:10],  # Limit results
            'subdirs': unexplored_subdirs[:20]
        }

    def force_exploration_tasks(self, unexplored_areas: Dict[str, List[str]]) -> None:
        """Force creation of exploration tasks for unexplored areas"""
        from ..tools.core.task import Task, TaskType
        
        tasks_added = 0
        
        # Add root directory exploration tasks
        for dir_name in unexplored_areas['root_dirs'][:3]:  # Limit to 3
            task = Task(TaskType.EXPLORE, dir_name, priority=80)
            self.task_queue.add_task(task)
            tasks_added += 1
            print(f"  [FORCE] Added exploration task: {dir_name}")
        
        # Add subdirectory exploration tasks  
        for subdir_path in unexplored_areas['subdirs'][:2]:  # Limit to 2
            task = Task(TaskType.EXPLORE, subdir_path, priority=75)
            self.task_queue.add_task(task)
            tasks_added += 1
            print(f"  [FORCE] Added subdir exploration: {subdir_path}")
            
        if tasks_added > 0:
            print(f"  [FORCE] Added {tasks_added} forced exploration tasks")

    def create_deep_exploration_tasks(self) -> int:
        """Create tasks for deep exploration of previously analyzed directories"""
        from ..tools.core.task import Task, TaskType
        
        explored_dirs = list(self.context.get_explored_directories())
        tasks_added = 0
        
        # Deep dive into analyzed directories - look for more files
        for explored_dir in explored_dirs[:5]:  # Limit to 5 directories
            try:
                dir_result = self.tools.list_directory(explored_dir)
                if "error" not in dir_result:
                    files = dir_result.get("files", [])
                    analyzed_files = set(self.context.get_analyzed_files())
                    
                    # Find unanalyzed files in explored directories
                    for file_name in files[:10]:  # Limit to 10 files per dir
                        file_path = f"{explored_dir.rstrip('/')}/{file_name}" if explored_dir != "." else file_name
                        if (file_path not in analyzed_files and
                            not file_name.startswith('.') and
                            file_name.endswith(('.py', '.js', '.ts', '.java', '.go', '.rs', '.cpp', '.c', '.php'))):
                            task = Task(TaskType.READ, file_path, priority=70)
                            self.task_queue.add_task(task)
                            tasks_added += 1
                            print(f"  [DEEP] Added deep analysis: {file_path}")
                            
                            if tasks_added >= 5:  # Limit total deep tasks
                                break
                                
                if tasks_added >= 5:
                    break
                    
            except Exception as e:
                print(f"  Error in deep exploration of {explored_dir}: {e}")
                continue
                
        print(f"  [DEEP] Added {tasks_added} deep exploration tasks")
        return tasks_added
    
    def smart_fallback_strategy(self, step_count: int, analysis_context: Dict) -> bool:
        """
        Unified intelligent fallback strategy based on analysis state
        Returns True if tasks were added, False if analysis should end
        """
        from ..tools.core.task import Task, TaskType
        from ..tools.core.path_validator import PathValidator
        
        # Initialize path validator
        path_validator = PathValidator(str(self.context.repo_path) if hasattr(self.context, 'repo_path') else None)
        
        tasks_added = 0
        analyzed_files = set(self.context.get_analyzed_files())
        explored_dirs = set(self.context.get_explored_directories())
        
        print(f"  [SMART_FALLBACK] Analyzing current state (step {step_count})...")
        print(f"    Analyzed files: {len(analyzed_files)}, Explored dirs: {len(explored_dirs)}")
        
        # Strategy 1: Focus on high-value unexplored areas
        if step_count < 50:  # Early/mid analysis - aggressive exploration
            unexplored = self.get_unexplored_areas()
            high_value_targets = []
            
            # Prioritize important directories
            important_patterns = ['src', 'app', 'core', 'main', 'lib', 'api', 'server', 'client']
            for root_dir in unexplored['root_dirs']:
                if any(pattern in root_dir.lower() for pattern in important_patterns):
                    high_value_targets.append(('explore', root_dir, 'Important directory pattern'))
            
            # Add some high-value subdirectories
            for subdir in unexplored['subdirs'][:3]:
                if any(pattern in subdir.lower() for pattern in important_patterns):
                    high_value_targets.append(('explore', subdir, 'Important subdirectory'))
            
            # Execute high-value targets
            for action_type, target, reason in high_value_targets[:3]:
                # 使用与LLM priority assessment相同的逻辑
                priority = 80  # medium priority (与LLM assessment的medium一致)
                
                if action_type == 'explore':
                    task = Task(TaskType.EXPLORE, target, priority=priority)
                    self.task_queue.add_task(task)
                    tasks_added += 1
                    print(f"    [HIGH_VALUE] EXPLORE {target} (priority: {priority}) - {reason}")
        
        # Strategy 2: Intelligent file discovery in known directories
        if tasks_added == 0 and len(explored_dirs) > 0:
            print("  [FILE_DISCOVERY] Looking for unanalyzed files in explored directories...")
            
            for explored_dir in list(explored_dirs)[:3]:  # Check top 3 explored dirs
                try:
                    dir_result = self.tools.list_directory(explored_dir)
                    if "error" not in dir_result:
                        files = dir_result.get("files", [])
                        
                        # Smart file filtering using path validator
                        candidates = []
                        for file_name in files:
                            file_path = os.path.join(explored_dir, file_name) if explored_dir != "." else file_name
                            
                            if file_path not in analyzed_files:
                                is_valid, reason = path_validator.validate_target(file_path, "analyze_file")
                                if is_valid:
                                    category = path_validator.get_path_category(file_path)
                                    # 简单的boost值，不使用rule-based计算
                                    boost = 0  # 不使用复杂的boost计算，让LLM决定优先级
                                    candidates.append((file_path, category, boost, reason))
                        
                        # Sort by priority boost and add top candidates
                        candidates.sort(key=lambda x: x[2], reverse=True)
                        
                        for file_path, category, boost, reason in candidates[:2]:  # Top 2 per directory
                            # 使用与LLM priority assessment相同的逻辑 - medium priority
                            priority = 80  # medium priority (与LLM assessment的medium一致)
                            
                            task = Task(TaskType.READ, file_path, priority=priority + boost)
                            self.task_queue.add_task(task)
                            tasks_added += 1
                            print(f"    [DISCOVER] READ {file_path} (priority: {priority + boost}) - {category}")
                            
                            if tasks_added >= 4:  # Limit discoveries
                                break
                                
                    if tasks_added >= 4:
                        break
                        
                except Exception as e:
                    print(f"    Error discovering files in {explored_dir}: {e}")
                    continue
        
        # Strategy 3: Last resort - systematic remaining exploration
        if tasks_added == 0 and step_count < 80:  # Late analysis
            print("  [LAST_RESORT] Systematic exploration of remaining areas...")
            
            unexplored = self.get_unexplored_areas()
            remaining_targets = unexplored['root_dirs'][:2] + unexplored['subdirs'][:2]
            
            for target in remaining_targets:
                # 使用与LLM priority assessment相同的逻辑 - low priority
                priority = 60  # low priority (与LLM assessment的low一致)
                
                task = Task(TaskType.EXPLORE, target, priority=priority)
                self.task_queue.add_task(task)
                tasks_added += 1
                print(f"    [SYSTEMATIC] EXPLORE {target} (priority: {priority})")
                
                if tasks_added >= 3:  # Limit systematic exploration
                    break
        
        # Final decision
        if tasks_added > 0:
            print(f"  [FALLBACK_SUCCESS] Added {tasks_added} intelligent fallback tasks")
            return True
        else:
            print(f"  [ANALYSIS_EXHAUSTED] No more meaningful tasks after {step_count} steps")
            return False