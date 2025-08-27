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

# Main analyzer - uses new modular structure
from .smart_analyzer import Analyzer

# Core components
from .core import CoreTools, AnalysisContext, Task, TaskQueue, ExecutionLogger

# Specialized components
from .analyzers import SecurityAnalyzer, PatternDetector, DataflowTracker, CallChainTracer
from .planners import AnalysisContextManager
from .executors import ToolExecutor
from .ai import LLMHelper

# Injection-specific tools - import with error handling
try:
    from .injection_specific import (
        identify_injection_points,
        inject_malicious_prompt,
        process_log_file,
        scan_file,
        scan_directory,
        SWEReXTool
    )
except ImportError:
    identify_injection_points = None
    inject_malicious_prompt = None
    process_log_file = None
    scan_file = None
    scan_directory = None
    SWEReXTool = None

try:
    from .output import save_analysis_results
except ImportError:
    save_analysis_results = None

try:
    from .executors import batch_process_trajectories
except ImportError:
    batch_process_trajectories = None

# Main exports - always available
__all__ = [
    # Main analyzer
    'Analyzer',
    # Core components  
    'CoreTools',
    'AnalysisContext',
    'Task',
    'TaskQueue',
    'ExecutionLogger',
    # Specialized components
    'SecurityAnalyzer',
    'PatternDetector',
    'DataflowTracker',
    'CallChainTracer',
    'AnalysisContextManager',
    'ToolExecutor',
    'LLMHelper',
]

# Add injection-specific tools that are available
_available_injection = []
if identify_injection_points is not None:
    _available_injection.append('identify_injection_points')
if inject_malicious_prompt is not None:
    _available_injection.append('inject_malicious_prompt')
if process_log_file is not None:
    _available_injection.append('process_log_file')
if scan_file is not None:
    _available_injection.extend(['scan_file', 'scan_directory'])
if SWEReXTool is not None:
    _available_injection.append('SWEReXTool')
if save_analysis_results is not None:
    _available_injection.append('save_analysis_results')
if batch_process_trajectories is not None:
    _available_injection.append('batch_process_trajectories')

__all__.extend(_available_injection)

# Backwards compatibility - provide smart_agent_analyze using new analyzer
def smart_agent_analyze(repo_path: str, max_steps: int = 40, tool_context=None):
    """
    Backwards compatibility function for legacy smart_agent_analyze
    Now uses the new streamlined analyzer
    """
    analyzer = Analyzer(repo_path)
    return analyzer.analyze(max_steps=max_steps, save_results=True, focus="security")

# Add to exports
__all__.append('smart_agent_analyze') 