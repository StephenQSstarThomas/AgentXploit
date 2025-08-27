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

from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import FunctionTool

from ..config import settings

from ..tools.analysis import (
    analyze_repository_static,
    scan_directory_security,
    analyze_call_graph,
    track_dataflow,
    detect_patterns,
    manage_analysis_tasks
)
from ..tools.analysis.context_tools import (
    initialize_analysis_context,
    get_project_overview,
    get_analysis_history,
    get_security_summary,
    add_analysis_todo,
    update_todo_status,
    get_current_todos,
    get_next_suggestions,
    record_analysis_result,
    record_directory_structure
)


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

1. **Static Repository Analysis**: 
   - Analyze directory structure and key files
   - Understand agent workflow and architecture  
   - Identify entry points and data flow patterns
   - Generate comprehensive architectural reports

2. **Security Scanning**:
   - Scan directories for security vulnerabilities
   - Identify injection points and attack surfaces
   - Assess risk levels and impact potential
   - Generate security assessment reports

3. **Call Graph Analysis**:
   - Map function call relationships
   - Trace execution paths through code
   - Identify critical control flow points
   - Analyze inter-module dependencies

4. **Data Flow Tracking**:
   - Track data movement through the system
   - Identify data transformation points
   - Map input/output relationships
   - Find potential data leakage points

5. **Pattern Detection**:
   - Detect common vulnerability patterns
   - Identify anti-patterns and code smells
   - Find configuration and deployment issues
   - Recognize security-relevant patterns

6. **Task Management**:
   - Manage analysis workflow tasks
   - Prioritize analysis steps
   - Track analysis progress
   - Coordinate multiple analysis phases

AUTONOMOUS DECISION MAKING:
You have access to context tools that help you make intelligent decisions about what to analyze next:

1. **get_project_overview()** - Understand current project structure and analysis progress
2. **get_analysis_history()** - See what has been discovered recently
3. **get_security_summary()** - Review security findings so far
4. **get_current_todos()** - Check your current analysis tasks
5. **get_next_suggestions()** - Get AI suggestions for next priorities
6. **add_analysis_todo()** - Create your own analysis tasks
7. **record_analysis_result()** - Record your findings for future reference

WORKFLOW:
1. Start by calling get_project_overview() and get_analysis_history() to understand context
2. Use your analysis tools to examine the repository
3. Record important findings with record_analysis_result()
4. Add new todos for follow-up analysis with add_analysis_todo()
5. Use get_next_suggestions() to identify priority areas
6. Make autonomous decisions about what to analyze next based on discoveries

Focus on security vulnerabilities, injection points, and architectural risks.
Be proactive - when you discover something interesting, investigate it thoroughly.
Manage your own analysis workflow using the context tools.
""",
        tools=[
            FunctionTool(analyze_repository_static),
            FunctionTool(scan_directory_security),
            FunctionTool(analyze_call_graph),
            FunctionTool(track_dataflow),
            FunctionTool(detect_patterns),
            FunctionTool(manage_analysis_tasks),
            # Context and todo management tools
            FunctionTool(initialize_analysis_context),
            FunctionTool(get_project_overview),
            FunctionTool(get_analysis_history),
            FunctionTool(get_security_summary),
            FunctionTool(add_analysis_todo),
            FunctionTool(update_todo_status),
            FunctionTool(get_current_todos),
            FunctionTool(get_next_suggestions),
            FunctionTool(record_analysis_result),
            FunctionTool(record_directory_structure),
        ],
    )
    
    return analysis_agent