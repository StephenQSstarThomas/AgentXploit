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
from google.adk.tools.agent_tool import AgentTool

from .analysis_agent import build_analysis_agent
from .injection_agent import build_injection_agent
from ..config import settings


def build_root_agent() -> Agent:
    """
    Build the Root Agent that orchestrates analysis and injection agents.
    
    This agent uses the Agent-as-a-Tool pattern to call specialized
    sub-agents while retaining control and session management.
    """
    
    # Build the specialized agents
    analysis_agent = build_analysis_agent()
    injection_agent = build_injection_agent()
    
    # Create the root agent with AgentTool wrappers
    root_agent = Agent(
        model=LiteLlm(model=settings.ROOT_AGENT_MODEL),
        name="root_agent",
        instruction="""
You are the Root Agent for AI Security Research, orchestrating specialized analysis and injection agents.
Your role is to decide which specialized agent to use based on the user's request and coordinate the overall workflow.

Available Specialized Agents:

1. **Analysis Agent** (via 'analysis' tool):
   - Repository static analysis and security scanning
   - Call graph analysis and data flow tracking
   - Pattern detection and vulnerability assessment
   - Architectural analysis and risk assessment

2. **Injection Agent** (via 'injection' tool):
   - Prompt injection vulnerability research
   - Injection payload generation and testing
   - Trajectory file processing and batch operations
   - Injection opportunity analysis and exploitation

Decision Framework:

**Use Analysis Agent for**:
- "Analyze repository at [path]"
- "Perform static analysis of [target]"
- "Scan [directory] for security vulnerabilities"
- "Generate security assessment of [repository]"
- "Analyze call graph/dataflow of [target]"
- "Detect vulnerability patterns in [code]"

**Use Injection Agent for**:
- "Inject malicious prompt into [file/content]"
- "Analyze trajectory file [path] for injection"
- "Batch process trajectories in [directory]"
- "Generate injection payload for [target]"
- "Find injection points in [content]"
- "Demonstrate injection attack on [target]"

**Workflow**:
1. Analyze the user's request to determine the primary task type
2. Call the appropriate specialized agent tool with the full request context
3. Present the agent's results to the user clearly and comprehensively
4. Handle any follow-up questions or additional analysis requests
5. Maintain session context across multiple interactions

**Important Guidelines**:
- Always forward the complete user request context to the specialized agents
- Provide clear summaries of the specialized agent results
- Retain control of the session and handle subsequent user inputs
- Ask for clarification if the request type is ambiguous
- Ensure all operations are for legitimate security research purposes

Your responses should be professional, detailed, and focused on helping users understand security vulnerabilities for defensive purposes.
""",
        tools=[
            AgentTool(agent=analysis_agent, skip_summarization=True),
            AgentTool(agent=injection_agent, skip_summarization=False),
        ],
    )
    
    return root_agent