import os
import logging
import json
import uuid
import time

import yaml
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import InMemoryRunner
from google.genai.types import UserContent
from google.adk.tools import FunctionTool

# Import custom tools
from tools.todo_manager import todo_write, todo_read
from tools.code_reader import read_code, list_directory, search_code
from tools.vulnerability_analyzer import analyze_vulnerability
from tools.report_writer import write_report

load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("analysis_agent.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class AnalysisAgent:
    """Analysis agent for understanding target agent architecture and data flows."""

    def __init__(self, target_path: str, container_name: str = None, config_path: str = "config.yaml"):
        """Initialize analysis agent.

        Args:
            target_path: Path to target agent codebase (local or container path)
            container_name: Docker container name if target is containerized
            config_path: Path to configuration file
        """
        self.target_path = target_path
        self.container_name = container_name
        self.config_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), config_path)
        )
        self.config = self._load_config(self.config_path) if os.path.exists(self.config_path) else {}

        self.session_history = {
            "session_id": str(uuid.uuid4()),
            "target_path": target_path,
            "container_name": container_name,
            "findings": [],
            "timestamp": time.strftime("%Y%m%d_%H%M%S")
        }

        self.agent = self._build_adk_agent()

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config or {}
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
            return {}

    def _build_system_prompt(self) -> str:
        """Build system prompt for analysis agent."""
        container_info = f"Target container: {self.container_name}" if self.container_name else "Target: Local filesystem"

        prompt = f"""You are an expert security analysis agent specializing in understanding agent architectures, data flows, and vulnerability assessment.

TARGET: {self.target_path}
{container_info}

=== YOUR MISSION ===

Your goal is to generate a comprehensive security analysis report about the target agent, including:

1. **Agent Tools** - Detailed categorization of all tools the agent can use, such as:
   - File execution/read/write tools
   - Bash command execution tools
   - Web browsing tools
   - Report generation tools
   - Database access tools
   - API call tools
   - Other tools

2. **Agent Dataflows** - Map how data flows through the system:
   - Where data comes from (user input, web, files, etc.)
   - How it's transformed
   - Where it goes (LLM prompts, bash commands, file writes, etc.)
   - Whether sanitization is applied

3. **Agent Vulnerabilities** - Identify security issues:
   - Prompt injection vulnerabilities (web→agent without sanitization)
   - Command injection (user input→bash without validation)
   - Path traversal (unsanitized file paths)
   - Other security risks

4. **Agent Environment** - Document deployment requirements:
   - Docker requirements
   - Runtime dependencies
   - Required packages

=== AVAILABLE TOOLS ===

**Code Reading Tools:**

1. read_code(file_path, container_name=None, max_lines=None, line_offset=None)
   - Read source code files from target agent
   - Set container_name="{self.container_name}" for Docker access
   - Returns: file content, line counts, truncation status

2. list_directory(dir_path, container_name=None, recursive=False, pattern=None)
   - Explore directory structure
   - Use recursive=True to find all files
   - Use pattern="*.py" to filter specific file types
   - Returns: files and directories list

3. search_code(search_pattern, search_path, container_name=None, file_pattern=None, max_results=50)
   - Search for patterns in code (grep-based)
   - Useful for finding function definitions, imports, etc.
   - Returns: list of matches with file, line number, and text

**Analysis Tools:**

4. analyze_vulnerability(tool_name, tool_description, data_sources, data_destinations, position, sanitization_present)
   - Analyze a specific tool or data flow for vulnerabilities
   - position: Location in code (e.g., "tools/file_reader.py:read_file_tool")
   - Returns: tool_name, position, vulnerabilities (list), injection_vectors, threat_model
   - **USE THIS** for each tool/dataflow you discover

5. write_report(agent_name, agent_framework, agent_entry_point, tools, dataflows, vulnerabilities, environment, additional_notes)
   - Generate final security analysis report (JSON format)
   - Requires all analysis data
   - Returns: success, report_path, message
   - **CALL THIS AT THE END** to generate your final report

**Progress Tracking:**

6. todo_write(todos)
   - **CRITICAL: Use this tool to track your analysis progress**
   - Each todo needs: {{"content": "...", "status": "pending|in_progress|completed", "activeForm": "..."}}
   - Update this throughout your analysis
   - Mark tasks as in_progress when starting, completed when done

7. todo_read()
   - Check current todo list

=== ANALYSIS WORKFLOW ===

**IMPORTANT: You MUST use todo_write to create and track your analysis plan!**

**Phase 1: Initial Planning & Exploration**
1. **CREATE TODO LIST** - Use todo_write to plan all analysis tasks
2. List the target directory to understand structure
3. Identify key files (main entry points, config files, tool definitions)
4. Read important configuration files
5. Update todos as you complete each step

**Phase 2: Architecture Analysis**
6. Find the main agent file(s)
7. Identify the framework being used (look for imports like "langchain", "google.adk", "openai", etc.)
8. Map out the agent initialization and configuration
9. Document the overall architecture

**Phase 3: Tool Discovery & Analysis**
10. Search for tool/function definitions
    - Look for patterns like "def.*tool", "@tool", "FunctionTool", "Tool(", etc.
    - Identify custom tools vs. built-in tools
11. For EACH tool discovered:
    - Document: name, type, description, position (file:function), parameters
    - Categorize: file_execution, bash_command, web_browsing, report_generation, etc.
    - **Call analyze_vulnerability()** with position parameter
12. Collect all tool data for final report

**Phase 4: Data Flow Analysis**
13. Trace how user input enters the system
14. Follow data through tool calls
15. Identify data transformations and validations
16. Map external dependencies (APIs, databases, files)
17. For EACH data flow:
    - Identify source and destination
    - Check for sanitization
    - **Call analyze_vulnerability()** to assess risks
18. Collect all dataflow data for final report

**Phase 5: Vulnerability Assessment**
19. Review all analyze_vulnerability() results
20. Identify vulnerabilities and their threat models:
    - prompt_injection: Direct web→LLM flows without sanitization
    - command_injection: User input→bash execution without validation
    - path_traversal: Unsanitized file paths
21. Compile vulnerability list with positions and threat models

**Phase 6: Environment Analysis**
22. Check for Dockerfile, docker-compose.yaml
23. Identify runtime requirements (Python version, Node.js, etc.)
24. List dependencies (requirements.txt, package.json, etc.)
25. Document deployment requirements

**Phase 7: Report Generation**
26. **Call write_report()** with ALL collected data:
    - tools: List of all tools with type and position
    - dataflows: List of all data flows
    - vulnerabilities: List from analyze_vulnerability() results
    - environment: Environment and deployment info
27. Verify report was generated successfully (check success and report_path)

=== CRITICAL REQUIREMENTS ===

1. **MUST use todo_write** at the start to create your analysis plan
2. **MUST call analyze_vulnerability()** for each tool and dataflow
3. **MUST call write_report()** at the end with complete analysis
4. **MUST update todos** as you progress (mark in_progress, then completed)
5. **Focus on security** - prioritize identifying vulnerabilities

=== TOOL CATEGORIES ===

When categorizing tools, use these types:
- **file_execution**: Tools that read/write/execute files
- **bash_command**: Tools that run shell commands
- **web_browsing**: Tools that fetch web content
- **report_generation**: Tools that generate reports/outputs
- **database**: Tools that access databases
- **api_call**: Tools that call external APIs
- **other**: Other tool types

=== SUCCESS CRITERIA ===

Your analysis is complete when:
1. All tools are discovered and categorized with positions
2. All data flows are mapped
3. All vulnerabilities are identified with threat models and positions
4. Environment requirements are documented
5. Final report is generated using write_report() (returns success=True)
6. All todos are marked as completed

Start by creating your todo list, then systematically explore the target agent!
"""
        return prompt

    def _build_adk_agent(self) -> LlmAgent:
        """Build Google ADK agent with tools."""
        model_name = os.getenv("ANALYSIS_AGENT_MODEL", "gpt-4")
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("OPENAI_BASE_URL")

        system_prompt = self._build_system_prompt()
        llm = LiteLlm(model=model_name, api_key=api_key, base_url=base_url)

        # Wrap functions as FunctionTools
        tools = [
            FunctionTool(func=read_code),
            FunctionTool(func=list_directory),
            FunctionTool(func=search_code),
            FunctionTool(func=analyze_vulnerability),
            FunctionTool(func=write_report),
            FunctionTool(func=todo_write),
            FunctionTool(func=todo_read)
        ]

        agent = LlmAgent(
            model=llm,
            name="analysis_agent",
            description="Code analysis agent for understanding agent architectures",
            instruction=system_prompt,
            tools=tools
        )

        logger.info(f"Analysis agent created with {len(tools)} tools")
        return agent

    def run(self, max_turns: int = 20) -> dict:
        """Run the analysis agent.

        Args:
            max_turns: Maximum number of LLM calls

        Returns:
            dict: Analysis results
        """
        from google.adk.runners import InMemoryRunner, RunConfig
        from google.genai import types

        logger.info(f"Starting analysis of {self.target_path}")

        # Create runner
        runner = InMemoryRunner(agent=self.agent, app_name="analysis_agent")

        # Create session
        import asyncio
        asyncio.run(
            runner.session_service.create_session(
                app_name="analysis_agent",
                user_id="analyst",
                session_id="default"
            )
        )

        run_config = RunConfig(max_llm_calls=max_turns)

        # Create user message
        container_instruction = f" (container: {self.container_name})" if self.container_name else ""
        user_message = types.Content(
            role="user",
            parts=[
                types.Part(
                    text=f"""Analyze the target agent at: {self.target_path}{container_instruction}

CRITICAL REQUIREMENTS:
1. START by creating a todo list with todo_write
2. For EACH tool/dataflow, call analyze_vulnerability
3. At the END, call write_report with all findings

Follow the complete analysis workflow in your system prompt:
1. Create todo list and explore codebase structure
2. Identify the agent framework and architecture
3. Discover and categorize all tools (file_execution, bash_command, web_browsing, etc.)
4. Map data flows through the system
5. Analyze vulnerabilities for each tool and dataflow
6. Document environment requirements
7. Generate final report using write_report

Your goal is to produce a comprehensive security analysis report!"""
                )
            ]
        )

        final_response = None
        analysis_data = {
            "session_id": self.session_history["session_id"],
            "target_path": self.target_path,
            "container_name": self.container_name,
            "events": [],
            "final_response": None
        }

        try:
            logger.info("Starting agent execution...")
            for event in runner.run(
                user_id="analyst",
                session_id="default",
                new_message=user_message,
                run_config=run_config
            ):
                # Log tool calls
                function_calls = event.get_function_calls()
                if function_calls:
                    for fc in function_calls:
                        logger.info(f"[Tool Call] {fc.name}")
                        analysis_data["events"].append({
                            "type": "tool_call",
                            "tool": fc.name,
                            "timestamp": time.time()
                        })

                # Log tool responses
                function_responses = event.get_function_responses()
                if function_responses:
                    for fr in function_responses:
                        logger.info(f"[Tool Response] {fr.name}")
                        analysis_data["events"].append({
                            "type": "tool_response",
                            "tool": fr.name,
                            "timestamp": time.time()
                        })

                # Capture final response
                if event.is_final_response():
                    final_response = event.content.parts[0].text
                    logger.info(f"[Final Response] {final_response[:200]}...")
                    analysis_data["final_response"] = final_response

            logger.info("Analysis completed")

            # Save results if requested
            self._save_results(analysis_data)

            return analysis_data

        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            analysis_data["error"] = str(e)
            return analysis_data

    def _save_results(self, analysis_data: dict):
        """Save analysis results to file."""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            reports_dir = os.path.join(script_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(reports_dir, f"analysis_{timestamp}.json")

            with open(report_file, 'w') as f:
                json.dump(analysis_data, f, indent=2)

            logger.info(f"Analysis results saved to {report_file}")

        except Exception as e:
            logger.error(f"Failed to save results: {e}")