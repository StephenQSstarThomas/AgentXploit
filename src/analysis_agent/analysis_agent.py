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
from tools.todo_manager import (
    todo_write, todo_read, todo_update, todo_add, todo_complete
)
from tools.code_reader import (
    read_code, list_directory, search_code,
    extract_imports, read_code_with_references
)
from tools.docker_executor import execute_docker_command
from tools.report_writer import write_report
from tools.tool_extractor import extract_tool_info, extract_dataflow, extract_vulnerabilities
from tools.session_manager import start_analysis_session, end_analysis_session
from tools.incremental_writer import (
    save_tool_analysis, log_analysis_event, save_environment_info,
    get_incremental_analysis_summary
)

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
        target_type = "Docker Container" if self.container_name else "Local Filesystem"
        container_info = f"Container: {self.container_name}" if self.container_name else f"Path: {self.target_path}"

        prompt = f"""You are a security analysis agent.

TARGET: {target_type} - {container_info}

=== TASK ===

Analyze the agent codebase:
1. Find all tools (file ops, bash, web, APIs, etc.)
2. Analyze dataflow for each tool
3. Identify security vulnerabilities
4. Document environment

=== TOOLS ===

Session: start_analysis_session(agent_name), end_analysis_session(session_id)
Reading: list_directory(path, recursive), read_code(file_path), search_code(pattern, path, file_pattern)
Analysis: extract_tool_info(), extract_dataflow(), extract_vulnerabilities(), save_tool_analysis()
Progress: get_incremental_analysis_summary(), save_environment_info()
Todos: todo_write(), todo_add(), todo_complete()
Report: write_report()

=== WORKFLOW ===

1. start_analysis_session(agent_name) and todo_write()
2. Explore and save_environment_info()
3. Search for tools
4. For EACH tool, complete ALL these steps IN SEQUENCE:
   - Read tool code
   - extract_tool_info(tool_name, code, position) → get framework → analyze → create tool_info JSON
   - extract_dataflow(tool_name, code, tool_description, position) → get framework → analyze → create dataflow JSON
   - extract_vulnerabilities(tool_name, code, tool_description, dataflow, position) → get framework → analyze → create vulnerabilities JSON
   - save_tool_analysis(tool_name, tool_info, dataflow, vulnerabilities, position)
   - get_incremental_analysis_summary()
   - If tools_count < 5: continue to next tool
5. Once tools_count >= 5: write_report()

CRITICAL: Complete ALL steps for EACH tool. Do NOT skip steps. Do NOT stop after extract_tool_info.
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
            # Code reading tools (LOCAL filesystem - with cross-reference support)
            FunctionTool(func=read_code),
            FunctionTool(func=read_code_with_references),
            FunctionTool(func=extract_imports),
            FunctionTool(func=list_directory),
            FunctionTool(func=search_code),
            # Docker container tools
            FunctionTool(func=execute_docker_command),
            # Session management
            FunctionTool(func=start_analysis_session),
            FunctionTool(func=end_analysis_session),
            # Tool Extractor (Sequential 3-round analysis framework)
            FunctionTool(func=extract_tool_info),
            FunctionTool(func=extract_dataflow),
            FunctionTool(func=extract_vulnerabilities),
            # Incremental analysis writer (CRITICAL - call after 3 rounds)
            FunctionTool(func=save_tool_analysis),
            FunctionTool(func=log_analysis_event),
            FunctionTool(func=save_environment_info),
            FunctionTool(func=get_incremental_analysis_summary),
            # Report writing (FINAL - call at the end)
            FunctionTool(func=write_report),
            # Todo tracking tools (with auto-tracking support)
            FunctionTool(func=todo_write),
            FunctionTool(func=todo_read),
            FunctionTool(func=todo_update),
            FunctionTool(func=todo_add),
            FunctionTool(func=todo_complete)
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

    def run(self, max_turns: int = 100, agent_name: str = None) -> dict:
        """Run the analysis agent.

        Args:
            max_turns: Maximum number of LLM calls
            agent_name: Name of the target agent being analyzed (for report generation)

        Returns:
            dict: Analysis results
        """
        from google.adk.runners import InMemoryRunner, RunConfig
        from google.genai import types

        logger.info(f"Starting analysis of {self.target_path}")

        # Infer agent name from target path if not provided
        if agent_name is None:
            agent_name = os.path.basename(self.target_path.rstrip('/'))
            logger.info(f"Inferred agent name: {agent_name}")

        # Store agent name for report writing (will be accessible via tool_context)
        self.agent_name = agent_name

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
        if self.container_name:
            target_location = f"Docker container: {self.container_name}"
            access_method = f"Use execute_docker_command(container_name='{self.container_name}', command='...') to access files"
        else:
            target_location = f"Local filesystem: {self.target_path}"
            access_method = "Use read_code(), list_directory(), search_code() for local file access"

        user_message = types.Content(
            role="user",
            parts=[
                types.Part(
                    text=f"""Analyze the agent at: {target_location}

Agent name: {agent_name}
Access method: {access_method}
Max turns available: {max_turns}

Task: Perform comprehensive security analysis of this agent codebase.

Steps:
1. start_analysis_session(agent_name="{agent_name}")
2. Create initial work plan with todo_write()
3. Explore: list_directory(recursive=True), read entry points, requirements, Dockerfile
4. save_environment_info() with framework, dependencies, entry_points, docker_required
5. Search for tools: search_code with patterns "def ", "@tool", "class "
6. Read files in tools/, utils/, skills/ directories

For EVERY tool you find, do ALL of these steps in sequence:
a) Read the tool's complete code
b) Call extract_tool_info(tool_name, code, position) - get framework with analysis_prompt
c) Analyze the code following the prompt, create JSON with tool info
d) Call extract_dataflow(tool_name, code, tool_description, position) - get framework with analysis_prompt
e) Analyze the dataflow following the prompt, create JSON with dataflow info
f) Call extract_vulnerabilities(tool_name, code, tool_description, dataflow, position) - get framework with analysis_prompt
g) Analyze security following the prompt, create JSON with vulnerability info
h) Call save_tool_analysis(tool_name, tool_info, dataflow, vulnerabilities, position)
i) Call get_incremental_analysis_summary() - check tools_count
j) If tools_count < 5: immediately continue to next tool (go back to step a)
k) If tools_count >= 5: continue to step 7

7. Once tools_count >= 5, call write_report()

Critical rules:
- You MUST complete steps a-h for EVERY tool before moving on
- Do NOT skip any steps in the a-h sequence
- Do NOT stop after just calling extract_tool_info - continue through all steps
- Use todo_write() and todo_add() to track your work
- Keep working until tools_count >= 5 AND write_report() is called
- The task is NOT complete until write_report() succeeds

Begin."""
                )
            ]
        )

        final_response = None
        write_report_call_count = 0
        security_report_path = None

        analysis_data = {
            "session_id": self.session_history["session_id"],
            "target_path": self.target_path,
            "container_name": self.container_name,
            "events": [],
            "final_response": None,
            "write_report_call_count": 0,
            "security_report_path": None
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
                        # Extract arguments
                        args = {}
                        try:
                            args = fc.args if hasattr(fc, 'args') else {}
                            if isinstance(args, str):
                                args = json.loads(args)
                        except Exception as e:
                            logger.warning(f"Failed to parse args for {fc.name}: {e}")

                        # Create detailed log entry
                        log_entry = {
                            "type": "tool_call",
                            "tool": fc.name,
                            "timestamp": time.time(),
                            "arguments": {}
                        }

                        # Extract key arguments based on tool type
                        if fc.name == "list_directory":
                            log_entry["arguments"]["dir_path"] = args.get("dir_path", "")
                            log_entry["arguments"]["recursive"] = args.get("recursive", False)
                            log_entry["arguments"]["pattern"] = args.get("pattern")
                            logger.info(f"[Tool Call] list_directory(dir_path='{args.get('dir_path', '')}', recursive={args.get('recursive', False)})")
                        elif fc.name == "read_code":
                            log_entry["arguments"]["file_path"] = args.get("file_path", "")
                            logger.info(f"[Tool Call] read_code(file_path='{args.get('file_path', '')}')")
                        elif fc.name == "read_code_with_references":
                            log_entry["arguments"]["file_path"] = args.get("file_path", "")
                            logger.info(f"[Tool Call] read_code_with_references(file_path='{args.get('file_path', '')}')")
                        elif fc.name == "search_code":
                            log_entry["arguments"]["search_pattern"] = args.get("search_pattern", "")
                            log_entry["arguments"]["search_path"] = args.get("search_path", "")
                            log_entry["arguments"]["file_pattern"] = args.get("file_pattern")
                            logger.info(f"[Tool Call] search_code(pattern='{args.get('search_pattern', '')}', path='{args.get('search_path', '')}')")
                        elif fc.name in ["extract_tool_info", "extract_dataflow", "extract_vulnerabilities"]:
                            log_entry["arguments"]["tool_name"] = args.get("tool_name", "")
                            log_entry["arguments"]["position"] = args.get("position", "")
                            logger.info(f"[Tool Call] {fc.name}(tool_name='{args.get('tool_name', '')}', position='{args.get('position', '')}')")
                        elif fc.name == "save_tool_analysis":
                            log_entry["arguments"]["tool_name"] = args.get("tool_name", "")
                            log_entry["arguments"]["position"] = args.get("position", "")
                            logger.info(f"[Tool Call] save_tool_analysis(tool_name='{args.get('tool_name', '')}', position='{args.get('position', '')}')")
                        elif fc.name == "write_report":
                            log_entry["arguments"]["agent_name"] = args.get("agent_name", "")
                            log_entry["arguments"]["incremental"] = args.get("incremental", False)
                            logger.info(f"[Tool Call] write_report(agent_name='{args.get('agent_name', '')}', incremental={args.get('incremental', False)})")
                        else:
                            logger.info(f"[Tool Call] {fc.name}")

                        analysis_data["events"].append(log_entry)

                        # Track write_report calls
                        if fc.name == "write_report":
                            write_report_call_count += 1
                            logger.info(f"write_report tool called (call #{write_report_call_count})")

                # Log tool responses
                function_responses = event.get_function_responses()
                if function_responses:
                    for fr in function_responses:
                        # Parse response for logging
                        response_summary = None
                        try:
                            if isinstance(fr.response, str):
                                response_data = json.loads(fr.response) if fr.response.startswith('{') else fr.response
                            else:
                                response_data = fr.response

                            # Extract summary based on tool type
                            if fr.name == "list_directory":
                                if isinstance(response_data, dict):
                                    file_count = len(response_data.get("files", []))
                                    dir_count = len(response_data.get("directories", []))
                                    response_summary = f"{file_count} files, {dir_count} directories"
                            elif fr.name in ["read_code", "read_code_with_references"]:
                                if isinstance(response_data, dict):
                                    line_count = response_data.get("total_lines", 0)
                                    response_summary = f"{line_count} lines"
                            elif fr.name == "search_code":
                                if isinstance(response_data, dict):
                                    match_count = len(response_data.get("matches", []))
                                    response_summary = f"{match_count} matches"
                            elif fr.name == "save_tool_analysis":
                                if isinstance(response_data, dict):
                                    tools_count = response_data.get("tools_count", 0)
                                    response_summary = f"tools_count: {tools_count}"
                            elif fr.name == "get_incremental_analysis_summary":
                                if isinstance(response_data, dict):
                                    tools_count = response_data.get("tools_count", 0)
                                    response_summary = f"tools_count: {tools_count}"
                        except Exception as e:
                            logger.debug(f"Failed to parse response for {fr.name}: {e}")

                        log_entry = {
                            "type": "tool_response",
                            "tool": fr.name,
                            "timestamp": time.time()
                        }
                        if response_summary:
                            log_entry["response_summary"] = response_summary
                            logger.info(f"[Tool Response] {fr.name} -> {response_summary}")
                        else:
                            logger.info(f"[Tool Response] {fr.name}")

                        analysis_data["events"].append(log_entry)

                        # Capture write_report result
                        if fr.name == "write_report":
                            try:
                                # Parse response to get report path
                                result = json.loads(fr.response) if isinstance(fr.response, str) else fr.response
                                if result.get("success"):
                                    security_report_path = result.get("report_path")
                                    logger.info(f"Security report updated: {security_report_path}")
                            except Exception as e:
                                logger.warning(f"Failed to parse write_report response: {e}")

                # Capture final response
                if event.is_final_response():
                    final_response = event.content.parts[0].text
                    logger.info(f"[Final Response] {final_response[:200]}...")
                    analysis_data["final_response"] = final_response

            logger.info("Analysis completed")

            # Update analysis data with report info
            analysis_data["write_report_call_count"] = write_report_call_count
            analysis_data["security_report_path"] = security_report_path

            # Log write_report statistics
            if write_report_call_count == 0:
                logger.warning("No write_report calls made during analysis")
            else:
                logger.info(f"write_report called {write_report_call_count} times during analysis")
                logger.info(f"Incremental report saved at: {security_report_path}")

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