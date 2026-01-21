import os
import logging
import json
import uuid
import time

import yaml
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import FunctionTool

# Import custom tools
from tools.todo_manager import todo_read, todo_write
from tools.file_tools import read, glob, grep, ls
from tools.analysis_writer import (
    create_analysis_json,
    write_tool_info,
    write_dataflow,
    write_vulnerabilities,
    write_environment,
    write_dependencies,
    write_final_report
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
        prompt = f"""You are an expert in AI Agent Security research.

Your task is to help users analyze agent codebases, thoroughly and meticulously identifying potential vulnerabilities.

=== TARGET ===

Path: {self.target_path}

=== TASK ===

Analyze the agent codebase to:
1. Understand environment and dependencies
2. Find all TOOLS - functions that interact with external environment (filesystem, web, bash, APIs, database, etc.)
3. Analyze dataflow for each tool
4. Identify security vulnerabilities

=== TOOLS ===

File Operations: ls(), glob(), grep(), read() - explore and read codebase
Todo Management: todo_read(), todo_write() - track analysis progress
Analysis Writers:
  - create_analysis_json() - initialize analysis file (call first)
  - write_environment() - write environment info
  - write_dependencies() - write dependency list
  - write_tool_info() - write/update tool description and functionality
  - write_dataflow() - write/update data flow analysis
  - write_vulnerabilities() - write/update security findings
  - write_final_report() - finalize report (call when done)

=== WORKFLOW ===

1. INITIALIZE: create_analysis_json(json_path) - json_path is provided in user message
2. ENVIRONMENT: Explore codebase, then write_environment() and write_dependencies()
3. FIND TOOLS: Search for tools that interact with external environment
   - Look for: file read/write, bash/shell execution, web requests, API calls, database operations and other similar types
4. FOR EACH TOOL:
   a) Read and understand the tool code
   b) write_tool_info() - document tool name, position, description, parameters
   c) write_dataflow() - analyze data sources, destinations, transformations
   d) write_vulnerabilities() - if vulnerabilities found
5. FINALIZE: write_final_report() when analysis is complete

=== CRITICAL VULNERABILITIES TO IDENTIFY ===

Focus on these two attack patterns:

1. **Untrusted Data → LLM Context/Decision**
   - External/untrusted data (web content, file content, user input, API responses) flows into LLM prompt or context
   - This enables indirect prompt injection attacks
   - Example: web_search results directly concatenated into prompt

2. **LLM Output → Sensitive Tool Execution**
   - LLM decisions/outputs are passed to dangerous tools without validation
   - This enables Remote Code Execution (RCE), data exfiltration, etc.
   - Example: LLM output used as bash command argument, file path, or API parameter

When you find such vulnerabilities, document them with write_vulnerabilities() including:
- Vulnerability type, severity, attack scenario
- End-to-end impact (what an attacker can achieve)
- Evidence from code/dataflow

=== RULES ===

- All write_* functions support overwriting - call them again to update findings
- Keep analyzing until you have thoroughly examined all tools
- Call write_final_report() ONLY when analysis is complete
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
            # File operations - explore and read codebase
            FunctionTool(func=read),
            FunctionTool(func=glob),
            FunctionTool(func=grep),
            FunctionTool(func=ls),
            # Todo management - track analysis progress
            FunctionTool(func=todo_read),
            FunctionTool(func=todo_write),
            # Analysis writers - write findings to JSON
            FunctionTool(func=create_analysis_json),
            FunctionTool(func=write_tool_info),
            FunctionTool(func=write_dataflow),
            FunctionTool(func=write_vulnerabilities),
            FunctionTool(func=write_environment),
            FunctionTool(func=write_dependencies),
            FunctionTool(func=write_final_report)
        ]

        agent = LlmAgent(
            model=llm,
            name="analysis_agent",
            description="Security analysis agent for AI agent codebases",
            instruction=system_prompt,
            tools=tools
        )

        logger.info(f"Analysis agent created with {len(tools)} tools")
        return agent

    def run(self, max_turns: int) -> dict:
        """Run the analysis agent.

        Args:
            max_turns: Maximum number of LLM calls (required, no default)

        Returns:
            dict: Analysis results

        Raises:
            ValueError: If max_turns is not provided
        """
        if max_turns is None:
            raise ValueError("max_turns is required")

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

        # Generate unique JSON path using target path hash and timestamp
        script_dir = os.path.dirname(os.path.abspath(__file__))
        reports_dir = os.path.join(script_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Create unique identifier from target path and timestamp
        path_hash = abs(hash(self.target_path)) % 10000
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        json_path = os.path.join(reports_dir, f"analysis_{path_hash}_{timestamp}.json")

        # Simple user message - details are in system prompt
        user_message = types.Content(
            role="user",
            parts=[
                types.Part(
                    text=f"""Target: {self.target_path}
Output JSON: {json_path}
Max turns: {max_turns}

Begin analysis. First call create_analysis_json("{json_path}")."""
                )
            ]
        )

        final_response = None
        final_report_called = False

        analysis_data = {
            "session_id": self.session_history["session_id"],
            "target_path": self.target_path,
            "json_path": json_path,
            "events": [],
            "final_response": None
        }

        # Detailed log data for tool calls and responses
        log_data = {
            "session_id": self.session_history["session_id"],
            "target_path": self.target_path,
            "json_path": json_path,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tool_calls": []
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
                        args = {}
                        try:
                            args = fc.args if hasattr(fc, 'args') else {}
                            if isinstance(args, str):
                                args = json.loads(args)
                        except Exception:
                            pass

                        log_entry = {
                            "type": "tool_call",
                            "tool": fc.name,
                            "timestamp": time.time()
                        }

                        # Detailed log entry for log_data
                        detailed_log_entry = {
                            "type": "tool_call",
                            "tool": fc.name,
                            "args": args,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "timestamp_unix": time.time()
                        }
                        log_data["tool_calls"].append(detailed_log_entry)

                        # Log based on tool type
                        if fc.name in ["ls", "glob", "grep", "read"]:
                            logger.info(f"[Tool Call] {fc.name}({args})")
                        elif fc.name.startswith("write_"):
                            tool_name = args.get("tool_name", "") if args else ""
                            logger.info(f"[Tool Call] {fc.name}(tool_name='{tool_name}')")
                            if fc.name == "write_final_report":
                                final_report_called = True
                        else:
                            logger.info(f"[Tool Call] {fc.name}")

                        analysis_data["events"].append(log_entry)

                # Log tool responses
                function_responses = event.get_function_responses()
                if function_responses:
                    for fr in function_responses:
                        response_summary = None
                        response_data = None
                        error_info = None
                        try:
                            if isinstance(fr.response, str):
                                response_data = json.loads(fr.response) if fr.response.startswith('{') else fr.response
                            else:
                                response_data = fr.response

                            if isinstance(response_data, dict):
                                if response_data.get("success") is not None:
                                    if response_data.get("success"):
                                        response_summary = "success"
                                    else:
                                        error_info = response_data.get("error") or response_data.get("message", "unknown")
                                        response_summary = f"error: {error_info}"
                        except Exception as parse_err:
                            error_info = str(parse_err)

                        log_entry = {
                            "type": "tool_response",
                            "tool": fr.name,
                            "timestamp": time.time()
                        }

                        # Detailed log entry for log_data
                        detailed_response_entry = {
                            "type": "tool_response",
                            "tool": fr.name,
                            "success": response_summary == "success" if response_summary else None,
                            "error": error_info,
                            "response_preview": str(response_data)[:500] if response_data else None,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "timestamp_unix": time.time()
                        }
                        log_data["tool_calls"].append(detailed_response_entry)

                        if response_summary:
                            logger.info(f"[Tool Response] {fr.name} -> {response_summary}")
                        else:
                            logger.info(f"[Tool Response] {fr.name}")

                        analysis_data["events"].append(log_entry)

                # Capture final response
                if event.is_final_response():
                    final_response = event.content.parts[0].text
                    logger.info(f"[Final Response] {final_response[:200]}...")
                    analysis_data["final_response"] = final_response

            logger.info("Analysis completed")

            if not final_report_called:
                logger.warning("write_final_report was not called during analysis")
            else:
                logger.info(f"Analysis report saved at: {json_path}")

            # Save log data to JSON file
            log_data["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            log_data["final_report_called"] = final_report_called
            self._save_log(log_data, path_hash, timestamp)

            self._save_results(analysis_data)
            return analysis_data

        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            analysis_data["error"] = str(e)
            # Also save log data on error
            log_data["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            log_data["error"] = str(e)
            self._save_log(log_data, path_hash, timestamp)
            return analysis_data

    def _save_log(self, log_data: dict, path_hash: int, timestamp: str):
        """Save detailed tool call log to JSON file.

        Args:
            log_data: Log data containing tool calls and responses
            path_hash: Hash of target path for unique filename
            timestamp: Timestamp string for filename
        """
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            reports_dir = os.path.join(script_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)

            log_file = os.path.join(reports_dir, f"log_{path_hash}_{timestamp}.json")

            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Tool call log saved to {log_file}")

        except Exception as e:
            logger.error(f"Failed to save log: {e}")

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