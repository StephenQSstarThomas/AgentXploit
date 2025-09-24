#!/usr/bin/env python3
"""
mcp_language_server_agent.py
MCP Language Server Agent - Final Version
"""

import os
import re
import json
from typing import List
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from mcp import StdioServerParameters
import asyncio
from google.adk.runners import InMemoryRunner
from google.genai.types import Part, UserContent
from google.adk.models.lite_llm import LiteLlm

# Load environment variables
load_dotenv()


class LanguageServerRunner:
    """Runner for MCP Language Server Agent"""

    def __init__(self):
        """Initialize the Language Server Runner with .env configuration"""
        # Read configuration from environment
        self.lsp_server = os.getenv("LSP_SERVER_TYPE", "pyright-langserver")
        self.model_name = os.getenv("MCP_AGENT_MODEL", "openai/gpt-4.1-2025-04-14")

        # Use current working directory as default workspace
        self.default_workspace = os.getcwd()

        # Create the agent
        self.agent = self._create_agent()

    def _create_agent(self) -> LlmAgent:
        """Create the MCP Language Server Agent"""
        return LlmAgent(
            model=LiteLlm(model=self.model_name),
            name="language_server_agent",
            instruction="""You are a code analysis assistant using Language Server Protocol.
            Analyze code dependencies and file relationships accurately.
            Always return results as a JSON array of file paths.""",
            tools=[
                MCPToolset(
                    connection_params=StdioServerParameters(
                        command="mcp-language-server",
                        args=[
                            "--workspace",
                            self.default_workspace,
                            "--lsp",
                            self.lsp_server,
                            "--",
                            "--stdio",
                        ],
                    ),
                )
            ],
        )

    def run(self, prompt: str) -> str:
        """Run the agent with a prompt using Google ADK runner"""
        try:
            # Create runner and session
            runner = InMemoryRunner(agent=self.agent)

            # Run the agent asynchronously - handle existing event loop properly
            try:
                # Check if we're already in an event loop
                asyncio.get_running_loop()
                # We're in an event loop, use thread-based execution
                import concurrent.futures
                
                def run_in_thread():
                    # Create new event loop for this thread
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(self._run_async_helper(runner, prompt))
                    finally:
                        new_loop.close()
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    result = future.result(timeout=60)  # 60 second timeout
                    return result
                    
            except RuntimeError:
                # No running event loop, safe to use asyncio.run()
                result = asyncio.run(self._run_async_helper(runner, prompt))
                return result

        except Exception:
            raise

    async def _run_async_helper(self, runner, prompt: str) -> str:
        """Async helper to run the agent"""
        try:
            # Create session
            session = await runner.session_service.create_session(
                app_name=runner.app_name, user_id="mcp_user"
            )

            # Create content
            content = UserContent(parts=[Part(text=prompt)])

            # Run agent and collect response
            response_text = ""
            async for event in runner.run_async(
                user_id=session.user_id,
                session_id=session.id,
                new_message=content,
            ):
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if part.text:
                            response_text += part.text

            return response_text or "[]"

        except Exception:
            raise

    def extract_file_list(self, response: str) -> List[str]:
        """Extract file list from agent response"""
        try:
            # Find JSON array in response
            json_match = re.search(r"\[.*?\]", response, re.DOTALL)
            if json_match:
                files = json.loads(json_match.group())
                # Filter to only return strings
                return [f for f in files if isinstance(f, str)]
        except Exception:
            raise

        # Extract file paths with common extensions
        patterns = r'["\']?([a-zA-Z0-9_\-/]+\.(?:py|js|ts|jsx|tsx|json|yaml|yml))["\']?'
        matches = re.findall(patterns, response)
        return list(set(matches))


# Global runner instance
_runner = None


def get_runner() -> LanguageServerRunner:
    """Get or create the global runner instance"""
    global _runner
    if _runner is None:
        _runner = LanguageServerRunner()
    return _runner
