import argparse
import asyncio
import logging
import os
import sys
from typing import Optional

# Setup logger
logger = logging.getLogger(__name__)

from google.adk.runners import InMemoryRunner
from google.genai import types
from .agent import root_agent
from .config import settings


def setup_environment():
    """Set up environment variables and logging."""
    # Set up OpenAI API key if provided
    if not os.environ.get("OPENAI_API_KEY"):
        try:
            api_key = getattr(settings, 'DEFAULT_OPENAI_API_KEY', None)
            if api_key and api_key.startswith('sk-'):
                os.environ["OPENAI_API_KEY"] = api_key
                logging.info("OpenAI API key set from configuration")
        except Exception:
            pass

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('agentxploit.log'),
            logging.StreamHandler()
        ]
    )


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="AgentXploit - Advanced AI Security Research and Exploit Agent"
    )

    parser.add_argument(
        "command",
        choices=['static', 'dynamic'],
        help="Command to execute: static (analysis agent) or dynamic (exploit agent)"
    )

    parser.add_argument(
        "-r", "--repository",
        help="Repository path for analysis"
    )

    parser.add_argument(
        "-p", "--payload",
        help="Custom payload or task description for dynamic mode"
    )

    parser.add_argument(
        "--image",
        help="Docker image to use for deployment (default: python:3.12)"
    )

    # Get default max_files from settings
    try:
        from .config import settings
        default_max_files = getattr(settings, 'MAX_FILES', 50)
    except:
        default_max_files = 50

    parser.add_argument(
        "--max-files",
        type=int,
        default=default_max_files,
        help="Maximum number of files to read during static analysis"
    )

    # Get default max_steps from settings
    try:
        from .config import settings
        default_max_steps = getattr(settings, 'MAX_STEPS', 150)
    except:
        default_max_steps = 150

    parser.add_argument(
        "--max-steps",
        type=int,
        default=default_max_steps,
        help="Maximum number of analysis steps to execute"
    )

    parser.add_argument(
        "--analysis-mode",
        choices=['intelligent', 'simple'],
        default='intelligent',
        help="Analysis mode: intelligent (iterative) or simple (batch)"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without making actual changes"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser


async def execute_command(args: argparse.Namespace) -> int:
    """Execute the specified command with given arguments."""
    try:
        # Handle dynamic command separately
        if args.command == 'dynamic':
            return await execute_dynamic_command(args)

        # Handle static command
        elif args.command == 'static':
            if not args.repository:
                logging.error("Repository path required for static command")
                return 1

            # Use analysis agent for static analysis
            logging.info(f"Starting analysis agent static analysis of: {args.repository}")
            try:
                from .agents.analysis_agent import AnalysisAgent

                max_files = getattr(args, 'max_files', getattr(settings, 'MAX_FILES', 50))
                max_steps = getattr(args, 'max_steps', getattr(settings, 'MAX_STEPS', 150))
                logging.info(f"Analysis will process up to {max_files} files and {max_steps} steps")

                analyzer = AnalysisAgent(args.repository)
                result = analyzer.analyze(
                    max_steps=max_steps,
                    save_results=True,
                    focus=None  # Let LLM generate dynamic focus
                )

                logging.info("Static analysis completed successfully")
                logging.info(f"Result: Analysis completed with {result['execution_summary']['steps_completed']} steps")
                return 0

            except Exception as e:
                logging.error(f"Static analysis failed: {e}")
                return 1

        else:
            logging.error(f"Unknown command: {args.command}")
            return 1

    except Exception as e:
        logging.error(f"Error executing command: {e}")
        if args.verbose:
            logging.exception("Full error details:")
        return 1


async def execute_dynamic_command(args: argparse.Namespace) -> int:
    """Execute dynamic command with interactive Docker setup."""
    try:
        if not args.repository:
            logging.error("Repository path required for dynamic command (-r)")
            return 1

        logging.info(f"Starting dynamic analysis for: {args.repository}")

        print("\nAgentXploit Dynamic Analysis")
        print("=" * 40)
        print("Intelligent Docker Setup Process:")
        print("1. LLM analyzes README for Docker images")
        print("2. Auto-detects Python version from pyproject/requirements")
        print("3. Creates appropriate Docker environment")
        print("4. Runs pip install for dependencies")
        print("5. Performs LLM-driven injection point analysis")
        print("=" * 40)

        # Import the exploit agent for interactive analysis
        from .agents.exploit_agent import execute_interactive_analysis, setup_analysis_environment

        # Configuration
        target_path = args.repository

        print(f"\nConfiguration:")
        print(f"  Target path: {target_path}")
        print(f"  Mode: Intelligent LLM-driven setup")

        # Handle dry-run mode
        if args.dry_run:
            print("\n[DRY RUN] Would proceed with intelligent dynamic analysis")
            return 0

        print(f"\nAutomatically starting intelligent environment setup...")

        # Step 1: Setup intelligent Docker environment
        env_result = await setup_analysis_environment(
            target_path=target_path,
            require_confirmation=True,  # User confirmation for Docker
            llm_client=None  # Will use agent's internal LLM
        )

        if not env_result['success']:
            if env_result.get('cancelled'):
                print("Environment setup cancelled by user.")
                return 0
            else:
                print(f"Environment setup failed: {env_result.get('error', 'Unknown error')}")
                return 1

        print(f"✓ Environment ready: {env_result['setup_type']}")
        if 'docker_image' in env_result:
            print(f"✓ Docker image: {env_result['docker_image']}")
        if 'dependencies_installed' in env_result:
            print(f"✓ Dependencies installed: {env_result['dependencies_installed']}")

        print(f"\nStarting interactive injection analysis...")

        # Step 2: Execute interactive analysis with existing deployment
        deployment_id = env_result.get('deployment_id')
        logger.info(f"Using existing deployment for analysis: {deployment_id}")

        result = await execute_interactive_analysis(
            target_path=target_path,
            require_user_input=True,
            existing_deployment_id=deployment_id
        )

        # Display results
        if result["success"]:
            print(f"\n✓ LLM-driven dynamic analysis completed successfully!")
            print(f"\nExecution Summary:")
            print(f"  - Analysis type: {result.get('analysis_type', 'LLM-driven')}")
            print(f"  - Target path: {result['target_path']}")

            # Injection points found
            injection_points = result.get('injection_points', [])
            print(f"\nInjection Point Analysis:")
            print(f"  - Total injection points found: {len(injection_points)}")
            print(f"  - Overall risk level: {result.get('overall_risk', 'UNKNOWN')}")

            # LLM generated commands
            llm_commands = result.get('llm_generated_commands', [])
            if llm_commands:
                print(f"  - LLM analysis commands executed: {len(llm_commands)}")
                print("  - Sample commands:")
                for cmd in llm_commands[:3]:
                    print(f"    • {cmd}")

            # Detailed results
            detailed = result.get('detailed_results', {})
            if detailed:
                print(f"\nDetailed Analysis:")
                if 'injection_points' in detailed:
                    for i, point in enumerate(detailed['injection_points'][:3], 1):
                        point_type = point.get('type', 'unknown')
                        risk = point.get('risk', 'unknown')
                        print(f"  {i}. {point_type.title()} injection (risk: {risk})")
                        if 'description' in point:
                            print(f"     {point['description'][:80]}...")

            print(f"\n📁 Analysis results available in logs")

        else:
            error_msg = result.get('error', 'Unknown error')
            print(f"\n❌ LLM-driven dynamic analysis failed: {error_msg}")
            return 1

        return 0

    except Exception as e:
        logging.error(f"Dynamic command execution failed: {e}")
        if args.verbose:
            logging.exception("Full error details:")
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    setup_environment()

    parser = create_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        return asyncio.run(execute_command(args))
    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
        return 130
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())