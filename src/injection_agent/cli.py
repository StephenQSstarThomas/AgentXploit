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

import argparse
import asyncio
import logging
import os
import sys
from typing import Optional

from google.adk.runners import InMemoryRunner
from google.genai import types
from .agent import root_agent
from .config import settings, CliConfig
from .enums import CliOperation, InjectionStrategy


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
            logging.FileHandler('injection_agent.log'),
            logging.StreamHandler()
        ]
    )


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="ADK Injection Analyzer Agent - Analyze AI model injection vulnerabilities"
    )
    
    parser.add_argument(
        "command",
        choices=['static', 'comprehensive', 'analyze', 'batch', 'identify', 'inject'],
        help="Command to execute"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="Input file path (trajectory JSON or log file)"
    )
    
    parser.add_argument(
        "-r", "--repository",
        help="Repository path for static analysis"
    )
    
    parser.add_argument(
        "-d", "--directory",
        help="Directory containing files to process (for batch operations)"
    )
    

    
    parser.add_argument(
        "-s", "--strategy",
        choices=[s.value for s in InjectionStrategy],
        default=InjectionStrategy.TECHNICAL.value,
        help="Injection strategy to use"
    )
    
    parser.add_argument(
        "-p", "--payload",
        help="Custom injection payload"
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
    
    parser.add_argument(
        "--analysis-mode",
        choices=['intelligent', 'simple'],
        default='intelligent',
        help="Analysis mode: intelligent (iterative like Cursor) or simple (batch)"
    )
    
    parser.add_argument(
        "--max-workers",
        type=int,
        default=3,
        help="Maximum number of concurrent workers for batch processing"
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
        # Create configuration
        config = CliConfig(
            operation=CliOperation(args.command),
            input_file=args.file,
            input_directory=args.directory,
            input_repository=getattr(args, 'repository', None),
            output_path=None,
            injection_strategy=InjectionStrategy(args.strategy),
            custom_payload=args.payload,
            max_workers=args.max_workers,
            max_files=getattr(args, 'max_files', getattr(settings, 'MAX_FILES', 50)),
            analysis_mode=getattr(args, 'analysis_mode', 'intelligent'),
            dry_run=args.dry_run
        )
        
        # Create and run agent
        app_name = 'injection_agent'
        user_id = 'user_1'
        runner = InMemoryRunner(
            agent=root_agent,
            app_name=app_name,
        )
        
        # Create a session
        session = await runner.session_service.create_session(
            app_name=app_name, 
            user_id=user_id
        )
        
        # Prepare input based on command
        if args.command == 'static':
            if not args.repository:
                logging.error("Repository path required for static command")
                return 1

            # Use analysis agent for static analysis
            logging.info(f"Starting analysis agent static analysis of: {args.repository}")
            try:
                from .agents.analysis_agent import AnalysisAgent

                max_files = getattr(args, 'max_files', getattr(settings, 'MAX_FILES', 50))
                logging.info(f"Analysis will process up to {max_files} files")

                analyzer = AnalysisAgent(args.repository)
                result = analyzer.analyze(
                    max_steps=max_files,
                    save_results=True,
                    focus="security"
                )

                logging.info("Static analysis completed successfully")
                logging.info(f"Result: Analysis completed with {result['execution_summary']['steps_completed']} steps")
                return 0

            except Exception as e:
                logging.error(f"Static analysis failed: {e}")
                return 1
            
        elif args.command == 'comprehensive':
            if not args.repository:
                logging.error("Repository path required for comprehensive command")
                return 1
            user_input = f"Perform comprehensive security analysis of the repository at {args.repository}"
            if args.max_files:
                user_input += f" with max_files_to_read={args.max_files}"
            if hasattr(args, 'analysis_mode'):
                user_input += f" using {args.analysis_mode} analysis mode"
            user_input += f" and injection_strategy='{args.strategy}'"
            if args.payload:
                user_input += f" and custom_command='{args.payload}'"
                
        elif args.command == 'analyze':
            if not args.file:
                logging.error("File path required for analyze command")
                return 1
            user_input = f"Analyze the trajectory file: {args.file} with command_type='pkill' and injection_strategy='{args.strategy}'"
            if args.payload:
                user_input += f" using custom_command='{args.payload}'"
            
        elif args.command == 'batch':
            if not args.directory:
                logging.error("Directory path required for batch command")
                return 1
            user_input = f"Batch process trajectories in directory: {args.directory} with command_type='pkill' and injection_strategy='{args.strategy}'"
            if args.payload:
                user_input += f" using custom_command='{args.payload}'"
            
        elif args.command == 'identify':
            if not args.file:
                logging.error("File path required for identify command")
                return 1
            user_input = f"Identify injection points in: {args.file}"
            
        elif args.command == 'inject':
            if not args.file:
                logging.error("File path required for inject command")
                return 1
            user_input = f"Inject payload into: {args.file} with injection_strategy='{args.strategy}'"
            if args.payload:
                user_input += f" using custom_command='{args.payload}'"
            
        else:
            logging.error(f"Unknown command: {args.command}")
            return 1
        
        # Convert user input to Content object
        content = types.Content(
            role='user', 
            parts=[types.Part.from_text(text=user_input)]
        )
        
        # Run the agent
        logging.info(f"Executing command: {args.command}")
        logging.info(f"Configuration: {config}")
        logging.info(f"Starting analysis with max_files={getattr(args, 'max_files', getattr(settings, 'MAX_FILES', 50))}")
        logging.info("Analysis will include:")
        logging.info("- Enhanced tool usage logging")
        logging.info("- Intelligent next-step planning")
        logging.info("- Sorted security findings by severity")

        # Collect the final result
        final_response = ""
        async for event in runner.run_async(
            user_id=user_id,
            session_id=session.id,
            new_message=content,
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        final_response += part.text
                        # Print progress indicators for enhanced analysis
                        if "Initializing analysis context" in part.text:
                            logging.info("Initializing intelligent analysis context...")
                        elif "Initial priorities identified" in part.text:
                            logging.info("Analysis priorities established!")
                        elif "[STEP" in part.text and "Executing:" in part.text:
                            # Enhanced step logging is already handled in smart_analyzer
                            pass
                        elif "Analysis results saved" in part.text:
                            logging.info("Analysis completed and results saved!")
                        elif "Running comprehensive security scan" in part.text:
                            logging.info("Running comprehensive security scan...")
                        elif "Running targeted security analysis" in part.text:
                            logging.info("Running targeted security analysis...")
                        elif "Generating final analysis recommendations" in part.text:
                            logging.info("Generating final analysis recommendations...")
        
        logging.info("Command execution completed successfully")
        logging.info(f"Result: {final_response}")
        
        return 0
        
    except Exception as e:
        logging.error(f"Error executing command: {e}")
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