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

# Setup logger
logger = logging.getLogger(__name__)

from google.adk.runners import InMemoryRunner
from google.genai import types
from .agent import root_agent
from .config import settings, CliConfig
from .enums.injection_types import CliOperation, InjectionStrategy


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
        choices=['static', 'analyze', 'batch', 'inject', 'dynamic'],
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
        help="Custom injection payload or service name for deployment"
    )
    
    parser.add_argument(
        "--image",
        help="Docker image to use for deployment (default: python:3.12)"
    )
    
    parser.add_argument(
        "--readme",
        help="Path to README file for automatic deployment parsing"
    )
    
    parser.add_argument(
        "--mode",
        choices=['manual', 'auto', 'hybrid', 'skip'],
        default='auto',
        help="Interactive deployment mode"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout for user input in interactive mode (seconds)"
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
        # Handle dynamic command separately (no max_files/max_steps needed)
        if args.command == 'dynamic':
            return await execute_dynamic_command(args)
        
        # Create configuration for static/analysis commands only
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
            max_steps=getattr(args, 'max_steps', getattr(settings, 'MAX_STEPS', 150)),
            analysis_mode=getattr(args, 'analysis_mode', 'intelligent'),
            dry_run=args.dry_run
        )
        
        # Create and run agent
        app_name = 'agentxploit'
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
                max_steps = getattr(args, 'max_steps', getattr(settings, 'MAX_STEPS', 150))
                logging.info(f"Analysis will process up to {max_files} files and {max_steps} steps")

                analyzer = AnalysisAgent(args.repository)
                result = analyzer.analyze(
                    max_steps=max_steps,
                    save_results=True,
                    focus="security"
                )

                logging.info("Static analysis completed successfully")
                logging.info(f"Result: Analysis completed with {result['execution_summary']['steps_completed']} steps")
                return 0

            except Exception as e:
                logging.error(f"Static analysis failed: {e}")
                return 1
            
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
            
        elif args.command == 'inject':
            if not args.file:
                logging.error("File path required for inject command")
                return 1
            user_input = f"Inject payload into: {args.file} with injection_strategy='{args.strategy}'"
            if args.payload:
                user_input += f" using custom_command='{args.payload}'"
        
        # Dynamic command is handled separately
            
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
        
        # Confirmation unless dry-run
        if not args.dry_run:
            proceed = input(f"\nProceed with intelligent dynamic analysis? (y/n): ").strip().lower()
            if proceed not in ['y', 'yes']:
                print("Dynamic analysis cancelled.")
                return 0
        else:
            print("\n[DRY RUN] Would proceed with intelligent dynamic analysis")
            return 0
        
        print(f"\nStarting intelligent environment setup...")
        
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
            existing_deployment_id=deployment_id  # 传递现有的 deployment_id
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


async def get_docker_image_input(detected_image: str = None) -> str:
    """Get Docker image through interactive input."""
    print(f"\nDocker Image Selection:")
    
    if detected_image:
        use_detected = input(f"Use detected image '{detected_image}'? (y/n): ").strip().lower()
        if use_detected in ['y', 'yes', '']:
            return detected_image
    
    print("\nSelect Docker image:")
    print("1. python:3.12 (recommended for Python apps)")
    print("2. python:3.12-slim (lighter Python image)")
    print("3. node:18-alpine (for Node.js apps)")
    print("4. ubuntu:22.04 (general purpose)")
    print("5. Custom image")
    
    choice = input("Enter choice (1-5) [default: 1]: ").strip() or "1"
    
    image_map = {
        "1": "python:3.12",
        "2": "python:3.12-slim", 
        "3": "node:18-alpine",
        "4": "ubuntu:22.04"
    }
    
    if choice in image_map:
        return image_map[choice]
    elif choice == "5":
        custom = input("Enter custom Docker image: ").strip()
        return custom if custom else "python:3.12"
    else:
        return "python:3.12"


async def get_port_mapping_input() -> str:
    """Get port mapping configuration."""
    print(f"\nPort Mapping:")
    print("Common port mappings:")
    print("1. 5000:5000 (Flask default)")
    print("2. 3000:3000 (Node.js/React default)")
    print("3. 8000:8000 (Django/FastAPI default)")
    print("4. 80:80 (HTTP)")
    print("5. Custom mapping")
    print("6. No port mapping")
    
    choice = input("Enter choice (1-6) [default: 1]: ").strip() or "1"
    
    port_map = {
        "1": "5000:5000",
        "2": "3000:3000",
        "3": "8000:8000", 
        "4": "80:80",
        "6": "none"
    }
    
    if choice in port_map:
        return port_map[choice]
    elif choice == "5":
        custom = input("Enter custom port mapping (host:container): ").strip()
        return custom if custom else "5000:5000"
    else:
        return "5000:5000"


async def interactive_command_session(deployment_id: str, analyzer) -> None:
    """Interactive command session with remote deployer."""
    print(f"\nInteractive Command Session")
    print(f"Deployment ID: {deployment_id}")
    print("Type commands to execute in the Docker environment.")
    print("Special commands: 'exit' to quit, 'status' for info")
    print("-" * 50)
    
    from .tools.exploit.subprocess_docker import execute_container_command as subprocess_execute
    
    while True:
        try:
            command = input(f"\n[{deployment_id[:8]}]$ ").strip()
            
            if not command:
                continue
                
            if command.lower() in ['exit', 'quit', 'q']:
                print("Ending interactive session...")
                break
                
            if command.lower() == 'status':
                print(f"Deployment ID: {deployment_id}")
                print(f"Target path: {analyzer.target_path}")
                print(f"Docker image: {analyzer.context.docker_image}")
                continue
            
            # Execute command in Docker environment
            print(f"Executing: {command}")
            result = await subprocess_execute(
                command=command,
                deployment_id=deployment_id,
                timeout=30.0
            )
            
            # Display results
            if result.success:
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print(f"stderr: {result.stderr}")
            else:
                print(f"Command failed: {result.stderr}")
                
        except KeyboardInterrupt:
            print("\n\nInteractive session interrupted.")
            break
        except Exception as e:
            print(f"Error: {e}")


async def execute_optimized_command(args: argparse.Namespace) -> int:
    """Execute optimized 3-phase exploit workflow command."""
    try:
        if not args.repository:
            logging.error("Repository path required for optimized command (-r)")
            return 1
        
        logging.info(f"Starting optimized 3-phase exploit workflow for: {args.repository}")
        
        print("\nAgentXploit Optimized 3-Phase Exploit Workflow")
        print("=" * 60)
        print("Phase 1: Environment Setup & Baseline Execution")
        print("Phase 2: Enhanced LLM-Driven Injection Analysis")
        print("Phase 3: Attack Execution & Verification")
        print("=" * 60)
        
        # Import optimized workflow here to avoid circular imports
        from .tools.exploit.workflow_engine import execute_optimized_exploit_workflow
        
        # Configuration
        benign_task = args.payload or "Fix bug: Change button color from blue to red in the main UI component"
        docker_image = args.image
        print(f"\nConfiguration:")
        print(f"  Target path: {args.repository}")
        print(f"  Benign task: {benign_task}")
        print(f"  Docker image: {docker_image or 'Auto-detected'}")
        
        # Confirmation unless dry-run
        if not args.dry_run:
            proceed = input(f"\nProceed with optimized exploit workflow? (y/n): ").strip().lower()
            if proceed not in ['y', 'yes']:
                print("Optimized workflow cancelled.")
                return 0
        else:
            print("\n[DRY RUN] Would proceed with optimized workflow")
            return 0
        
        print(f"\nStarting optimized exploit workflow...")
        
        # Execute optimized workflow
        result = await execute_optimized_exploit_workflow(
            target_path=args.repository,
            benign_task=benign_task,
            docker_image=docker_image,
        )
        
        # Display results
        if result["success"]:
            workflow_results = result["results"]
            
            print(f"\nOptimized exploit workflow completed successfully!")
            print(f"\nExecution Summary:")
            print(f"  - Workflow ID: {result['workflow_id']}")
            print(f"  - Execution time: {workflow_results.get('execution_time', 0):.1f}s")
            print(f"  - Current phase: {workflow_results.get('current_phase', 'unknown')}")
            
            # Phase 1 results
            if 'baseline_execution' in workflow_results:
                baseline = workflow_results['baseline_execution']
                print(f"\nPhase 1 - Baseline Execution:")
                print(f"    ✓ Deployment successful: {baseline['success']}")
                print(f"    ✓ Trace entries collected: {baseline['trace_entries']}")
                print(f"    ✓ Setup commands: {baseline['metadata']['setup_commands']}")
            
            # Phase 2 results
            if 'injection_analysis' in workflow_results:
                analysis = workflow_results['injection_analysis']
                print(f"\nPhase 2 - Injection Analysis:")
                print(f"    ✓ Injection points found: {analysis['injection_points_found']}")
                print(f"    ✓ High-confidence points: {analysis['high_confidence_points']}")
                print(f"    ✓ Risk summary: {analysis['risk_summary']}")
                print(f"    ✓ Suggested payloads: {analysis['suggested_payloads']}")
            
            # Phase 3 results
            if 'attack_verification' in workflow_results:
                attack = workflow_results['attack_verification']
                print(f"\nPhase 3 - Attack Verification:")
                print(f"    ✓ Attacks attempted: {attack['attacks_attempted']}")
                print(f"    ✓ Successful attacks: {attack['successful_attacks']}")
                print(f"    ✓ Success rate: {attack['success_rate']:.1%}")
                print(f"    ✓ Final verdict: {attack['final_verdict']['overall_risk_level']}")
            
            # Security recommendations
            if 'attack_verification' in workflow_results and 'final_verdict' in workflow_results['attack_verification']:
                recommendations = workflow_results['attack_verification']['final_verdict'].get('recommendations', [])
                if recommendations:
                    print(f"\nSecurity Recommendations:")
                    for i, rec in enumerate(recommendations[:5], 1):
                        print(f"    {i}. {rec}")
            
            print(f"\nResults saved to workflow_results/ directory")
            
        else:
            error_msg = result.get('error', 'Unknown error')
            print(f"\nOptimized exploit workflow failed: {error_msg}")
            return 1
        
        return 0
        
    except Exception as e:
        logging.error(f"Optimized command execution failed: {e}")
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