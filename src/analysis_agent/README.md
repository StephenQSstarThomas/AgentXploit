# Analysis Agent

An autonomous agent for analyzing target agent codebases using Google ADK framework.

## Features

- **Autonomous Code Analysis**: Agent-driven exploration of target codebases
- **Todo Tracking**: Claude Code-style todo management for tracking analysis progress
- **Flexible Code Reading**: Support for both local filesystem and Docker containers
- **Comprehensive Tools**: Read files, list directories, search code patterns

## Architecture

The Analysis Agent is built on Google ADK framework with custom tools:

### Tools

1. **todo_write** - Track analysis progress (mimics Claude Code's TodoWrite)
2. **todo_read** - Read current todo list
3. **read_code** - Read source files (local or Docker)
4. **list_directory** - Explore directory structure
5. **search_code** - Search for code patterns using grep

## Installation

```bash
pip install google-adk python-dotenv pyyaml
```

## Configuration

Create a `.env` file:

```env
ANALYSIS_AGENT_MODEL=gpt-4
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://api.openai.com/v1
```

## Usage

### Basic Usage

```python
from analysis_agent import AnalysisAgent

# Analyze local codebase
agent = AnalysisAgent(
    target_path="/path/to/target/agent",
    container_name=None
)

results = agent.run(max_turns=20)
print(results['final_response'])
```

### Analyze Dockerized Agent

```python
# Analyze agent running in Docker container
agent = AnalysisAgent(
    target_path="/app",
    container_name="target_container"
)

results = agent.run(max_turns=20)
```

### Example Script

```bash
# Test tools directly
python example_usage.py test

# Analyze local agent
python example_usage.py local

# Analyze dockerized agent
python example_usage.py docker
```

## Tool Design

### Todo Manager (todo_write)

Based on Claude Code's TodoWrite functionality:

```python
todo_write(todos=[
    {
        "content": "Analyze authentication flow",
        "status": "completed",
        "activeForm": "Analyzing authentication flow"
    },
    {
        "content": "Map data flows",
        "status": "in_progress",
        "activeForm": "Mapping data flows"
    }
])
```

Status values: `pending`, `in_progress`, `completed`

### Code Reader (read_code)

Flexible file reading with Docker support:

```python
# Read from local filesystem
read_code(file_path="/path/to/file.py", max_lines=100)

# Read from Docker container
read_code(
    file_path="/app/agent.py",
    container_name="target_container",
    max_lines=100,
    line_offset=50
)
```

### Directory Listing (list_directory)

```python
# List directory
list_directory(dir_path="/app", recursive=True, pattern="*.py")

# With Docker
list_directory(
    dir_path="/app",
    container_name="target_container",
    recursive=True
)
```

### Code Search (search_code)

```python
# Search for patterns
search_code(
    search_pattern="class.*Agent",
    search_path="/app",
    file_pattern="*.py",
    max_results=50
)
```

## Analysis Workflow

The agent follows a structured workflow:

1. **Initial Exploration** - List directories, identify key files
2. **Architecture Analysis** - Find framework, agent structure
3. **Tool Discovery** - Locate and document all tools
4. **Data Flow Analysis** - Map data paths through system
5. **Security Analysis** - Identify injection points and vulnerabilities

## Output

Analysis results are saved to `reports/analysis_<timestamp>.json`:

```json
{
  "session_id": "...",
  "target_path": "/path/to/target",
  "container_name": null,
  "events": [...],
  "final_response": "Detailed analysis report..."
}
```

The agent provides a structured report including:
- Agent type and framework
- Tool definitions and parameters
- Data flows and transformations
- Injection points
- Security observations

## Google ADK Integration

This agent demonstrates Google ADK custom tool implementation:

```python
from google.adk.tools import FunctionTool

# Create custom tools
tools = [
    FunctionTool(func=read_code),
    FunctionTool(func=list_directory),
    FunctionTool(func=search_code),
    FunctionTool(func=todo_write),
    FunctionTool(func=todo_read)
]

# Create agent with tools
agent = LlmAgent(
    model=llm,
    instruction=system_prompt,
    tools=tools
)
```

## References

- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [Claude Code Todo Tracking](https://docs.claude.com/en/api/agent-sdk/todo-tracking)
- [Google ADK Custom Tools](https://google.github.io/adk-docs/tools-custom/)
