"""
Tool analysis framework for main analysis agent.

This module provides THREE INDEPENDENT ADK tools that should be used sequentially:
1. extract_tool_info() - Round 1: Analyze tool description and functionality
2. extract_dataflow() - Round 2: Analyze data flow (requires Round 1 results)
3. extract_vulnerabilities() - Round 3: Security analysis (requires Round 1 & 2 results)

**IMPORTANT**: These tools DO NOT call any LLM. They return analysis prompts/frameworks
for the main analysis agent to process using its own LLM.

**Recommended Workflow** (in system prompt):
1. Call extract_tool_info(tool_name, code, position)
   → Analyze the returned prompt and produce tool description
2. Call extract_dataflow(tool_name, code, tool_description, position)
   → Analyze data flow using the description from step 1
3. Call extract_vulnerabilities(tool_name, code, tool_description, dataflow, position)
   → Analyze vulnerabilities using results from steps 1 & 2
"""
import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)

try:
    from google.adk.tools import ToolContext
except ImportError:
    ToolContext = Any


def extract_tool_info(
    tool_name: str,
    code_snippet: str,
    position: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    ROUND 1: Return analysis framework for extracting tool information.

    This tool does NOT perform LLM analysis. Instead, it returns a structured
    analysis framework that the main agent should analyze and respond to.

    Args:
        tool_name: Name of the discovered tool
        code_snippet: The tool's implementation code
        position: Location in code (e.g., "tools/file_reader.py:read_file")
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "task": "extract_tool_info",
            "tool_name": str,
            "position": str,
            "code": str,
            "analysis_prompt": str (what the agent should analyze),
            "required_output": dict (expected JSON structure)
        }
    """
    logger.info(f"[ROUND 1 Framework] Generating analysis prompt for: {tool_name}")

    analysis_prompt = f"""You are analyzing an AI agent tool. Extract detailed information about this tool.

**Tool Name:** {tool_name}
**Location:** {position}

**Code:**
```python
{code_snippet}
```

**Your Task:**
Analyze this tool and provide:
1. A clear, concise description of what this tool does
2. Detailed functionality explanation
3. List of parameters (name, type, purpose)
4. Return type and what it returns

**Output Format (JSON):**
{{
  "tool_name": "{tool_name}",
  "position": "{position}",
  "description": "One-sentence clear description",
  "functionality": "Detailed explanation of what this tool does, how it works",
  "parameters": [
    {{
      "name": "param_name",
      "type": "param_type",
      "purpose": "What this parameter is used for"
    }}
  ],
  "return_type": "What type is returned",
  "return_description": "What the return value represents"
}}

Provide ONLY valid JSON."""

    result = {
        "task": "extract_tool_info",
        "tool_name": tool_name,
        "position": position,
        "code": code_snippet,
        "analysis_prompt": analysis_prompt,
        "required_output": {
            "tool_name": "string",
            "position": "string",
            "description": "string",
            "functionality": "string",
            "parameters": "list of dicts",
            "return_type": "string",
            "return_description": "string"
        },
        "instructions": "Analyze the code according to the analysis_prompt and return the result as JSON matching required_output structure."
    }

    logger.info(f"[ROUND 1 Framework] Generated for: {tool_name}")
    return result


def extract_dataflow(
    tool_name: str,
    code_snippet: str,
    tool_description: str,
    position: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    ROUND 2: Return analysis framework for data flow analysis.

    This tool does NOT perform LLM analysis. Instead, it returns a structured
    analysis framework that the main agent should analyze and respond to.

    Args:
        tool_name: Name of the tool
        code_snippet: The tool's implementation code
        tool_description: Description from Round 1
        position: Location in code
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "task": "extract_dataflow",
            "tool_name": str,
            "position": str,
            "code": str,
            "tool_description": str (from Round 1),
            "analysis_prompt": str,
            "required_output": dict
        }
    """
    logger.info(f"[ROUND 2 Framework] Generating dataflow analysis prompt for: {tool_name}")

    analysis_prompt = f"""You are analyzing data flow in an AI agent tool.

**Tool Name:** {tool_name}
**Description:** {tool_description}
**Location:** {position}

**Code:**
```python
{code_snippet}
```

**Your Task:**
Analyze the data flow in this tool:
1. **Data Sources**: Where does data come from? (e.g., "user_input", "web_content", "file_read", "database", "llm_output", "api_response")
2. **Data Destinations**: Where does data go? (e.g., "llm_prompt", "file_write", "bash_command", "api_call", "database_write", "user_output")
3. **Data Transformations**: How is data transformed? (e.g., "sanitization", "encoding", "parsing", "concatenation")
4. **Flow Description**: Describe the complete data flow path

**Important Categories:**
- User/external input: "user_input", "external_input", "web_content", "document", "file_content"
- LLM interactions: "llm_prompt", "llm_output", "agent_decision"
- Privileged operations: "bash_command", "file_write", "file_delete", "system_call"
- Network: "api_call", "web_request", "network_write"

**Output Format (JSON):**
{{
  "tool_name": "{tool_name}",
  "position": "{position}",
  "data_sources": ["source1", "source2"],
  "data_destinations": ["dest1", "dest2"],
  "data_transformations": ["transformation1", "transformation2"],
  "flow_description": "Complete description of data flow from source to destination",
  "sensitive_flows": [
    {{
      "from": "source",
      "to": "destination",
      "risk_level": "high|medium|low",
      "reason": "Why this flow is sensitive"
    }}
  ]
}}

Provide ONLY valid JSON."""

    result = {
        "task": "extract_dataflow",
        "tool_name": tool_name,
        "position": position,
        "code": code_snippet,
        "tool_description": tool_description,
        "analysis_prompt": analysis_prompt,
        "required_output": {
            "tool_name": "string",
            "position": "string",
            "data_sources": "list of strings",
            "data_destinations": "list of strings",
            "data_transformations": "list of strings",
            "flow_description": "string",
            "sensitive_flows": "list of dicts with from/to/risk_level/reason"
        },
        "instructions": "Analyze the code according to the analysis_prompt and return the result as JSON matching required_output structure."
    }

    logger.info(f"[ROUND 2 Framework] Generated for: {tool_name}")
    return result


def extract_vulnerabilities(
    tool_name: str,
    code_snippet: str,
    tool_description: str,
    dataflow: dict,
    position: str,
    tool_context: Optional[ToolContext] = None
) -> dict:
    """
    ROUND 3: Return analysis framework for vulnerability analysis.

    This tool does NOT perform LLM analysis. Instead, it returns a structured
    analysis framework that the main agent should analyze and respond to.

    Args:
        tool_name: Name of the tool
        code_snippet: The tool's implementation code
        tool_description: Description from Round 1
        dataflow: Dataflow analysis from Round 2
        position: Location in code
        tool_context: ADK tool context (auto-injected)

    Returns:
        dict: {
            "task": "extract_vulnerabilities",
            "tool_name": str,
            "position": str,
            "code": str,
            "tool_description": str (from Round 1),
            "dataflow": dict (from Round 2),
            "analysis_prompt": str,
            "required_output": dict
        }
    """
    logger.info(f"[ROUND 3 Framework] Generating vulnerability analysis prompt for: {tool_name}")

    # Format dataflow for prompt
    import json
    dataflow_json = json.dumps(dataflow, indent=2)

    analysis_prompt = f"""You are a security expert analyzing an AI agent tool for vulnerabilities.

**Tool Name:** {tool_name}
**Description:** {tool_description}
**Location:** {position}

**Code:**
```python
{code_snippet}
```

**Data Flow Analysis:**
{dataflow_json}

---

**Your Task:**
Analyze this tool for security vulnerabilities with focus on:

1. **Path Traversal**: Check if code uses secure path handling (os.path.abspath, os.path.realpath, pathlib.Path.resolve).
   - ONLY report if INSECURE patterns exist (direct user input without normalization)
   - DO NOT report if secure functions are used

2. **Command Injection**: Check for unsafe command execution
   - shell=True without sanitization
   - Direct user input to os.system/subprocess
   - Note: shlex.quote provides some protection but shell=True is still risky

3. **Prompt Injection (End-to-End)**: Analyze untrusted content flowing to LLM prompts
   - Untrusted documents/web content → LLM → consequences
   - Task misfollowing (agent does wrong tasks)
   - Incorrect research/report generation
   - Data exfiltration via crafted prompts
   - Unintended actions

4. **Indirect Prompt Injection**: LLM output controlling privileged operations
   - Prompt injection → LLM manipulation → bash/file operations
   - Automated exploitation chains

5. **Other Agent-Specific Vulnerabilities**:
   - Workflow manipulation
   - Data poisoning in outputs
   - Information disclosure
   - Unauthorized access

**Output Format (JSON):**
{{
  "has_vulnerabilities": true/false,
  "vulnerabilities": [
    {{
      "type": "vulnerability_type",
      "severity": "critical|high|medium|low",
      "description": "Clear description of the vulnerability",
      "attack_scenario": "Detailed, realistic attack scenario (step-by-step)",
      "end_to_end_impact": [
        "Concrete impact 1 (e.g., 'Malicious document causes agent to leak API keys')",
        "Concrete impact 2",
        "Concrete impact 3"
      ],
      "evidence": "Why this is vulnerable (reference code patterns or dataflow)",
      "mitigation": "Suggested fix or mitigation strategy"
    }}
  ],
  "injection_vectors": [
    {{
      "type": "vector_type",
      "source": "data_source",
      "destination": "data_destination",
      "severity": "critical|high|medium|low",
      "exploitability": "easy|medium|hard"
    }}
  ],
  "threat_model": ["threat1", "threat2"],
  "overall_risk": "critical|high|medium|low",
  "risk_summary": "Summary of overall security posture"
}}

**Critical Rules:**
- BE PRECISE: Don't report path traversal if code uses os.path.abspath/realpath/Path.resolve()
- BE REALISTIC: Only report vulnerabilities you can actually see in code/dataflow
- BE DETAILED: For prompt injection, describe the FULL attack chain with concrete steps
- PROVIDE EVIDENCE: Reference specific code patterns or dataflow that prove the vulnerability
- If no vulnerabilities: {{"has_vulnerabilities": false, "vulnerabilities": [], "injection_vectors": [], "threat_model": [], "overall_risk": "low", "risk_summary": "No significant vulnerabilities detected"}}

Provide ONLY valid JSON."""

    result = {
        "task": "extract_vulnerabilities",
        "tool_name": tool_name,
        "position": position,
        "code": code_snippet,
        "tool_description": tool_description,
        "dataflow": dataflow,
        "analysis_prompt": analysis_prompt,
        "required_output": {
            "has_vulnerabilities": "boolean",
            "vulnerabilities": "list of dicts with type/severity/description/attack_scenario/end_to_end_impact/evidence/mitigation",
            "injection_vectors": "list of dicts with type/source/destination/severity/exploitability",
            "threat_model": "list of strings",
            "overall_risk": "string (critical|high|medium|low)",
            "risk_summary": "string"
        },
        "instructions": "Analyze the code according to the analysis_prompt and return the result as JSON matching required_output structure."
    }

    logger.info(f"[ROUND 3 Framework] Generated for: {tool_name}")
    return result


__all__ = [
    "extract_tool_info",
    "extract_dataflow",
    "extract_vulnerabilities"
]
