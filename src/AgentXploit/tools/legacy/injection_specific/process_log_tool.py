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

import json
import os
from typing import Dict, Any, Optional
from google.adk.tools import ToolContext


def process_log_file(filepath: str, tool_context: Optional[ToolContext] = None) -> Dict[str, Any]:
    """
    Parse a JSON log file and extract structured information.
    
    This tool processes agent trajectory log files to extract user input,
    agent responses, and agent actions in a structured format.
    
    Args:
        filepath: Path to the JSON log file to process
        tool_context: ADK tool context (optional)
        
    Returns:
        Dictionary containing:
        - task_id: Identifier for the task
        - user_input: Original user input from the log
        - agent_response: Initial agent response
        - agent_actions: List of agent actions with function calls and results
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Input file not found: '{filepath}'")
    
    filename = os.path.basename(filepath)
    task_id = os.path.splitext(filename)[0]
    
    with open(filepath, 'r', encoding='utf-8') as f:
        log_data = json.load(f)
    
    # Create event map for quick lookup
    event_map = {event['id']: event for event in log_data}
    
    structured_output = {
        "task_id": task_id,
        "user_input": None,
        "agent_response": None,
        "agent_actions": []
    }
    
    processed_cause_ids = set()
    
    for event in log_data:
        source = event.get("source")
        
        # Extract user input
        if source == "user" and structured_output["user_input"] is None:
            message_content = event.get("message", "")
            if isinstance(message_content, str) and message_content.strip():
                structured_output["user_input"] = message_content
        
        # Extract initial agent response
        elif source == "agent" and event.get("action") == "message":
            if not structured_output["agent_actions"] and structured_output["agent_response"] is None:
                structured_output["agent_response"] = event.get("message")
        
        # Extract agent actions with function calls
        elif "cause" in event and event.get("cause") is not None:
            cause_id = event["cause"]
            
            if cause_id in processed_cause_ids:
                continue
            
            request_event = event_map.get(cause_id)
            
            if request_event and "tool_call_metadata" in request_event:
                processed_cause_ids.add(cause_id)
                
                # Extract function calls
                function_calls = []
                tool_calls_data = (request_event.get("tool_call_metadata", {})
                                 .get("model_response", {})
                                 .get("choices", [{}])[0]
                                 .get("message", {})
                                 .get("tool_calls", []))
                
                for call in tool_calls_data:
                    function_info = call.get("function", {})
                    function_calls.append({
                        "tool_call_id": call.get("id"),
                        "function_name": function_info.get("name"),
                        "arguments": function_info.get("arguments")
                    })
                
                # Extract execution results
                agent_thought = event.get("message") if event.get("source") == "agent" else None
                execution_result = {
                    "observation": event.get("observation"),
                    "content": event.get("content")
                }
                
                # Handle special case where content is None
                if execution_result["content"] is None and agent_thought:
                    if event.get("observation"):
                        execution_result["content"] = agent_thought
                        agent_thought = None
                
                # Build action details
                action_id = len(structured_output["agent_actions"]) + 1
                action_details = {
                    "id": action_id,
                    "request_event_id": request_event["id"],
                    "result_event_id": event["id"],
                    "function_calls": function_calls,
                    "execution_result": execution_result
                }
                
                # Only add agent_thought if it exists
                if agent_thought:
                    action_details["agent_thought"] = agent_thought
                
                structured_output["agent_actions"].append(action_details)
    
    return structured_output 