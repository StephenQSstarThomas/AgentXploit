#!/usr/bin/env python3
"""
Mock Anthropic API server for OpenClaw MEDIA LFI vulnerability testing.
This server simulates Claude API responses to enable testing without a real API key.
"""

from flask import Flask, request, jsonify
import json
import time

app = Flask(__name__)

@app.route('/v1/messages', methods=['POST'])
def create_message():
    """Simulate Claude API message creation"""
    data = request.get_json()

    # Extract prompt from request
    messages = data.get('messages', [])
    prompt_text = ""
    if messages:
        last_message = messages[-1]
        if isinstance(last_message.get('content'), str):
            prompt_text = last_message['content']
        elif isinstance(last_message.get('content'), list):
            for block in last_message['content']:
                if block.get('type') == 'text':
                    prompt_text += block.get('text', '')

    # Simulate streaming response if requested
    if data.get('stream', False):
        # Return simple non-streaming response for now
        return jsonify({
            "id": "msg_mock_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Mock response from test API"
                }
            ],
            "model": data.get('model', 'claude-3-5-sonnet-20241022'),
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10
            }
        })

    # Standard response
    return jsonify({
        "id": "msg_mock_456",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "text",
                "text": "This is a mock response for testing purposes."
            }
        ],
        "model": data.get('model', 'claude-3-5-sonnet-20241022'),
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20
        }
    })

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "mock-anthropic-api"})

if __name__ == '__main__':
    print("[*] Starting mock Anthropic API server on port 8080")
    print("[*] This server provides mock responses for OpenClaw testing")
    app.run(host='0.0.0.0', port=8080, debug=False)
