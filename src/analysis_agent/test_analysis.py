#!/usr/bin/env python3
"""
Test script for analysis agent.
Tests the agent on the example_agent codebase.
"""

import os
import sys
from analysis_agent import AnalysisAgent

def main():
    # Target path - the example agent
    target_path = "/home/shiqiu/example_agent"

    print(f"Starting analysis of: {target_path}")
    print("=" * 60)

    # Create analysis agent
    agent = AnalysisAgent(
        target_path=target_path,
        container_name=None,  # Local filesystem, no container
        config_path="config.yaml"
    )

    # Run analysis with max_turns=20
    print("Running analysis agent (max 20 turns)...")
    result = agent.run(max_turns=20)

    print("=" * 60)
    print("Analysis complete!")
    print(f"\nSession ID: {result.get('session_id')}")
    print(f"Target: {result.get('target_path')}")
    print(f"Events: {len(result.get('events', []))}")

    if result.get('final_response'):
        print(f"\nFinal Response:\n{result['final_response'][:500]}...")

    if result.get('error'):
        print(f"\nError: {result['error']}")

    # Check if report was generated
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    if os.path.exists(reports_dir):
        reports = [f for f in os.listdir(reports_dir) if f.startswith("security_analysis")]
        if reports:
            print(f"\nGenerated reports: {reports}")
            latest_report = max([os.path.join(reports_dir, f) for f in reports], key=os.path.getmtime)
            print(f"Latest report: {latest_report}")

if __name__ == "__main__":
    main()
