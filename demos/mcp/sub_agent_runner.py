#!/usr/bin/env python3
"""
Sub-agent runner for Stratium MCP demo.

Spawns a real Claude sub-agent using the Anthropic Agent SDK with a
narrowed delegation token. The sub-agent connects to its own stratium-mcp
instance configured with the child delegation.

Usage:
    python3 sub_agent_runner.py \
        --task "Summarize public financial reports" \
        --agent-name "claude-junior-analyst" \
        --mcp-config /tmp/stratium-subagent-xxx/mcp_config.json \
        --delegation-token <jwt>
"""

import argparse
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Stratium sub-agent runner")
    parser.add_argument("--task", required=True, help="Task for the sub-agent")
    parser.add_argument("--agent-name", required=True, help="Sub-agent display name")
    parser.add_argument("--mcp-config", required=True, help="Path to MCP config JSON")
    parser.add_argument("--delegation-token", required=True, help="Child delegation JWT")
    parser.add_argument("--model", default="claude-sonnet-4-6-20250514", help="Model to use")
    args = parser.parse_args()

    # Verify MCP config exists
    if not os.path.exists(args.mcp_config):
        print(f"Error: MCP config not found at {args.mcp_config}", file=sys.stderr)
        sys.exit(1)

    try:
        import anthropic
        from anthropic import Anthropic
    except ImportError:
        print(
            "Error: anthropic package not installed. "
            "Install with: pip install anthropic",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load MCP config
    with open(args.mcp_config) as f:
        mcp_config = json.load(f)

    # Create the sub-agent
    client = Anthropic()

    system_prompt = f"""You are {args.agent_name}, a sub-agent operating under a narrowed
delegation from a parent agent. You have restricted permissions — use the
stratium MCP tools to execute actions within your authorized scope.

Your delegation token is pre-configured. When accessing resources, always use
the execute_action tool to verify authorization before proceeding.

If an action is DENIED, report the denial reason and move on — do not retry
denied actions.

Your task: {args.task}"""

    # Use the Messages API with tool use
    # The sub-agent will interact with its own stratium-mcp instance
    # via the MCP config that has the child delegation token
    response = client.messages.create(
        model=args.model,
        max_tokens=4096,
        system=system_prompt,
        messages=[
            {
                "role": "user",
                "content": f"Please complete this task: {args.task}\n\n"
                f"Use the Stratium MCP tools to check your permissions and "
                f"access resources within your authorized scope.",
            }
        ],
    )

    # Extract text content from response
    output_parts = []
    for block in response.content:
        if hasattr(block, "text"):
            output_parts.append(block.text)

    result = {
        "agent_name": args.agent_name,
        "task": args.task,
        "model": args.model,
        "output": "\n".join(output_parts),
        "usage": {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        },
        "stop_reason": response.stop_reason,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
