"""
Incident Response AI — Week 2
Playbook Generator: Sends parsed logs to Claude AI
and generates a MITRE ATT&CK mapped IR playbook

Run: python3 playbook_generator.py <log_file>
Example: python3 playbook_generator.py ../week1/sample_logs/sample_syslog.txt
"""

import sys
import os
import json
from dotenv import load_dotenv
import anthropic

# Load API key from .env
load_dotenv()

# Add week1 to path so we can import the parser
sys.path.append(os.path.join(os.path.dirname(__file__), "../week1"))
from log_parser import parse_log


# ── CLAUDE CLIENT ─────────────────────────────────────────────────────────────
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


# ── PROMPT BUILDER ────────────────────────────────────────────────────────────
def build_prompt(parsed_log: dict) -> str:
    """Build a prompt for Claude from parsed log data."""
    return f"""You are a senior SOC analyst and incident response expert.

Analyze the following parsed security log data and generate a structured incident response playbook.

PARSED LOG DATA:
{json.dumps(parsed_log, indent=2)}

Your response must include:

1. INCIDENT SUMMARY
   - What happened in plain English
   - Severity level (Critical / High / Medium / Low)
   - Affected systems or IPs

2. MITRE ATT&CK MAPPING
   - Tactic name
   - Technique ID and name (e.g. T1110 - Brute Force)
   - Brief explanation of why it matches

3. IMMEDIATE RESPONSE STEPS
   - Numbered list of actions to take right now
   - Be specific (e.g. "Block IP 192.168.1.105 at the firewall")

4. INVESTIGATION STEPS
   - What logs to check next
   - What evidence to collect

5. CONTAINMENT & RECOVERY
   - How to contain the threat
   - How to recover and harden the system

Keep your response clear, structured, and actionable.
"""


# ── PLAYBOOK GENERATOR ────────────────────────────────────────────────────────
def generate_playbook(log_file: str) -> str:
    """Parse a log file and generate an IR playbook using Claude."""

    print(f"[*] Parsing log file: {log_file}")
    parsed_log = parse_log(log_file)

    print(f"[*] Sending to Claude AI for analysis...")
    prompt = build_prompt(parsed_log)

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1500,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    playbook = message.content[0].text
    return playbook


# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 playbook_generator.py <log_file>")
        print("Example: python3 playbook_generator.py ../week1/sample_logs/sample_syslog.txt")
        sys.exit(1)

    log_file = sys.argv[1]
    playbook = generate_playbook(log_file)

    print("\n" + "="*60)
    print("INCIDENT RESPONSE PLAYBOOK")
    print("="*60)
    print(playbook)
    print("="*60)