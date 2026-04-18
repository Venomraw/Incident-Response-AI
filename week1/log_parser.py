"""
Incident Response AI — Week 1
Log Parser: Parses Nmap XML, syslog, and generic logs

Run: python log_parser.py
"""

import xml.etree.ElementTree as ET
import re
import json
from datetime import datetime


# ── NMAP PARSER ──────────────────────────────────────────────────────────────
def parse_nmap(file_path: str) -> dict:
    """Parse Nmap XML scan output."""
    tree = ET.parse(file_path)
    root = tree.getroot()

    results = {
        "source": "nmap",
        "parsed_at": datetime.utcnow().isoformat(),
        "hosts": []
    }

    for host in root.findall("host"):
        ip = host.find("address").get("addr", "unknown")
        ports = []

        for port in host.findall(".//port"):
            state = port.find("state").get("state", "unknown")
            service = port.find("service")
            ports.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state,
                "service": service.get("name", "unknown") if service is not None else "unknown"
            })

        results["hosts"].append({"ip": ip, "ports": ports})

    return results


# ── SYSLOG PARSER ─────────────────────────────────────────────────────────────
def parse_syslog(file_path: str) -> dict:
    """Parse standard syslog format."""
    results = {
        "source": "syslog",
        "parsed_at": datetime.utcnow().isoformat(),
        "events": []
    }

    # Syslog pattern: Month Day Time Host Process: Message
    pattern = r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.*)"

    with open(file_path, "r") as f:
        for line in f:
            match = re.match(pattern, line.strip())
            if match:
                timestamp, host, process, message = match.groups()
                results["events"].append({
                    "timestamp": timestamp,
                    "host": host,
                    "process": process,
                    "message": message,
                    "severity": detect_severity(message)
                })

    return results


# ── SEVERITY DETECTOR ─────────────────────────────────────────────────────────
def detect_severity(message: str) -> str:
    """Detect severity based on keywords in log message."""
    message = message.lower()

    critical_keywords = ["failed password", "authentication failure",
                         "invalid user", "refused connect", "attack", "exploit"]
    warning_keywords  = ["warning", "denied", "unauthorized", "error", "failed"]

    if any(kw in message for kw in critical_keywords):
        return "CRITICAL"
    elif any(kw in message for kw in warning_keywords):
        return "WARNING"
    else:
        return "INFO"


# ── MAIN ──────────────────────────────────────────────────────────────────────
def parse_log(file_path: str) -> dict:
    """Auto-detect log type and parse it."""
    if file_path.endswith(".xml"):
        return parse_nmap(file_path)
    elif file_path.endswith(".log") or file_path.endswith(".txt"):
        return parse_syslog(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python log_parser.py <log_file>")
        print("Example: python log_parser.py sample_logs/sample_syslog.txt")
        sys.exit(1)

    file_path = sys.argv[1]
    result = parse_log(file_path)

    print(json.dumps(result, indent=2))