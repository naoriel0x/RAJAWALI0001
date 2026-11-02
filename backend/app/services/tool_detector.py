import re
from typing import Optional

TOOL_SIGNATURES = {
    r"nmap":                        "nmap",
    r"masscan":                     "masscan",
    r"zmap":                        "zmap",
    r"unicornscan":                 "unicornscan",
    r"hydra":                       "hydra",
    r"medusa":                      "medusa",
    r"patator":                     "patator",
    r"crowbar":                     "crowbar",
    r"nikto":                       "nikto",
    r"sqlmap":                      "sqlmap",
    r"dirbuster":                   "dirbuster",
    r"gobuster":                    "gobuster",
    r"wfuzz":                       "wfuzz",
    r"ffuf":                        "ffuf",
    r"burpsuite|burp suite":        "burpsuite",
    r"metasploit|msfconsole|msf":   "metasploit",
    r"cobalt.?strike":              "cobalt_strike",
    r"empire":                      "powershell_empire",
    r"covenant":                    "covenant",
    r"shodan":                      "shodan",
    r"censys":                      "censys",
    r"subfinder":                   "subfinder",
    r"amass":                       "amass",
    r"dnsx":                        "dnsx",
    r"python-requests":             "python_requests",
    r"python/\d":                   "python_script",
    r"go-http-client":              "go_script",
    r"curl/\d":                     "curl",
    r"wget/\d":                     "wget",
    r"openvas":                     "openvas",
    r"nessus":                      "nessus",
    r"acunetix":                    "acunetix",
    r"libssh":                      "libssh",
    r"paramiko":                    "paramiko",
    r"ssh.?brute":                  "ssh_brute",
}

EVENT_TYPE_HINTS = {
    "port_scan":    "nmap",
    "ssh_login":    "hydra",
    "http_crawl":   "gobuster",
    "http_request": "curl",
}

def detect_tool(payload: str, event_type: str = "") -> Optional[str]:
    if not payload:
        return EVENT_TYPE_HINTS.get(event_type)

    payload_lower = payload.lower()

    for pattern, tool_name in TOOL_SIGNATURES.items():
        if re.search(pattern, payload_lower):
            return tool_name

    return EVENT_TYPE_HINTS.get(event_type)


def detect_multiple_tools(payload: str) -> list:
    if not payload:
        return []

    payload_lower = payload.lower()
    found = []

    for pattern, tool_name in TOOL_SIGNATURES.items():
        if re.search(pattern, payload_lower) and tool_name not in found:
            found.append(tool_name)

    return found


def get_tool_risk(tool_name: str) -> str:
    HIGH_RISK = ["metasploit", "cobalt_strike", "powershell_empire", "covenant"]
    MEDIUM_RISK = ["sqlmap", "hydra", "medusa", "nikto", "burpsuite"]

    if tool_name in HIGH_RISK:
        return "critical"
    elif tool_name in MEDIUM_RISK:
        return "high"
    else:
        return "medium"