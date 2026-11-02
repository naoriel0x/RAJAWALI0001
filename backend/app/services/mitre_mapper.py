MITRE_MAP = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Reconnaissance",
        "kill_chain": "reconnaissance"
    },
    "dns_recon": {
        "technique_id": "T1590",
        "technique_name": "Gather Victim Network Information",
        "tactic": "Reconnaissance",
        "kill_chain": "reconnaissance"
    },
    "banner_grab": {
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "kill_chain": "reconnaissance"
    },
    "threat_intel": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "kill_chain": "reconnaissance"
    },
    # SSH
    "ssh_connect": {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "kill_chain": "lateral-movement"
    },
    "ssh_login": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "kill_chain": "exploitation"
    },
    "ssh_command": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "kill_chain": "installation"
    },
    # HTTP
    "http_request": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "kill_chain": "delivery"
    },
    "http_crawl": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "kill_chain": "reconnaissance"
    },
    "lure_access": {
        "technique_id": "T1056",
        "technique_name": "Input Capture",
        "tactic": "Collection",
        "kill_chain": "actions-on-objectives"
    },
}

def map_to_mitre(event_type: str, context: dict = {}) -> dict:
    result = deepcopy(MITRE_MAP.get(event_type, {
        "technique_id": "T1000",
        "technique_name": "Unknown Technique",
        "tactic": "Unknown",
        "kill_chain": "unknown"
    }))
    
    if event_type == "ssh_login" and context.get("username") == "root":
        result["technique_name"] = "Brute Force: Password Spraying"
        result["technique_id"] = "T1110.003"

    return result

def get_all_techniques() -> list:
    seen = set()
    techniques = []
    for v in MITRE_MAP.values():
        if v["technique_id"] not in seen:
            seen.add(v["technique_id"])
            techniques.append({
                "id": v["technique_id"],
                "name": v["technique_name"],
                "tactic": v["tactic"]
            })
    return techniques
from copy import deepcopy
