import logging
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.errors import SlackApiError
from app.core.config import settings

logger = logging.getLogger(__name__)

COLORS = {
    "recon":    "#FFA500",
    "ssh":      "#FF4444",
    "http":     "#FFD700",
    "critical": "#FF0000",
    "blocked":  "#00FF00",
}

async def send_alert(alert_type: str, attacker, event) -> bool:
    if not settings.SLACK_BOT_TOKEN or not settings.SLACK_CHANNEL_ID:
        logger.warning("Slack not configured, skipping alert.")
        return False

    client = AsyncWebClient(token=settings.SLACK_BOT_TOKEN)

    if alert_type == "recon":
        title   = "RAJAWALI EARLY WARNING — Reconnaissance Detected"
        fields  = _build_recon_fields(attacker, event)
    elif alert_type == "ssh":
        title   = "RAJAWALI ALERT — SSH Attack Attempt"
        fields  = _build_ssh_fields(attacker, event)
    elif alert_type == "http":
        title   = "RAJAWALI ALERT — HTTP Attack Detected"
        fields  = _build_http_fields(attacker, event)
    elif alert_type == "blocked":
        title   = "RAJAWALI — Attacker Blocked"
        fields  = _build_blocked_fields(attacker)
    else:
        title   = "RAJAWALI ALERT"
        fields  = []

    color = COLORS.get(alert_type, "#888888")

    try:
        await client.chat_postMessage(
            channel=settings.SLACK_CHANNEL_ID,
            attachments=[{
                "color":        color,
                "title":        title,
                "fields":       fields,
                "footer":       "RAJAWALI Cyber Defense System",
                "footer_icon":  "https://cdn-icons-png.flaticon.com/512/1534/1534959.png",
                "ts":           _get_ts()
            }]
        )
        logger.info(f"Slack alert sent: {alert_type} for {attacker.ip_address}")
        return True

    except SlackApiError as e:
        logger.error(f"Slack alert failed: {e.response['error']}")
        return False


def _build_recon_fields(attacker, event) -> list:
    return [
        {"title": "IP Address",     "value": attacker.ip_address,               "short": True},
        {"title": "Country",        "value": attacker.country_name or "Unknown", "short": True},
        {"title": "Event Type",     "value": str(event.event_type),              "short": True},
        {"title": "Port Targeted",  "value": str(event.dst_port or "N/A"),       "short": True},
        {"title": "Tool Detected",  "value": event.tool_detected or "Unknown",   "short": True},
        {"title": "MITRE",          "value": event.mitre_technique or "N/A",     "short": True},
        {"title": "Threat Score",   "value": f"{attacker.threat_score:.1f}/100", "short": True},
        {"title": "Status",         "value": "WATCHLIST — Monitoring active",    "short": True},
    ]

def _build_ssh_fields(attacker, event) -> list:
    return [
        {"title": "IP Address",     "value": attacker.ip_address,               "short": True},
        {"title": "Country",        "value": attacker.country_name or "Unknown", "short": True},
        {"title": "Username Tried", "value": event.username or "N/A",            "short": True},
        {"title": "Event Type",     "value": str(event.event_type),              "short": True},
        {"title": "Tool Detected",  "value": event.tool_detected or "Unknown",   "short": True},
        {"title": "MITRE",          "value": event.mitre_technique or "N/A",     "short": True},
        {"title": "Total Attempts", "value": str(attacker.ssh_attempts),         "short": True},
        {"title": "Threat Score",   "value": f"{attacker.threat_score:.1f}/100", "short": True},
    ]

def _build_http_fields(attacker, event) -> list:
    return [
        {"title": "IP Address",     "value": attacker.ip_address,               "short": True},
        {"title": "Method",         "value": event.http_method or "N/A",         "short": True},
        {"title": "Path",           "value": event.http_path or "N/A",           "short": True},
        {"title": "User Agent",     "value": (event.user_agent or "N/A")[:50],   "short": False},
        {"title": "Tool Detected",  "value": event.tool_detected or "Unknown",   "short": True},
        {"title": "MITRE",          "value": event.mitre_technique or "N/A",     "short": True},
    ]

def _build_blocked_fields(attacker) -> list:
    return [
        {"title": "IP Address",     "value": attacker.ip_address,               "short": True},
        {"title": "Country",        "value": attacker.country_name or "Unknown", "short": True},
        {"title": "Tools Used",     "value": ", ".join(attacker.tools_detected or []) or "N/A", "short": False},
        {"title": "Total Events",   "value": str(attacker.total_events),         "short": True},
        {"title": "Threat Score",   "value": f"{attacker.threat_score:.1f}/100", "short": True},
        {"title": "Action",         "value": "IP BLOCKED via iptables",          "short": True},
    ]

def _get_ts() -> int:
    from app.core.timezone import now_wib
    return int(now_wib().timestamp())