"""Create the initial RAJAWALI schema.

Revision ID: 001_init
Revises:
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_init"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    attacker_type = sa.Enum("human", "bot", "unknown", name="attackertype")
    skill_level = sa.Enum("low", "medium", "high", "advanced", name="skilllevel")
    attacker_status = sa.Enum("active", "blocked", "monitoring", "resolved", name="attackerstatus")
    event_type = sa.Enum(
        "port_scan", "dns_recon", "threat_intel", "banner_grab", "ssh_connect",
        "ssh_login", "ssh_command", "http_request", "http_crawl", "lure_access",
        "ip_blocked", "tarpit_applied", "fake_intel_fed", name="eventtype",
    )
    event_severity = sa.Enum("info", "low", "medium", "high", "critical", name="eventseverity")
    threat_level = sa.Enum("minimal", "low", "medium", "high", "critical", name="threatlevel")
    threat_category = sa.Enum(
        "reconnaissance", "brute_force", "exploitation", "lateral_movement",
        "exfiltration", "apt", "botnet", "unknown", name="threatcategory",
    )
    for enum in (attacker_type, skill_level, attacker_status, event_type, event_severity, threat_level, threat_category):
        enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "attackers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("hostname", sa.String(255)),
        sa.Column("country_code", sa.String(10)),
        sa.Column("country_name", sa.String(100)),
        sa.Column("isp", sa.String(255)),
        sa.Column("org", sa.String(255)),
        sa.Column("threat_score", sa.Float(), server_default="0"),
        sa.Column("attacker_type", attacker_type, server_default="unknown"),
        sa.Column("skill_level", skill_level, server_default="low"),
        sa.Column("status", attacker_status, server_default="monitoring"),
        sa.Column("tools_detected", sa.JSON(), server_default="[]"),
        sa.Column("mitre_ttps", sa.JSON(), server_default="[]"),
        sa.Column("mitre_stages", sa.JSON(), server_default="[]"),
        sa.Column("total_events", sa.Integer(), server_default="0"),
        sa.Column("ssh_attempts", sa.Integer(), server_default="0"),
        sa.Column("http_attempts", sa.Integer(), server_default="0"),
        sa.Column("login_attempts", sa.Integer(), server_default="0"),
        sa.Column("commands_executed", sa.Integer(), server_default="0"),
        sa.Column("is_known_malicious", sa.Integer(), server_default="0"),
        sa.Column("abuse_confidence", sa.Float(), server_default="0"),
        sa.Column("blacklist_sources", sa.JSON(), server_default="[]"),
        sa.Column("is_blocked", sa.Integer(), server_default="0"),
        sa.Column("is_tarpitted", sa.Integer(), server_default="0"),
        sa.Column("fake_intel_fed", sa.Integer(), server_default="0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("blocked_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("ip_address"),
    )
    op.create_index("ix_attackers_ip_address", "attackers", ["ip_address"])

    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("attacker_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("attackers.id"), nullable=False),
        sa.Column("event_type", event_type, nullable=False),
        sa.Column("severity", event_severity, server_default="info"),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer()),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("protocol", sa.String(10)),
        sa.Column("raw_payload", sa.Text()),
        sa.Column("parsed_data", sa.JSON(), server_default="{}"),
        sa.Column("username", sa.String(255)),
        sa.Column("password", sa.String(255)),
        sa.Column("command", sa.Text()),
        sa.Column("http_method", sa.String(10)),
        sa.Column("http_path", sa.String(1024)),
        sa.Column("user_agent", sa.String(512)),
        sa.Column("headers", sa.JSON(), server_default="{}"),
        sa.Column("mitre_technique", sa.String(20)),
        sa.Column("mitre_technique_name", sa.String(255)),
        sa.Column("tool_detected", sa.String(100)),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("interval_ms", sa.Float()),
    )
    op.create_index("ix_events_attacker_id", "events", ["attacker_id"])
    op.create_index("ix_events_event_type", "events", ["event_type"])
    op.create_index("ix_events_timestamp", "events", ["timestamp"])

    op.create_table(
        "threats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("attacker_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("attackers.id"), nullable=False),
        sa.Column("threat_level", threat_level, server_default="low"),
        sa.Column("threat_category", threat_category, server_default="unknown"),
        sa.Column("threat_score", sa.Float(), server_default="0"),
        sa.Column("cluster_id", sa.Integer()),
        sa.Column("behavior_signature", sa.String(255)),
        sa.Column("is_human", sa.Integer(), server_default="1"),
        sa.Column("human_confidence", sa.Float(), server_default="0.5"),
        sa.Column("ml_features", sa.JSON(), server_default="{}"),
        sa.Column("mitre_tactics", sa.JSON(), server_default="[]"),
        sa.Column("mitre_techniques", sa.JSON(), server_default="[]"),
        sa.Column("kill_chain_phase", sa.String(100)),
        sa.Column("detected_tools", sa.JSON(), server_default="[]"),
        sa.Column("tool_signatures", sa.JSON(), server_default="{}"),
        sa.Column("avg_interval_ms", sa.Float()),
        sa.Column("min_interval_ms", sa.Float()),
        sa.Column("max_interval_ms", sa.Float()),
        sa.Column("timing_pattern", sa.String(50)),
        sa.Column("known_apt_group", sa.String(255)),
        sa.Column("ioc_matches", sa.JSON(), server_default="[]"),
        sa.Column("summary", sa.Text()),
        sa.Column("recommendations", sa.JSON(), server_default="[]"),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_threats_attacker_id", "threats", ["attacker_id"])

    op.create_table(
        "threat_intel_cache",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("is_malicious", sa.Integer(), server_default="0"),
        sa.Column("abuse_confidence", sa.Float(), server_default="0"),
        sa.Column("abuse_reports", sa.Integer(), server_default="0"),
        sa.Column("categories", sa.JSON(), server_default="[]"),
        sa.Column("last_reported", sa.DateTime(timezone=True)),
        sa.Column("raw_response", sa.JSON(), server_default="{}"),
        sa.Column("cached_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("ip_address"),
    )
    op.create_index("ix_threat_intel_cache_ip_address", "threat_intel_cache", ["ip_address"])


def downgrade() -> None:
    op.drop_table("threat_intel_cache")
    op.drop_index("ix_threats_attacker_id", table_name="threats")
    op.drop_table("threats")
    op.drop_index("ix_events_timestamp", table_name="events")
    op.drop_index("ix_events_event_type", table_name="events")
    op.drop_index("ix_events_attacker_id", table_name="events")
    op.drop_table("events")
    op.drop_index("ix_attackers_ip_address", table_name="attackers")
    op.drop_table("attackers")
    for name in ("threatcategory", "threatlevel", "eventseverity", "eventtype", "attackerstatus", "skilllevel", "attackertype"):
        sa.Enum(name=name).drop(op.get_bind(), checkfirst=True)
