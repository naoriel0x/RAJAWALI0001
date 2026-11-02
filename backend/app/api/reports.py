from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.timezone import now_wib
import io
import logging

from app.core.database import get_db
from app.models.attacker import Attacker
from app.models.event import Event
from app.models.threat import Threat

router = APIRouter()
logger = logging.getLogger(__name__)
REPORT_EVENT_LIMIT = 50


@router.get("/attacker/{attacker_id}/pdf", summary="Generate a PDF report for one attacker")
async def generate_attacker_report(attacker_id: str, db: AsyncSession = Depends(get_db)):
    attacker_res = await db.execute(select(Attacker).where(Attacker.id == attacker_id))
    attacker = attacker_res.scalar_one_or_none()
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    threat_res = await db.execute(select(Threat).where(Threat.attacker_id == attacker_id))
    threat = threat_res.scalar_one_or_none()

    events_res = await db.execute(
        select(Event).where(Event.attacker_id == attacker_id).order_by(desc(Event.timestamp)).limit(REPORT_EVENT_LIMIT)
    )
    events = events_res.scalars().all()

    pdf_bytes = _build_pdf(attacker, threat, events)

    filename = f"RAJAWALI_Report_{attacker.ip_address.replace('.', '_')}_{now_wib().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/summary/json", summary="Return a JSON summary for all attackers")
async def summary_report_json(db: AsyncSession = Depends(get_db)):
    attackers = (await db.execute(select(Attacker).order_by(desc(Attacker.threat_score)))).scalars().all()
    threats = (await db.execute(select(Threat))).scalars().all()
    threat_map = {str(t.attacker_id): t for t in threats}

    report = {
        "generated_at": now_wib().isoformat(),
        "system": "RAJAWALI",
        "total_attackers": len(attackers),
        "attackers": [
            {
                "id": str(a.id),
                "ip": a.ip_address,
                "country": a.country_name,
                "country_code": a.country_code,
                "isp": a.isp,
                "org": a.org,
                "threat_score": a.threat_score,
                "skill_level": a.skill_level,
                "attacker_type": a.attacker_type,
                "status": a.status,
                "total_events": a.total_events,
                "mitre_ttps": a.mitre_ttps,
                "tools_detected": a.tools_detected,
                "known_apt": threat_map.get(str(a.id), {}) and getattr(threat_map.get(str(a.id)), "known_apt_group", None),
            }
            for a in attackers
        ],
    }
    return report


def _build_pdf(attacker, threat, events) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import cm

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("title", parent=styles["Title"], textColor=colors.HexColor("#dc2626"), fontSize=20)
    story.append(Paragraph("RAJAWALI — Threat Intelligence Report", title_style))
    story.append(Paragraph(f"Generated: {now_wib().strftime('%Y-%m-%d %H:%M WIB')}", styles["Normal"]))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Attacker Profile", styles["Heading2"]))
    attacker_data = [
        ["IP Address", attacker.ip_address],
        ["Country", f"{attacker.country_name} ({attacker.country_code})" if attacker.country_code else "Unknown"],
        ["ISP / Org", attacker.isp or "N/A"],
        ["Threat Score", f"{attacker.threat_score:.1f} / 100"],
        ["Attacker Type", str(attacker.attacker_type)],
        ["Skill Level", str(attacker.skill_level)],
        ["Status", str(attacker.status)],
        ["Total Events", str(attacker.total_events)],
        ["First Seen", str(attacker.first_seen)],
        ["Is Blocked", "YES" if attacker.is_blocked else "NO"],
    ]
    t = Table(attacker_data, colWidths=[5*cm, 12*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    if threat:
        story.append(Paragraph("Threat Intelligence", styles["Heading2"]))
        threat_data = [
            ["Threat Level", str(threat.threat_level)],
            ["Category", str(threat.threat_category)],
            ["Human Confidence", f"{threat.human_confidence*100:.0f}%"],
            ["Timing Pattern", threat.timing_pattern or "N/A"],
            ["Known APT Group", threat.known_apt_group or "Unknown"],
            ["Kill Chain Phase", threat.kill_chain_phase or "N/A"],
            ["MITRE Tactics", ", ".join(threat.mitre_tactics or [])],
            ["Detected Tools", ", ".join(threat.detected_tools or [])],
        ]
        t2 = Table(threat_data, colWidths=[5*cm, 12*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#7f1d1d")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t2)

        if threat.summary:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Summary", styles["Heading3"]))
            story.append(Paragraph(threat.summary, styles["Normal"]))

        story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph(f"Recent Events (last {REPORT_EVENT_LIMIT})", styles["Heading2"]))
    if events:
        event_data = [["Timestamp", "Type", "Severity", "Tool", "MITRE"]]
        for e in events:
            event_data.append([
                str(e.timestamp)[:19] if e.timestamp else "",
                str(e.event_type),
                str(e.severity),
                e.tool_detected or "",
                e.mitre_technique or "",
            ])
        t3 = Table(event_data, colWidths=[4*cm, 3.5*cm, 2.5*cm, 3*cm, 2*cm])
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        story.append(t3)

    doc.build(story)
    return buf.getvalue()