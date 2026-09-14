from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.redaction import redact
from app.core.errors import AppError
from app.domain.analysis import REVIEW_CAVEAT, latest_analysis
from app.domain.incidents import add_event, require_incident
from app.repository.models import Postmortem, TimelineEvent, utcnow


async def get_postmortem(
    session: AsyncSession, incident_id: str, lock: bool = False
) -> Postmortem:
    query = select(Postmortem).where(Postmortem.incident_id == incident_id)
    if lock:
        query = query.with_for_update()
    postmortem = await session.scalar(query)
    if postmortem is None:
        raise AppError("postmortem_not_found", "Generate a postmortem first", 404)
    return postmortem


async def generate_postmortem(session: AsyncSession, incident_id: str) -> Postmortem:
    incident = await require_incident(session, incident_id, lock=True)
    try:
        analysis = await latest_analysis(session, incident_id)
    except AppError:
        analysis = None
    events = list(
        (
            await session.scalars(
                select(TimelineEvent)
                .where(TimelineEvent.incident_id == incident_id)
                .order_by(TimelineEvent.created_at)
                .limit(1000)
            )
        ).all()
    )
    timeline_lines: list[str] = []
    remaining = 60000
    for event in events:
        line = f"- {event.created_at.isoformat()}: {event.message}"
        if len(line) > remaining:
            timeline_lines.append(
                "- Additional timeline content omitted from this draft. Review the full incident timeline."
            )
            break
        timeline_lines.append(line)
        remaining -= len(line) + 1
    sections = [
        f"# Postmortem: {incident.title}",
        f"> DRAFT - {REVIEW_CAVEAT}",
        "## Incident",
        f"- ID: {incident.id}\n- Service: {incident.service}\n- Severity: {incident.severity}\n- Status: {incident.status}\n- Started: {incident.created_at.isoformat()}\n- Resolved: {incident.resolved_at.isoformat() if incident.resolved_at else 'Ongoing'}",
        "## Summary",
        (
            analysis.summary
            if analysis
            else incident.description or "Add an engineer-reviewed incident summary."
        ),
        "## Impact",
        "To be completed by the incident owner: affected users, duration, and business impact.",
        "## Probable cause (requires verification)",
        (
            analysis.probable_cause
            if analysis
            else "No analysis yet. Document the verified cause and supporting evidence."
        ),
    ]
    if analysis:
        sections += [
            f"Model confidence: {analysis.confidence:.0%}. This is not a calibrated probability.",
            "## Supporting evidence",
            "\n".join(f"- {evidence}" for evidence in analysis.evidence)
            or "- No supporting evidence available.",
            "## Suggested remediation",
            "\n".join(f"- [ ] {step}" for step in analysis.remediation_steps)
            or "- [ ] Review the incident with the service owner.",
        ]
    sections += [
        "## Timeline (UTC)",
        "\n".join(timeline_lines),
        "## What went well",
        "To be completed during the blameless review.",
        "## What could improve",
        "To be completed during the blameless review.",
        "## Follow-up actions",
        "- [ ] Assign an owner and due date to each corrective action.\n- [ ] Confirm monitoring covers the failure mode.\n- [ ] Review and approve this draft before publication.",
    ]
    if analysis and analysis.caveats:
        sections += [
            "## Limitations",
            "\n".join(f"- {caveat}" for caveat in analysis.caveats),
        ]
    markdown = redact("\n\n".join(sections) + "\n")
    postmortem = await session.scalar(
        select(Postmortem).where(Postmortem.incident_id == incident_id)
    )
    if postmortem:
        postmortem.markdown = markdown
        postmortem.version += 1
        postmortem.updated_at = utcnow()
    else:
        postmortem = Postmortem(incident_id=incident_id, markdown=markdown)
        session.add(postmortem)
    add_event(
        session,
        incident_id,
        "postmortem_generated",
        "Generated an editable postmortem draft; engineer review required.",
    )
    await session.flush()
    return postmortem
