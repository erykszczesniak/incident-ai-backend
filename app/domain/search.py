import logging
import math
import re

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.client import LLMClient
from app.ai.redaction import redact
from app.core.config import Settings
from app.repository.models import Incident
from app.schemas.api import IncidentRead, SearchItem, SearchResults

logger = logging.getLogger("incident_ai.search")


async def search_incidents(
    session: AsyncSession,
    query: str,
    limit: int,
    llm: LLMClient,
    settings: Settings,
    exclude_id: str | None = None,
) -> SearchResults:
    query = redact(query)
    try:
        vector = await llm.embed(query)
        if not vector or any(not math.isfinite(value) for value in vector):
            raise ValueError("Invalid embedding")
        if session.get_bind().dialect.name == "postgresql":
            # pgvector distance runs in PostgreSQL. Different model dimensions
            # are filtered first, preventing incompatible vector comparisons.
            distance = Incident.embedding.cosine_distance(vector)
            statement = select(Incident, distance.label("distance")).where(
                Incident.embedding.is_not(None),
                Incident.embedding_model == settings.embedding_model,
                func.vector_dims(Incident.embedding) == len(vector),
            )
            if exclude_id:
                statement = statement.where(Incident.id != exclude_id)
            rows = (
                await session.execute(statement.order_by(distance).limit(limit))
            ).all()
            if rows:
                return SearchResults(
                    items=[
                        SearchItem(
                            incident=IncidentRead.model_validate(incident),
                            score=round(max(-1.0, min(1.0, 1.0 - float(value))), 4),
                        )
                        for incident, value in rows
                    ],
                    mode="semantic",
                )
        else:
            statement = select(Incident).where(
                Incident.embedding.is_not(None),
                Incident.embedding_model == settings.embedding_model,
            )
            if exclude_id:
                statement = statement.where(Incident.id != exclude_id)
            scored: list[tuple[float, Incident]] = []
            magnitude = math.sqrt(sum(value * value for value in vector))
            for incident in (await session.scalars(statement)).all():
                values = incident.embedding
                if values is None or len(values) != len(vector):
                    continue
                denominator = magnitude * math.sqrt(
                    sum(value * value for value in values)
                )
                if denominator:
                    score = (
                        sum(
                            left * right
                            for left, right in zip(vector, values, strict=True)
                        )
                        / denominator
                    )
                    scored.append((score, incident))
            if scored:
                scored.sort(key=lambda item: item[0], reverse=True)
                return SearchResults(
                    items=[
                        SearchItem(
                            incident=IncidentRead.model_validate(incident),
                            score=round(score, 4),
                        )
                        for score, incident in scored[:limit]
                    ],
                    mode="semantic",
                )
    except Exception as exc:
        logger.info(
            "Semantic search unavailable; using lexical matching",
            extra={"exception_type": type(exc).__name__},
        )
        # A PostgreSQL SQL error aborts a transaction. Search embedding/SQL runs
        # without mutations, so rollback safely permits the documented fallback.
        await session.rollback()
    tokens = list(dict.fromkeys(re.findall(r"\w+", query.lower())))[:20]
    if not tokens:
        return SearchResults(items=[], mode="lexical")
    text_column = func.lower(
        Incident.title + " " + Incident.service + " " + Incident.description
    )
    statement = select(Incident).where(
        or_(*(text_column.contains(token, autoescape=True) for token in tokens))
    )
    if exclude_id:
        statement = statement.where(Incident.id != exclude_id)
    # All matching rows participate in ranking, rather than silently searching
    # only the newest page. SQL prefilters irrelevant incidents.
    lexical: list[tuple[float, Incident]] = []
    for incident in (await session.scalars(statement)).all():
        words = f"{incident.title} {incident.service} {incident.description}".lower()
        score = sum(token in words for token in tokens) / len(tokens)
        lexical.append((score, incident))
    lexical.sort(key=lambda item: (item[0], item[1].created_at), reverse=True)
    return SearchResults(
        items=[
            SearchItem(
                incident=IncidentRead.model_validate(incident), score=round(score, 4)
            )
            for score, incident in lexical[:limit]
        ],
        mode="lexical",
    )
