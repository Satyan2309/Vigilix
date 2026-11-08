from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5
from typing import Any

from sqlalchemy import DateTime, Float, Integer, String, Text, create_engine, select, func, ForeignKey, inspect, text, delete
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.engine import make_url

from app.config import DATABASE_URL
from app.schemas import NormalizedEvent


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(24), default="analyst")
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class EventRow(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    event_time: Mapped[str] = mapped_column(String(64), index=True)
    event_name: Mapped[str] = mapped_column(String(256), index=True)
    event_source: Mapped[str] = mapped_column(String(256), default="unknown")
    principal: Mapped[str] = mapped_column(String(512), index=True, default="unknown")
    source_ip: Mapped[str] = mapped_column(String(128), index=True, default="unknown")
    region: Mapped[str] = mapped_column(String(64), default="unknown")
    provider: Mapped[str] = mapped_column(String(32), default="aws")
    severity: Mapped[float | None] = mapped_column(Float, nullable=True)
    normalized_json: Mapped[str] = mapped_column(Text)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IncidentRow(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32))
    risk_score: Mapped[int] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="OPEN")
    report_json: Mapped[str] = mapped_column(Text)


class ChatMessageRow(Base):
    __tablename__ = "chat_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(String(36), index=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


_url = make_url(DATABASE_URL)
_connect_args = {"check_same_thread": False} if _url.get_backend_name() == "sqlite" else {}
if _url.get_backend_name() == "sqlite" and _url.database and _url.database != ":memory:":
    from pathlib import Path
    Path(_url.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
    **({"pool_size": 10, "max_overflow": 20, "pool_timeout": 30} if _url.get_backend_name() != "sqlite" else {}),
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # Lightweight migration for existing SQLite/Postgres MVP databases.
    inspector = inspect(engine)
    for table in ("events", "incidents"):
        if table in inspector.get_table_names():
            columns = {column["name"] for column in inspector.get_columns(table)}
            if "owner_id" not in columns:
                with engine.begin() as connection:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN owner_id VARCHAR(36)"))
                with engine.begin() as connection:
                    connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table}_owner_id ON {table} (owner_id)"))
    if "incidents" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("incidents")}
        if "status" not in columns:
            with engine.begin() as connection:
                connection.execute(text("ALTER TABLE incidents ADD COLUMN status VARCHAR(32) DEFAULT 'OPEN'"))


def _storage_event_id(owner_id: str | None, event_id: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"cloudsentry:{owner_id}:{event_id}")) if owner_id is not None else event_id


def save_events(events: list[NormalizedEvent], owner_id: str | None = None) -> int:
    if not events:
        return 0
    inserted = 0
    with SessionLocal() as session:
        storage_ids = [_storage_event_id(owner_id, event.event_id) for event in events]
        existing: dict[str, EventRow] = {}
        for offset in range(0, len(storage_ids), 500):
            batch = storage_ids[offset:offset + 500]
            query = select(EventRow).where(EventRow.event_id.in_(batch))
            query = query.where(EventRow.owner_id == owner_id) if owner_id is not None else query.where(EventRow.owner_id.is_(None))
            rows = session.execute(query).scalars().all()
            existing.update({row.event_id: row for row in rows})
        for event, storage_id in zip(events, storage_ids):
            row = existing.get(storage_id)
            payload = event.model_dump_json()
            if row is None:
                row = EventRow(event_id=storage_id, owner_id=owner_id, event_time=event.event_time,
                    event_name=event.event_name, event_source=event.event_source, principal=event.principal,
                    source_ip=event.source_ip, region=event.region, provider=event.provider,
                    severity=event.severity, normalized_json=payload)
                session.add(row)
                existing[storage_id] = row
                inserted += 1
            else:
                row.event_time=event.event_time; row.event_name=event.event_name; row.event_source=event.event_source
                row.principal=event.principal; row.source_ip=event.source_ip; row.region=event.region
                row.provider=event.provider; row.severity=event.severity; row.normalized_json=payload
        try:
            session.commit()
        except Exception as exc:
            session.rollback()
            raise RuntimeError("Could not save events. Check the database connection, schema, and server logs.") from exc
    return inserted


def list_events(limit: int = 200, event_ids: list[str] | None = None, from_time: str | None = None,
    to_time: str | None = None, event_name: str | None = None, principal: str | None = None,
    source_ip: str | None = None, provider: str | None = None, owner_id: str | None = None) -> list[NormalizedEvent]:
    with SessionLocal() as session:
        query = select(EventRow)
        query = query.where(EventRow.owner_id == owner_id) if owner_id is not None else query.where(EventRow.owner_id.is_(None))
        if event_ids is not None:
            if not event_ids: return []
            stored_ids = [_storage_event_id(owner_id, event_id) for event_id in event_ids]
            query = query.where(EventRow.event_id.in_(stored_ids))
        if from_time: query = query.where(EventRow.event_time >= from_time)
        if to_time: query = query.where(EventRow.event_time < to_time)
        if event_name and event_name.strip(): query = query.where(EventRow.event_name.ilike(f"%{event_name.strip()}%"))
        if principal and principal.strip(): query = query.where(EventRow.principal.ilike(f"%{principal.strip()}%"))
        if source_ip and source_ip.strip(): query = query.where(EventRow.source_ip.ilike(f"%{source_ip.strip()}%"))
        if provider and provider.strip(): query = query.where(EventRow.provider == provider.strip())
        rows = session.execute(query.order_by(EventRow.event_time.desc()).limit(limit)).scalars().all()
        result=[]
        for row in rows:
            try: result.append(NormalizedEvent.model_validate_json(row.normalized_json))
            except Exception: continue
        return result


def count_events(owner_id: str | None = None) -> int:
    with SessionLocal() as session:
        query = select(func.count()).select_from(EventRow)
        query = query.where(EventRow.owner_id == owner_id) if owner_id is not None else query.where(EventRow.owner_id.is_(None))
        return int(session.execute(query).scalar_one())


def count_event_name(owner_id: str, event_name: str | None = None, provider: str | None = None, failed_only: bool = False) -> int:
    with SessionLocal() as session:
        query = select(EventRow).where(EventRow.owner_id == owner_id)
        if event_name: query = query.where(EventRow.event_name.ilike(f"%{event_name}%"))
        if provider: query = query.where(EventRow.provider == provider)
        if not failed_only:
            return int(session.execute(select(func.count()).select_from(query.subquery())).scalar_one())
        rows = session.execute(query).scalars().all()
        count = 0
        for row in rows:
            try:
                event = NormalizedEvent.model_validate_json(row.normalized_json)
                if event.error_code or event.raw.get("errorCode") or event.raw.get("errorMessage"):
                    count += 1
            except Exception:
                continue
        return count


def clear_events(owner_id: str) -> int:
    with SessionLocal() as session:
        count = session.execute(select(func.count()).select_from(EventRow).where(EventRow.owner_id == owner_id)).scalar_one()
        session.execute(delete(EventRow).where(EventRow.owner_id == owner_id))
        session.commit()
        return int(count)


def save_incident(report: dict[str, Any], owner_id: str | None = None) -> None:
    with SessionLocal() as session:
        status = report.get("status", "OPEN").upper().strip()
        report["status"] = status
        row = IncidentRow(
            incident_id=report["incident_id"],
            owner_id=owner_id,
            title=report["title"],
            severity=report["severity"],
            risk_score=int(report["risk_score"]),
            summary=report["summary"],
            status=status,
            report_json=json.dumps(report, default=str),
        )
        session.merge(row)
        session.commit()


def list_incidents(limit: int = 50, owner_id: str | None = None) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        query = select(IncidentRow)
        query = query.where(IncidentRow.owner_id == owner_id) if owner_id is not None else query.where(IncidentRow.owner_id.is_(None))
        rows = session.execute(query.order_by(IncidentRow.created_at.desc()).limit(limit)).scalars().all()
        result = []
        for row in rows:
            try:
                data = json.loads(row.report_json)
                data["status"] = getattr(row, "status", data.get("status", "OPEN"))
                result.append(data)
            except Exception:
                continue
        return result


def get_incident(incident_id: str, owner_id: str | None = None) -> dict[str, Any] | None:
    with SessionLocal() as session:
        query = select(IncidentRow).where(IncidentRow.incident_id == incident_id)
        query = query.where(IncidentRow.owner_id == owner_id) if owner_id is not None else query.where(IncidentRow.owner_id.is_(None))
        row = session.execute(query).scalar_one_or_none()
        if not row:
            return None
        data = json.loads(row.report_json)
        data["status"] = getattr(row, "status", data.get("status", "OPEN"))
        return data


def update_incident_status(incident_id: str, status: str, owner_id: str | None = None) -> dict[str, Any] | None:
    with SessionLocal() as session:
        query = select(IncidentRow).where(IncidentRow.incident_id == incident_id)
        if owner_id is not None:
            query = query.where(IncidentRow.owner_id == owner_id)
        row = session.execute(query).scalar_one_or_none()
        if not row:
            return None
        new_status = status.upper().strip()
        row.status = new_status
        data = json.loads(row.report_json)
        data["status"] = new_status
        row.report_json = json.dumps(data, default=str)
        session.commit()
        return data


def toggle_incident_action(incident_id: str, action_idx: int, completed: bool, owner_id: str | None = None) -> dict[str, Any] | None:
    with SessionLocal() as session:
        query = select(IncidentRow).where(IncidentRow.incident_id == incident_id)
        if owner_id is not None:
            query = query.where(IncidentRow.owner_id == owner_id)
        row = session.execute(query).scalar_one_or_none()
        if not row:
            return None
        data = json.loads(row.report_json)
        actions = data.get("defensive_actions", [])
        if 0 <= action_idx < len(actions):
            item = actions[action_idx]
            if isinstance(item, dict):
                item["completed"] = completed
            else:
                actions[action_idx] = {"text": str(item), "completed": completed}
            data["defensive_actions"] = actions
            row.report_json = json.dumps(data, default=str)
            session.commit()
        return data


def delete_incident(incident_id: str, owner_id: str | None = None) -> bool:
    with SessionLocal() as session:
        query = select(IncidentRow).where(IncidentRow.incident_id == incident_id)
        if owner_id is not None:
            query = query.where(IncidentRow.owner_id == owner_id)
        row = session.execute(query).scalar_one_or_none()
        if not row:
            return False
        session.delete(row)
        session.commit()
        return True


def get_telemetry_stats(owner_id: str) -> dict[str, Any]:
    with SessionLocal() as session:
        total = session.execute(select(func.count()).select_from(EventRow).where(EventRow.owner_id == owner_id)).scalar_one()

        # Top event names
        top_events_rows = session.execute(
            select(EventRow.event_name, func.count(EventRow.event_id))
            .where(EventRow.owner_id == owner_id)
            .group_by(EventRow.event_name)
            .order_by(func.count(EventRow.event_id).desc())
            .limit(6)
        ).all()

        # Top IPs
        top_ips_rows = session.execute(
            select(EventRow.source_ip, func.count(EventRow.event_id))
            .where(EventRow.owner_id == owner_id, EventRow.source_ip != "unknown")
            .group_by(EventRow.source_ip)
            .order_by(func.count(EventRow.event_id).desc())
            .limit(6)
        ).all()

        # Top Principals
        top_principals_rows = session.execute(
            select(EventRow.principal, func.count(EventRow.event_id))
            .where(EventRow.owner_id == owner_id, EventRow.principal != "unknown")
            .group_by(EventRow.principal)
            .order_by(func.count(EventRow.event_id).desc())
            .limit(6)
        ).all()

        # Failed logins
        failed_logins = session.execute(
            select(func.count())
            .select_from(EventRow)
            .where(EventRow.owner_id == owner_id, EventRow.event_name.ilike("%ConsoleLogin%"))
        ).scalar_one()

        # Distinct principals count
        principals_count = session.execute(
            select(func.count(func.distinct(EventRow.principal)))
            .where(EventRow.owner_id == owner_id, EventRow.principal != "unknown")
        ).scalar_one()

        # Distinct source IPs count
        ips_count = session.execute(
            select(func.count(func.distinct(EventRow.source_ip)))
            .where(EventRow.owner_id == owner_id, EventRow.source_ip != "unknown")
        ).scalar_one()

        return {
            "total_events": int(total),
            "unique_principals": int(principals_count),
            "unique_ips": int(ips_count),
            "failed_logins": int(failed_logins),
            "top_events": [{"name": row[0], "count": int(row[1])} for row in top_events_rows],
            "top_ips": [{"ip": row[0], "count": int(row[1])} for row in top_ips_rows],
            "top_principals": [{"principal": row[0], "count": int(row[1])} for row in top_principals_rows],
        }


def claim_legacy_data(owner_id: str) -> None:
    """Assign pre-authentication MVP records to the first account without exposing them globally."""
    with SessionLocal() as session:
        legacy_events = session.execute(select(EventRow).where(EventRow.owner_id.is_(None))).scalars().all()
        for row in legacy_events:
            try:
                original_id = NormalizedEvent.model_validate_json(row.normalized_json).event_id
            except Exception:
                original_id = row.event_id
            row.event_id = _storage_event_id(owner_id, original_id)
            row.owner_id = owner_id
        legacy_incidents = session.execute(select(IncidentRow).where(IncidentRow.owner_id.is_(None))).scalars().all()
        for row in legacy_incidents:
            row.owner_id = owner_id
        session.commit()


def create_user(user_id: str, email: str, full_name: str, password_hash: str, role: str) -> UserRow:
    with SessionLocal() as session:
        row = UserRow(id=user_id, email=email.lower().strip(), full_name=full_name.strip(), password_hash=password_hash, role=role)
        session.add(row)
        session.commit()
        session.refresh(row)
        return row


def get_user_by_email(email: str) -> UserRow | None:
    with SessionLocal() as session:
        return session.execute(select(UserRow).where(UserRow.email == email.lower().strip())).scalar_one_or_none()


def get_user_by_id(user_id: str) -> UserRow | None:
    with SessionLocal() as session:
        return session.get(UserRow, user_id)


def user_count() -> int:
    with SessionLocal() as session:
        return int(session.execute(select(func.count()).select_from(UserRow)).scalar_one())


def update_user_profile(user_id: str, full_name: str) -> UserRow | None:
    with SessionLocal() as session:
        row = session.get(UserRow, user_id)
        if row is None:
            return None
        row.full_name = full_name.strip()
        session.commit()
        session.refresh(row)
        return row


def save_chat_message(owner_id: str, session_id: str, role: str, content: str) -> None:
    with SessionLocal() as session:
        session.add(ChatMessageRow(owner_id=owner_id, session_id=session_id, role=role, content=content))
        session.commit()


def list_chat_messages(owner_id: str, session_id: str, limit: int = 20) -> list[dict[str, str]]:
    with SessionLocal() as session:
        rows = session.execute(select(ChatMessageRow).where(ChatMessageRow.owner_id == owner_id,
            ChatMessageRow.session_id == session_id).order_by(ChatMessageRow.id.desc()).limit(limit)).scalars().all()
        rows.reverse()
        return [{"role": row.role, "content": row.content} for row in rows]


def list_users() -> list[UserRow]:
    with SessionLocal() as session:
        return session.execute(select(UserRow).order_by(UserRow.created_at.asc())).scalars().all()


def update_user_role(user_id: str, role: str) -> UserRow | None:
    with SessionLocal() as session:
        row = session.get(UserRow, user_id)
        if row is None:
            return None
        row.role = role
        session.commit()
        session.refresh(row)
        return row
