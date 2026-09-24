from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column, Index, UniqueConstraint, text
from sqlmodel import Field, SQLModel


def now_utc():
    return datetime.now(UTC)


class Service(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("host", "port", name="uq_service_host_port"),)

    id: int | None = Field(default=None, primary_key=True)
    host: str = Field(index=True)
    port: int = 443
    service_name: str | None = None
    owner: str | None = None
    criticality: str = "medium"
    created_at: datetime = Field(default_factory=now_utc)


class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    started_at: datetime = Field(default_factory=now_utc)
    finished_at: datetime | None = None
    status: str = "running"
    total: int = 0
    processed: int = 0
    triggered_by: str = "cli"


class CertResult(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    service_id: int = Field(index=True)
    reachable: bool = False
    error: str | None = None
    resolved_ip: str | None = None
    leaf_pem: str | None = None
    subject_cn: str | None = None
    san_dns: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    san_ip: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    issuer_cn: str | None = None
    issuer_full: str | None = None
    serial: str | None = None
    thumbprint_sha1: str | None = None
    thumbprint_sha256: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_type: str | None = None
    key_size: int | None = None
    sig_hash: str | None = None
    tls_version: str | None = None
    chain_verify_code: int | None = None
    chain_verify_message: str | None = None
    days_left: int | None = None
    status: str = "Unreachable"
    chain_status: str = "unknown"
    hostname_match: bool | None = None
    self_signed: bool | None = None
    weak_crypto: bool | None = None
    risk_score: int | None = None
    risk_level: str = "N/A"
    findings: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))


class NotificationLog(SQLModel, table=True):
    __table_args__ = (
        Index(
            "uq_notification_success",
            "thumbprint_sha1",
            "threshold",
            "channel",
            unique=True,
            sqlite_where=text("success = 1"),
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    service_id: int
    thumbprint_sha1: str
    threshold: int
    channel: str
    sent_at: datetime = Field(default_factory=now_utc)
    success: bool = True
    message: str


class AuditLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=now_utc)
    actor: str = "local-user"
    action: str
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class Setting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: Any = Field(default=None, sa_column=Column(JSON))
