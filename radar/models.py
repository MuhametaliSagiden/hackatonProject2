from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


def now_utc(): return datetime.now(UTC)

class Service(SQLModel, table=True):
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
    scan_id: int
    service_id: int
    reachable: bool = False
    error: str | None = None
    resolved_ip: str | None = None
    leaf_pem: str | None = None
    subject_cn: str | None = None
    san_dns: str = "[]"
    san_ip: str = "[]"
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
    findings: str = "[]"

class NotificationLog(SQLModel, table=True):
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
    details: str = "{}"
