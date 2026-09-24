from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlmodel import Session, SQLModel, create_engine, select

from radar.models import CertResult, Scan, Service, Setting
from radar.services import recompute_latest


def make_certificate(host: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=5))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_recompute_uses_updated_thresholds_and_refreshes_checks(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'recompute.db').as_posix()}")
    SQLModel.metadata.create_all(engine)
    service = Service(host="expiring.example", owner="owner@example")
    with Session(engine) as db:
        db.add(service)
        db.commit()
        db.refresh(service)
        db.add(Scan(id=1, status="done", total=1, processed=1))
        db.add(
            CertResult(
                scan_id=1,
                service_id=service.id,
                reachable=True,
                leaf_pem=make_certificate(service.host),
                not_after=datetime.now(UTC) + timedelta(days=5),
                san_dns=["expiring.example"],
                chain_verify_code=0,
                status="Critical",
                chain_status="unknown",
            )
        )
        db.add(Setting(key="critical_days", value="3"))
        db.add(Setting(key="warning_days", value="30"))
        db.add(Setting(key="info_days", value="60"))
        db.commit()

    monkeypatch.setattr("radar.services.session", lambda: Session(engine, expire_on_commit=False))
    monkeypatch.setattr(
        "radar.services.load_config",
        lambda: {
            "thresholds": {"info_days": 60, "warning_days": 30, "critical_days": 14},
        },
    )
    monkeypatch.setattr("radar.services.audit", lambda *args, **kwargs: None)

    assert recompute_latest() == 1

    with Session(engine) as db:
        result = db.exec(select(CertResult)).one()
    assert result.status == "Warning"
    assert result.days_left == 4
    assert result.hostname_match is True
    assert result.self_signed is True
    assert result.weak_crypto is False
    assert result.chain_status == "self_signed"
    assert any(f["code"] == "SELF_SIGNED" for f in result.findings)
