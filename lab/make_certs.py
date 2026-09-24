from datetime import UTC, datetime, timedelta
from pathlib import Path
import shutil
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(__file__).resolve().parent / "certs"


def gen_rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def make_name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def get_pfx_builder(password: bytes = b"RadarLab123!"):
    return (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password)
    )


def generate(out_dir: Path | str | None = None, now: datetime | None = None):
    out = Path(out_dir) if out_dir else OUT
    out.mkdir(parents=True, exist_ok=True)
    now = now or datetime.now(UTC)

    # 1. Root CA (10 years)
    root_key = gen_rsa_key(2048)
    root_subject = make_name("Radar Lab Root CA")
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    (out / "root_ca.pem").write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    (out / "root_ca.key").write_bytes(
        root_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    # 2. Intermediate CA (signed by Root CA)
    inter_key = gen_rsa_key(2048)
    inter_subject = make_name("Radar Lab Intermediate CA")
    inter_cert = (
        x509.CertificateBuilder()
        .subject_name(inter_subject)
        .issuer_name(root_subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    (out / "intermediate_ca.pem").write_bytes(inter_cert.public_bytes(serialization.Encoding.PEM))
    (out / "intermediate_ca.key").write_bytes(
        inter_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    # 3. Rogue CA (untrusted self-signed root)
    rogue_key = gen_rsa_key(2048)
    rogue_subject = make_name("Radar Lab Rogue CA")
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(rogue_subject)
        .issuer_name(rogue_subject)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rogue_key, hashes.SHA256())
    )
    (out / "rogue_ca.pem").write_bytes(rogue_cert.public_bytes(serialization.Encoding.PEM))

    pfx_builder = get_pfx_builder(b"RadarLab123!")

    # Helper to issue leaf certificates
    def issue_leaf(
        cn: str,
        issuer_cert: x509.Certificate,
        issuer_key: rsa.RSAPrivateKey,
        not_before: datetime,
        not_after: datetime,
        sans: list[str] | None = None,
        san_ips: list[str] | None = None,
        key_size: int = 2048,
        chain_certs: list[x509.Certificate] | None = None,
        append_chain_to_pem: bool = True,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        leaf_key = gen_rsa_key(key_size)
        builder = (
            x509.CertificateBuilder()
            .subject_name(make_name(cn))
            .issuer_name(issuer_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        alt_names: list[x509.GeneralName] = []
        if sans:
            for s in sans:
                alt_names.append(x509.DNSName(s))
        if san_ips:
            import ipaddress
            for ip_s in san_ips:
                alt_names.append(x509.IPAddress(ipaddress.ip_address(ip_s)))
        if alt_names:
            builder = builder.add_extension(x509.SubjectAlternativeName(alt_names), critical=False)

        cert = builder.sign(issuer_key, hashes.SHA256())
        return leaf_key, cert

    def write_bundle(
        name: str,
        leaf_key: rsa.RSAPrivateKey,
        leaf_cert: x509.Certificate,
        chain_certs: list[x509.Certificate] | None = None,
        append_chain_to_pem: bool = True,
    ):
        pem_bytes = leaf_cert.public_bytes(serialization.Encoding.PEM)
        if append_chain_to_pem and chain_certs:
            for c in chain_certs:
                pem_bytes += b"\n" + c.public_bytes(serialization.Encoding.PEM)
        (out / f"{name}.pem").write_bytes(pem_bytes)
        (out / f"{name}.key").write_bytes(
            leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name.encode("utf-8"),
            leaf_key,
            leaf_cert,
            chain_certs,
            pfx_builder,
        )
        (out / f"{name}.pfx").write_bytes(pfx_bytes)

    # 4. Standard Intermediate CA signed targets
    # Future dates: +N days +2 hours; past: -N days +2 hours
    specs = [
        # valid: +200 days +2h
        ("valid.lab.local", "valid.lab.local", ["valid.lab.local"], now - timedelta(days=365), now + timedelta(days=200, hours=2)),
        # expiring: +5 days +2h
        ("expiring.lab.local", "expiring.lab.local", ["expiring.lab.local"], now - timedelta(days=365), now + timedelta(days=5, hours=2)),
        # warning: +25 days +2h
        ("warning.lab.local", "warning.lab.local", ["warning.lab.local"], now - timedelta(days=365), now + timedelta(days=25, hours=2)),
        # info: +45 days +2h
        ("info.lab.local", "info.lab.local", ["info.lab.local"], now - timedelta(days=365), now + timedelta(days=45, hours=2)),
        # expired: from -400d to -5d +2h
        ("expired.lab.local", "expired.lab.local", ["expired.lab.local"], now - timedelta(days=400), now - timedelta(days=5) + timedelta(hours=2)),
        # mismatch: CN and SAN = other.lab.local
        ("mismatch.lab.local", "other.lab.local", ["other.lab.local"], now - timedelta(days=30), now + timedelta(days=365, hours=2)),
        # app.wild: *.wild.lab.local
        ("app.wild.lab.local", "app.wild.lab.local", ["*.wild.lab.local"], now - timedelta(days=30), now + timedelta(days=365, hours=2)),
        # ip.lab.local: with IP SAN 127.0.0.1
        ("ip.lab.local", "ip.lab.local", ["ip.lab.local"], now - timedelta(days=30), now + timedelta(days=365, hours=2)),
    ]

    for host_name, cn, sans, nb, na in specs:
        san_ips = ["127.0.0.1"] if host_name == "ip.lab.local" else None
        l_key, l_cert = issue_leaf(
            cn=cn,
            issuer_cert=inter_cert,
            issuer_key=inter_key,
            not_before=nb,
            not_after=na,
            sans=sans,
            san_ips=san_ips,
        )
        write_bundle(host_name, l_key, l_cert, [inter_cert, root_cert])

    # 5. Incomplete chain scenario: signed by Intermediate CA, but served without intermediate CA in bundle
    inc_key, inc_cert = issue_leaf(
        cn="incomplete-chain.lab.local",
        issuer_cert=inter_cert,
        issuer_key=inter_key,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365, hours=2),
        sans=["incomplete-chain.lab.local"],
    )
    write_bundle("incomplete-chain.lab.local", inc_key, inc_cert, [inter_cert], append_chain_to_pem=False)

    # 6. Chain error (signed by Rogue CA)
    ch_key, ch_cert = issue_leaf(
        cn="chain.lab.local",
        issuer_cert=rogue_cert,
        issuer_key=rogue_key,
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=365, hours=2),
        sans=["chain.lab.local"],
    )
    write_bundle("chain.lab.local", ch_key, ch_cert, [rogue_cert])

    # 7. Self-signed
    self_key = gen_rsa_key(2048)
    self_name = make_name("selfsigned.lab.local")
    self_cert = (
        x509.CertificateBuilder()
        .subject_name(self_name)
        .issuer_name(self_name)
        .public_key(self_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=365, hours=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("selfsigned.lab.local")]), critical=False)
        .sign(self_key, hashes.SHA256())
    )
    write_bundle("selfsigned.lab.local", self_key, self_cert, None)

    # 8. Weak certificate: RSA 1024 and SHA-1
    weak_key_path = out / "weak.lab.local.key"
    weak_pem_path = out / "weak.lab.local.pem"
    weak_pfx_path = out / "weak.lab.local.pfx"
    openssl_bin = shutil.which("openssl")
    generated_with_openssl = False
    if openssl_bin:
        try:
            cmd = [
                openssl_bin,
                "req",
                "-x509",
                "-newkey",
                "rsa:1024",
                "-keyout",
                str(weak_key_path),
                "-out",
                str(weak_pem_path),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=weak.lab.local",
                "-sha1",
            ]
            res = subprocess.run(cmd, capture_output=True, check=True)
            if res.returncode == 0 and weak_pem_path.exists():
                generated_with_openssl = True
                weak_der = x509.load_pem_x509_certificate(weak_pem_path.read_bytes())
                weak_priv = serialization.load_pem_private_key(weak_key_path.read_bytes(), password=None)
                pfx_bytes = pkcs12.serialize_key_and_certificates(
                    b"weak.lab.local",
                    weak_priv,
                    weak_der,
                    None,
                    pfx_builder,
                )
                weak_pfx_path.write_bytes(pfx_bytes)
        except Exception:
            generated_with_openssl = False

    if not generated_with_openssl:
        w_key = gen_rsa_key(1024)
        w_cert = (
            x509.CertificateBuilder()
            .subject_name(make_name("weak.lab.local"))
            .issuer_name(make_name("weak.lab.local"))
            .public_key(w_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now + timedelta(days=365, hours=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("weak.lab.local")]), critical=False)
            .sign(w_key, hashes.SHA256())
        )
        write_bundle("weak.lab.local", w_key, w_cert, None)

    try:
        print(f"Сертификаты созданы: {out}")
    except UnicodeEncodeError:
        print(f"Certificates created: {out}")


import contextlib


def main():
    if hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(Exception):
            sys.stdout.reconfigure(encoding="utf-8")
    generate(OUT)


if __name__ == "__main__":
    main()
