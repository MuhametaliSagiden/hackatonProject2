from datetime import UTC, datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent / "certs"

def key(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def write(path, data): path.write_bytes(data)

def issue(cn, issuer_cert, issuer_key, *, days=365, sans=None, subject_key=None):
    subject_key=subject_key or key(); now=datetime.now(UTC)
    builder=(x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer_cert.subject).public_key(subject_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=365)).not_valid_after(now+timedelta(days=days)).add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in (sans or [cn])]), critical=False))
    return subject_key, builder.sign(issuer_key, hashes.SHA256())

def main():
    OUT.mkdir(parents=True, exist_ok=True); root_key=key(); now=datetime.now(UTC)
    root=(x509.CertificateBuilder().subject_name(name("Radar Lab Root CA")).issuer_name(name("Radar Lab Root CA")).public_key(root_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(root_key,hashes.SHA256()))
    write(OUT/"root_ca.pem", root.public_bytes(serialization.Encoding.PEM))
    specs={"valid.lab.local":365,"expiring.lab.local":5,"expired.lab.local":-1,"mismatch.lab.local":365}
    for host,days in specs.items():
        cert_cn="other.lab.local" if host=="mismatch.lab.local" else host
        leaf_key,cert=issue(cert_cn,root,root_key,days=days,sans=[cert_cn]); write(OUT/f"{host}.pem",cert.public_bytes(serialization.Encoding.PEM)); write(OUT/f"{host}.key",leaf_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())); write(OUT/f"{host}.pfx",pkcs12.serialize_key_and_certificates(host.encode(),leaf_key,cert,[root],serialization.NoEncryption()))
    self_key=key(); self_root=(x509.CertificateBuilder().subject_name(name("selfsigned.lab.local")).issuer_name(name("selfsigned.lab.local")).public_key(self_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName("selfsigned.lab.local")]),False).sign(self_key,hashes.SHA256()))
    write(OUT/"selfsigned.lab.local.pem",self_root.public_bytes(serialization.Encoding.PEM)); write(OUT/"selfsigned.lab.local.key",self_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())); write(OUT/"selfsigned.lab.local.pfx",pkcs12.serialize_key_and_certificates(b"selfsigned.lab.local",self_key,self_root,None,serialization.NoEncryption()))
    print(f"Сертификаты созданы: {OUT}")

if __name__ == "__main__": main()
