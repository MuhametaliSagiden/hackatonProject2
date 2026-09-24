from cryptography import x509
def is_self_signed(pem):
    try:
        cert=x509.load_pem_x509_certificate(pem.encode())
        return cert.issuer == cert.subject and cert.verify_directly_issued_by(cert) is None
    except (AttributeError,ValueError,TypeError): return False
