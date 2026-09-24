def weak_key(key_type, key_size):
    return bool(key_size and ((key_type == "RSA" and key_size < 2048) or (key_type == "EC" and key_size < 256)))
def weak_signature(sig_hash): return bool(sig_hash and sig_hash.lower() in {"md5","sha1"})
