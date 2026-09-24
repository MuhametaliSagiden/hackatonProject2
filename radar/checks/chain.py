def chain_status(verify_code, self_signed=False):
    if self_signed or verify_code == 18: return "self_signed"
    if verify_code in (0,9,10): return "trusted"
    return "untrusted"
