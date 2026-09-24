def matches(host, pattern):
    host,pattern=host.lower().rstrip("."),pattern.lower().rstrip(".")
    if pattern.startswith("*."): return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return host == pattern
