from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import threading

CERTS = Path(__file__).resolve().parent / "certs"

HOSTS_MAP = {
    "valid.lab.local": "valid.lab.local",
    "expiring.lab.local": "expiring.lab.local",
    "warning.lab.local": "warning.lab.local",
    "info.lab.local": "info.lab.local",
    "expired.lab.local": "expired.lab.local",
    "selfsigned.lab.local": "selfsigned.lab.local",
    "chain.lab.local": "chain.lab.local",
    "mismatch.lab.local": "mismatch.lab.local",
    "weak.lab.local": "weak.lab.local",
    "app.wild.lab.local": "app.wild.lab.local",
    "ip.lab.local": "ip.lab.local",
    "incomplete-chain.lab.local": "incomplete-chain.lab.local",
}


class LabRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        host = getattr(self.connection, "sni_hostname", "unknown")
        body = f"Radar lab: {host}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress request logging
        pass


def make_context(certs_dir: Path, cert_name: str, seclevel_zero: bool = False) -> ssl.SSLContext | None:
    pem = certs_dir / f"{cert_name}.pem"
    key = certs_dir / f"{cert_name}.key"
    if not pem.exists() or not key.exists():
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if seclevel_zero:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    try:
        ctx.load_cert_chain(str(pem), str(key))
        return ctx
    except Exception:
        return None


def create_contexts(certs_dir: Path) -> dict[str, ssl.SSLContext]:
    contexts: dict[str, ssl.SSLContext] = {}
    for host, cert_name in HOSTS_MAP.items():
        is_weak = host == "weak.lab.local"
        ctx = make_context(certs_dir, cert_name, seclevel_zero=is_weak)
        if ctx:
            contexts[host] = ctx
    return contexts


def start_server(
    certs_dir: Path | str | None = None,
    port: int = 0,
) -> tuple[ThreadingHTTPServer, int, threading.Thread]:
    c_dir = Path(certs_dir) if certs_dir else CERTS
    contexts = create_contexts(c_dir)
    if not contexts:
        from .make_certs import generate
        generate(c_dir)
        contexts = create_contexts(c_dir)

    default_ctx = contexts.get("mismatch.lab.local") or next(iter(contexts.values()))

    def sni_callback(sock, server_name, initial_context):
        name = (server_name or "").lower()
        sock.context = contexts.get(name, default_ctx)
        sock.sni_hostname = name

    default_ctx.set_servername_callback(sni_callback)

    server = ThreadingHTTPServer(("127.0.0.1", port), LabRequestHandler)
    server.socket = default_ctx.wrap_socket(server.socket, server_side=True)
    actual_port = server.server_address[1]

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port, thread


def main(port: int = 8443):
    server, actual_port, thread = start_server(CERTS, port=port)
    print(f"TLS lab started: https://127.0.0.1:{actual_port}")
    try:
        thread.join()
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()
        print("\nTLS lab stopped.")


if __name__ == "__main__":
    main()
