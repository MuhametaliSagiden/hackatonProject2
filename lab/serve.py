import socket, ssl
from pathlib import Path

CERTS=Path(__file__).resolve().parent/"certs"; HOSTS=["valid.lab.local","information.lab.local","warning.lab.local","expiring.lab.local","expired.lab.local","mismatch.lab.local","chain.lab.local","app.wild.lab.local","selfsigned.lab.local"]
def context(host):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERTS/f"{host}.pem",CERTS/f"{host}.key"); return ctx
def main(port=8443):
    contexts={host:context(host) for host in HOSTS}; default=contexts[HOSTS[0]]
    def sni(sock,name,_): sock.context=contexts.get(name,default)
    default.set_servername_callback(sni); server=socket.create_server(("127.0.0.1",port),reuse_port=False); print(f"TLS lab: 127.0.0.1:{port}")
    while True:
        raw,_=server.accept()
        try:
            conn=default.wrap_socket(raw,server_side=True); conn.recv(1); conn.close()
        except (ssl.SSLError,OSError): raw.close()
if __name__ == "__main__": main()
