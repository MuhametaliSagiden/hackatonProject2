# Certificate Radar

Read-only TLS certificate inventory and risk dashboard. The application performs TLS handshakes only; it never sends HTTP requests to targets.

## Быстрый старт

```text
uv sync
uv run radar init-db
uv run radar import targets.csv
uv run radar scan
uv run radar serve
```

Targets may be DNS names, IP addresses, `host:port`, HTTPS URLs, or CIDR ranges.

