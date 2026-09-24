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

## Лабораторный стенд

```text
uv run python lab/make_certs.py
uv run python lab/serve.py
uv run python scripts/demo_reset.py --seed
uv run radar serve
```

Откройте `http://127.0.0.1:8000`. Лаборатория использует только локальные TLS-подключения и SNI; HTTP-запросы к целям не выполняются.

## Архитектура и безопасность

`radar/scanner` выполняет DNS и TLS, `analysis.py` формирует находки, `risk.py` считает риск, `notify` отправляет уведомления, `export` формирует отчёты, а `web` предоставляет UI/API. Секреты задаются через переменные окружения. Продукт работает в read-only режиме относительно целевых сервисов.

## Ограничения MVP

SQLite рассчитан на один экземпляр приложения. Проверка цепочки использует системное хранилище, certifi и дополнительные CA-файлы. Сканер не выполняет HTTP-запросы и не определяет сертификаты сервисов без TLS. Изменение интервала расписания применяется после перезапуска приложения.
