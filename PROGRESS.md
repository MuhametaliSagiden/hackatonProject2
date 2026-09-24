# Progress

- Step 1: implemented project skeleton, configuration, database models, parser, scanner, analysis, risk engine, CLI and web API (24.09.2026)
- Steps 2-6: packaging, exports, audit, notifications, settings, hostname/self-signed and chain analysis (24.09.2026)
- Steps 7-17: web/API, background scans, scheduler, external notifications, launch scripts, local TLS lab and IIS setup (24.09.2026)
- Steps 18-20: notification settings, filtered exports, E2E/API checks and demo artifacts (24.09.2026)
- Post-release: unified check pipeline, Jinja feedback pages, isolated notification/load/E2E tests and test database isolation (24.09.2026)

## Финальный чек-лист

- [x] Загрузка DNS/IP/URL/CIDR файлом и вручную, валидация и дедупликация.
- [x] Параллельные TLS-подключения, таймаут и Unreachable.
- [x] CN, SAN, Issuer, thumbprints, даты, ключ и TLS-версия.
- [x] Days Left и статусы срока.
- [x] Проверка hostname, wildcard и IP SAN.
- [x] Проверка цепочки и self-signed.
- [x] Настраиваемые пороги статусов.
- [x] Dashboard, фильтры, сортировка и карточка.
- [x] CSV, XLSX и HTML-экспорт.
- [x] Уведомления без дублей: console, SMTP и Telegram.
- [x] Risk Score, владельцы, критичность, история и аудит.
- [x] Read-only режим и модульные проверки.
- [x] Изолированная тестовая SQLite-БД и нагрузочная проверка 256 недоступных целей.
- [x] Сквозной изолированный E2E: импорт, скан, Dashboard, фильтр, карточка, экспорт и уведомление.
- [ ] PowerShell parser и IIS-стенд: нужен Windows Server/pwsh; в текущем окружении `pwsh` отсутствует.
