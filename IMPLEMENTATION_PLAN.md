Ниже единый план, рассчитанный на исполнение ИИ-агентом. Его можно целиком передать исполняющей модели. Решения в нём уже приняты, шаги идут строго по порядку, у каждого шага есть проверка и упрощение на случай неудачи.
ПЛАН РАЗРАБОТКИ MVP «CERTIFICATE RADAR» ДЛЯ ИИ-АГЕНТА-ИСПОЛНИТЕЛЯ
ЧАСТЬ 0. Правила для исполнителя (прочитать первыми и соблюдать всегда)
1. Выполняй шаги строго по порядку: 1, 2, 3… Не пропускай шаги и не объединяй их.
2. Не принимай архитектурных решений сам: стек, структура, модель данных, формулы и тексты уже заданы ниже. Если чего-то нет в плане, не делай этого.
3. После каждого шага выполни его «Проверку». Шаг считается сделанным, только если проверка прошла.
4. Если проверка не проходит после 3 попыток исправления:
- запиши проблему в BLOCKERS.md (шаг, ошибка, что пробовал);
- примени «Упрощение» из этого шага;
- переходи дальше.
5. После каждого успешного шага:
- запусти uv run ruff check . --fix и uv run pytest -q: оба должны пройти;
- сделай коммит git commit -m "step N: <название>";
- допиши строку в PROGRESS.md: номер шага, статус, дата.
6. Используй только зависимости из шага 1. Новые зависимости не добавляй.
7. Не используй LLM или внешние AI API в коде продукта. Все тексты рекомендаций статические.
8. Весь интерфейс, сообщения и отчёты на русском языке. Код, имена переменных и комментарии на английском.
9. Код должен работать на Windows и Linux. Пути только через pathlib. Время в БД хранится в UTC (timezone-aware), даты в интерфейсе показываются в формате ДД.ММ.ГГГГ.
10. Продукт работает в режиме Read Only: только TLS-рукопожатие с целью, без HTTP-запросов, без логинов, без изменений на целевых системах.
11. Если перед тобой начало новой сессии, прочитай PROGRESS.md и продолжай с первого невыполненного шага.
ЧАСТЬ 1. Итоговый результат
Веб-приложение, которое запускается одной командой (uv run radar serve) и умеет:
- принимать цели (DNS, IP, URL, CIDR) файлом CSV/TXT или вручную, с валидацией и дедупликацией;
- параллельно сканировать TLS (по умолчанию порт 443) с таймаутами; недоступные цели получают статус Unreachable;
- собирать атрибуты сертификата, проверять срок, цепочку доверия, соответствие имени, self-signed и слабую криптографию;
- считать Risk Score с причинами и рекомендациями;
- показывать Dashboard, таблицу с фильтрами и сортировкой, карточку сертификата;
- вести инвентарь (владелец, критичность) и историю сканов;
- отправлять уведомления по порогам 60/30/14/7/1;
- экспортировать CSV/XLSX/HTML;
- хранить настройки порогов и журнал аудита.
ЧАСТЬ 2. Зафиксированный стек
- Python 3.12 или новее, менеджер uv.
- Зависимости: fastapi, uvicorn[standard], jinja2, python-multipart, sqlmodel, cryptography>=42, certifi, httpx, openpyxl, pyyaml, apscheduler>=3.10,<4.
- Dev-зависимости: pytest, ruff.
- UI: серверный рендеринг Jinja2 + Bootstrap 5.3 (файлы bootstrap.min.css и bootstrap.bundle.min.js лежат локально в radar/web/static/) + минимальный vanilla JS. Никакого React и никакой сборки фронтенда.
- БД: SQLite, файл data/radar.db.
- Параллельность: concurrent.futures.ThreadPoolExecutor и синхронные socket + ssl.
ЧАСТЬ 3. Структура репозитория (создать ровно такую)
- Корень certificate-radar/: pyproject.toml, README.md, AGENTS.md, PROGRESS.md, BLOCKERS.md, DEMO.md, config.example.yaml, .env.example, .gitignore.
- radar/:
- __init__.py, config.py, db.py, models.py, audit.py, services.py, risk.py, recommendations.py, recommendations_ru.yaml, analysis.py, scheduler.py, cli.py
- radar/targets/parser.py
- radar/scanner/: resolver.py, tls.py, engine.py
- radar/checks/: base.py, expiry.py, chain.py, hostname.py, selfsigned.py, crypto.py, owner.py, __init__.py (реестр проверок)
- radar/notify/: base.py, console.py, email.py, telegram.py, service.py
- radar/export/: csv_export.py, xlsx_export.py, html_export.py
- radar/web/: app.py, routes_ui.py, routes_api.py, templates/, static/
- lab/: make_certs.py, serve.py, targets_lab.csv, windows/setup-iis-lab.ps1, windows/README.md
- scripts/demo_reset.py
- tests/
- В .gitignore: data/, logs/, lab/certs/, .env, exports/.
ЧАСТЬ 4. Спецификация (единственный источник правды)
4.1. Модель данных (radar/models.py, SQLModel)
- Service: id, host (lowercase), port (int, по умолчанию 443), service_name (str | None), owner (str | None), criticality (high / medium / low, по умолчанию medium), created_at. Уникальность по паре (host, port).
- Scan: id, started_at, finished_at (None, пока идёт), status (running / done / failed), total, processed, triggered_by (ui / cli / schedule).
- CertResult:
- связи и доступность: id, scan_id, service_id, reachable (bool), error (str | None), resolved_ip;
- сертификат: leaf_pem (str | None), subject_cn, san_dns (JSON list), san_ip (JSON list), issuer_cn, issuer_full, serial, thumbprint_sha1 (HEX в верхнем регистре), thumbprint_sha256, not_before, not_after, key_type, key_size, sig_hash, tls_version;
- результаты проверки цепочки: chain_verify_code (int | None), chain_verify_message;
- результаты анализа: days_left (int | None), status, chain_status, hostname_match (bool | None), self_signed (bool | None), weak_crypto (bool | None), risk_score (int | None), risk_level (str), findings (JSON list объектов {code, severity, reason, recommendation}).
- NotificationLog: id, service_id, thumbprint_sha1, threshold (int; 0 означает «истёк»), channel, sent_at, success (bool), message. Уникальность по тройке (thumbprint_sha1, threshold, channel) среди записей с success=True.
- AuditLog: id, ts, actor (по умолчанию local-user), action, details (JSON).
- Setting: key (PK), value (JSON).
Текущее состояние — это результаты последнего скана со статусом done.
4.2. Настройки (config.yaml; редактируемые хранятся в таблице Setting и перекрывают YAML)
- thresholds: info_days: 60, warning_days: 30, critical_days: 14. Условие корректности: info > warning > critical ≥ 0.
- notify_thresholds: [60, 30, 14, 7, 1]
- scan: timeout_sec: 5, workers: 32, max_cidr_hosts: 256, schedule_hours: 0 (0 — расписание выключено)
- trust: extra_ca_files: []. Файлы в PEM или DER добавляются к системному хранилищу и certifi.
- dns_overrides: {}. Поддерживаются точные имена и маски вида "*.lab.local": "127.0.0.1".
- notify: email_enabled, smtp_host, smtp_port, smtp_from, email_to (список), telegram_enabled. Секреты TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, SMTP_USER, SMTP_PASSWORD берутся из .env.
4.3. Формат входных целей (radar/targets/parser.py)
- TXT: одна цель на строку. Пустые строки и строки, начинающиеся с #, игнорируются.
- CSV: заголовок target,service_name,owner,criticality. Обязательна только колонка target. Разделитель , или ; определяется автоматически. Кодировка UTF-8, BOM допускается.
- Допустимые формы цели: host, host:port, https://host[:port][/path], IPv4, IPv4:port, CIDR a.b.c.d/nn.
- Правила:
- порт по умолчанию 443, допустимый диапазон 1–65535;
- имя хоста проверяется по RFC 1123: метки 1–63 символа из [a-z0-9-], не начинаются и не заканчиваются дефисом, общая длина до 253;
- имя приводится к нижнему регистру, точка в конце удаляется;
- CIDR раскрывается в адреса хостов; если адресов больше max_cidr_hosts, строка считается ошибкой;
- дедупликация по паре (host, port).
- Результат: ImportReport(added, updated, duplicates, invalid: list[(line_no, text, reason)]). Если у существующего Service в файле указаны owner или criticality, они обновляются.
4.4. Сбор данных (radar/scanner/)
- resolver.resolve(host):
1. проверить dns_overrides (точное совпадение, затем маска *.);
2. если хост является IP-адресом, вернуть его;
3. иначе socket.getaddrinfo с предпочтением IPv4.
При ошибке error="DNS: не удалось разрешить имя".
- tls.grab(host, port, timeout, trust_ctx) возвращает RawResult.
- Подключение 1 (получить сертификат всегда):
- SSLContext(PROTOCOL_TLS_CLIENT), check_hostname=False, verify_mode=CERT_NONE;
- set_ciphers("DEFAULT:@SECLEVEL=0"); попытаться выставить minimum_version = TLSv1, а при ошибке пропустить;
- SNI: server_hostname=host, если хост не IP; для IP передать None;
- забрать getpeercert(binary_form=True), version().
- Подключение 2 (проверить цепочку):
- ssl.create_default_context(), затем load_verify_locations(certifi.where()) и загрузить все extra_ca_files (DER передаётся через cadata);
- check_hostname=False, verify_mode=CERT_REQUIRED;
- при успехе chain_verify_code=0; при ssl.SSLCertVerificationError сохранить verify_code и verify_message.
- Ошибки: любое исключение подключения 1 (таймаут, отказ соединения, reset) даёт reachable=False и понятный текст error на русском. Скан при этом не прерывается.
- engine.run_scan(scan_id): обходит все Service через ThreadPoolExecutor(workers), каждый результат анализирует (4.5) и сохраняет, обновляет processed, в конце выставляет status=done и вызывает уведомления (4.8). Исключение по одной цели не должно ронять весь скан.
4.5. Анализ (radar/analysis.py)
Анализ — чистая функция analyze(raw_or_stored, service, settings, now) -> AnalysisResult, без сети и без БД. Для каждой цели она последовательно вызывает все проверки из checks/. Интерфейс проверки: run(ctx) -> list[Finding]. Благодаря этому смена порогов пересчитывается без повторного скана.
- expiry:
- days_left = floor((not_after - now).total_seconds() / 86400);
- статус: days_left < 0 → Expired, ≤ critical → Critical, ≤ warning → Warning, ≤ info → Information, иначе OK; для недоступной цели статус Unreachable;
- находки: EXPIRED для Expired; EXPIRING для Critical, Warning и Information.
- selfsigned: issuer == subject, и cert.verify_directly_issued_by(cert) не бросает исключение. Находка SELF_SIGNED.
- chain:
- chain_status: коды 0, 9 и 10 → trusted (цепочка построена, срок проверяется отдельно); код 18 → self_signed; все остальные коды → untrusted;
- находка CHAIN_ERROR при untrusted. Если сертификат self-signed, CHAIN_ERROR не добавляется.
- hostname:
- если цель — IP: совпадение, когда IP есть в SAN IP;
- иначе сравниваются имена из SAN DNS, а если их нет — CN; сравнение без учёта регистра;
- wildcard допускается, только если * занимает всю левую метку, и покрывает ровно одну метку: *.a.com совпадает с x.a.com, но не с a.com и не с x.y.a.com;
- находка HOSTNAME_MISMATCH.
- crypto:
- RSA < 2048 бит, EC < 256 бит → находка WEAK_KEY;
- хеш подписи md5 или sha1 → находка WEAK_SIGNATURE;
- weak_crypto = True, если есть любая из этих находок.
- owner: пустой owner → находка NO_OWNER.
- Недоступная цель: только находка UNREACHABLE, risk_score=None, risk_level="N/A".
4.6. Risk Score (radar/risk.py)
Балл — сумма компонентов, максимум 100:
- Срок: Expired 60; Critical при days_left ≤ 7 — 60, иначе 45; Warning 30; Information 10; OK 0.
- Цепочка и имя: CHAIN_ERROR +35, SELF_SIGNED +30, HOSTNAME_MISMATCH +35.
- Криптография: WEAK_KEY или WEAK_SIGNATURE +15 один раз, даже если сработали обе.
- Критичность: high +20, medium +10, low 0.
- Владелец: NO_OWNER +10.
Уровень: ≥80 Critical, 60–79 High, 30–59 Medium, <30 Low. Severity каждой находки: EXPIRED, CHAIN_ERROR, HOSTNAME_MISMATCH → high; SELF_SIGNED, EXPIRING при Critical → high; EXPIRING при Warning, WEAK_* → medium; остальные → low.
4.7. Рекомендации (radar/recommendations_ru.yaml)
Для каждого кода нужны два поля: reason (шаблон с плейсхолдерами {days}, {host}, {issuer}, {names}, {bits}, {hash}, {error}) и recommendation. Тексты:
- EXPIRED: «Срок действия сертификата истёк {days} дн. назад» / «Срочно перевыпустите сертификат и установите его на сервис. Проверьте, не нарушена ли работа клиентов».
- EXPIRING: «Сертификат истекает через {days} дн.» / «Запланируйте перевыпуск и замену сертификата до даты окончания. Назначьте ответственного».
- SELF_SIGNED: «Сертификат самоподписанный, клиенты не могут проверить его подлинность» / «Замените сертификат на выпущенный корпоративным или публичным центром сертификации».
- CHAIN_ERROR: «Ошибка цепочки доверия: {error}» / «Установите на сервере полную цепочку (промежуточные сертификаты) или используйте сертификат доверенного центра сертификации».
- HOSTNAME_MISMATCH: «Имя {host} не совпадает с CN/SAN сертификата: {names}» / «Перевыпустите сертификат с корректным именем в SAN или исправьте привязку сертификата на сервисе».
- WEAK_KEY: «Слабый ключ: {bits} бит» / «Перевыпустите сертификат с ключом RSA не менее 2048 бит или ECDSA P-256».
- WEAK_SIGNATURE: «Устаревший алгоритм подписи: {hash}» / «Перевыпустите сертификат с подписью SHA-256 или выше».
- NO_OWNER: «Не назначен владелец сервиса» / «Назначьте ответственного в инвентаре, чтобы уведомления доходили до исполнителя».
- UNREACHABLE: «Сервис недоступен: {error}» / «Проверьте доступность хоста и порта, правила межсетевого экрана и корректность DNS-имени».
4.8. Уведомления (radar/notify/)
- Выбор порога: для каждого доступного результата последнего скана с сертификатом:
- если days_left < 0, порог 0;
- иначе берётся наименьший порог t из notify_thresholds, для которого days_left ≤ t;
- если такого порога нет, уведомление не нужно.
- Отправка без дублей: уведомление уходит в каждый включённый канал, только если в NotificationLog нет успешной записи с той же тройкой (thumbprint, порог, канал).
- Каналы:
- console включён всегда: пишет в лог и в NotificationLog;
- email: smtplib, при smtp_port=465 используется SSL;
- telegram: httpx.post("https://api.telegram.org/bot{token}/sendMessage").
- Текст: «Certificate Radar: сертификат {host}:{port} ({service_name}) истекает через {days} дн. (порог {t}). Владелец: {owner или "не назначен"}. Risk {score} ({level}). Рекомендация: {recommendation}». Для порога 0 вместо «истекает через…» пишется «ИСТЁК {abs(days)} дн. назад».
- Тестовая отправка: функция send_test() отправляет тестовое сообщение во все включённые каналы.
4.9. Журнал аудита (radar/audit.py)
Функция audit(action, details). Действия: IMPORT_TARGETS, SERVICE_UPDATED, SCAN_STARTED, SCAN_FINISHED, SETTINGS_UPDATED, RECOMPUTE, EXPORT, NOTIFICATION_SENT, NOTIFICATION_TEST. Дополнительно всё пишется в logs/radar.log через logging с ротацией 5 МБ × 3 файла.
4.10. Экспорт (radar/export/)
- Колонки: Сервис, Хост, Порт, Владелец, Критичность, CN, SAN, Issuer, Thumbprint (SHA-1), Действует с, Действует до, Дней осталось, Статус, Цепочка, Имя совпадает, Self-signed, Ключ, Подпись, Risk Score, Уровень риска, Проблемы, Рекомендации.
- CSV: UTF-8 с BOM, разделитель ;.
- XLSX: жирный заголовок, автофильтр, закреплённая первая строка, заливка колонки «Статус» по цветам из 4.11.
- HTML: один самодостаточный файл со встроенным CSS: заголовок, дата, сводка по статусам и таблица.
- Фильтры: экспорт учитывает текущие фильтры таблицы.
4.11. Интерфейс (radar/web/templates/, общий base.html с навигацией)
Цвета статусов: OK — зелёный, Information — синий, Warning — жёлтый, Critical — оранжевый, Expired — тёмно-красный, Unreachable — серый. Страницы:
- / Dashboard:
- карточки с количеством по статусам и по уровням риска;
- горизонтальная сегментированная полоса распределения статусов (Bootstrap progress);
- блок «Ближайшие окончания»: 10 записей по возрастанию days_left, истёкшие включены;
- блок «Требуют внимания»: записи с риском Critical и High;
- дата последнего скана, кнопка «Запустить скан».
- /certificates:
- колонки: Сервис, Хост:порт, Issuer, Действует до, Дней, Статус, Риск, Владелец;
- фильтры GET-параметрами: q (поиск по сервису и хосту), owner (select), issuer (select), status (несколько чекбоксов), risk_level, days_max;
- сортировка кликом по заголовку через параметры sort и dir;
- кнопки экспорта CSV, XLSX и HTML с текущими параметрами.
- /certificates/{result_id}: все атрибуты, Risk Score крупно, находки (причина и рекомендация) и история этого сервиса по сканам.
- /targets:
- форма загрузки файла и textarea для ручного ввода;
- отчёт импорта: добавлено, обновлено, дубликаты, ошибки со строкой и причиной;
- таблица сервисов с редактированием владельца и критичности прямо в строке;
- кнопка «Запустить скан».
- /scans: история сканов. Страница /scans/{id} показывает прогресс processed/total с автообновлением каждые 2 секунды, пока идёт скан, и сводку после завершения.
- /settings: пороги статусов, пороги уведомлений, интервал расписания, кнопки «Сохранить и пересчитать» и «Отправить тестовое уведомление».
- /notifications: журнал отправок.
- /audit: журнал аудита.
4.12. JSON API (radar/web/routes_api.py, тонкая обёртка над services.py)
- POST /api/targets/import (файл или текст)
- GET /api/services
- PATCH /api/services/{id}
- POST /api/scans
- GET /api/scans
- GET /api/scans/{id}
- GET /api/results (фильтры как в UI)
- GET /api/results/{id}
- GET /api/settings
- PUT /api/settings
- POST /api/notifications/test
- GET /api/export?format=csv|xlsx|html
- GET /health
Вся бизнес-логика живёт в services.py. UI-маршруты и API вызывают одни и те же функции.
4.13. Эталонный тестовый стенд (lab/targets_lab.csv и ожидаемые результаты)
В демо-файле, помимо 10 целей из таблицы, есть дубликат строки valid и невалидная строка not a host!!. Импорт должен дать: добавлено 10, дубликатов 1, ошибок 1.
Цель | Сервис / владелец / критичность | Сертификат | Ожидаемо: статус / находки / риск
valid.lab.local:8443 | Портал / ivanov@lab.local / medium | Промежуточный CA, +200 дн, полная цепочка | OK / — / 10 Low
expiring.lab.local:8443 | Почта OWA / petrov@lab.local / high | Промежуточный CA, +5 дн | Critical / EXPIRING / 80 Critical
warning.lab.local:8443 | VPN / — / high | Промежуточный CA, +25 дн | Warning / EXPIRING, NO_OWNER / 60 High
info.lab.local:8443 | Wiki / sidorov@lab.local / low | Промежуточный CA, +45 дн | Information / EXPIRING / 10 Low
expired.lab.local:8443 | CRM / — / high | Промежуточный CA, действовал с −400 до −5 дн | Expired / EXPIRED, NO_OWNER / 90 Critical
selfsigned.lab.local:8443 | Jenkins / ops@lab.local / medium | Self-signed, +365 дн | OK / SELF_SIGNED / 40 Medium
chain.lab.local:8443 | HR-портал / hr@lab.local / medium | Подписан недоверенным Rogue CA, +365 дн | OK / CHAIN_ERROR / 45 Medium
mismatch.lab.local:8443 | API Gateway / api@lab.local / high | CN и SAN = other.lab.local, +365 дн | OK / HOSTNAME_MISMATCH / 55 Medium
weak.lab.local:8443 | Legacy App / — / low | RSA 1024 + SHA-1, +365 дн | OK / WEAK_KEY, WEAK_SIGNATURE, NO_OWNER / 25 Low
dead.lab.local:8499 | Old Service / — / low | Порт закрыт | Unreachable / UNREACHABLE / N/A
- Даты: чтобы floor давал ровные дни, будущие даты окончания задаются как «+N дней +2 часа», прошлые — как «−N дней +2 часа».
- Доверие и DNS: в config.yaml для лаборатории задать dns_overrides: {"*.lab.local": "127.0.0.1"} и extra_ca_files: ["lab/certs/root_ca.pem"].
- Ожидаемые уведомления после первого скана: expiring → порог 7, warning → 30, info → 60, expired → 0. Всего 4 сообщения на канал. Повторный скан не отправляет ничего.
ЧАСТЬ 5. Шаги реализации
Фаза A. Каркас
Шаг 1. Инициализация проекта.
- Сделать:
- git init, uv init --package, структура из Части 3 (пустые модули с __init__.py);
- pyproject.toml с зависимостями из Части 2, [project.scripts] radar = "radar.cli:main", настройки ruff (line-length 110) и pytest (testpaths=["tests"], маркер integration);
- AGENTS.md с копией Части 0 и Части 2;
- PROGRESS.md, BLOCKERS.md, .gitignore;
- скачать Bootstrap 5.3 (bootstrap.min.css, bootstrap.bundle.min.js) в radar/web/static/;
- тест tests/test_smoke.py с проверкой import radar.
- Проверка: uv sync проходит без ошибок, uv run pytest -q зелёный.
- Упрощение: если нет доступа в интернет за Bootstrap, написать минимальный app.css вручную.
Шаг 2. Конфигурация, БД, аудит.
- Сделать:
- config.py: загрузка config.yaml (если его нет, копировать из config.example.yaml), .env (через os.environ, парсер пишется вручную) и перекрытие значениями из таблицы Setting;
- db.py: engine SQLite, get_session(), init_db() создаёт папки data/ и logs/;
- models.py по 4.1;
- audit.py по 4.9.
- Проверка: тест создаёт БД во временной папке, пишет и читает по одной записи каждой модели, audit() создаёт запись в AuditLog.
Шаг 3. Каркас веб-приложения и CLI.
- Сделать:
- web/app.py: create_app() с подключением static, templates и роутеров;
- base.html с навигацией: Dashboard, Сертификаты, Цели, Сканы, Уведомления, Аудит, Настройки;
- GET /health возвращает {"status":"ok"};
- cli.py на argparse с командами init-db, import <file>, scan, serve [--host 127.0.0.1 --port 8000], recompute.
- Проверка: uv run radar init-db, затем uv run radar serve; /health отвечает 200, главная страница открывается (пока пустая); тест через fastapi.testclient.
Фаза B. Локальный тестовый стенд
Шаг 4. Генератор сертификатов lab/make_certs.py.
- Сделать:
- на cryptography сгенерировать Radar Lab Root CA (10 лет), Radar Lab Intermediate CA (подписан Root, BasicConstraints CA=true), Rogue CA (отдельный self-signed корень, в доверенные не добавляется) и листовые сертификаты по таблице 4.13;
- у всех листовых: SAN DNS = имя хоста (кроме mismatch), EKU serverAuth; ключ RSA 2048 и SHA-256 (кроме weak: RSA 1024 и SHA-1);
- выход в lab/certs/: root_ca.pem, <name>.pem (лист + промежуточный для подписанных промежуточным CA), <name>.key, <name>.pfx;
- PFX с паролем RadarLab123! в совместимом формате: PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000).key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(password);
- функция generate(out_dir, now) плюс запуск из командной строки.
- Проверка: тест генерирует сертификаты во временную папку и проверяет not_valid_after_utc, издателя и SAN для каждого сертификата.
Шаг 5. Лабораторный TLS-сервер lab/serve.py и файл целей.
- Сделать:
- один ThreadingHTTPServer на 127.0.0.1:8443, SNI-выбор сертификата через sni_callback: отдельный SSLContext на каждый хост, по умолчанию отдаётся сертификат mismatch;
- для контекста weak выставить set_ciphers("DEFAULT:@SECLEVEL=0");
- ответ на HTTP: текст Radar lab: <имя>;
- функция start_server(certs_dir, port=0) -> (server, port, thread) для тестов;
- lab/targets_lab.csv по 4.13; config.example.yaml с лабораторными dns_overrides и extra_ca_files в закомментированном виде и с пояснением.
- Проверка: интеграционный тест поднимает сервер на свободном порту, подключается с server_hostname="valid.lab.local" и получает сертификат с CN valid.lab.local; то же для selfsigned.
- Упрощение: если weak не поднимается через SNI, вынести его на отдельный порт 8444 и поправить CSV. Если не получается и так, исключить weak из стенда и записать это в BLOCKERS.
Фаза C. Ядро
Шаг 6. Парсер целей (4.3).
- Сделать: parse_text(), parse_file(bytes, filename), ImportReport.
- Проверка (тесты):
- каждая форма цели из 4.3;
- https://A.lab.local:8443/x превращается в (a.lab.local, 8443);
- /30 даёт 2 хоста, /16 даёт ошибку;
- дубликаты считаются;
- невалидные строки получают причину;
- CSV с ; и BOM читается;
- targets_lab.csv даёт 10 целей, 1 дубликат и 1 ошибку.
Шаг 7. Resolver и TLS-сбор (4.4).
- Сделать: resolver.py и tls.py (два подключения, RawResult, извлечение атрибутов через cryptography: CN, SAN DNS/IP, issuer, serial, SHA-1/SHA-256, даты, тип и размер ключа, хеш подписи).
- Проверка (интеграционные тесты на лабораторном сервере):
- valid: chain_verify_code=0 (Root CA лаборатории передан как доверенный);
- chain: ненулевой код;
- selfsigned: код 18;
- dead (закрытый порт): reachable=False за время не больше timeout + 1 с;
- маска *.lab.local из overrides работает.
Шаг 8. Проверки (4.5).
- Сделать: checks/base.py (dataclass Finding, класс CheckContext, протокол Check), шесть модулей проверок, реестр ALL_CHECKS, analysis.analyze().
- Проверка (юнит-тесты на сертификатах, сгенерированных в tests/conftest.py, без сети):
- границы статусов: 61 → OK, 60 → Information, 31 → Information, 30 → Warning, 15 → Warning, 14 → Critical, 0 → Critical, −1 → Expired;
- wildcard: 3 положительных и 3 отрицательных случая;
- совпадение по IP в SAN;
- fallback на CN, если SAN отсутствует;
- self-signed не даёт находку CHAIN_ERROR;
- RSA 1024 и SHA-1 дают обе находки WEAK_*;
- пустой owner даёт NO_OWNER.
Шаг 9. Risk Score и рекомендации (4.6, 4.7).
- Сделать: risk.py, recommendations_ru.yaml, recommendations.py (подстановка плейсхолдеров, в каждой Finding заполнены reason и recommendation).
- Проверка:
- пример из ТЗ: 5 дней + high + нет владельца = 90 Critical;
- все 10 строк таблицы 4.13 дают ожидаемые баллы и уровни (тест на синтетических входах без сети);
- все коды находок имеют тексты.
Шаг 10. Движок скана, сохранение, пересчёт.
- Сделать:
- в services.py: import_targets(), create_scan(), run_scan_background(scan_id) (в отдельном потоке), latest_results(filters, sort), recompute_latest() (заново анализирует сохранённые leaf_pem и коды цепочки с текущими настройками);
- engine.run_scan() по 4.4;
- аудит SCAN_STARTED, SCAN_FINISHED, IMPORT_TARGETS, RECOMPUTE.
- Проверка:
- интеграционный тест импортирует лабораторные цели (порт подменяется на порт тестового сервера), запускает скан и сверяет каждую строку с таблицей 4.13 (статус, набор кодов находок, уровень риска);
- после смены critical_days на 3 и вызова recompute_latest() цель expiring получает статус Warning.
Шаг 11. CLI-скан.
- Сделать: radar import печатает отчёт импорта, radar scan печатает таблицу (хост, статус, дни, риск, коды находок).
- Проверка (вручную):
1. uv run python lab/make_certs.py
2. в отдельном терминале uv run python lab/serve.py
3. uv run radar import lab/targets_lab.csv
4. uv run radar scan
Вывод должен совпасть с таблицей 4.13.
КОНТРОЛЬНАЯ ТОЧКА K1. Шаги 1–11 зелёные, и вывод CLI совпадает с эталоном. Если нет, не переходи к UI:
- приоритет исправления: expiry → hostname → selfsigned → chain → risk;
- если chain не удаётся за 3 попытки, упростить до trusted/untrusted по признаку code == 0;
- если crypto не удаётся, отключить её и записать в BLOCKERS.
Фаза D. Веб-интерфейс
Шаг 12. Страница «Цели».
- Сделать: /targets по 4.11: загрузка файла и textarea, отчёт импорта, таблица сервисов с формой правки владельца и критичности (POST → SERVICE_UPDATED), кнопка «Запустить скан».
- Проверка: TestClient загружает targets_lab.csv и видит в HTML «Добавлено: 10», «Дубликаты: 1», «Ошибки: 1»; правка владельца сохраняется.
Шаг 13. Сканы и прогресс.
- Сделать: POST «Запустить скан» создаёт скан, запускает его в фоне и перенаправляет на /scans/{id} с автообновлением <meta http-equiv="refresh" content="2">, пока status=running; /scans показывает историю.
- Проверка: через TestClient скан завершается со статусом done, счётчики совпадают с числом целей.
Шаг 14. Dashboard.
- Сделать: / по 4.11. Если сканов ещё нет, показать пустое состояние с кнопкой «Загрузить цели».
- Проверка: после лабораторного скана на странице есть 6 карточек статусов с верными числами (OK 5, Information 1, Warning 1, Critical 1, Expired 1, Unreachable 1); первая строка «Ближайших окончаний» — expired.lab.local.
Шаг 15. Таблица сертификатов.
- Сделать: /certificates, фильтры и сортировка по 4.11; значения для select owner и issuer берутся из данных.
- Проверка (тесты):
- status=Expired оставляет одну строку;
- owner=petrov@lab.local оставляет одну строку;
- sort=days_left&dir=asc ставит первой строку expired;
- q=mail оставляет одну строку (сервис «Почта OWA» ищется по хосту expiring? нет — поиск по сервису: используй q=OWA).
- Упрощение: если мультивыбор статусов не работает, оставить одиночный select.
Шаг 16. Карточка сертификата.
- Сделать: /certificates/{id}: все атрибуты, SAN списком, Risk Score с цветным бейджем, таблица находок (причина и рекомендация), история сервиса по сканам.
- Проверка: карточка mismatch содержит текст «не совпадает с CN/SAN» и рекомендацию; карточка dead показывает причину недоступности.
КОНТРОЛЬНАЯ ТОЧКА K2. Сквозной сценарий в браузере работает: загрузка → скан → Dashboard → фильтр → карточка. Если нет, исправлять только его; шаги 17–20 не начинать.
Фаза E. Уведомления, экспорт, настройки
Шаг 17. Уведомления (4.8).
- Сделать:
- каналы console, email и telegram, notify_after_scan(scan_id), send_test();
- вызов уведомлений в конце скана;
- страница /notifications;
- аудит NOTIFICATION_SENT и NOTIFICATION_TEST;
- ошибка канала пишется в лог с success=False и не прерывает работу.
- Проверка (тест с каналом console): первый скан даёт ровно 4 записи с порогами {7, 30, 60, 0}, второй скан не даёт новых записей. Email проверяется тестом с фиктивным SMTP (monkeypatch smtplib.SMTP), telegram — тестом с httpx.MockTransport.
Шаг 18. Экспорт (4.10).
- Сделать: три экспортёра, маршрут /export?format=... с фильтрами из таблицы, аудит EXPORT.
- Проверка:
- CSV начинается с BOM и содержит 10 строк данных;
- XLSX открывается через openpyxl.load_workbook с автофильтром;
- HTML содержит <table> и сводку;
- экспорт с status=Expired содержит 1 строку.
Шаг 19. Настройки, пересчёт, расписание.
- Сделать:
- /settings: форма порогов с валидацией 4.2 (ошибки показываются в форме), порогов уведомлений (через запятую) и schedule_hours;
- «Сохранить и пересчитать» пишет Setting, вызывает recompute_latest() и аудит SETTINGS_UPDATED;
- кнопка тестового уведомления;
- scheduler.py: APScheduler BackgroundScheduler, при schedule_hours > 0 задача run_scan(triggered_by="schedule"); старт вместе с приложением.
- Проверка: после установки critical_days=3 expiring становится Warning; некорректные пороги (warning > info) отклоняются с сообщением.
Шаг 20. Аудит-страница и JSON API.
- Сделать: страница /audit (последние 500 записей) и все эндпоинты 4.12.
- Проверка: тесты на каждый эндпоинт (код 200 и ключевые поля); после сценария «импорт → скан → экспорт → настройки» в аудите есть все соответствующие действия.
КОНТРОЛЬНАЯ ТОЧКА K3. Закрыты все 10 пунктов MVP из ТЗ 3.11. Если не хватает времени или что-то не работает, резать в таком порядке:
1. расписание;
2. HTML-экспорт;
3. XLSX (CSV оставить);
4. Telegram (console и email оставить);
5. история сервиса в карточке;
6. JSON API, кроме /health.
Фаза F. Стенд на Windows Server (сценарий из ТЗ)
Шаг 21. Скрипт lab/windows/setup-iis-lab.ps1 и lab/windows/README.md.
- Сделать: PowerShell-скрипт для запуска администратором на ВМ Windows Server 2019+. Параметр -CertsPath указывает на папку с PFX из шага 4. Скрипт:
1. устанавливает IIS: Install-WindowsFeature Web-Server -IncludeManagementTools;
2. импортирует root_ca.pem и промежуточный CA: Root CA в Cert:\LocalMachine\Root, промежуточный в Cert:\LocalMachine\CA, чтобы IIS отдавал полную цепочку;
3. импортирует каждый листовой PFX (Import-PfxCertificate в Cert:\LocalMachine\My, FriendlyName RadarLab-<name>);
4. для каждого хоста из 4.13 (кроме dead) создаёт папку и сайт IIS с HTTPS-привязкой на 443 с SNI: New-WebBinding -Protocol https -Port 443 -HostHeader <name>.lab.local -SslFlags 1 плюс New-Item "IIS:\SslBindings\!443!<name>.lab.local" -Thumbprint <thumb> -SSLFlags 1;
5. открывает 443 в брандмауэре;
6. работает идемпотентно: при повторном запуске удаляет старые сайты, привязки и сертификаты RadarLab.
Скрипт генерирует targets_windows.csv с теми же целями на порту 443. В README описать:
- сеть ВМ: host-only и статический IP;
- на машине сканера: dns_overrides "*.lab.local": "<IP ВМ>" и extra_ca_files: ["lab/certs/root_ca.pem"];
- повторный запуск make_certs.py и этого скрипта перед демо, потому что даты считаются от момента генерации.
- Проверка: PowerShell-синтаксис проверяется pwsh -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile(...)", если pwsh доступен. Запуск на ВМ выполняет человек. Исполнитель проверяет только, что скрипт и README полные и логичные.
- Упрощение: если weak (RSA 1024) не импортируется, исключить эту цель из Windows-стенда.
Фаза G. Стабилизация и демо
Шаг 22. E2E-тест и нагрузка.
- Сделать:
- tests/test_e2e.py: лабораторный сервер → импорт через UI-маршрут → скан → Dashboard → фильтр → карточка → экспорт → проверка уведомлений;
- тест нагрузки: 256 целей из CIDR 127.0.0.0/24 с портом, где сервера нет, выполняются за время не больше (256 / workers + 1) × timeout; приложение не падает, все цели Unreachable.
- Проверка: uv run pytest -q полностью зелёный.
Шаг 23. Удобство запуска и демо-скрипты.
- Сделать:
- scripts/demo_reset.py: бэкап data/radar.db в data/backup-<ts>.db, очистка БД, перегенерация лабораторных сертификатов, импорт lab/targets_lab.csv;
- флаг --seed: сразу выполнить скан и сохранить копию data/radar_demo_seed.db (запасная БД);
- сгенерировать в demo/ готовые экспорты CSV, XLSX и HTML;
- файлы run.ps1 и run.sh: uv sync, init-db, serve;
- README.md на русском с разделами: назначение, быстрый старт (5 команд), лабораторный стенд, Windows-стенд, настройки, архитектура (модули и как добавить новую проверку — новый файл в checks/ и регистрация в ALL_CHECKS), безопасность (Read Only, без учётных данных к целям, аудит, секреты в .env), ограничения MVP.
- Проверка: на чистом клоне репозитория шаги из README приводят к работающему Dashboard с лабораторными данными.
Шаг 24. Финальная приёмка и DEMO.md.
- Сделать:
- пройти чек-лист Части 6 и отметить каждый пункт в PROGRESS.md;
- записать DEMO.md: сценарий на 7 минут с репликами (1 — проблема и принцип «обнаружить до инцидента»; 2 — импорт с валидацией; 3 — скан; 4 — Dashboard; 5 — фильтры; 6 — карточка с риском и рекомендацией; 7 — уведомление; 8 — экспорт; 9 — смена порога и пересчёт; 10 — аудит; 11 — архитектура и развитие в Infrastructure Risk Radar);
- в DEMO.md описать запасной план: ВМ не работает → лабораторный стенд lab/serve.py; скан падает → скопировать radar_demo_seed.db в radar.db; приложение не стартует → готовые файлы из demo/ и видео; нет интернета → канал console/email через smtp4dev.
- Проверка: все пункты Части 6 отмечены, тесты зелёные, финальный коммит release: mvp.
ЧАСТЬ 6. Финальный чек-лист приёмки (соответствие ТЗ 3.11)
1. Загрузка списка DNS/IP файлом и вручную, с валидацией и дедупликацией.
2. Автоматическое параллельное подключение к TLS, порт 443 по умолчанию, таймауты, Unreachable не ломает скан.
3. Атрибуты: хост и порт, CN, SAN, Issuer, Thumbprint, даты.
4. Дата окончания и Days Left.
5. Проверка соответствия имени, включая wildcard и IP.
6. Базовая проверка цепочки доверия и self-signed.
7. Статусы OK / Information / Warning / Critical / Expired с настраиваемыми порогами.
8. Dashboard, таблица с фильтрами и сортировкой (сервис, владелец, Issuer, срок, статус), карточка с рекомендациями.
9. Экспорт хотя бы в CSV (плюс XLSX и HTML).
10. Уведомления по порогам 60/30/14/7/1 без дублей, минимум один внешний канал.
Дополнительно:
- Risk Score с причинами;
- инвентарь владельцев и критичности;
- история сканов;
- журнал аудита;
- режим Read Only;
- модульные проверки.
ЧАСТЬ 7. Что остаётся человеку (исполнитель этого не делает)
- Поднять ВМ Windows Server и запустить на ней setup-iis-lab.ps1 (шаг 21).
- Вписать в .env токен Telegram-бота и chat_id или данные SMTP. Для офлайн-демо можно поднять smtp4dev.
- Накануне демо выполнить demo_reset.py --seed, перезапустить скрипт на ВМ и записать запасное видео по DEMO.md.
Два момента, которые стоит поправить перед передачей плана:
- Недоделанный тест в шаге 15. В четвёртом пункте проверки остался неоконченный черновик. Замените его на: «q=OWA оставляет одну строку». Слабая модель выполняет текст буквально и может запутаться.
- Разбивка на сессии. Если у модели ограниченный контекст, отдавайте ей план по фазам (A, B, C…). Части 0–4 передавайте каждый раз целиком.