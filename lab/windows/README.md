# Windows Server / IIS lab

## Требования

- Windows Server 2019+ (для демо рекомендуется Windows Server 2025 Datacenter
  x64 Gen2 с GUI);
- статический IP и host-only/internal сеть между VM и машиной сканера;
- запуск PowerShell от имени администратора;
- папка `lab/certs`, созданная командой `uv run python lab/make_certs.py`.

## Запуск

На машине разработки:

```powershell
uv run python lab/make_certs.py
```

Скопируйте `lab/certs` на Windows Server и выполните:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\setup-iis-lab.ps1 -CertsPath C:\Radar\lab\certs
```

Скрипт устанавливает IIS, импортирует root/intermediate CA и листовые PFX,
создаёт сайты с HTTPS/SNI на 443, открывает firewall rule и генерирует
`targets_windows.csv`. Повторный запуск удаляет старые RadarLab-сайты,
bindings и сертификаты перед созданием актуальной конфигурации.

## Настройка сканера

В `config.yaml` укажите IP Windows VM:

```yaml
dns_overrides:
  "*.lab.local": "192.168.56.20"
trust:
  extra_ca_files:
    - "lab/certs/root_ca.pem"
```

Скопируйте `targets_windows.csv` в проект и импортируйте его обычной командой.
Перед демонстрацией заново выполните `make_certs.py` и setup-скрипт: сроки
действия сертификатов рассчитываются от момента генерации.

## Проверка скрипта

Если установлен `pwsh`, проверьте синтаксис без выполнения изменений:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  "lab/windows/setup-iis-lab.ps1", [ref]$null, [ref]$errors
) | Out-Null
$errors
```

Фактический запуск IIS выполняется только человеком на Windows VM.
