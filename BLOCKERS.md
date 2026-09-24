# Ограничения проверки

- Windows Server/IIS стенд не запускался: для него нужна отдельная Windows Server VM.
- Отдельный `pwsh` отсутствует в текущем окружении. Синтаксис `lab/windows/setup-iis-lab.ps1`
  проверен встроенным Windows PowerShell Parser API; запуск IIS-стенда по-прежнему требует
  отдельной Windows Server VM.
- Полный UI-прогон через настоящий браузер не выполнялся; E2E покрыт изолированным TestClient-сценарием.
