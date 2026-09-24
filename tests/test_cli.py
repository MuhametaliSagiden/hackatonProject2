import sys
from contextlib import contextmanager
from types import SimpleNamespace

from radar import cli


def test_scan_cli_prints_required_table(monkeypatch, capsys):
    scan = SimpleNamespace(id=7, processed=1, total=1, status="done")
    result = SimpleNamespace(
        service_id=1,
        status="Warning",
        days_left=25,
        risk_score=70,
        risk_level="High",
        findings=[{"code": "EXPIRING"}, {"code": "CHAIN_ERROR"}],
    )
    service = SimpleNamespace(id=1, host="mail.example", port=443)

    @contextmanager
    def fake_session():
        class FakeDb:
            def exec(self, statement):
                statement_text = str(statement)
                if "certresult" in statement_text:
                    return iter([result])
                return iter([service])

        yield FakeDb()

    monkeypatch.setattr(cli, "run_scan", lambda triggered_by: scan)
    monkeypatch.setattr(cli, "session", fake_session)
    monkeypatch.setattr(sys, "argv", ["radar", "scan"])

    cli.main()
    output = capsys.readouterr().out

    assert "Хост" in output
    assert "Статус" in output
    assert "Дни" in output
    assert "Риск" in output
    assert "Находки" in output
    assert "mail.example:443" in output
    assert "EXPIRING, CHAIN_ERROR" in output
