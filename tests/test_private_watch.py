"""The private 12-hour watch is watch --once, not the nightly six.

Hermetic: no network. The unit file comes from the existing launchd/systemd
printers. Behavioral stays off. --loop is not in the unit.
"""
from __future__ import annotations

import json
import plistlib
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from provenance_probe.cli import main
from provenance_probe.config import load_targets
from provenance_probe import serve

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "examples" / "private-watch.json"
NIGHTLY_HOSTS = {
    "api.deepseek.com",
    "api.openai.com",
    "api.anthropic.com",
    "api.moonshot.ai",
}
TIMER = (
    "provenance-probe watch --print-launchd --config examples/private-watch.json "
    "--interval 12h"
)


@pytest.fixture
def client():
    return serve.app.test_client()


@pytest.mark.unit
def test_private_watch_is_three_authorized_gemini_models():
    targets = load_targets(str(CONFIG))
    assert len(targets) == 3
    assert [t.name for t in targets] == [
        "gemini-flash-latest", "gemini-2.5-flash", "gemini-flash-lite-latest",
    ]
    for t in targets:
        assert t.authorized is True
        assert t.auth_value_env == "GEMINI_API_KEY"
        assert t.api_style == "openai"
        host = urlsplit(t.base_url).hostname
        assert host == "generativelanguage.googleapis.com"
        assert host not in NIGHTLY_HOSTS
        assert "flash" in t.model


@pytest.mark.unit
def test_launchd_12h_runs_once_without_behavioral_or_loop(capsys):
    rc = main([
        "watch", "--print-launchd", "--config", str(CONFIG), "--interval", "12h",
    ])
    assert rc in (None, 0)
    data = plistlib.loads(capsys.readouterr().out.encode())
    assert data["StartInterval"] == 12 * 3600
    args = data["ProgramArguments"]
    assert "--once" in args
    assert "--loop" not in args
    assert "--behavioral" not in args
    assert "--deception" not in args
    assert str(CONFIG.resolve()) in args


@pytest.mark.unit
def test_systemd_12h_runs_once(capsys):
    rc = main([
        "watch", "--print-systemd", "--config", str(CONFIG), "--interval", "12h",
    ])
    assert rc in (None, 0)
    text = capsys.readouterr().out
    assert "OnUnitActiveSec=43200" in text
    assert "watch --once --config" in text
    assert "--loop" not in text
    assert "--behavioral" not in text


@pytest.mark.unit
def test_watch_help_names_the_12h_once_timer(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["watch", "--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "12h" in out
    assert "--once" in out
    assert "examples/private-watch.json" in out
    assert "not --loop" in out or "Do not install this beside" in out


@pytest.mark.unit
def test_docs_name_the_timer_and_the_observatory_add_path():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert TIMER in readme
    assert "watch --once" in readme
    assert "watch --loop" in readme
    assert "17 3 * * *" in readme
    assert "targets.yaml" in readme
    assert "adding-targets.md" in readme
    assert "Behavioral checks stay off" in readme
    raw = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert len(raw) == 3


@pytest.mark.unit
def test_watch_page_shows_the_12h_timer_and_add_path(client):
    body = client.get("/watch").get_data(as_text=True)
    assert "Watch status" in body
    assert TIMER in body
    assert "watch --once" in body
    assert "watch --loop" in body
    assert "Behavioral checks stay off" in body
    assert "targets.yaml" in body
    assert "adding-targets.md" in body
    assert "03:17 UTC" in body
    assert 'href="/wizard"' in body
