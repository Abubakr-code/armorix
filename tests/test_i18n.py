import re

import pytest

from armorix import i18n
from armorix.cli import main
from armorix.report_html import to_html
from armorix.rules import ALL_RULES
from armorix.scanner import scan

BANNED = re.compile(r"juda xavfsiz|xavfsiz tizim|favqulodda xavfsizlik", re.IGNORECASE)


def test_every_rule_is_translated():
    for rule in ALL_RULES:
        for lang in ("uz", "ru"):
            title, why, fix = i18n.RULES[rule.id][lang]
            assert title and why and fix, (rule.id, lang)


def test_ui_keys_match_across_languages():
    assert set(i18n.UI["uz"]) == set(i18n.UI["ru"]) == set(i18n.UI["en"])


def test_no_banned_marketing_phrases():
    text = repr(i18n.RULES) + repr(i18n.UI) + repr(i18n.DEP)
    assert not BANNED.search(text)


@pytest.mark.parametrize("lang, heading, label", [("uz", "Xavfsizlik hisoboti", "manba"), ("ru", "Отчёт по безопасности кода", "источник"), ("en", "Security report", "source")])
def test_html_is_localised(lang, heading, label):
    page = to_html(scan("examples/vuln-shop", deps=False), lang)
    assert f'lang="{lang}"' in page and heading in page and f">{label}<" in page


def test_localised_message_keeps_the_source():
    f = next(f for f in scan("examples/vuln-shop", deps=False).findings if f.rule_id == "ARX-SQLI" and f.file == "server.js")
    _, message, _ = i18n.localize(f, "uz")
    assert "Manba: `req.query.id`" in message


def test_cli_lang_flag(capsys):
    main(["scan", "examples/vuln-shop", "--lang", "ru", "--fail-on", "none"])
    out = capsys.readouterr().out
    assert "SQL-инъекция" in out and "итог" in out


def test_detect(monkeypatch):
    monkeypatch.delenv("ARMORIX_LANG", raising=False)
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    assert i18n.detect() == "ru"
    assert i18n.detect("uz") == "uz"
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    assert i18n.detect() == "en"
