"""The rule registry stays complete and in sync with its generated document."""

from __future__ import annotations

from gifthorse import registry, report
from gifthorse.model import Severity

from .conftest import ROOT


def test_every_rule_has_complete_metadata() -> None:
    for rule in registry.all_rules():
        for field in (rule.id, rule.title, rule.family, rule.means, rule.why):
            assert field.strip(), rule.id
        assert rule.id.startswith("GH")
        assert isinstance(rule.severity, Severity)


def test_every_rule_has_a_non_empty_trigger_and_next_step() -> None:
    for rule in registry.all_rules():
        assert rule.trigger.strip(), f"{rule.id} has no trigger"
        assert rule.next_step.strip(), f"{rule.id} has no next_step"


def test_rule_ids_are_unique() -> None:
    ids = [rule.id for rule in registry.all_rules()]
    assert len(ids) == len(set(ids))


def test_generated_rules_doc_matches_the_registry() -> None:
    on_disk = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
    assert on_disk == report.render_rules_markdown(), "docs/RULES.md is stale; regenerate it"


def test_no_dash_characters_in_registry_text() -> None:
    em_dash = chr(0x2014)
    en_dash = chr(0x2013)
    for rule in registry.all_rules():
        blob = " ".join([rule.title, rule.means, rule.why, rule.trigger, rule.next_step])
        assert em_dash not in blob, rule.id
        assert en_dash not in blob, rule.id


def test_explain_each_rule_renders() -> None:
    for rule in registry.all_rules():
        text = report.render_explain(rule.id)
        assert text is not None
        assert rule.title in text
        assert rule.severity_text() in text
        assert rule.trigger in text
        assert rule.next_step in text


def test_every_declared_level_is_named_in_the_severity_text() -> None:
    for rule in registry.all_rules():
        text = rule.severity_text()
        for level in rule.levels:
            assert level.value in text, rule.id
        if rule.also:
            assert rule.when.strip(), f"{rule.id} has other levels but no condition"
        else:
            assert not rule.when, f"{rule.id} has a condition but no other level"


def test_rules_that_escalate_declare_both_levels() -> None:
    expected = {
        "GH101": {"review", "block"},
        "GH103": {"info", "block"},
        "GH108": {"info", "review"},
        "GH202": {"review", "block"},
        "GH301": {"review", "block"},
        "GH302": {"review", "block"},
        "GH401": {"review", "block"},
        "GH403": {"review", "block"},
        "GH407": {"review", "block"},
        "GH501": {"review", "block"},
        "GH504": {"review", "block"},
        "GH606": {"review", "block"},
    }
    for rule in registry.all_rules():
        levels = {level.value for level in rule.levels}
        assert levels == expected.get(rule.id, {rule.severity.value}), rule.id


def test_unknown_rule_explains_to_none() -> None:
    assert report.render_explain("GH999") is None
