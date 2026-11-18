"""Scoring: noisy-OR combination, per-rule dedupe, combos, levels, explanation."""

import pytest

from tripwire.models import Evidence
from tripwire.scoring import FLAG_THRESHOLD, analyzer_strengths, level_for, score


def e(analyzer, rule, w, msg="m"):
    return Evidence(analyzer, rule, w, msg)


@pytest.mark.parametrize("value,level", [
    (0, "none"), (19, "none"), (20, "low"), (49, "low"), (50, "medium"), (69, "medium"),
    (70, "high"), (84, "high"), (85, "critical"), (100, "critical"),
])
def test_levels(value, level):
    assert level_for(value) == level


def test_flag_line_is_medium():
    assert FLAG_THRESHOLD == 50 and level_for(FLAG_THRESHOLD) == "medium"


def test_no_evidence():
    assert score([]) == (0, "none", "No suspicious signals found.")


def test_single_signal_maps_to_its_weight():
    assert score([e("network", "raw_ip", 0.45)])[0] == 45


def test_noisy_or_within_an_analyser():
    # two different rules of 0.5 each: 1 - 0.5 * 0.5 = 0.75
    assert score([e("network", "a", 0.5), e("network", "b", 0.5)])[0] == 75


def test_same_rule_counts_once():
    ev = [e("obfuscation", "base64_blob", 0.45, f"file {i}") for i in range(50)]
    assert score(ev)[0] == 45


def test_context_evidence_adds_nothing():
    assert score([e("install_hooks", "npm_hook_build", 0.05), e("obfuscation", "x", 0.15)])[0] == 0


def test_weight_point_two_counts_but_does_not_fire_combos():
    value, _, _ = score([e("install_hooks", "npm_hook_runs_file", 0.2), e("credentials", "env_harvest", 0.25)])
    # 1 - 0.8 * 0.75 = 0.40, and no combo because neither reaches 0.30
    assert value == 40


def test_combo_bonus_credentials_and_network():
    plain = score([e("credentials", "ssh_keys", 0.5)])[0]
    combo = score([e("credentials", "ssh_keys", 0.5), e("network", "raw_ip", 0.45)])[0]
    # 1 - 0.5 * 0.55 = 0.725, plus 0.20 for the pair = 0.925 -> 92 (round half to even)
    assert plain == 50 and combo == 92


def test_combo_text_in_explanation():
    _, _, text = score([e("credentials", "ssh_keys", 0.5), e("network", "raw_ip", 0.45)])
    assert "reads secrets and also contains a place to send them" in text


def test_score_is_capped_at_100():
    ev = [e(a, "r", 0.9) for a in ("install_hooks", "network", "credentials", "obfuscation", "typosquat")]
    assert score(ev)[0] == 100


def test_single_weight_is_capped_below_one():
    assert analyzer_strengths([e("x", "r", 1.0)]) == {"x": 0.97}


def test_explanation_names_strongest_findings_and_flag_line():
    _, level, text = score([e("network", "raw_ip", 0.45, "Talks to a raw IP.")])
    assert level == "low"
    assert text.startswith("Risk 45/100 (low). Below the flag line")
    assert "Talks to a raw IP." in text


def test_explanation_lists_at_most_three_analysers():
    ev = [e(a, "r", 0.4, f"{a} said so") for a in ("a1", "a2", "a3", "a4")]
    text = score(ev)[2]
    assert sum(f"a{i} said so" in text for i in range(1, 5)) == 3
