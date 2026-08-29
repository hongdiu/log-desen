"""规则集与校验函数测试。"""

import json

from log_desensitizer.rules import (
    builtin_rules,
    idcard_ok,
    ipv4_ok,
    load_custom_rules,
    luhn_ok,
    rule_ids,
)


def test_luhn():
    assert luhn_ok("4111111111111111") is True
    assert luhn_ok("4999999999999999") is False


def test_idcard():
    assert idcard_ok("110101199003078574") is True
    assert idcard_ok("110101199003078570") is False  # 校验位错
    assert idcard_ok("11010119900307857") is False   # 长度不足


def test_ipv4():
    assert ipv4_ok("192.168.1.1") is True
    assert ipv4_ok("999.1.1.1") is False


def test_builtin_count():
    assert len(builtin_rules()) >= 15


def test_rule_ids_unique():
    ids = rule_ids()
    assert len(ids) == len(set(ids))


def test_load_custom_rules(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(
        json.dumps([{"id": "myorder", "pattern": "ORD\\d{6}"}]),
        encoding="utf-8",
    )
    rules = load_custom_rules(str(p))
    assert len(rules) == 1
    assert rules[0].id == "myorder"
