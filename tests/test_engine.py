"""核心引擎与策略测试。"""

from log_desensitizer.engine import Engine
from log_desensitizer.rules import builtin_rules
from log_desensitizer.strategies import HashStrategy, RedactStrategy


def _eng():
    return Engine(builtin_rules())


def test_phone_mask():
    t, h = _eng().mask_text("call 13812345678 now")
    assert "138****5678" in t
    assert any(x.rule_id == "phone" for x in h)


def test_idcard_valid_masked():
    t, _ = _eng().mask_text("id 110101199003078574")
    assert "110101199003078574" not in t


def test_idcard_invalid_kept():
    # 校验位错误，不应脱敏
    t, h = _eng().mask_text("id 110101199003078570")
    assert "110101199003078570" in t
    assert not any(x.rule_id == "idcard" for x in h)


def test_bankcard_luhn_masked():
    t, h = _eng().mask_text("card 4111111111111111")
    assert "4111" in t
    assert "4111111111111111" not in t
    assert any(x.rule_id == "bankcard" for x in h)


def test_bankcard_invalid_kept():
    t, h = _eng().mask_text("card 4999999999999999")
    assert "4999999999999999" in t
    assert not any(x.rule_id == "bankcard" for x in h)


def test_secret_kv_only_value():
    t, _ = _eng().mask_text("password=hello123 end")
    assert "password=" in t
    assert "hello123" not in t


def test_db_conn_only_password():
    t, _ = _eng().mask_text("mysql://user:secretpass@host/db")
    assert "secretpass" not in t
    assert "user" in t and "host" in t


def test_scan_text_does_not_replace():
    src = "phone 13812345678"
    hits = _eng().scan_text(src)
    assert any(x.rule_id == "phone" and x.count == 1 for x in hits)
    assert "13812345678" in src  # 原文未变


def test_strategy_hash():
    eng = Engine(builtin_rules(), HashStrategy())
    t, _ = eng.mask_text("p 13812345678")
    assert "[phone:" in t


def test_strategy_redact():
    eng = Engine(builtin_rules(), RedactStrategy())
    t, _ = eng.mask_text("p 13812345678")
    assert "[REDACTED:phone]" in t


def test_mask_file(tmp_path):
    src = tmp_path / "a.log"
    out = tmp_path / "a.masked.log"
    src.write_text("phone 13812345678\n", encoding="utf-8")
    hits = _eng().mask_file(str(src), str(out))
    content = out.read_text(encoding="utf-8")
    assert "138****5678" in content
    assert any(x.rule_id == "phone" for x in hits)
