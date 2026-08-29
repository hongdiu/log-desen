"""字段级确认脱敏测试：scan_field_candidates 与 mask_with_fields。

验证「确认后脱敏」模式：扫描按字段去重生成候选、按确认字段集合脱敏、
未确认字段保留原值。
"""

import pytest

from log_desensitizer.engine import Engine, FieldCandidate
from log_desensitizer.rules import builtin_rules


@pytest.fixture
def sample_log(tmp_path):
    """生成含中文姓名字段的测试日志（含误报：报障人后跟地名）。"""
    lines = [
        "2026-08-29 10:00:00 INFO user=张三 处理请求\n",
        "2026-08-29 10:01:00 INFO user=李四 完成\n",
        "2026-08-29 10:02:00 INFO 联系人:王五 电话\n",
        "2026-08-29 10:03:00 INFO 报障人=北京分公司\n",
        "2026-08-29 10:04:00 INFO 报障人=上海中心\n",
        "2026-08-29 10:05:00 INFO user=王五 跟进\n",
    ]
    p = tmp_path / "test.log"
    p.write_text("".join(lines), encoding="utf-8")
    return str(p)


def test_scan_field_candidates_groups_by_field(sample_log):
    """扫描应按 key 去重：user、联系人、报障人 各一条候选。"""
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(sample_log)

    ch_cands = [c for c in cands if c.rule_id == "ch_name"]
    assert len(ch_cands) >= 3, "应至少有 user/联系人/报障人 三条字段候选"

    fields = {c.field_label for c in ch_cands}
    assert "user" in fields
    assert "联系人" in fields
    assert "报障人" in fields

    # user 字段应命中 3 次（张三、李四、王五）
    user_cand = next(c for c in ch_cands if c.field_label == "user")
    assert user_cand.count == 3
    # 报障人 字段应命中 2 次（北京、上海）
    bao_cand = next(c for c in ch_cands if c.field_label == "报障人")
    assert bao_cand.count == 2
    # 候选应含日志原文样本
    assert len(user_cand.samples) >= 1
    assert "user=张三" in user_cand.samples[0]


def test_scan_field_candidate_is_field_candidate_type(sample_log):
    """返回类型应为 FieldCandidate。"""
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(sample_log)
    assert all(isinstance(c, FieldCandidate) for c in cands)


def test_dynamic_field_forms(tmp_path):
    """动态扫描应覆盖各种 key 分隔符形式（形式不限）。"""
    lines = [
        "userName: '张三' done\n",
        "user=张三 done\n",
        "userName='李四' done\n",
        'name="王五" done\n',
        "联系人：赵六 done\n",
    ]
    p = tmp_path / "forms.log"
    p.write_text("".join(lines), encoding="utf-8")
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(str(p))
    ch_cands = [c for c in cands if c.rule_id == "ch_name"]
    fields = {c.field_label for c in ch_cands}
    # 各种形式的 key 都应被提取
    assert "userName" in fields
    assert "user" in fields
    assert "name" in fields
    assert "联系人" in fields
    # userName 应命中 2 次（'张三' 和 '李四'）
    un_cand = next(c for c in ch_cands if c.field_label == "userName")
    assert un_cand.count == 2


def test_ch_name_not_in_auto_mask(tmp_path):
    """ch_name 是候选规则，不应参与一键脱敏（mask_text），避免误报。"""
    eng = Engine(builtin_rules())
    # proj=内部项目代号 不应被 ch_name 自动脱敏
    text, hits = eng.mask_text("proj=内部项目代号 done")
    assert "proj=内部项目代号" in text  # 原文保留
    # ch_name 不在自动脱敏命中
    assert not any(h.rule_id == "ch_name" for h in hits)


def test_mask_with_fields_partial_confirm(sample_log, tmp_path):
    """确认 user 和 联系人，不确认 报障人。报障人保留原值。"""
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(sample_log)
    # 只确认 user 和 联系人 的 field_key
    confirmed = set()
    for c in cands:
        if c.rule_id == "ch_name" and c.field_label in ("user", "联系人"):
            confirmed.add(c.field_key)
    assert confirmed, "应能找到 user 和 联系人 的 field_key"

    out = str(tmp_path / "out.log")
    eng.mask_with_fields(sample_log, out, confirmed)
    content = open(out, encoding="utf-8").read()

    # user= 姓名被脱敏（原值不再出现）
    assert "张三" not in content
    assert "李四" not in content
    assert "王五" not in content
    # 报障人= 未确认，保留原值
    assert "北京分公司" in content
    assert "上海中心" in content


def test_mask_with_fields_all_confirmed(sample_log, tmp_path):
    """全确认 = 所有 ch_name 姓名脱敏（含误报地名）。"""
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(sample_log)
    confirmed = {c.field_key for c in cands if c.rule_id == "ch_name"}

    out = str(tmp_path / "out.log")
    eng.mask_with_fields(sample_log, out, confirmed)
    content = open(out, encoding="utf-8").read()

    # 所有姓名脱敏
    assert "张三" not in content
    assert "北京分公司" not in content  # 误报地名也脱敏（全确认）


def test_mask_with_fields_none_confirmed(sample_log, tmp_path):
    """零确认 = ch_name 不脱敏，姓名保留原值。"""
    eng = Engine(builtin_rules())
    out = str(tmp_path / "out.log")
    eng.mask_with_fields(sample_log, out, set())
    content = open(out, encoding="utf-8").read()

    # ch_name 未确认，姓名保留
    assert "user=张三" in content
    assert "报障人=北京分公司" in content


def test_mask_with_fields_preserves_other_rules(sample_log, tmp_path):
    """确认模式不影响其他规则：phone 等仍按既有逻辑脱敏。

    ch_name 未确认时姓名保留，但 phone 等规则仍应正常工作。
    """
    lines = [
        "user=张三 phone=13812345678 done\n",
    ]
    p = tmp_path / "mix.log"
    p.write_text("".join(lines), encoding="utf-8")
    eng = Engine(builtin_rules())
    out = str(tmp_path / "out.log")
    # 不确认任何 ch_name 字段
    eng.mask_with_fields(str(p), out, set())
    content = open(out, encoding="utf-8").read()
    # 姓名保留（未确认）
    assert "user=张三" in content
    # 手机号仍被 phone 规则脱敏
    assert "13812345678" not in content
    assert "138****5678" in content  # 默认 MaskStrategy 保留前3后4


def test_mask_with_fields_custom_replace_still_runs(sample_log, tmp_path):
    """确认模式不抑制自定义敏感词替换。"""
    eng = Engine(
        builtin_rules(),
        custom_replacements=[("北京", "[地名]")],
    )
    out = str(tmp_path / "out.log")
    # 即使 ch_name 未确认，敏感词替换仍执行
    eng.mask_with_fields(sample_log, out, set())
    content = open(out, encoding="utf-8").read()
    assert "[地名]" in content
    assert "北京" not in content


def test_mask_with_fields_returns_hits(sample_log, tmp_path):
    """mask_with_fields 应返回命中统计。"""
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(sample_log)
    confirmed = {c.field_key for c in cands if c.rule_id == "ch_name"}
    out = str(tmp_path / "out.log")
    hits = eng.mask_with_fields(sample_log, out, confirmed)
    # 应有 ch_name 命中
    ch_hit = next((h for h in hits if h.rule_id == "ch_name"), None)
    assert ch_hit is not None
    assert ch_hit.count == 6  # 张三+李四+王五(联系人)+北京+上海+王五(user) = 6
