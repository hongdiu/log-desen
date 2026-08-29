"""字段级确认脱敏测试：scan_field_candidates 与 mask_with_fields。

验证「确认后脱敏」模式：扫描按字段去重生成候选、按确认字段集合脱敏、
未确认字段保留原值。
"""

import pytest

from log_desensitizer.engine import Engine, FieldCandidate
from log_desensitizer.rules import builtin_rules


@pytest.fixture
def sample_log(tmp_path):
    """生成含中文姓名字段的测试日志（含边界：报障人后跟姓氏开头的
    非姓名词，如 罗天/张江，靠用户人工兜底取消）。"""
    lines = [
        "2026-08-29 10:00:00 INFO user=张三 处理请求\n",
        "2026-08-29 10:01:00 INFO user=李四 完成\n",
        "2026-08-29 10:02:00 INFO 联系人:王五 电话\n",
        "2026-08-29 10:03:00 INFO 报障人=罗天\n",      # 罗=姓氏但非姓名（地名）, 需用户取消
        "2026-08-29 10:04:00 INFO 报障人=张江\n",      # 张=姓氏但非姓名（地名）, 需用户取消
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


def test_surname_filter_removes_false_positives(tmp_path):
    """姓氏首字过滤：进行/流水/微信/支付/成功 等非姓氏开头自动排除，
    PR 单号正则本身不匹配 value(英文/数字) 也不会进候选。"""
    lines = [
        "PR2093133026094645248: 进行联合账户汇总信息画像表落库\n",
        "流水报告：获取策略引擎结果，流程开启\n",
        "pdf_displayName=微信支付交易明细证明(20250101)\n",
        "status=成功 level=信息\n",
        "user=张三 createdBy=李四\n",  # 真正的姓名（张/李=姓氏）
    ]
    p = tmp_path / "fp.log"
    p.write_text("".join(lines), encoding="utf-8")
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(str(p))
    ch_cands = [c for c in cands if c.rule_id == "ch_name"]
    labels = {c.field_label for c in ch_cands}
    # 误报字段不应出现（首字非姓氏或 value 非中文）
    assert "PR2093133026094645248" not in labels, "PR 单号不应进候选（value=进行, 进✗姓氏）"
    assert "pdf_displayName" not in labels, "微信（微✗姓氏）应排除"
    assert "status" not in labels, "成功（成✗姓氏）应排除"
    assert "level" not in labels, "信息（信✗姓氏）应排除"
    # 真正的姓名字段应保留
    assert "user" in labels, "张三（张✓姓氏）应保留"
    assert "createdBy" in labels, "李四（李✓姓氏）应保留"


def test_custom_english_key_not_blocked(tmp_path):
    """通用工具不限英文 key 名：自定义英文字段（非白名单）只要 value 是姓氏开头
    的 2-4 字中文，就应保留候选。"""
    # bizHandlerName / reqOriginator 是任意自定义字段，非内置 name/user 字典
    lines = [
        "bizHandlerName: 王小明\n",
        "reqOriginator=刘德华\n",
        "contactPerson='张三丰'\n",
        "projStatus=进行中\n",  # 进非姓氏，应排除
    ]
    p = tmp_path / "custom.log"
    p.write_text("".join(lines), encoding="utf-8")
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(str(p))
    ch_cands = [c for c in cands if c.rule_id == "ch_name"]
    labels = {c.field_label for c in ch_cands}
    # 自定义英文字段名不应被排除（通用）
    assert "bizHandlerName" in labels, "自定义英文 key 不应该被白名单排除"
    assert "reqOriginator" in labels, "自定义英文 key 不应该被白名单排除"
    assert "contactPerson" in labels
    # 非姓名 value 排除
    assert "projStatus" not in labels, "进行中（进✗姓氏）应排除"


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
    # 报障人= 未确认，保留原值（罗天/张江 = 姓氏开头但非姓名，人工兜底取消）
    assert "罗天" in content
    assert "张江" in content


def test_mask_with_fields_all_confirmed(sample_log, tmp_path):
    """全确认 = 所有 ch_name 姓名脱敏（含误报地名）。"""
    eng = Engine(builtin_rules())
    cands = eng.scan_field_candidates(sample_log)
    confirmed = {c.field_key for c in cands if c.rule_id == "ch_name"}

    out = str(tmp_path / "out.log")
    eng.mask_with_fields(sample_log, out, confirmed)
    content = open(out, encoding="utf-8").read()

    # 所有姓名脱敏（罗天/张江也脱敏，因全确认人工勾选了）
    assert "张三" not in content
    assert "李四" not in content
    assert "王五" not in content
    assert "罗天" not in content
    assert "张江" not in content


def test_mask_with_fields_none_confirmed(sample_log, tmp_path):
    """零确认 = ch_name 不脱敏，姓名保留原值。"""
    eng = Engine(builtin_rules())
    out = str(tmp_path / "out.log")
    eng.mask_with_fields(sample_log, out, set())
    content = open(out, encoding="utf-8").read()

    # ch_name 未确认，姓名保留
    assert "user=张三" in content
    assert "报障人=罗天" in content
    assert "报障人=张江" in content


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
        custom_replacements=[("罗天", "[误报地名]")],
    )
    out = str(tmp_path / "out.log")
    # 即使 ch_name 未确认，敏感词替换仍执行
    eng.mask_with_fields(sample_log, out, set())
    content = open(out, encoding="utf-8").read()
    assert "[误报地名]" in content
    assert "罗天" not in content


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
    # 张三+李四+王五(联系人)+罗天(误报)+张江(误报)+王五(user) = 6
    assert ch_hit.count == 6
