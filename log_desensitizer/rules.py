"""内置脱敏规则集。

开箱即用，覆盖常见敏感数据，非技术人员无需手写正则。
所有规则 strategy=None，统一由引擎全局策略决定（默认掩码保留首尾）。
技术人员可通过 load_custom_rules 追加项目特定规则。

说明：纯启发式（正则 + Luhn/校验位 + 敏感键名字典），非 AI 识别，
覆盖面广但非 100% 准确，可能有误报/漏报；GUI 支持单条规则开关与扫描预览。
"""

import copy
import json
import os
from typing import List, Optional

from .engine import Rule


# ---------- 校验函数（降低误报） ----------

def luhn_ok(s: str) -> bool:
    """Luhn 校验，用于银行卡/信用卡。"""
    if not s.isdigit():
        return False
    total = 0
    reverse = s[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_IDCARD_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_IDCARD_CHECK = ('1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2')


def idcard_ok(s: str) -> bool:
    """身份证 18 位校验位 + 生日合理性。"""
    if len(s) != 18:
        return False
    if not s[:17].isdigit():
        return False
    body, tail = s[:17], s[17].upper()
    total = sum(int(body[i]) * _IDCARD_WEIGHTS[i] for i in range(17))
    if _IDCARD_CHECK[total % 11] != tail:
        return False
    year, month, day = int(body[6:10]), int(body[10:12]), int(body[12:14])
    if not (1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31):
        return False
    return True


def ipv4_ok(s: str) -> bool:
    """IPv4 各段 0-255。"""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or int(p) > 255:
            return False
    return True


# ---------- 内置规则定义 ----------

# key=value 形式的敏感键名（只脱敏 value，保留键名）
# 按 key 长度降序排列：避免短前缀（如 pwd/auth）先尝试失败再回溯，
# 长前缀（如 refresh_token）优先匹配，减少 secret_kv 在大日志上的回溯开销。
_SENSITIVE_KEYS = (
    "refresh_token|client_secret|authorization|access_token|private_key|"
    "session_key|access_key|app_secret|credential|appsecret|accesskey|"
    "password|api_key|apikey|passwd|secret|token|auth|pwd"
)

# 注：private_key 规则按行处理时无法匹配跨行的 PEM 块，
# 后续可在文件级处理增强；当前匹配同行 BEGIN...END。
_RULE_DEFINITIONS: List[Rule] = [
    Rule(id="phone", pattern=r"\b1[3-9]\d{9}\b"),
    Rule(id="idcard", pattern=r"\b\d{17}[\dXx]\b", validator=idcard_ok),
    Rule(id="bankcard", pattern=r"\b[456]\d{14,18}\b", validator=luhn_ok),
    Rule(
        id="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    ),
    Rule(
        id="ipv4",
        pattern=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        validator=ipv4_ok,
    ),
    Rule(id="mac", pattern=r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    Rule(id="iban", pattern=r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    Rule(
        id="uuid",
        pattern=r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    ),
    Rule(id="jwt", pattern=r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    Rule(id="aws_key", pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    Rule(id="gcp_key", pattern=r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    Rule(id="github_token", pattern=r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    Rule(id="openai_key", pattern=r"\bsk-[A-Za-z0-9]{20,}\b"),
    Rule(id="slack_token", pattern=r"\bxox[bp]-[A-Za-z0-9-]{10,}\b"),
    Rule(id="stripe_key", pattern=r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    Rule(
        id="private_key",
        pattern=r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    # 数据库连接串：scheme://user:password@host，只脱敏密码（第 1 组）
    Rule(
        id="db_conn",
        pattern=r"(?:mysql|postgresql|postgres|mongodb|redis|amqp)://[^\s:@/]+:([^\s:@/]+)@",
        replace_group=1,
    ),
    # Azure 连接串 AccountKey=...，只脱敏值（第 1 组）
    Rule(id="azure_key", pattern=r"AccountKey=([^&\s\"']+)", replace_group=1),
    # 通用 key=value 敏感键，只脱敏 value（第 2 组）
    # 左边界用 (?<![\w]) 替代 \b，更精确；值部分排除引号与控制字符，
    # 减少贪婪回溯（大日志性能关键）。
    Rule(
        id="secret_kv",
        pattern=r"(?i)(?<![\w])(" + _SENSITIVE_KEYS + r")\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^\s&;\"'\x00-\x1f]+)",
        replace_group=2,
    ),
    # 中文姓名候选：匹配常见姓名字段名后的 2-4 字中文值（只脱敏姓名，第 1 组）。
    # 纯启发式，会误报地名/项目名（如 报障人=北京）；靠「确认后脱敏」模式
    # 由用户根据日志原文样本判断字段真伪后勾选，人工兜底误报。
    Rule(
        id="ch_name",
        pattern=r"(?:user|name|username|姓名|联系人|经办人|报障人|客户|经办|操作人|处理人|上报人|责任人)\s*[:：=]\s*([\u4e00-\u9fa5]{2,4})",
        replace_group=1,
    ),
]


def builtin_rules() -> List[Rule]:
    """返回内置规则列表（深拷贝，避免多引擎共享编译缓存）。"""
    return copy.deepcopy(_RULE_DEFINITIONS)


def rule_ids() -> List[str]:
    """返回内置规则 id 列表（用于 GUI 规则开关显示）。"""
    return [r.id for r in _RULE_DEFINITIONS]


# ---------- 自定义规则加载 ----------

def load_custom_rules(path: str) -> List[Rule]:
    """从 JSON/YAML 文件加载自定义规则，追加到内置规则之后。

    JSON 格式示例::

        [
          {"id": "my_order", "pattern": "ORD\\d{10}", "replace_group": 0},
          {"id": "my_token", "pattern": "CT-\\w{20}"}
        ]

    YAML 暂不支持（避免引入 PyYAML 依赖），用 JSON 即可。
    """
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".json",):
        raise ValueError("自定义规则仅支持 JSON 格式，避免引入额外依赖")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    rules: List[Rule] = []
    for item in data:
        rules.append(
            Rule(
                id=item["id"],
                pattern=item["pattern"],
                replace_group=int(item.get("replace_group", 0)),
                enabled=bool(item.get("enabled", True)),
            )
        )
    return rules


def all_rules(custom_path: Optional[str] = None) -> List[Rule]:
    """内置规则 + 可选自定义规则。"""
    rules = builtin_rules()
    if custom_path:
        rules += load_custom_rules(custom_path)
    return rules
