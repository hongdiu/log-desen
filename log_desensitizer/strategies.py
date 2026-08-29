"""脱敏策略：决定匹配到的敏感数据如何替换。

三种内置策略：
- MaskStrategy  掩码保留首尾（如 138****1234），默认策略
- HashStrategy  同值同哈希，便于厂商在日志中关联同一对象而看不到原值
- RedactStrategy 彻底替换为 [REDACTED:类型]，最安全
"""

import hashlib
import hmac
from typing import Optional


class Strategy:
    """策略基类。"""

    name = "base"

    def apply(self, value: str, rule_id: str) -> str:  # pragma: no cover - 接口
        raise NotImplementedError


class MaskStrategy(Strategy):
    """掩码保留首尾：保留前 keep_prefix 位与后 keep_suffix 位，中间用 mask_char 填充。

    值过短时（不足以同时保留首尾）整串掩码，避免泄露。
    """

    name = "mask"

    def __init__(
        self,
        keep_prefix: int = 3,
        keep_suffix: int = 4,
        mask_char: str = "*",
    ):
        self.keep_prefix = keep_prefix
        self.keep_suffix = keep_suffix
        self.mask_char = mask_char

    def apply(self, value: str, rule_id: str) -> str:
        n = len(value)
        if n == 0:
            return value
        kp = min(self.keep_prefix, n)
        ks = min(self.keep_suffix, n - kp)
        mid_len = n - kp - ks
        if mid_len <= 0:
            # 值过短，整串掩码避免泄露
            return self.mask_char * n
        return value[:kp] + self.mask_char * mid_len + value[n - ks:]


class HashStrategy(Strategy):
    """同值同哈希：同一敏感值在日志各处产生相同哈希，便于关联排查。

    可选 HMAC key，带 key 时更难被彩虹表反查。
    """

    name = "hash"

    def __init__(self, key: str = ""):
        self.key = key

    def apply(self, value: str, rule_id: str) -> str:
        if self.key:
            digest = hmac.new(
                self.key.encode("utf-8"),
                value.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        else:
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return "[{0}:{1}]".format(rule_id, digest[:12])


class RedactStrategy(Strategy):
    """彻底替换为 [REDACTED:类型]，不保留任何可识别信息。"""

    name = "redact"

    def apply(self, value: str, rule_id: str) -> str:
        return "[REDACTED:{0}]".format(rule_id)


# 默认策略：掩码保留首尾
DEFAULT_STRATEGY = MaskStrategy()
