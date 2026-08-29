"""核心脱敏引擎：加载规则、匹配敏感数据、按策略替换。

纯标准库实现，兼容 Python 3.8+。核心入口为 Engine，支持文本/文件脱敏。
"""

import os
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from .strategies import DEFAULT_STRATEGY, Strategy

# 进度回调签名：(current, total)
ProgressCb = Callable[[int, int], None]


def _safe_size(path: str) -> int:
    """安全获取文件大小，失败返回 0。"""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


@dataclass
class Rule:
    """一条脱敏规则。

    - id         规则标识（用于命中清单与替换占位）
    - pattern    正则表达式
    - replace_group 大于 0 时只脱敏该捕获组（其余部分原样保留），0 表示整体脱敏
    - validator  命中后可选校验（如 Luhn、身份证校验位），返回 False 则不脱敏、保留原值
    - strategy   单规则专属策略，None 时用引擎全局策略
    """

    id: str
    pattern: str
    enabled: bool = True
    replace_group: int = 0
    validator: Optional[Callable[[str], bool]] = None
    strategy: Optional[Strategy] = None
    _compiled: Optional["re.Pattern"] = field(default=None, repr=False)

    def compile(self) -> "re.Pattern":
        if self._compiled is None:
            self._compiled = re.compile(self.pattern)
        return self._compiled


@dataclass
class Hit:
    """单次脱敏命中统计。"""

    rule_id: str
    count: int = 0


class Engine:
    """脱敏引擎。

    用法::

        from log_desensitizer.engine import Engine
        from log_desensitizer.rules import builtin_rules
        eng = Engine(builtin_rules())
        masked, hits = eng.mask_text("联系 13812345678")
    """

    def __init__(
        self,
        rules: List[Rule],
        strategy: Optional[Strategy] = None,
        custom_replacements: Optional[List[Tuple[str, str]]] = None,
    ):
        self.rules = [r for r in rules if r.enabled]
        self.default_strategy = strategy or DEFAULT_STRATEGY
        self.custom_replacements = custom_replacements or []
        for r in self.rules:
            r.compile()

    def _rule_strategy(self, r: Rule) -> Strategy:
        return r.strategy if r.strategy is not None else self.default_strategy

    def mask_text(self, text: str) -> Tuple[str, List[Hit]]:
        """对一段文本脱敏，返回脱敏后文本与命中清单。

        多条规则按顺序依次作用于上一步结果。每条规则内通过 finditer
        重建文本，仅替换通过 validator 的匹配，避免误报。
        """
        hits = {r.id: 0 for r in self.rules}
        for r in self.rules:
            pat = r.compile()
            strat = self._rule_strategy(r)
            out_parts: List[str] = []
            last = 0
            count = 0
            for m in pat.finditer(text):
                start, end = m.start(), m.end()
                if r.replace_group and r.replace_group <= m.re.groups:
                    g = r.replace_group
                    v_start, v_end = m.start(g), m.end(g)
                    matched = m.group(g)
                    if r.validator is not None and not r.validator(matched):
                        out_parts.append(text[last:end])
                        last = end
                        continue
                    out_parts.append(text[last:v_start])
                    out_parts.append(strat.apply(matched, r.id))
                    last = v_end
                else:
                    matched = m.group(0)
                    if r.validator is not None and not r.validator(matched):
                        out_parts.append(text[last:end])
                        last = end
                        continue
                    out_parts.append(text[last:start])
                    out_parts.append(strat.apply(matched, r.id))
                    last = end
                count += 1
            out_parts.append(text[last:])
            if count:
                text = "".join(out_parts)
                hits[r.id] = count
        # 自定义字符串全局替换（在所有正则规则之后）
        for old, new in self.custom_replacements:
            if not old:
                continue
            n = text.count(old)
            if n:
                text = text.replace(old, new)
                hits["custom_replace"] = hits.get("custom_replace", 0) + n
        return text, [Hit(k, v) for k, v in hits.items() if v > 0]

    def mask_file(
        self,
        in_path: str,
        out_path: str,
        encoding: str = "utf-8",
        on_progress: Optional[ProgressCb] = None,
    ) -> List[Hit]:
        """按行处理文件脱敏，避免大文件一次性读入内存。

        errors="replace" 容忍非法字节，避免中断。
        on_progress(done_bytes, total_bytes) 用于进度反馈。
        """
        total: dict = {}
        total_bytes = _safe_size(in_path)
        done = 0
        with open(in_path, "r", encoding=encoding, errors="replace") as fin, \
                open(out_path, "w", encoding=encoding, newline="") as fout:
            for line in fin:
                masked, hits = self.mask_text(line)
                fout.write(masked)
                for h in hits:
                    total[h.rule_id] = total.get(h.rule_id, 0) + h.count
                done += len(line.encode(encoding, errors="replace"))
                if on_progress is not None and total_bytes > 0:
                    on_progress(done, total_bytes)
        if on_progress is not None and total_bytes > 0:
            on_progress(total_bytes, total_bytes)
        return [Hit(k, v) for k, v in total.items()]

    def mask_dir(
        self,
        in_dir: str,
        out_dir: str,
        encoding: str = "utf-8",
        on_progress: Optional[ProgressCb] = None,
    ) -> dict:
        """批量处理目录下所有文件（不递归子目录）。

        on_progress(done_files, total_files) 按文件数反馈进度。
        """
        os.makedirs(out_dir, exist_ok=True)
        names = [n for n in os.listdir(in_dir)
                 if os.path.isfile(os.path.join(in_dir, n))]
        results: dict = {}
        total = len(names)
        for i, name in enumerate(names, 1):
            ip = os.path.join(in_dir, name)
            op = os.path.join(out_dir, name)
            results[name] = self.mask_file(ip, op, encoding)
            if on_progress is not None and total > 0:
                on_progress(i, total)
        return results

    def scan_text(self, text: str) -> List[Hit]:
        """仅扫描统计敏感信息命中，不替换。

        用于"校验日志是否有敏感信息"场景：先扫描看命中哪些规则、各多少处，
        再决定是否脱敏。返回命中清单，文本本身不变。
        """
        hits = {r.id: 0 for r in self.rules}
        for r in self.rules:
            pat = r.compile()
            count = 0
            for m in pat.finditer(text):
                g = r.replace_group
                matched = m.group(g) if g and g <= m.re.groups else m.group(0)
                if r.validator is not None and not r.validator(matched):
                    continue
                count += 1
            if count:
                hits[r.id] = count
        # 自定义字符串替换命中也统计到扫描结果
        for old, _ in self.custom_replacements:
            if not old:
                continue
            n = text.count(old)
            if n:
                hits["custom_replace"] = hits.get("custom_replace", 0) + n
        return [Hit(k, v) for k, v in hits.items() if v > 0]

    def scan_file(self, in_path: str, encoding: str = "utf-8",
                  on_progress: Optional[ProgressCb] = None) -> List[Hit]:
        """扫描文件敏感信息命中统计（按行，不写入、不替换）。"""
        total: dict = {}
        total_bytes = _safe_size(in_path)
        done = 0
        with open(in_path, "r", encoding=encoding, errors="replace") as fin:
            for line in fin:
                for h in self.scan_text(line):
                    total[h.rule_id] = total.get(h.rule_id, 0) + h.count
                done += len(line.encode(encoding, errors="replace"))
                if on_progress is not None and total_bytes > 0:
                    on_progress(done, total_bytes)
        if on_progress is not None and total_bytes > 0:
            on_progress(total_bytes, total_bytes)
        return [Hit(k, v) for k, v in total.items()]
