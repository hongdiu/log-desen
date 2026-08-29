"""核心脱敏引擎：加载规则、匹配敏感数据、按策略替换。

优先使用 regex 库（性能更优），未安装时回退到标准库 re。
兼容 Python 3.8+。核心入口为 Engine，支持文本/文件脱敏。
"""

import os
# 优先使用 regex 库（对复杂正则如 secret_kv 的 alternation+回溯性能优于
# 标准库 re 2-5 倍）；未安装时回退到标准库 re，保证纯标准库环境可运行。
try:
    import regex as re  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
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
    - field_group  大于 0 时该捕获组作为「字段标识」用于确认脱敏去重（如 ch_name
                   的 key 名 userName），0 表示不参与字段确认（整体脱敏规则照常脱敏）
    - validator  命中后可选校验（如 Luhn、身份证校验位），返回 False 则不脱敏、保留原值
    - strategy   单规则专属策略，None 时用引擎全局策略
    """

    id: str
    pattern: str
    enabled: bool = True
    replace_group: int = 0
    field_group: int = 0
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


@dataclass
class FieldCandidate:
    """字段级脱敏候选（用于「确认后脱敏」模式）。

    - rule_id       所属规则 id
    - field_key     归一化字段标识（去空白后的字段模式，或规则名），用于去重与确认集合
    - field_label   展示用字段标签（保留原样分隔符的原文片段，或规则名）
    - samples       前 5 个日志原文上下文片段（匹配前后各 15 字），帮用户判断字段真伪
    - count         该字段下总命中次数
    """

    rule_id: str
    field_key: str
    field_label: str
    samples: List[str] = field(default_factory=list)
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
        候选规则（field_group>0，如 ch_name）不参与自动脱敏，只用于
        「确认后脱敏」模式，避免误报破坏原文。
        """
        hits = {r.id: 0 for r in self.rules}
        for r in self.rules:
            if r.field_group and r.field_group > 0:
                continue
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
        # 自定义敏感词全局替换（在所有正则规则之后）
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
        on_progress(done_bytes, total_bytes) 用于进度反馈，用底层二进制流的
        tell() 取真实字节偏移，避免每行 encode 计算的开销（大文件关键优化）。
        """
        import io
        total: dict = {}
        total_bytes = _safe_size(in_path)
        with io.open(in_path, "rb") as fb, \
                io.TextIOWrapper(fb, encoding=encoding, errors="replace",
                                 newline="") as fin, \
                open(out_path, "w", encoding=encoding, newline="") as fout:
            for line in fin:
                masked, hits = self.mask_text(line)
                fout.write(masked)
                for h in hits:
                    total[h.rule_id] = total.get(h.rule_id, 0) + h.count
                if on_progress is not None and total_bytes > 0:
                    on_progress(fb.tell(), total_bytes)
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
            # 候选规则不参与自动扫描统计（只用于确认脱敏）
            if r.field_group and r.field_group > 0:
                continue
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
        # 自定义敏感词替换命中也统计到扫描结果
        for old, _ in self.custom_replacements:
            if not old:
                continue
            n = text.count(old)
            if n:
                hits["custom_replace"] = hits.get("custom_replace", 0) + n
        return [Hit(k, v) for k, v in hits.items() if v > 0]

    def scan_file(self, in_path: str, encoding: str = "utf-8",
                  on_progress: Optional[ProgressCb] = None) -> List[Hit]:
        """扫描文件敏感信息命中统计（按行，不写入、不替换）。

        用底层二进制流 tell() 取真实字节偏移做进度反馈（大文件优化）。
        """
        import io
        total: dict = {}
        total_bytes = _safe_size(in_path)
        with io.open(in_path, "rb") as fb, \
                io.TextIOWrapper(fb, encoding=encoding,
                                 errors="replace", newline="") as fin:
            for line in fin:
                for h in self.scan_text(line):
                    total[h.rule_id] = total.get(h.rule_id, 0) + h.count
                if on_progress is not None and total_bytes > 0:
                    on_progress(fb.tell(), total_bytes)
        if on_progress is not None and total_bytes > 0:
            on_progress(total_bytes, total_bytes)
        return [Hit(k, v) for k, v in total.items()]

    # ---------- 字段级确认脱敏 ----------

    def _field_key(self, r: Rule, m) -> str:
        """从匹配中提取归一化字段标识（去空白）。

        field_group>0 时取该捕获组作为字段标识（如 ch_name 的 key 名 userName）；
        否则 replace_group>0 时取值之前的原文片段（如 user=）；
        整体脱敏规则用规则名。
        """
        if r.field_group and r.field_group <= m.re.groups:
            return re.sub(r"\s", "", m.group(r.field_group))
        if r.replace_group and r.replace_group <= m.re.groups:
            g = r.replace_group
            prefix = m.group(0)[: m.start(g) - m.start(0)]
        else:
            prefix = r.id
        return re.sub(r"\s", "", prefix)

    def _field_label(self, r: Rule, m) -> str:
        """展示用字段标签（保留原样分隔符）。"""
        if r.field_group and r.field_group <= m.re.groups:
            return m.group(r.field_group)
        if r.replace_group and r.replace_group <= m.re.groups:
            g = r.replace_group
            return m.group(0)[: m.start(g) - m.start(0)].strip()
        return r.id

    def scan_field_candidates(
        self,
        in_path: str,
        encoding: str = "utf-8",
        on_progress: Optional[ProgressCb] = None,
    ) -> List["FieldCandidate"]:
        """扫描文件，按 (规则, 字段) 去重生成字段级候选清单。

        每个不同字段模式（如 user=、联系人:）生成一条候选，
        含前 5 个日志原文上下文样本与总命中次数。
        用于「确认后脱敏」模式：用户查看样本判断字段真伪后勾选。
        """
        import io
        agg: dict = {}
        total_bytes = _safe_size(in_path)
        with io.open(in_path, "rb") as fb, \
                io.TextIOWrapper(fb, encoding=encoding,
                                 errors="replace", newline="") as fin:
            for line in fin:
                for r in self.rules:
                    # 仅 field_group>0 的规则参与字段确认（如 ch_name 动态
                    # 提取 key 名）。其他规则（phone/idcard/secret_kv 等）
                    # 无需确认、误报率低，照常自动脱敏。
                    if not (r.field_group and r.field_group > 0):
                        continue
                    pat = r.compile()
                    for m in pat.finditer(line):
                        g = r.replace_group
                        if g and g <= m.re.groups:
                            matched_val = m.group(g)
                        else:
                            matched_val = m.group(0)
                        if r.validator is not None and not r.validator(matched_val):
                            continue
                        fkey = self._field_key(r, m)
                        flabel = self._field_label(r, m)
                        agg_key = (r.id, fkey)
                        if agg_key not in agg:
                            agg[agg_key] = {
                                "rule_id": r.id,
                                "field_key": fkey,
                                "field_label": flabel,
                                "samples": [],
                                "count": 0,
                            }
                        entry = agg[agg_key]
                        entry["count"] += 1
                        if len(entry["samples"]) < 5:
                            ctx_start = max(0, m.start(0) - 15)
                            ctx_end = min(len(line), m.end(0) + 15)
                            entry["samples"].append(
                                line[ctx_start:ctx_end].strip())
                if on_progress is not None and total_bytes > 0:
                    on_progress(fb.tell(), total_bytes)
        if on_progress is not None and total_bytes > 0:
            on_progress(total_bytes, total_bytes)
        return [
            FieldCandidate(
                rule_id=e["rule_id"],
                field_key=e["field_key"],
                field_label=e["field_label"],
                samples=e["samples"],
                count=e["count"],
            )
            for e in agg.values()
        ]

    def mask_with_fields(
        self,
        in_path: str,
        out_path: str,
        confirmed_field_keys,
        encoding: str = "utf-8",
        on_progress: Optional[ProgressCb] = None,
    ) -> List[Hit]:
        """按确认字段集合脱敏文件。

        confirmed_field_keys 为字段标识集合（scan_field_candidates 返回的
        field_key），只脱敏集合内字段下的匹配，未确认字段保留原值。
        自定义敏感词替换不受字段确认影响，始终执行。
        """
        import io
        total: dict = {}
        total_bytes = _safe_size(in_path)
        with io.open(in_path, "rb") as fb, \
                io.TextIOWrapper(fb, encoding=encoding, errors="replace",
                                 newline="") as fin, \
                open(out_path, "w", encoding=encoding, newline="") as fout:
            for line in fin:
                masked, hits = self._mask_text_with_fields(
                    line, confirmed_field_keys)
                fout.write(masked)
                for h in hits:
                    total[h.rule_id] = total.get(h.rule_id, 0) + h.count
                if on_progress is not None and total_bytes > 0:
                    on_progress(fb.tell(), total_bytes)
        if on_progress is not None and total_bytes > 0:
            on_progress(total_bytes, total_bytes)
        return [Hit(k, v) for k, v in total.items()]

    def _mask_text_with_fields(self, text: str, confirmed_field_keys):
        """按确认字段集合脱敏一段文本。

        confirmed_field_keys 为 None 时等同 mask_text（全脱敏）。
        未确认字段保留原值（不拼接、不更新 last，自然保留）。
        自定义敏感词替换始终执行，不受字段确认影响。
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
                # 字段确认：仅对 field_group>0 的规则（如 ch_name）生效；
                # 其他规则（phone/idcard/secret_kv 等）无字段概念，照常脱敏。
                if (confirmed_field_keys is not None
                        and r.field_group and r.field_group <= m.re.groups):
                    fkey = self._field_key(r, m)
                    if fkey not in confirmed_field_keys:
                        continue
                if r.replace_group and r.replace_group <= m.re.groups:
                    g = r.replace_group
                    matched = m.group(g)
                    if r.validator is not None and not r.validator(matched):
                        continue
                    v_start, v_end = m.start(g), m.end(g)
                    out_parts.append(text[last:v_start])
                    out_parts.append(strat.apply(matched, r.id))
                    last = v_end
                else:
                    matched = m.group(0)
                    if r.validator is not None and not r.validator(matched):
                        continue
                    out_parts.append(text[last:start])
                    out_parts.append(strat.apply(matched, r.id))
                    last = end
                count += 1
            out_parts.append(text[last:])
            if count:
                text = "".join(out_parts)
                hits[r.id] = count
        # 自定义敏感词替换（始终执行，不受字段确认影响）
        for old, new in self.custom_replacements:
            if not old:
                continue
            n = text.count(old)
            if n:
                text = text.replace(old, new)
                hits["custom_replace"] = hits.get("custom_replace", 0) + n
        return text, [Hit(k, v) for k, v in hits.items() if v > 0]
