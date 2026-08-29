"""Tkinter 图形界面。

面向非技术人员：选择日志文件 → 一键脱敏 → 输出可安全发给厂商的文件。
支持「扫描」模式（只报告敏感信息命中）与「脱敏」模式（替换并输出）。
入口：python -m log_desensitizer
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .engine import Engine, Hit
from .rules import all_rules, builtin_rules, rule_ids
from .strategies import HashStrategy, MaskStrategy, RedactStrategy


def _build_strategy(choice: str):
    if choice == "hash":
        return HashStrategy()
    if choice == "redact":
        return RedactStrategy()
    return MaskStrategy()


_RULE_HELP_TEXT = """自定义规则 JSON 格式说明

文件内容为 JSON 数组，每个元素是一条规则。

字段：
  id            规则标识（必填），用于命中清单显示与替换占位。
                例如 "myorder"、"internal_token"。
  pattern       正则表达式字符串（必填），用于匹配敏感内容。
                注意 JSON 字符串里的反斜杠需双写，如 \\d 写成 \\\\d。
  replace_group 整数（可选，默认 0）。
                0  = 整体脱敏（整个匹配替换掉）；
                >0 = 只脱敏该捕获组的值，其余部分原样保留。
                例如 (mysql)://user:(password)@host 想只脱敏密码，
                可把密码用括号包起来并设 replace_group=1。
  enabled       布尔（可选，默认 true）。是否启用此规则。

示例：
[
  {
    "id": "my_order",
    "pattern": "ORD\\\\d{10}",
    "replace_group": 0
  },
  {
    "id": "my_token",
    "pattern": "CT-[A-Za-z0-9]{20}"
  },
  {
    "id": "conn_pwd",
    "pattern": "(oracle|sqlserver)://[^:@]+:([^@]+)@",
    "replace_group": 2,
    "enabled": true
  }
]

说明：
- 自定义规则会追加到内置规则之后执行。
- 命中后按当前选择的脱敏策略（掩码/Hash/彻底替换）处理。
- 自定义规则默认启用，无需在内置规则勾选区勾选。
- 敏感词替换（GUI 上方"敏感词替换"区）与正则规则相互独立，
  在所有正则规则之后整体替换，适合精确关键词/敏感词替换。
"""


class _ConfirmDialog(tk.Toplevel):
    """字段级确认弹窗：展示日志原文样本，用户勾选要脱敏的字段。

    点击「勾选」列切换状态；看「日志原文样本」判断字段真伪，
    样本是地名/项目名则取消勾选。默认全勾，仅需取消误报项。
    """

    def __init__(self, master, candidates):
        super().__init__(master)
        self.title("确认脱敏字段")
        self.geometry("960x560")
        self.transient(master)
        self.grab_set()
        self._confirmed = None
        # field_key -> BooleanVar，默认全勾选（仅需取消误报项）
        self._checks = {
            c.field_key: tk.BooleanVar(value=True) for c in candidates
        }

        ttk.Label(
            self,
            text="勾选要脱敏的字段（看「日志原文样本」判断字段真伪，"
                 "样本是地名/项目名则取消勾选）",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=12, pady=(10, 6))

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        cols = ("check", "rule", "field", "samples", "count")
        self.tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings", height=22)
        self.tree.heading("check", text="勾选")
        self.tree.heading("rule", text="规则")
        self.tree.heading("field", text="字段")
        self.tree.heading("samples", text="日志原文样本（前3条）")
        self.tree.heading("count", text="命中数")
        self.tree.column("check", width=50, anchor="center", stretch=False)
        self.tree.column("rule", width=100, stretch=False)
        self.tree.column("field", width=140, stretch=False)
        self.tree.column("samples", width=520)
        self.tree.column("count", width=80, anchor="e", stretch=False)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        # 点击/双击「勾选」列切换状态
        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<Double-1>", self._on_click)

        for c in candidates:
            samples_str = " | ".join(c.samples[:3]) if c.samples else ""
            if len(samples_str) > 100:
                samples_str = samples_str[:100] + "…"
            checked = "☑" if self._checks[c.field_key].get() else "☐"
            self.tree.insert(
                "", "end", iid=c.field_key,
                values=(checked, c.rule_id, c.field_label, samples_str, c.count))

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=12, pady=(0, 12))
        ttk.Button(btn_frame, text="全选",
                   command=lambda: self._set_all(True)).pack(side="left")
        ttk.Button(btn_frame, text="全不选",
                   command=lambda: self._set_all(False)).pack(
                       side="left", padx=(8, 0))
        self._info_label = ttk.Label(btn_frame, text="", style="Muted.TLabel")
        self._info_label.pack(side="left", padx=(16, 0))
        ttk.Button(btn_frame, text="取消",
                   command=self._cancel).pack(side="right")
        ttk.Button(btn_frame, text="开始脱敏", style="Accent.TButton",
                   command=self._ok).pack(side="right", padx=(0, 8))
        self._update_info()

    def _on_click(self, event):
        col = self.tree.identify_column(event.x)
        if col != "#1":  # 只响应勾选列
            return
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        cur = self._checks[iid].get()
        self._checks[iid].set(not cur)
        self._refresh_row(iid)
        self._update_info()

    def _refresh_row(self, iid):
        vals = list(self.tree.item(iid, "values"))
        vals[0] = "☑" if self._checks[iid].get() else "☐"
        self.tree.item(iid, values=vals)

    def _set_all(self, val):
        for k, v in self._checks.items():
            v.set(val)
        for iid in self.tree.get_children():
            self._refresh_row(iid)
        self._update_info()

    def _update_info(self):
        n = sum(1 for v in self._checks.values() if v.get())
        total = len(self._checks)
        self._info_label.config(text="已勾选 {0}/{1} 个字段".format(n, total))

    def _ok(self):
        self._confirmed = {k for k, v in self._checks.items() if v.get()}
        self.destroy()

    def _cancel(self):
        self._confirmed = None
        self.destroy()

    def get_confirmed(self):
        return self._confirmed


class LogDesensitizerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("日志脱敏工具")
        self.geometry("780x680")
        self.minsize(640, 560)
        self._apply_style()

        self.current_path: Optional[str] = None
        self.path_type = "file"
        self.path_var = tk.StringVar(value="未选择")
        self.strategy_var = tk.StringVar(value="mask")
        self.custom_path: Optional[str] = None
        self.rule_vars = {rid: tk.BooleanVar(value=True) for rid in rule_ids()}
        self._out_path = ""

        self._build_ui()

    # ---------- 样式 ----------
    def _apply_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        bg = "#F7F7F8"
        accent = "#4B3FE3"
        self.configure(bg=bg)
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground="#171717",
                        font=("Microsoft YaHei", 11))
        style.configure("Title.TLabel", background=bg, foreground=accent,
                        font=("Microsoft YaHei", 18, "bold"))
        style.configure("Muted.TLabel", background=bg, foreground="#52525B",
                        font=("Microsoft YaHei", 10))
        style.configure("Accent.TButton", font=("Microsoft YaHei", 11, "bold"),
                        padding=10)
        style.map("Accent.TButton",
                  background=[("active", "#6054F1"), ("!disabled", accent)],
                  foreground=[("!disabled", "#FFFFFF")])
        style.configure("TButton", font=("Microsoft YaHei", 10), padding=8)
        style.configure("TCheckbutton", background=bg, foreground="#171717",
                        font=("Microsoft YaHei", 10))
        style.configure("TRadiobutton", background=bg, foreground="#171717",
                        font=("Microsoft YaHei", 10))
        style.configure("Treeview", background="#FFFFFF", foreground="#171717",
                        fieldbackground="#FFFFFF", font=("Microsoft YaHei", 10), rowheight=24)
        style.configure("Treeview.Heading", font=("Microsoft YaHei", 10, "bold"))

    # ---------- 布局 ----------
    def _build_ui(self):
        # 整体可滚动容器：窗口比屏幕短时，所有内容都能上下滚
        bg = "#F7F7F8"
        self._canvas = tk.Canvas(self, bg=bg, highlightthickness=0,
                                 borderwidth=0)
        vsb = ttk.Scrollbar(self, orient="vertical",
                            command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._inner = ttk.Frame(self._canvas, style="TFrame")
        self._inner_id = self._canvas.create_window(
            (0, 0), window=self._inner, anchor="nw")
        self._inner.bind(
            "<Configure>",
            lambda e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")))
        self._canvas.bind(
            "<Configure>",
            lambda e: self._canvas.itemconfig(
                self._inner_id, width=e.width))
        # 鼠标滚轮（Windows 用 Button-4/5）
        self._canvas.bind("<Enter>", self._bind_wheel)
        self._canvas.bind("<Leave>", self._unbind_wheel)

        ttk.Label(self._inner, text="日志脱敏工具",
                  style="Title.TLabel").pack(anchor="w", padx=16, pady=(16, 0))
        ttk.Label(self._inner, text="选择日志文件，一键脱敏后安全发给厂商",
                  style="Muted.TLabel").pack(anchor="w", padx=16, pady=(0, 10))

        file_frame = ttk.Frame(self._inner)
        file_frame.pack(fill="x", padx=16, pady=8)
        ttk.Button(file_frame, text="选择文件",
                   command=self._pick_file).pack(side="left")
        ttk.Button(file_frame, text="选择目录(批量)",
                   command=self._pick_dir).pack(side="left", padx=(8, 0))
        ttk.Label(file_frame, textvariable=self.path_var,
                  style="Muted.TLabel").pack(side="left", padx=12)

        strat_frame = ttk.Frame(self._inner)
        strat_frame.pack(fill="x", padx=16, pady=8)
        ttk.Label(strat_frame, text="脱敏策略：").pack(side="left")
        for text, val in [("掩码保留首尾", "mask"), ("Hash关联", "hash"),
                          ("彻底替换", "redact")]:
            ttk.Radiobutton(strat_frame, text=text, variable=self.strategy_var,
                            value=val).pack(side="left", padx=(8, 0))

        custom_frame = ttk.Frame(self._inner)
        custom_frame.pack(fill="x", padx=16, pady=8)
        ttk.Label(custom_frame, text="自定义规则(JSON，可选)：").pack(side="left")
        ttk.Button(custom_frame, text="选择规则文件",
                   command=self._pick_custom).pack(side="left", padx=(8, 0))
        ttk.Button(custom_frame, text="格式说明",
                   command=self._show_rule_help).pack(side="left", padx=(8, 0))
        self.custom_label = ttk.Label(custom_frame, text="无",
                                      style="Muted.TLabel")
        self.custom_label.pack(side="left", padx=12)

        # 自定义敏感词全局替换：用户指定"查找→替换为"对
        repl_frame = ttk.Frame(self._inner)
        repl_frame.pack(fill="x", padx=16, pady=8)
        ttk.Label(repl_frame, text="敏感词替换：").pack(side="left")
        ttk.Label(repl_frame, text="查找", style="Muted.TLabel").pack(
            side="left", padx=(8, 4))
        self.repl_find_var = tk.StringVar()
        ttk.Entry(repl_frame, textvariable=self.repl_find_var,
                  width=18).pack(side="left")
        ttk.Label(repl_frame, text="→", style="Muted.TLabel").pack(
            side="left", padx=(6, 4))
        self.repl_to_var = tk.StringVar()
        ttk.Entry(repl_frame, textvariable=self.repl_to_var,
                  width=18).pack(side="left")
        ttk.Button(repl_frame, text="添加",
                   command=self._add_replacement).pack(side="left", padx=(8, 0))
        self.repl_list = tk.Listbox(repl_frame, height=3,
                                   font=("Microsoft YaHei", 10))
        self.repl_list.pack(side="left", fill="x", expand=True, padx=(8, 0))
        ttk.Button(repl_frame, text="删除",
                   command=self._del_replacement).pack(side="left", padx=(6, 0))

        ttk.Label(self._inner, text="内置规则（可勾选/取消）：").pack(
            anchor="w", padx=16, pady=(8, 4))
        rules_frame = ttk.Frame(self._inner)
        rules_frame.pack(fill="x", padx=16)
        ids = rule_ids()
        for i, rid in enumerate(ids):
            r, c = divmod(i, 4)
            ttk.Checkbutton(rules_frame, text=rid,
                            variable=self.rule_vars[rid]).grid(
                row=r, column=c, sticky="w", padx=6, pady=4)
        for c in range(4):
            rules_frame.columnconfigure(c, weight=1)

        btn_frame = ttk.Frame(self._inner)
        btn_frame.pack(fill="x", pady=(12, 4))
        ttk.Button(btn_frame, text="扫描敏感信息",
                   command=self._scan).pack(side="left", padx=16)
        ttk.Button(btn_frame, text="一键脱敏", style="Accent.TButton",
                   command=self._mask).pack(side="left")
        ttk.Button(btn_frame, text="确认后脱敏",
                   command=self._confirm_mask).pack(side="left", padx=(8, 0))

        ttk.Label(self._inner, text="命中清单：").pack(
            anchor="w", padx=16, pady=(8, 2))
        tree_frame = ttk.Frame(self._inner)
        tree_frame.pack(fill="x", padx=16, pady=(0, 8))
        self.tree = ttk.Treeview(tree_frame, columns=("rule", "count"),
                                show="headings", height=10)
        self.tree.heading("rule", text="规则")
        self.tree.heading("count", text="命中数")
        self.tree.column("rule", width=260)
        self.tree.column("count", width=120)
        tree_vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                                 command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_vsb.set)
        tree_vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self._inner, textvariable=self.status_var,
                  style="Muted.TLabel").pack(anchor="w", padx=16, pady=(8, 2))
        # 进度条：扫描/脱敏时按字节或文件数反馈进度
        self.progress = ttk.Progressbar(self._inner, orient="horizontal",
                                        mode="determinate", length=400)
        self.progress.pack(fill="x", padx=16, pady=(0, 12))

    def _on_wheel(self, event):
        delta = -1 if event.delta > 0 else 1
        self._canvas.yview_scroll(delta, "units")

    def _bind_wheel(self, _event):
        self._canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _event):
        self._canvas.unbind_all("<MouseWheel>")

    # ---------- 事件 ----------
    def _pick_file(self):
        p = filedialog.askopenfilename(title="选择日志文件")
        if p:
            self.current_path = p
            self.path_type = "file"
            self.path_var.set(os.path.basename(p))

    def _pick_dir(self):
        p = filedialog.askdirectory(title="选择日志目录")
        if p:
            self.current_path = p
            self.path_type = "dir"
            self.path_var.set(os.path.basename(p) + "/ (目录)")

    def _pick_custom(self):
        p = filedialog.askopenfilename(title="选择自定义规则JSON",
                                       filetypes=[("JSON", "*.json")])
        if p:
            self.custom_path = p
            self.custom_label.config(text=os.path.basename(p))

    def _show_rule_help(self):
        """自定义规则 JSON 格式说明弹窗。"""
        win = tk.Toplevel(self)
        win.title("自定义规则 JSON 格式说明")
        win.geometry("680x520")
        win.transient(self)
        txt = tk.Text(win, wrap="word", font=("Microsoft YaHei", 10),
                      padx=16, pady=16)
        txt.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(win, command=txt.yview)
        sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set)
        txt.insert("1.0", _RULE_HELP_TEXT)
        txt.configure(state="disabled")

    def _add_replacement(self):
        find = self.repl_find_var.get()
        to = self.repl_to_var.get()
        if not find:
            messagebox.showinfo("提示", "请输入要查找的字符串")
            return
        self.repl_list.insert("end", "{0}  →  {1}".format(find, to))
        self.repl_find_var.set("")
        self.repl_to_var.set("")

    def _del_replacement(self):
        for idx in self.repl_list.curselection():
            self.repl_list.delete(idx)

    def _get_replacements(self):
        items = self.repl_list.get(0, "end")
        pairs = []
        for it in items:
            if "→" not in it:
                continue
            left, right = it.split("→", 1)
            pairs.append((left.strip(), right.strip()))
        return pairs

    def _engine(self) -> Engine:
        rules = all_rules(self.custom_path) if self.custom_path else builtin_rules()
        enabled = []
        for r in rules:
            v = self.rule_vars.get(r.id)
            if v is None:          # 自定义规则默认启用
                enabled.append(r)
            elif v.get():          # 内置规则按勾选
                enabled.append(r)
        return Engine(enabled, _build_strategy(self.strategy_var.get()),
                      custom_replacements=self._get_replacements())

    def _set_progress(self, cur, total):
        """工作线程通过 after 调用，更新进度条与状态文本。"""
        if total <= 0:
            return
        pct = int(cur * 100 / total)
        if pct > 100:
            pct = 100
        self.progress["value"] = pct
        self.status_var.set("处理中… {0}/{1}  ({2}%)".format(cur, total, pct))

    def _run_async(self, task, done_msg: str = "完成"):
        self.status_var.set("处理中…")
        self.progress["value"] = 0

        def worker():
            try:
                task()
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("出错", str(e)))
                self.after(0, lambda: self.status_var.set("出错"))
                return
            self.after(0, lambda: self.progress.configure(value=100))
            self.after(0, lambda: self.status_var.set(done_msg))

        threading.Thread(target=worker, daemon=True).start()

    def _scan(self):
        if not self.current_path:
            messagebox.showinfo("提示", "请先选择文件或目录")
            return
        eng = self._engine()
        path = self.current_path
        ptype = self.path_type

        def task():
            if ptype == "file":
                hits = eng.scan_file(
                    path, on_progress=lambda c, t: self.after(
                        0, lambda c=c, t=t: self._set_progress(c, t)))
            else:
                agg = {}
                files = [n for n in os.listdir(path)
                         if os.path.isfile(os.path.join(path, n))]
                total = len(files)
                for i, name in enumerate(files, 1):
                    fp = os.path.join(path, name)
                    for h in eng.scan_file(fp):
                        agg[h.rule_id] = agg.get(h.rule_id, 0) + h.count
                    self.after(0, lambda i=i, t=total: self._set_progress(i, t))
                hits = [Hit(k, v) for k, v in agg.items()]
            self.after(0, lambda: self._show_hits(hits))

        self._run_async(task, "扫描完成")

    def _mask(self):
        if not self.current_path:
            messagebox.showinfo("提示", "请先选择文件或目录")
            return
        eng = self._engine()
        path = self.current_path
        ptype = self.path_type

        def task():
            if ptype == "file":
                base, ext = os.path.splitext(path)
                out = base + ".masked" + ext
                hits = eng.mask_file(
                    path, out,
                    on_progress=lambda c, t: self.after(
                        0, lambda c=c, t=t: self._set_progress(c, t)))
            else:
                out = os.path.join(path, "desensitized")
                res = eng.mask_dir(
                    path, out,
                    on_progress=lambda c, t: self.after(
                        0, lambda c=c, t=t: self._set_progress(c, t)))
                agg = {}
                for fhits in res.values():
                    for h in fhits:
                        agg[h.rule_id] = agg.get(h.rule_id, 0) + h.count
                hits = [Hit(k, v) for k, v in agg.items()]
            self._out_path = out
            self.after(0, lambda: self._show_hits(hits))
            self.after(0, lambda: messagebox.showinfo("完成", "已输出到：\n" + out))

        self._run_async(task, "脱敏完成 → " + getattr(self, "_out_path", ""))

    def _confirm_mask(self):
        """确认后脱敏：扫描字段候选 → 弹窗确认 → 按勾选字段脱敏。

        流程：阶段1 扫描字段候选（按字段去重，每条含日志原文样本）→
        阶段2 弹 _ConfirmDialog 让用户看样本勾选字段 →
        阶段3 按确认字段集合调用 mask_with_fields 脱敏。
        """
        if not self.current_path:
            messagebox.showinfo("提示", "请先选择文件")
            return
        if self.path_type == "dir":
            messagebox.showinfo("提示", "确认后脱敏暂仅支持单文件")
            return
        eng = self._engine()
        path = self.current_path
        self.status_var.set("扫描字段中…")
        self.progress["value"] = 0

        def scan_worker():
            try:
                candidates = eng.scan_field_candidates(
                    path,
                    on_progress=lambda c, t: self.after(
                        0, lambda c=c, t=t: self._set_progress(c, t)))
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("出错", str(e)))
                self.after(0, lambda: self.status_var.set("出错"))
                return
            self.after(0, lambda: self._after_scan(candidates, eng, path))

        threading.Thread(target=scan_worker, daemon=True).start()

    def _after_scan(self, candidates, eng, path):
        """扫描完成后：弹确认窗，等用户勾选，再启动脱敏 worker。"""
        if not candidates:
            self.status_var.set("未发现可脱敏字段")
            messagebox.showinfo("提示", "未发现可脱敏字段")
            return
        self.status_var.set("等待确认…")
        dlg = _ConfirmDialog(self, candidates)
        self.wait_window(dlg)
        confirmed = dlg.get_confirmed()
        if not confirmed:
            self.status_var.set("已取消")
            return
        self.status_var.set("脱敏中…")
        self.progress["value"] = 0

        def mask_worker():
            try:
                base, ext = os.path.splitext(path)
                out = base + ".masked" + ext
                hits = eng.mask_with_fields(
                    path, out, confirmed,
                    on_progress=lambda c, t: self.after(
                        0, lambda c=c, t=t: self._set_progress(c, t)))
                self._out_path = out
                self.after(0, lambda: self._show_hits(hits))
                self.after(0, lambda: self.status_var.set(
                    "脱敏完成 → " + out))
                self.after(0, lambda: messagebox.showinfo(
                    "完成", "已输出到：\n" + out))
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("出错", str(e)))
                self.after(0, lambda: self.status_var.set("出错"))

        threading.Thread(target=mask_worker, daemon=True).start()

    def _show_hits(self, hits):
        for it in self.tree.get_children():
            self.tree.delete(it)
        if not hits:
            self.tree.insert("", "end", values=("（无敏感信息命中）", ""))
            return
        for h in hits:
            self.tree.insert("", "end", values=(h.rule_id, h.count))


def main():
    app = LogDesensitizerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
