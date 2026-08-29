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
        ttk.Label(self, text="日志脱敏工具", style="Title.TLabel").pack(
            anchor="w", padx=16, pady=(16, 0))
        ttk.Label(self, text="选择日志文件，一键脱敏后安全发给厂商",
                  style="Muted.TLabel").pack(anchor="w", padx=16, pady=(0, 10))

        file_frame = ttk.Frame(self)
        file_frame.pack(fill="x", padx=16, pady=8)
        ttk.Button(file_frame, text="选择文件", command=self._pick_file).pack(side="left")
        ttk.Button(file_frame, text="选择目录(批量)", command=self._pick_dir).pack(
            side="left", padx=(8, 0))
        ttk.Label(file_frame, textvariable=self.path_var,
                  style="Muted.TLabel").pack(side="left", padx=12)

        strat_frame = ttk.Frame(self)
        strat_frame.pack(fill="x", padx=16, pady=8)
        ttk.Label(strat_frame, text="脱敏策略：").pack(side="left")
        for text, val in [("掩码保留首尾", "mask"), ("Hash关联", "hash"),
                          ("彻底替换", "redact")]:
            ttk.Radiobutton(strat_frame, text=text, variable=self.strategy_var,
                            value=val).pack(side="left", padx=(8, 0))

        custom_frame = ttk.Frame(self)
        custom_frame.pack(fill="x", padx=16, pady=8)
        ttk.Label(custom_frame, text="自定义规则(JSON，可选)：").pack(side="left")
        ttk.Button(custom_frame, text="选择规则文件",
                   command=self._pick_custom).pack(side="left", padx=(8, 0))
        self.custom_label = ttk.Label(custom_frame, text="无", style="Muted.TLabel")
        self.custom_label.pack(side="left", padx=12)

        ttk.Label(self, text="内置规则（可勾选/取消）：").pack(anchor="w", padx=16, pady=(8, 4))
        rules_frame = ttk.Frame(self)
        rules_frame.pack(fill="x", padx=16)
        ids = rule_ids()
        for i, rid in enumerate(ids):
            r, c = divmod(i, 4)
            ttk.Checkbutton(rules_frame, text=rid,
                            variable=self.rule_vars[rid]).grid(
                row=r, column=c, sticky="w", padx=6, pady=4)
        for c in range(4):
            rules_frame.columnconfigure(c, weight=1)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=(12, 4))
        ttk.Button(btn_frame, text="扫描敏感信息",
                   command=self._scan).pack(side="left", padx=16)
        ttk.Button(btn_frame, text="一键脱敏", style="Accent.TButton",
                   command=self._mask).pack(side="left")

        ttk.Label(self, text="命中清单：").pack(anchor="w", padx=16, pady=(8, 2))
        self.tree = ttk.Treeview(self, columns=("rule", "count"),
                                 show="headings", height=10)
        self.tree.heading("rule", text="规则")
        self.tree.heading("count", text="命中数")
        self.tree.column("rule", width=260)
        self.tree.column("count", width=120)
        self.tree.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self, textvariable=self.status_var,
                  style="Muted.TLabel").pack(anchor="w", padx=16, pady=(0, 12))

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

    def _engine(self) -> Engine:
        rules = all_rules(self.custom_path) if self.custom_path else builtin_rules()
        enabled = []
        for r in rules:
            v = self.rule_vars.get(r.id)
            if v is None:          # 自定义规则默认启用
                enabled.append(r)
            elif v.get():          # 内置规则按勾选
                enabled.append(r)
        return Engine(enabled, _build_strategy(self.strategy_var.get()))

    def _run_async(self, task, done_msg: str = "完成"):
        self.status_var.set("处理中…")

        def worker():
            try:
                task()
            except Exception as e:  # noqa: BLE001
                self.after(0, lambda: messagebox.showerror("出错", str(e)))
                self.after(0, lambda: self.status_var.set("出错"))
                return
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
                hits = eng.scan_file(path)
            else:
                agg = {}
                for name in os.listdir(path):
                    fp = os.path.join(path, name)
                    if os.path.isfile(fp):
                        for h in eng.scan_file(fp):
                            agg[h.rule_id] = agg.get(h.rule_id, 0) + h.count
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
                hits = eng.mask_file(path, out)
            else:
                out = os.path.join(path, "desensitized")
                res = eng.mask_dir(path, out)
                agg = {}
                for fhits in res.values():
                    for h in fhits:
                        agg[h.rule_id] = agg.get(h.rule_id, 0) + h.count
                hits = [Hit(k, v) for k, v in agg.items()]
            self._out_path = out
            self.after(0, lambda: self._show_hits(hits))
            self.after(0, lambda: messagebox.showinfo("完成", "已输出到：\n" + out))

        self._run_async(task, "脱敏完成 → " + getattr(self, "_out_path", ""))

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
