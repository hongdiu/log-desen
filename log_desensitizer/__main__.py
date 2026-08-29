"""模块入口：python -m log_desensitizer 启动 GUI。

兼容两种运行方式：
1) 作为包成员执行（python -m log_desensitizer 或 PyInstaller -m 入口）
   → 使用相对导入 from .gui import main
2) 作为顶层脚本执行（PyInstaller 老版本/直接 python __main__.py）
   → 无 known parent package，切换为绝对导入
"""

try:
    from .gui import main  # 方式 1
except (ImportError, ValueError):
    # 方式 2：相对导入失败，降级为绝对导入
    import os as _os
    import sys as _sys
    _here = _os.path.dirname(_os.path.abspath(__file__))
    _parent = _os.path.dirname(_here)
    if _parent not in _sys.path:
        _sys.path.insert(0, _parent)
    from log_desensitizer.gui import main  # type: ignore

if __name__ == "__main__":
    main()
