#!/usr/bin/env bash
# 跑全部测试。CI 与本地均可使用。
set -euo pipefail
cd "$(dirname "$0")"
python -m pip install -r requirements.txt
python -m pytest tests/ -v
