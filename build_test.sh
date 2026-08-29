#!/usr/bin/env bash
# 日志脱敏工具全量测试脚本
# 用法: bash build_test.sh [bench_size_mb]
#   不带参数: 只跑单元测试
#   带参数:   单元测试 + 性能基准(指定 MB 数, 如 100)
set -e

PY="${PYTHON:-python}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "=================================================="
echo "[1/2] 单元测试 (pytest)"
echo "=================================================="
"$PY" -m pytest tests/test_rules.py tests/test_engine.py -v

if [ -n "$1" ]; then
    echo ""
    echo "=================================================="
    echo "[2/2] 性能基准 (${1}MB)"
    echo "=================================================="
    "$PY" tests/bench_large.py "$1"
fi

echo ""
echo "全部测试完成"
