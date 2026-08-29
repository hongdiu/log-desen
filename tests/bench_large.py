"""大文件性能基准测试。

生成约 500MB 日志文件（含敏感数据），测试脱敏耗时与内存占用，
用于评估 1G/几个 G 日志的处理可行性。
"""
import os
import sys
import time
import tempfile
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from log_desensitizer.engine import Engine
from log_desensitizer.rules import builtin_rules

LINE_TEMPLATE = (
    "2026-08-29 10:00:00 INFO req={req} user=1381234{phone:07d} "
    "id=1101011990030{id:05d}78574 card=4111111111111111 "
    "mail=user{mail}@example.com ip=192.168.{ip}.1 "
    "token=ghp_12345678901234567890123456789012 password=secret{pwd} "
    "desc=内部项目代号ProjectX session=eyJhbGci.payload.sig\n"
)


def gen(path, target_bytes):
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        written = 0
        while written < target_bytes:
            m = n % 100000
            f.write(LINE_TEMPLATE.format(
                req=m, phone=m, id=m, mail=m, ip=m % 255, pwd=m))
            written += 200  # 近似行长
            n += 1
    return n


def main():
    target_mb = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "big.log")
    out = os.path.join(tmp, "big.masked.log")

    print("生成测试文件 {0}MB ...".format(target_mb))
    t0 = time.time()
    lines = gen(src, target_mb * 1024 * 1024)
    size = os.path.getsize(src)
    print("  生成完成: {0:.1f}MB, {1} 行, 耗时 {2:.1f}s".format(
        size / 1024 / 1024, lines, time.time() - t0))

    eng = Engine(builtin_rules())
    print("开始脱敏 ...")
    tracemalloc.start()
    t1 = time.time()
    hits = eng.mask_file(src, out)
    elapsed = time.time() - t1
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    out_size = os.path.getsize(out)
    total_hits = sum(h.count for h in hits)
    print("=" * 50)
    print("脱敏耗时: {0:.2f}s ({1:.1f}MB/s)".format(
        elapsed, size / 1024 / 1024 / elapsed))
    print("输入: {0:.1f}MB -> 输出: {1:.1f}MB".format(
        size / 1024 / 1024, out_size / 1024 / 1024))
    print("命中: {0} 处, 规则: {1}".format(
        total_hits, [(h.rule_id, h.count) for h in hits]))
    print("内存峰值: {0:.1f}MB (当前 {1:.1f}MB)".format(
        peak / 1024 / 1024, cur / 1024 / 1024))
    print("=" * 50)
    print("推算 1GB: ~{0:.0f}s, 5GB: ~{1:.0f}s".format(
        elapsed * 1024 / (size / 1024 / 1024) * 1,
        elapsed * 1024 / (size / 1024 / 1024) * 5))

    os.remove(src)
    os.remove(out)
    os.rmdir(tmp)


if __name__ == "__main__":
    main()
