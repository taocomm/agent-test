#!/usr/bin/env python3
"""chain_tee — 把 stdin 的逐行事件接成 SHA-256 哈希链后输出。

任何事件生产者(03 号采集器、04 号 hub/node、05 号 fwshim 证据)套一层:

    <producer> ... | chain_tee.py > events.chained.jsonl

每行输出 = {"v","seq","ts","prev","hash","data"};data 是原行(合法 JSON
按 JSON 存,否则存 {"__chainraw__": 行}(保留键,不与业务 payload 撞))。
v2 格式(2026-11-08):hash = sha256(prev || "\n" || ts || "\n" ||
canonical_json(data))—— ts 入哈希,链记录元数据不可被静默改写(接线时
发现的 v1 盲点);v1(不含 ts)仅历史文件/02 号世界 fixture 保留,verify.py
按记录的 v 字段双格式验算。canonical = sort_keys + 紧凑分隔符,跨平台
重算稳定。空行跳过。验证/还原/封存见 verify.py。
"""
import hashlib
import json
import sys
from datetime import datetime, timezone

GENESIS = "0" * 64


def canonical(data) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def step(prev: str, data) -> str:
    """v1 链数学(不含 ts):保留给 02 号 seed_ledger 等既有单源调用方。"""
    return hashlib.sha256((prev + "\n" + canonical(data)).encode()).hexdigest()


def step2(prev: str, ts: str, data) -> str:
    """v2 链数学:ts 入哈希,链记录元数据不可被静默改写。"""
    return hashlib.sha256((prev + "\n" + ts + "\n" + canonical(data)).encode()).hexdigest()


def main():
    prev, seq = GENESIS, 0
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        seq += 1
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            data = {"__chainraw__": line}
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        h = step2(prev, ts, data)
        rec = {
            "v": 2,
            "seq": seq,
            "ts": ts,
            "prev": prev,
            "hash": h,
            "data": data,
        }
        sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
        prev = h
    print(f"[chain_tee] {seq} events chained, head={prev[:16]}…",
          file=sys.stderr)


if __name__ == "__main__":
    main()
