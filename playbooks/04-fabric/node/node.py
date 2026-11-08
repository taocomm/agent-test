#!/usr/bin/env python3
"""node — 单机侧:tail 本机 events.jsonl,批量上报 hub。

    python3 node/node.py --hub http://127.0.0.1:8765 --host nodeA --file events.jsonl [--follow]

- 事件若缺 host/session 字段则用命令行值补齐(canonical schema 见 ../schema/);
- 默认读到 EOF 即退出(便于脚本化/测试);--follow 持续 tail(常驻);
- 每 --batch 条或 --interval 秒 flush 一次。
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.request


def post(hub, events, timeout=5):
    req = urllib.request.Request(
        hub.rstrip("/") + "/ingest",
        data=json.dumps({"events": events}, ensure_ascii=False).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--host", default=socket.gethostname())
    ap.add_argument("--session", default=os.environ.get("AGENT_SESSION_ID", "?"))
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--batch", type=int, default=50)
    a = ap.parse_args()

    buf = []
    last = time.time()

    def flush():
        nonlocal buf, last
        if buf:
            try:
                post(a.hub, buf)
                print(f"[node] 上报 {len(buf)} 条 → {a.hub}", file=sys.stderr)
                buf = []
            except urllib.error.URLError as e:
                print(f"[node] 上报失败,保留缓冲重试: {e}", file=sys.stderr)  # 不丢数据
        last = time.time()

    f = open(a.file, errors="replace")
    while True:
        line = f.readline()
        if line:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                e = {"type": "raw", "raw": line}
            e.setdefault("host", a.host)
            e.setdefault("session", a.session)
            e.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
            buf.append(e)
        elif not a.follow:
            flush()
            break
        if len(buf) >= a.batch or (buf and time.time() - last >= a.interval):
            flush()
        if not line and a.follow:
            time.sleep(0.5)
    print("[node] 文件读完,退出", file=sys.stderr)


if __name__ == "__main__":
    main()
