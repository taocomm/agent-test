#!/usr/bin/env python3
"""fw2fabric — 05 安装期防火墙证据 → 04-fabric 桥。

把 fw-run 的 JSONL 证据转成 canonical schema(04-fabric/schema/events.schema.json),
落盘给 node/node.py 上报,或直接 POST hub /ingest:

    fw2fabric.py --evidence ev.jsonl --out events.jsonl          # 转换落盘,交给 node.py
    fw2fabric.py --evidence ev.jsonl --hub http://127.0.0.1:8765 \
                 --host ci-runner --session ci-20261104-1        # 直接上报

映射:
  event=resolve|connect|sni → type=net(connect 对端进 dst;解析/SNI 申报的域名进 qname)
  event=session         → type=raw(start/end)
  fw 行的 action/note/comm/argv/pid/ppid 原样保留(hub 全量存 payload,可回放);
  fw 的 host 字段(被查询域名)改名 qname —— canonical 的 host 是"哪台机器"。
"""
import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone


def convert(fw, host, session):
    ev = fw.get("event")
    out = {
        "ts": datetime.fromtimestamp(fw["ts"] / 1000, tz=timezone.utc).isoformat(),
        "type": "net" if ev in ("resolve", "connect", "sni") else "raw",
        "host": host,
        "session": session,
        "pid": fw.get("pid"),
        "ppid": fw.get("ppid"),
        "comm": fw.get("comm"),
        "argv": fw.get("argv"),
        "fw_event": ev,
        "action": fw.get("action"),
        "note": fw.get("note"),
    }
    if ev == "connect":
        out["dst"] = fw.get("dst", "")
        if fw.get("host"):
            # LSM 模式 connect 证据带已解析域名(2026-11-06 起,install_fw.py enrich);
            # shim 的 connect 事件 host 恒空,不受影响
            out["qname"] = fw["host"]
    elif ev == "resolve":
        out["qname"] = fw.get("host", "")
    elif ev == "sni":
        out["qname"] = fw.get("host", "")
        if fw.get("dst"):
            out["dst"] = fw["dst"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out")
    ap.add_argument("--hub")
    ap.add_argument("--host", default="?")
    ap.add_argument("--session", required=True)
    a = ap.parse_args()
    if not a.out and not a.hub:
        ap.error("需要 --out 或 --hub 之一")

    events = []
    with open(a.evidence, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                fw = json.loads(line)
            except json.JSONDecodeError:
                print(f"[fw2fabric] 跳过坏行: {line[:80]}", file=sys.stderr)
                continue
            if "ts" not in fw or "event" not in fw:
                continue
            events.append(convert(fw, a.host, a.session))

    if a.out:
        with open(a.out, "w") as f:
            for e in events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
    if a.hub:
        req = urllib.request.Request(
            a.hub.rstrip("/") + "/ingest",
            data=json.dumps({"events": events}, ensure_ascii=False).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            if r.status != 204:
                print(f"[fw2fabric] hub 返回 {r.status}", file=sys.stderr)
    print(f"[fw2fabric] {len(events)} 条事件 ← {a.evidence}"
          f"{' → ' + a.out if a.out else ''}{' → ' + a.hub if a.hub else ''}", file=sys.stderr)


if __name__ == "__main__":
    main()
