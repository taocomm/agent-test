#!/usr/bin/env python3
"""hub — 集中收事件、按 session 出时间线。仅标准库 + sqlite。

    python3 hub/hub.py --port 8765 --db fabric.db

API:
    POST /ingest   body: {"events":[{...}, ...]}            → 204
    GET  /timeline?session=X&limit=200                      → JSON(按 ts 排序)
    GET  /health                                            → {"ok":true}
    GET  /chain                                             → 链账本状态(--chain 时)
    GET  /                                                  → 网页查看器

--chain PATH(07 号接生产流,2026-11-08):每条入库事件同步追加进 07 号
SHA-256 哈希链账本(v2 格式,ts 入哈希)。启动时对已有账本全量重算验算,
破损即拒绝启动(fail-closed);追加逐条 flush+fsync。防单机改账:账本副本
+ seal 交另一台机/ outbox(chainlog/verify.py --seal-file + --seal-key),
hub 机上重写账本(含链合法重写)与外部封存点核对即暴露。
"""
import argparse
import html
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = "fabric.db"
CHAIN_PATH = None       # --chain 时为账本路径;None = 不接链,行为与旧版逐字节一致
_chain_seq = 0
_chain_prev = None
_chain_fh = None
_step2 = None

# 07 号链数学单源(sibling playbook);只在 --chain 时才需要存在

def _chainlog_dir():
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))),
        "07-evidence-chain", "chainlog")


def init_chain(path):
    global CHAIN_PATH, _chain_seq, _chain_prev, _chain_fh, _step2
    d = _chainlog_dir()
    if not os.path.isdir(d):
        print(f"hub: 找不到 07 号 chainlog({d}),--chain 不可用", file=sys.stderr)
        sys.exit(2)
    sys.path.insert(0, d)
    from chain_tee import GENESIS, step, step2  # noqa: E402
    _step2 = step2
    _chain_seq, _chain_prev = 0, GENESIS
    if os.path.exists(path):
        # 启动全量验算:seq 连续/prev 链接/hash 重算,破损拒绝启动(fail-closed)
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    print(f"hub: 账本 {path}:{lineno} 非 JSON,拒绝启动", file=sys.stderr)
                    sys.exit(2)
                if rec.get("seq") != _chain_seq + 1 or rec.get("prev") != _chain_prev:
                    print(f"hub: 账本 {path}:{lineno} 链结构破损,拒绝启动", file=sys.stderr)
                    sys.exit(2)
                if rec.get("v") == 2:
                    exp = step2(_chain_prev, str(rec.get("ts")), rec.get("data"))
                else:
                    exp = step(_chain_prev, rec.get("data"))
                if rec.get("hash") != exp:
                    print(f"hub: 账本 {path}:{lineno} hash 失配,拒绝启动", file=sys.stderr)
                    sys.exit(2)
                _chain_seq, _chain_prev = rec["seq"], rec["hash"]
        print(f"hub: 账本续接 {path}(seq={_chain_seq},head={_chain_prev[:16]}…)",
              file=sys.stderr)
    _chain_fh = open(path, "a", encoding="utf-8")
    CHAIN_PATH = path


def chain_append(e):
    """每条入库事件同步入链;逐条 flush+fsync(证据级耐久)。"""
    global _chain_seq, _chain_prev
    _chain_seq += 1
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    h = _step2(_chain_prev, ts, e)
    rec = {"v": 2, "seq": _chain_seq, "ts": ts,
           "prev": _chain_prev, "hash": h, "data": e}
    _chain_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    _chain_fh.flush()
    os.fsync(_chain_fh.fileno())
    _chain_prev = h


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL, session TEXT NOT NULL, ts TEXT NOT NULL,
        type TEXT NOT NULL, pid INTEGER, payload TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON events(session, ts)")
    return conn


class Handler(BaseHTTPRequestHandler):
    server_version = "agent-fabric/0.1"

    def log_message(self, *a):  # 静默访问日志
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if urlparse(self.path).path != "/ingest":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            batch = json.loads(self.rfile.read(n) or b"{}").get("events", [])
        except (ValueError, json.JSONDecodeError) as e:
            return self._send(400, {"error": f"bad json: {e}"})
        rows = []
        for e in batch:
            rows.append((str(e.get("host", "?")), str(e.get("session", "?")),
                         str(e.get("ts", "")), str(e.get("type", "raw")),
                         e.get("pid"), json.dumps(e, ensure_ascii=False)))
        with db() as conn:
            conn.executemany(
                "INSERT INTO events(host,session,ts,type,pid,payload) VALUES(?,?,?,?,?,?)", rows)
        if CHAIN_PATH:
            for e in batch:
                chain_append(e)
        self._send(204, b"")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            return self._send(200, {"ok": True})
        if u.path == "/timeline":
            q = parse_qs(u.query)
            session = (q.get("session") or [""])[0]
            limit = min(int((q.get("limit") or ["200"])[0]), 5000)
            if not session:
                return self._send(400, {"error": "need ?session="})
            with db() as conn:
                rows = conn.execute(
                    "SELECT host,session,ts,type,pid,payload FROM events "
                    "WHERE session=? ORDER BY ts LIMIT ?", (session, limit)).fetchall()
            return self._send(200, {"session": session, "count": len(rows),
                                    "events": [json.loads(r[5]) for r in rows]})
        if u.path == "/chain":
            if not CHAIN_PATH:
                return self._send(404, {"error": "chain disabled (start with --chain)"})
            return self._send(200, {"path": CHAIN_PATH, "seq": _chain_seq,
                                    "head": _chain_prev})
        if u.path == "/":
            return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
        self._send(404, {"error": "not found"})


INDEX_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>agent fabric</title>
<style>body{font-family:ui-monospace,monospace;background:#111;color:#ddd;margin:2em}
input,button{font:inherit;background:#222;color:#ddd;border:1px solid #444;padding:.3em .6em}
table{border-collapse:collapse;margin-top:1em;width:100%}
td,th{border:1px solid #333;padding:.25em .6em;text-align:left;font-size:.9em}
td.host{color:#7ec8ff}td.net{color:#ffd479}td.exec{color:#ff9d9d}td.llm{color:#b59dff}
#meta{color:#888;margin-top:.5em}</style></head><body>
<h2>agent 行为 fabric — 跨主机时间线</h2>
<form onsubmit="load();return false">
<input id="s" size="40" placeholder="AGENT_SESSION_ID(uuid)">
<button>查时间线</button></form>
<div id="meta"></div><div id="out"></div>
<script>
async function load(){
 const s=document.getElementById('s').value.trim();
 const r=await fetch('/timeline?session='+encodeURIComponent(s));
 const j=await r.json();
 document.getElementById('meta').textContent=`session ${j.session} · ${j.count} 事件 · ${[...new Set(j.events.map(e=>e.host))].length} 台主机`;
 let h='<table><tr><th>ts</th><th>host</th><th>type</th><th>pid</th><th>详情</th></tr>';
 for(const e of j.events){
  const d=[e.comm,e.argv,e.path,e.dst,e.host&&e.type=='llm'?e.host+' '+e.model:'']
    .filter(Boolean).join(' ');
  h+=`<tr><td>${e.ts}</td><td class="host">${e.host}</td><td class="${e.type}">${e.type}</td><td>${e.pid??''}</td><td>${d}</td></tr>`;}
 document.getElementById('out').innerHTML=h+'</table>';}
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="fabric.db")
    ap.add_argument("--chain", default="",
                    help="07 号链账本路径(每条入库事件同步入链;不设则不接链)")
    a = ap.parse_args()
    global DB_PATH
    DB_PATH = a.db
    if a.chain:
        init_chain(a.chain)
    srv = HTTPServer(("127.0.0.1", a.port), Handler)
    print(f"hub listening http://127.0.0.1:{a.port} (db={a.db})", file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
