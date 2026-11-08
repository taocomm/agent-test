#!/usr/bin/env python3
"""doh-server.py — 本机假 DoH 解析器 + 假共享 CDN(测试专用,无害,只碰本机)

用法: doh-server.py <port> <cert.pem> <key.pem>

  POST /dns-query: 解析 DNS wire-format 查询,按 qname 返回 A 记录:
      qname 以 "ext." 开头 → 203.0.113.10(TEST-NET-3,不可路由,模拟白名单外目标)
      其余                → 127.0.0.1(模拟"C2 与白名单服务共用同一 CDN IP")
  GET  /任意       → 200 "shared-cdn-ok"(充当 CDN 的默认 vhost)

一个实例同时扮演"DoH 解析器"与"共享 CDN"两个角色——测试叙事里两者本来就是
同一个 IP,这正是 SNI 门要堵的场景:IP 门对它放行,域门只看 SNI/Host。
"""
import ssl
import struct
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def parse_qname_wire(msg):
    """返回 (qname 点分串, question 段结束偏移)"""
    labels = []
    i = 12
    while i < len(msg) and msg[i]:
        n = msg[i]
        labels.append(msg[i + 1:i + 1 + n].decode("latin1"))
        i += 1 + n
    return ".".join(labels), i + 1 + 4        # 跨过根 0 与 QTYPE/QCLASS


def build_response(query):
    qname, qend = parse_qname_wire(query)
    ip = b"\xcb\x00\x71\x0a" if qname.startswith("ext.") else b"\x7f\x00\x00\x01"
    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + ip   # 指针 0xC00C 指向 question
    return (query[:2] + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0)
            + query[12:qend] + ans)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        resp = build_response(self.rfile.read(n))
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):
        body = b"shared-cdn-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("[doh-server] " + (fmt % args) + "\n")


def main():
    port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    sys.stderr.write(f"[doh-server] ready 127.0.0.1:{port}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
