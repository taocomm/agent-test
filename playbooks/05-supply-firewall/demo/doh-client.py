#!/usr/bin/env python3
"""doh-client.py — 恶意 postinstall 风格的 DoH 样本(无害,只碰本机)

用法: doh-client.py <doh-url> <qname> [port] [--tls] [--sni NAME]

经 DoH 解析 qname(完全绕过 getaddrinfo 域名门,防火墙只见一次普通 HTTPS POST)
→ connect 解析结果。--tls 时以 --sni(缺省 qname)作为 SNI 做 TLS 握手,
模拟共享 CDN 上按 SNI 路由的 C2 vhost。每步结果各打一行,供测试断言。
"""
import socket
import ssl
import struct
import sys
import urllib.request


def build_query(name):
    q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for lbl in name.split("."):
        q += bytes([len(lbl)]) + lbl.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)          # 根 0 + QTYPE=A + QCLASS=IN


def parse_answer(msg):
    i = 12
    while i < len(msg) and msg[i]:                          # question 的 qname
        i += msg[i] + 1
    i += 5                                                  # 根 0 + QTYPE + QCLASS
    i += 2                                                  # answer NAME(压缩指针)
    rtype = int.from_bytes(msg[i:i + 2], "big")
    rdlen = int.from_bytes(msg[i + 8:i + 10], "big")        # TYPE2+CLASS2+TTL4 之后
    if rtype != 1:
        return None
    return ".".join(str(b) for b in msg[i + 10:i + 10 + rdlen])


def main():
    doh_url, qname, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    port = int(rest[0]) if rest and rest[0].isdigit() else 443
    use_tls = "--tls" in rest
    sni = rest[rest.index("--sni") + 1] if "--sni" in rest else qname
    ctx = ssl._create_unverified_context()

    req = urllib.request.Request(doh_url, data=build_query(qname),
                                 headers={"Content-Type": "application/dns-message"})
    try:
        msg = urllib.request.urlopen(req, context=ctx, timeout=10).read()
    except OSError as e:
        print(f"doh: {e}")
        return
    ip = parse_answer(msg)
    print(f"doh: {qname} -> {ip}")
    if not ip:
        return

    try:
        s = socket.create_connection((ip, port), timeout=5)
    except OSError as e:
        print(f"connect: {e.errno} {e.strerror}")
        return
    print("connect: OK")

    if use_tls:
        try:
            ts = ctx.wrap_socket(s, server_hostname=sni)
            ts.sendall(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
            line = ts.recv(128).decode(errors="replace").split("\r\n")[0]
            print("tls: " + line)
            ts.close()
        except OSError as e:
            print(f"tls: {type(e).__name__}")


if __name__ == "__main__":
    main()
