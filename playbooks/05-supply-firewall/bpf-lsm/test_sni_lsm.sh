#!/usr/bin/env bash
# test_sni_lsm.sh — 05 安装期防火墙 BPF LSM 模式 SNI 域门 E2E(VM 专用:root + bcc + 6.12)
#
# 对偶 preload 侧 test_fw.sh 场景组 I(共享 CDN 死角),在内核侧闭环:
#   L1  curl(OpenSSL 系)白名单 SNI 正向:200 + sni allow 行
#   L2  curl 未申报 SNI(IP 已在白名单=共享 CDN 形态):ClientHello 出不了门
#       → 客户端失败 + sni deny + send 拦发行 + 服务端零请求
#   L3  node(自带 OpenSSL,--sni-bin 挂 SSL_ctrl)白名单 SNI 正向
#   L4  node 未申报 SNI → 拦发(40 轮定案的 preload 对 node/npm 盲区,此处闭环);
#       失败形态 = ClientHello 被拦后握手停摆 → 客户端超时(拦截有效但不瞬时);
#       comm 断言用 MainThread(node 主线程 pthread_setname_np,非 node)
#   L4b npm run 生命周期脚本形态(leaf=node,验证 fork 继承 + node 钩子)
#   L5  python(_ssl → libssl.so.3)未申报 SNI → 拦发;正向对照
#   L6  范围对照:不经 install_fw 的同动作畅通(圈外零影响)
#   L7  IP 门回归:--sni 不开,白名单外 connect EPERM(十轮四联判定不回退)
#   L8/L9 GnuTLS fixture(gnutls_server_name_set uprobe):deny/allow 捕获行
#
# 运行:bash test_sni_lsm.sh   (每例独立 load BPF + 独立证据文件,~10s/例)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d /tmp/fw-lsm-sni.XXXXXX)
PASS=0 FAIL=0 SKIP=0 SRV=""

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  ok   $name"; PASS=$((PASS+1))
  else
    echo "  FAIL $name"; FAIL=$((FAIL+1))
  fi
}
skip() { echo "  SKIP $1"; SKIP=$((SKIP+1)); }

cleanup() {
  [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
  pkill -f 'doh-server.py 8443' 2>/dev/null
  [ "${KEEP_E2E_WORK:-}" = "1" ] || rm -rf "$WORK"   # CI 置 1 保留证据目录供 artifact 上传
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "需要 root(bcc/LSM)"; exit 1; }
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY

IFW="python3 $ROOT/bpf-lsm/install_fw.py"
NODE_BIN=$(command -v node 2>/dev/null || true)

# ---- 公共:自签证书 + 假共享 CDN(TLS;GET 任意路径 → 200 shared-cdn-ok)----
if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP 全部:无 openssl CLI,生成不了自签证书"; exit 0
fi
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
  -days 2 -nodes -subj "/CN=shared-cdn" 2>/dev/null
python3 "$ROOT/demo/doh-server.py" 8443 "$WORK/c.pem" "$WORK/k.pem" \
  2> "$WORK/server.log" & SRV=$!
for _ in $(seq 1 50); do
  grep -q ready "$WORK/server.log" 2>/dev/null && break
  sleep 0.2
done
grep -q ready "$WORK/server.log" || { echo "SKIP 全部:本地 TLS 服务起不来"; exit 0; }

# 白名单:IP 一条(共享 CDN 形态)+ 域名一条(无法解析也必须进 SNI 哈希,考"域门不依赖 DNS")
ALLOW="$WORK/allow.txt"
printf '127.0.0.1/32\nallowed.internal\n' > "$ALLOW"

echo "== 场景组 L:BPF LSM SNI 域门(共享 CDN 形态) =="

# L1 curl 正向
timeout 25 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l1.jsonl" --sni -- \
  curl -sk --resolve allowed.internal:8443:127.0.0.1 https://allowed.internal:8443/tag-l1 \
  > "$WORK/l1.out" 2>&1
check "L1 curl 白名单 SNI → 共享 CDN 应答 200" grep -q shared-cdn-ok "$WORK/l1.out"
check "L1' sni allow 证据行" \
  grep -q '"event":"sni","action":"allow","host":"allowed.internal"' "$WORK/ev-l1.jsonl"
check "L1\" 服务端见到请求" grep -q 'GET /tag-l1' "$WORK/server.log"

# L2 curl 拒(共享 CDN IP 白名单内,仅 SNI 不在)
rc=0
timeout 25 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l2.jsonl" --sni -- \
  curl -sk --resolve evil.internal:8443:127.0.0.1 https://evil.internal:8443/tag-l2 \
  > "$WORK/l2.out" 2>&1 || rc=$?
check "L2 未申报 SNI(共享 CDN IP 已批)→ 客户端失败" test "$rc" -ne 0
check "L2' sni deny 证据行" \
  grep -q '"event":"sni","action":"deny","host":"evil.internal"' "$WORK/ev-l2.jsonl"
check "L2\" send 拦发证据行(note=bpf-lsm-sni-gate)" \
  grep -q '"event":"send","action":"deny".*"note":"bpf-lsm-sni-gate"' "$WORK/ev-l2.jsonl"
check "L2³ 服务端零请求(ClientHello 未出门)" bash -c "! grep -q 'GET /tag-l2' '$WORK/server.log'"

# L3/L4 node(自带 OpenSSL;npm 生命周期脚本同运行时)
if [ -n "$NODE_BIN" ]; then
  cat > "$WORK/nget.js" <<'EOF'
const https = require('https');
const [tag, sni] = [process.argv[2], process.argv[3]];
const req = https.get({ host: '127.0.0.1', port: 8443, path: '/' + tag,
  servername: sni, rejectUnauthorized: false, timeout: 5000 },
  res => { let b = ''; res.on('data', d => b += d);
           res.on('end', () => { console.log('BODY:' + b); process.exit(0); }); });
req.on('timeout', () => req.destroy(new Error('timeout')));
req.on('error', e => { console.log('ERR:' + e.message); process.exit(1); });
EOF
  timeout 30 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l3.jsonl" --sni --sni-bin "$NODE_BIN" -- \
    node "$WORK/nget.js" tag-l3 allowed.internal > "$WORK/l3.out" 2>&1
  check "L3 node 白名单 SNI → 200" grep -q 'BODY:shared-cdn-ok' "$WORK/l3.out"
  check "L3' node 侧 sni allow 行(自带 SSL_ctrl 命中,comm=MainThread)" \
    grep -q '"comm":"MainThread","event":"sni","action":"allow"' "$WORK/ev-l3.jsonl"
  check "L3\" 服务端见到 node 请求" grep -q 'GET /tag-l3' "$WORK/server.log"

  rc=0
  timeout 30 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l4.jsonl" --sni --sni-bin "$NODE_BIN" -- \
    node "$WORK/nget.js" tag-l4 evil.internal > "$WORK/l4.out" 2>&1 || rc=$?
  check "L4 node 未申报 SNI → 失败" test "$rc" -ne 0
  check "L4' sni deny(comm=MainThread)" \
    grep -q '"comm":"MainThread","event":"sni","action":"deny","host":"evil.internal"' "$WORK/ev-l4.jsonl"
  check "L4\" send 拦发行" grep -q '"event":"send","action":"deny"' "$WORK/ev-l4.jsonl"
  check "L4³ 服务端零请求" bash -c "! grep -q 'GET /tag-l4' '$WORK/server.log'"

  # L4b npm run 生命周期脚本形态(免 registry:scripts 直接跑本地 client)
  if command -v npm >/dev/null 2>&1; then
    mkdir -p "$WORK/pkg"
    cat > "$WORK/pkg/package.json" <<EOF
{ "name": "lsm-sni-probe", "version": "1.0.0",
  "scripts": { "phone-home": "node nget.js tag-l4b evil.internal" } }
EOF
    cp "$WORK/nget.js" "$WORK/pkg/"
    rc=0
    (cd "$WORK/pkg" && timeout 40 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l4b.jsonl" \
      --sni --sni-bin "$NODE_BIN" -- npm run --silent phone-home) \
      > "$WORK/l4b.out" 2>&1 || rc=$?
    check "L4b npm 生命周期脚本形态 → 失败" test "$rc" -ne 0
    check "L4b' sni deny(leaf node,经 npm→sh→node 谱系)" \
      grep -q '"comm":"MainThread","event":"sni","action":"deny","host":"evil.internal"' "$WORK/ev-l4b.jsonl"
    check "L4b\" 服务端零请求" bash -c "! grep -q 'GET /tag-l4b' '$WORK/server.log'"
  else
    skip "L4b(无 npm)"
  fi
else
  skip "L3/L4/L4b(无 node)"
fi

# L5 python(_ssl 动态链 libssl.so.3)
cat > "$WORK/psni.py" <<'EOF'
import socket, ssl, sys
tag, sni = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 8443), timeout=6),
                        server_hostname=sni)
    s.sendall(f"GET /{tag} HTTP/1.0\r\nHost: {sni}\r\n\r\n".encode())
    data = b""
    while True:                      # 读到 EOF:recv(200) 只够响应头部,body 在外
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    data = data.decode(errors="replace")
    print("BODY-OK" if "shared-cdn-ok" in data else "BODY-BAD")
    sys.exit(0)
except Exception as e:
    print("ERR:" + type(e).__name__)
    sys.exit(1)
EOF
rc=0
timeout 25 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l5.jsonl" --sni -- \
  python3 "$WORK/psni.py" tag-l5 evil.internal > "$WORK/l5.out" 2>&1 || rc=$?
check "L5 python 未申报 SNI → 失败" test "$rc" -ne 0
check "L5' sni deny(comm=python3)" \
  grep -q '"comm":"python3","event":"sni","action":"deny","host":"evil.internal"' "$WORK/ev-l5.jsonl"
check "L5\" 服务端零请求" bash -c "! grep -q 'GET /tag-l5' '$WORK/server.log'"

timeout 25 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l5b.jsonl" --sni -- \
  python3 "$WORK/psni.py" tag-l5b allowed.internal > "$WORK/l5b.out" 2>&1
check "L5b python 白名单 SNI → 200 正向对照" grep -q BODY-OK "$WORK/l5b.out"

# L6 范围对照:圈外同动作畅通
curl -sk --resolve evil.internal:8443:127.0.0.1 https://evil.internal:8443/tag-l6 \
  > "$WORK/l6.out" 2>&1
check "L6 圈外同动作畅通(范围对照)" grep -q shared-cdn-ok "$WORK/l6.out"
check "L6' 服务端见到圈外请求" grep -q 'GET /tag-l6' "$WORK/server.log"

# L7 IP 门回归(--sni 不开,行为与二轮逐字节同族)
rc=0
timeout 20 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l7.jsonl" -- \
  curl -s --max-time 8 http://203.0.113.10/ > "$WORK/l7.out" 2>&1 || rc=$?
check "L7 IP 门回归:白名单外 connect EPERM(curl exit 7)" test "$rc" -eq 7
check "L7' connect deny 证据行" \
  grep -q '"event":"connect","action":"deny","dst":"203.0.113.10' "$WORK/ev-l7.jsonl"

# L8/L9 GnuTLS fixture(只考 SNI 捕获行;拦发路径与 OpenSSL 同 poison map,L2 已证)
if ls /usr/lib/x86_64-linux-gnu/libgnutls.so.30 >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
  cat > "$WORK/gsns.c" <<'EOF'
#include <stdio.h>
#include <string.h>
int gnutls_init(void **session, unsigned int flags);
int gnutls_server_name_set(void *session, int type, const void *name, size_t namelen);
int main(int argc, char **argv) {
    void *s = 0;
    int r1 = gnutls_init(&s, 1);                                      /* GNUTLS_CLIENT */
    int r2 = gnutls_server_name_set(s, 0, argv[1], strlen(argv[1]));  /* GNUTLS_NAME_DNS */
    printf("gnutls init=%d sns=%d\n", r1, r2);
    return 0;
}
EOF
  if gcc -O2 -Wall -o "$WORK/gsns" "$WORK/gsns.c" -Wl,-l:libgnutls.so.30 2>/dev/null; then
    timeout 25 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l8.jsonl" --sni -- \
      "$WORK/gsns" evil.internal > "$WORK/l8.out" 2>&1
    check "L8 GnuTLS 路径 sni deny 捕获行" \
      grep -q '"event":"sni","action":"deny","host":"evil.internal"' "$WORK/ev-l8.jsonl"
    timeout 25 $IFW --allow "$ALLOW" --evidence "$WORK/ev-l9.jsonl" --sni -- \
      "$WORK/gsns" allowed.internal > "$WORK/l9.out" 2>&1
    check "L9 GnuTLS 路径 sni allow 捕获行" \
      grep -q '"event":"sni","action":"allow","host":"allowed.internal"' "$WORK/ev-l9.jsonl"
  else
    skip "L8/L9(libgnutls 链接失败)"
  fi
else
  skip "L8/L9(无 libgnutls.so.30 或 gcc)"
fi

echo
if [ "${KEEP_E2E_WORK:-}" = "1" ]; then
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP  E2E_WORK=$WORK"
else
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP  (workdir 已清)"
fi
[ "$FAIL" -eq 0 ]
