#!/usr/bin/env bash
# test_fw.sh — 安装期防火墙 E2E(无 root,LD_PRELOAD 模式)
# 场景:
#   A 白名单放行:benign 包 postinstall 连本机采集器(白名单内)→ 通,证据记 allow
#   B 白名单拦截:evil 包 postinstall 连本机 9999(白名单外)→ EPERM,域名 C2 掐在解析器
#   C 范围对照:同一动作不经 fw-run 直接跑 → 不受影响(防火墙只罩安装调用树)
#   D audit 模式:同 B 但只记不拦 → 连接真发生(ECONNREFUSED),证据记 audit-deny
#   E legacy 解析器家族:gethostbyname{,_r}(ctypes 直调 libc)/ getaddrinfo_a 同策略,
#     且解析结果进缓存喂 connect(DNS 刷新不误拒)
#   F cargo:build.rs 构建期外联(rustc 默认 glibc 动态链接,落在 preload 罩内)
#   G uv/pypi:setup.py 构建后端外联(构建后端 setuptools 预取走代理,防火墙内 --offline)
#   H 证据桥:ev.jsonl → fw2fabric → node → hub /timeline 全链路
#   I DoH 与共享 CDN IP:假 DoH 解析器 + 假共享 CDN(同 IP),SNI 门在 IP 门放行的
#     死角里拦 C2 vhost;FW_DOH=deny 强制拒已知解析器;curl --doh-url 真端到端
set -Eeuo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/fw05-e2e-XXXXXX)"
SRV_PID="" HUB_PID="" DOH_PID=""
PASS=0; FAIL=0

cleanup() {
  [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
  [[ -n "$HUB_PID" ]] && kill "$HUB_PID" 2>/dev/null || true
  [[ -n "$DOH_PID" ]] && kill "$DOH_PID" 2>/dev/null || true
  [[ "${KEEP_E2E_WORK:-}" = "1" ]] || rm -rf "$WORK"   # CI 置 1 保留证据目录供 artifact 上传
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check() { # check <描述> <命令...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
fw() { "$ROOT/shim/fw-run" "$@"; }

echo "== 0. 编译 shim"
gcc -O2 -Wall -Wextra -shared -fPIC -o "$WORK/fwshim.so" "$ROOT/shim/fwshim.c" -ldl -lpthread
export FW_SHIM="$WORK/fwshim.so"
ok "编译零告警"

echo "== 1. 起本机采集器(白名单内外的目标都在本机,测试不依赖外网)"
mkdir -p "$WORK/pub"
python3 -m http.server 8080 --bind 127.0.0.1 --directory "$WORK/pub" >/dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

npm_flags=(--no-audit --no-fund --offline --foreground-scripts --loglevel=error --cache "$WORK/.npmcache")
npm_pack() { npm pack "$1" --pack-destination "$WORK" 2>/dev/null | tail -1; }

# npm 11 默认不跑未批准脚本:先裸装一次(脚本被闸住,无副作用)拿 approve,清场;
# 真正带脚本的安装由各场景自己经 fw-run 执行。
npm_preflight_approve() { # <场景目录> <tarball> <pkg名>
  ( cd "$1" && npm install "${npm_flags[@]}" "$2" >/dev/null 2>&1 || true
    # npm <11.4 无 install-scripts 子命令(默认放行脚本,无需准入)→ 护栏防 set -e 中断;
    # 准入制 npm 上真实失败会在场景断言上以 FAIL 呈现
    npm install-scripts approve "$3" >/dev/null 2>&1 || true
    rm -rf node_modules package-lock.json )
}

echo "== 2. 场景A:白名单内放行(benign postinstall → 127.0.0.1:8080)"
printf 'registry.npmjs.org\nlocalhost\n127.0.0.1\n' > "$WORK/allow-a.txt"
mkdir -p "$WORK/a" && printf '{"name":"fw-a","version":"1.0.0"}\n' > "$WORK/a/package.json"
TGZ_A="$(npm_pack "$ROOT/demo/benign-pkg")"
npm_preflight_approve "$WORK/a" "$WORK/$TGZ_A" totally-benign
( cd "$WORK/a" && \
  fw --mode enforce --allow "$WORK/allow-a.txt" --evidence "$WORK/ev-a.jsonl" -- \
  npm install "${npm_flags[@]}" "$WORK/$TGZ_A" ) > "$WORK/a.out" 2>&1
check "A1 benign postinstall 拿到 HTTP 200" grep -q "collector HTTP 200" "$WORK/a.out"
check "A2 证据含 allow 127.0.0.1:8080" grep -q '"event":"connect","action":"allow","dst":"127.0.0.1:8080"' "$WORK/ev-a.jsonl"
if grep -q '"action":"deny"' "$WORK/ev-a.jsonl"; then bad "A3 场景A 无 deny(白名单放行闭环)"; else ok "A3 场景A 无 deny(白名单放行闭环)"; fi

echo "== 3. 场景B:白名单外拦截(evil postinstall → 127.0.0.1:9999 + c2.evil.example)"
mkdir -p "$WORK/b" && printf '{"name":"fw-b","version":"1.0.0"}\n' > "$WORK/b/package.json"
TGZ_B="$(npm_pack "$ROOT/demo/evil-pkg")"
npm_preflight_approve "$WORK/b" "$WORK/$TGZ_B" left-pad-pro
( cd "$WORK/b" && \
  fw --mode enforce --allow "$ROOT/allowlists/npm.txt" --evidence "$WORK/ev-b.jsonl" -- \
  npm install "${npm_flags[@]}" "$WORK/$TGZ_B" ) > "$WORK/b.out" 2>&1
check "B1 evil postinstall 的 connect 得 EPERM(而非 ECONNREFUSED)" grep -q "c2 connect: EPERM" "$WORK/b.out"
check "B2 evil postinstall 的 resolve 得 ENOTFOUND(掐在解析器)" grep -q "resolve c2: ENOTFOUND" "$WORK/b.out"
check "B3 证据含 deny 127.0.0.1:9999" grep -q '"event":"connect","action":"deny","dst":"127.0.0.1:9999"' "$WORK/ev-b.jsonl"
check "B4 证据含 resolve deny c2.evil.example" grep -q '"event":"resolve","action":"deny"' "$WORK/ev-b.jsonl" && grep -q '"host":"c2.evil.example"' "$WORK/ev-b.jsonl"
check "B5 安装整体 exit 0(拦的是网,不是流程)" test -d "$WORK/b/node_modules/left-pad-pro"

echo "== 4. 场景C:范围对照(不经 fw-run,同样动作畅通)"
node -e "require('http').get('http://127.0.0.1:8080/',r=>{console.log('HTTP',r.statusCode);process.exit(0)}).on('error',e=>{console.log('ERR',e.code);process.exit(1)})" > "$WORK/c.out" 2>&1
check "C1 无防火墙时 127.0.0.1:8080 正常 200(防火墙非系统级)" grep -q "HTTP 200" "$WORK/c.out"

echo "== 5. 场景D:audit 模式(同 B,只记不拦)"
mkdir -p "$WORK/d" && printf '{"name":"fw-d","version":"1.0.0"}\n' > "$WORK/d/package.json"
npm_preflight_approve "$WORK/d" "$WORK/$TGZ_B" left-pad-pro
( cd "$WORK/d" && \
  fw --mode audit --allow "$ROOT/allowlists/npm.txt" --evidence "$WORK/ev-d.jsonl" -- \
  npm install "${npm_flags[@]}" "$WORK/$TGZ_B" ) > "$WORK/d.out" 2>&1
check "D1 audit 下 evil connect 真发生(ECONNREFUSED 而非 EPERM)" grep -q "c2 connect: ECONNREFUSED" "$WORK/d.out"
check "D2 证据记 audit-deny 127.0.0.1:9999" grep -q '"event":"connect","action":"audit-deny","dst":"127.0.0.1:9999"' "$WORK/ev-d.jsonl"

echo "== 6. 场景E:legacy 解析器家族(gethostbyname 家族 / getaddrinfo_a)"
# Python3.13 的 socket.gethostbyname 内部走 getaddrinfo,要验 legacy 钩子必须 ctypes 直调 libc
legacy_block='
import ctypes
libc = ctypes.CDLL(None)
libc.gethostbyname.restype = ctypes.c_void_p
h = libc.gethostbyname(b"example.com")
print("ghbn:", "NULL(blocked)" if not h else "OK")'
fw --mode enforce --allow "$ROOT/allowlists/npm.txt" --evidence "$WORK/ev-e1.jsonl" -- \
  python3 -c "$legacy_block" > "$WORK/e1.out" 2>&1
check "E1 gethostbyname 未申报域名掐在解析器(NULL + h_errno)" grep -q "ghbn: NULL" "$WORK/e1.out"
check "E1' 证据 note=legacy-resolver" grep -q '"action":"deny","dst":"","host":"example.com","note":"legacy-resolver"' "$WORK/ev-e1.jsonl"

legacy_cache='
import ctypes, socket
libc = ctypes.CDLL(None)
libc.gethostbyname.restype = ctypes.c_void_p
h = libc.gethostbyname(b"localhost")
print("ghbn:", "OK" if h else "NULL")
try:
    socket.create_connection(("127.0.0.1", 9999), timeout=2); print("connect: OK")
except OSError as e: print("connect:", e.errno, e.strerror)'
printf 'localhost\n' > "$WORK/allow-e2.txt"
fw --mode enforce --allow "$WORK/allow-e2.txt" --evidence "$WORK/ev-e2.jsonl" -- \
  python3 -c "$legacy_cache" > "$WORK/e2.out" 2>&1
check "E2 legacy 解析结果进缓存 → 裸 IP connect 放行(ECONNREFUSED 非 EPERM)" \
  grep -q "connect: 111 Connection refused" "$WORK/e2.out"
check "E2' 证据含 connect allow 127.0.0.1:9999" grep -q '"event":"connect","action":"allow","dst":"127.0.0.1:9999"' "$WORK/ev-e2.jsonl"

legacy_r='
import ctypes
libc = ctypes.CDLL(None)
libc.gethostbyname_r.restype = ctypes.c_int
he = ctypes.create_string_buffer(512); buf = ctypes.create_string_buffer(1024)
res = ctypes.c_void_p(); err = ctypes.c_int()
r = libc.gethostbyname_r(b"example.com", he, buf, 1024, ctypes.byref(res), ctypes.byref(err))
print("ghbn_r ret:", r)'
fw --mode enforce --allow "$ROOT/allowlists/npm.txt" --evidence "$WORK/ev-e3.jsonl" -- \
  python3 -c "$legacy_r" > "$WORK/e3.out" 2>&1
check "E3 gethostbyname_r 同策略(ret=HOST_NOT_FOUND=1)" grep -q "ghbn_r ret: 1" "$WORK/e3.out"
check "E3' 证据 note=legacy-resolver" grep -q '"note":"legacy-resolver"' "$WORK/ev-e3.jsonl"

cat > "$WORK/gai_a.c" <<'EOF'
#define _GNU_SOURCE
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdio.h>
int main(int argc, char **argv) {
  struct gaicb req; struct gaicb *list[1] = { &req };
  memset(&req, 0, sizeof(req));
  req.ar_name = argv[1];
  if (argv[2][0] == 'w') {                     /* 同步路径:只验域名门 */
    int r = getaddrinfo_a(GAI_WAIT, list, 1, NULL);
    printf("gai_a ret=%d\n", r);
    return 0;
  }
  int r = getaddrinfo_a(GAI_NOWAIT, list, 1, NULL);
  if (r) { printf("gai_a ret=%d\n", r); return 0; }
  r = gai_suspend((const struct gaicb *const *)list, 1, NULL);
  if (r || !req.ar_result) { printf("gai_a suspend=%d result=none\n", r); return 0; }
  int fd = socket(req.ar_result->ai_family, SOCK_STREAM, 0);
  int c = connect(fd, req.ar_result->ai_addr, req.ar_result->ai_addrlen);
  printf("gai_a suspend=0 result=ok connect=%s\n", c == 0 ? "OK" : strerror(errno));
  return 0;
}
EOF
gcc -O2 -Wall -o "$WORK/gai_a" "$WORK/gai_a.c"
fw --mode enforce --allow "$ROOT/allowlists/npm.txt" --evidence "$WORK/ev-e4.jsonl" -- \
  "$WORK/gai_a" example.com w > "$WORK/e4.out" 2>&1
check "E4 getaddrinfo_a 未申报域名整批 EAI_NONAME(fail-closed)" grep -q "gai_a ret=-2" "$WORK/e4.out"
check "E4' 证据 note=getaddrinfo_a" grep -q '"note":"getaddrinfo_a"' "$WORK/ev-e4.jsonl"
fw --mode enforce --allow "$WORK/allow-e2.txt" --evidence "$WORK/ev-e5.jsonl" -- \
  "$WORK/gai_a" localhost a > "$WORK/e5.out" 2>&1
check "E5 getaddrinfo_a+gai_suspend 结果入缓存 → connect 放行(ECONNREFUSED)" \
  grep -q "suspend=0 result=ok connect=Connection refused" "$WORK/e5.out"

echo "== 7. 场景F:cargo build.rs 构建期外联(rustc 默认 glibc 动态链接,罩内)"
fw --mode enforce --allow "$ROOT/allowlists/cargo.txt" --evidence "$WORK/ev-f.jsonl" -- \
  cargo build --offline -vv --manifest-path "$ROOT/demo/cargo-evil/Cargo.toml" \
  --target-dir "$WORK/cargo-tgt" > "$WORK/f.out" 2>&1
check "F1 build.rs 的 connect 得 EPERM(os error 1)" grep -q "c2 connect: Operation not permitted" "$WORK/f.out"
check "F2 build.rs 的 resolve 掐在解析器" grep -q "c2 resolve: failed to lookup address information" "$WORK/f.out"
check "F3 证据含 deny 127.0.0.1:9999" grep -q '"event":"connect","action":"deny","dst":"127.0.0.1:9999"' "$WORK/ev-f.jsonl"
check "F4 证据 comm=build-script-bu(15字符截断,可回放定位)" grep -q '"comm":"build-script-bu"' "$WORK/ev-f.jsonl"
check "F5 构建产物照常生成(拦的是网,不是流程)" test -x "$WORK/cargo-tgt/debug/cargo-evil"

echo "== 8. 场景G:uv 源码包 setup.py(pypi 构建后端)外联"
# 构建后端 setuptools 预取走代理 = CI 镜像预装工具链(防火墙外);防火墙内 --offline 用缓存
if uv venv "$WORK/venv" --quiet >/dev/null 2>&1 \
   && https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 \
      uv pip install --python "$WORK/venv/bin/python" setuptools --quiet >/dev/null 2>&1; then
  fw --mode enforce --allow "$ROOT/allowlists/pypi.txt" --evidence "$WORK/ev-g.jsonl" -- \
    uv pip install --offline --python "$WORK/venv/bin/python" "$ROOT/demo/pypi-evil" \
    > "$WORK/g.out" 2>&1
  check "G1 恶意 sdist 的 resolve 掐在解析器(构建后端内)" \
    grep -q '"event":"resolve","action":"deny","dst":"","host":"c2.evil.example"' "$WORK/ev-g.jsonl"
  check "G2 恶意 sdist 的 connect 得 EPERM" \
    grep -q '"event":"connect","action":"deny","dst":"127.0.0.1:9999"' "$WORK/ev-g.jsonl"
  check "G3 安装整体完成(拦的是网,不是流程)" grep -q "Installed 1 package" "$WORK/g.out"
  if grep -q "cannot open allowlist" "$WORK/ev-g.jsonl"; then
    bad "G4 白名单相对路径经 fw-run 绝对化后构建后端内可读"
  else
    ok "G4 白名单相对路径经 fw-run 绝对化后构建后端内可读"
  fi
else
  echo "  SKIP: 场景G(构建后端 setuptools 预取失败,需代理 7890)"
fi

echo "== 9. 场景H:证据 → 04-fabric(fw2fabric → node → hub)全链路"
python3 "$ROOT/../04-fabric/hub/hub.py" --port 8765 --db "$WORK/fabric.db" >/dev/null 2>&1 &
HUB_PID=$!
sleep 0.7
python3 "$ROOT/fabric/fw2fabric.py" --evidence "$WORK/ev-b.jsonl" \
  --out "$WORK/events.jsonl" --host ci-runner --session ci-e2e-1 >/dev/null 2>&1
python3 "$ROOT/../04-fabric/node/node.py" --hub http://127.0.0.1:8765 \
  --file "$WORK/events.jsonl" --host ci-runner --session ci-e2e-1 >/dev/null 2>&1
tl=$(curl -s "http://127.0.0.1:8765/timeline?session=ci-e2e-1")
check "H1 hub 时间线收到 net 事件(deny 连接)" \
  bash -c "echo '$tl' | grep -qE '\"type\": ?\"net\"' && echo '$tl' | grep -q '127.0.0.1:9999'"
check "H2 hub 时间线含被掐域名(qname 字段)" \
  bash -c "echo '$tl' | grep -q 'c2.evil.example'"
check "H3 host/session 归属正确(跨机可关联)" \
  bash -c "echo '$tl' | grep -qE '\"host\": ?\"ci-runner\"' && echo '$tl' | grep -qE '\"session\": ?\"ci-e2e-1\"'"

echo "== 10. 场景I:DoH 与共享 CDN IP(SNI 门)"
# 假 DoH 解析器 + 假共享 CDN 同一实例同一 IP(doh-server.py):IP 门对它放行,
# 域门只看 SNI —— 正是 preload 模式唯一拦不住的死角,现在由 SSL_ctrl/gnutls 钩子堵上。
if command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -keyout "$WORK/doh-key.pem" -out "$WORK/doh-cert.pem" \
    -days 2 -nodes -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
  python3 "$ROOT/demo/doh-server.py" 8443 "$WORK/doh-cert.pem" "$WORK/doh-key.pem" \
    > /dev/null 2>"$WORK/dohsrv.log" &
  DOH_PID=$!
  sleep 0.7
  DOH_URL=https://127.0.0.1:8443/dns-query
  CLI="$ROOT/demo/doh-client.py"
  printf '127.0.0.1\nallowed.example\n1.1.1.1\n' > "$WORK/allow-i.txt"

  # I1 DoH 解析器不在白名单:connect 层默认拒绝(enforce 下 DoH 不是出网绕过)
  fw --mode enforce --allow "$ROOT/allowlists/npm.txt" --evidence "$WORK/ev-i1.jsonl" -- \
    python3 "$CLI" "$DOH_URL" c2.evil.example > "$WORK/i1.out" 2>&1
  check "I1 DoH 解析器不在白名单 → connect EPERM(默认拒绝)" \
    grep -q '"event":"connect","action":"deny","dst":"127.0.0.1:8443"' "$WORK/ev-i1.jsonl"
  check "I1' 客户端见到 Operation not permitted" grep -q "Operation not permitted" "$WORK/i1.out"

  # I2 解析器白名单内:DoH 拿到白名单外目标 IP → connect 层照样拒
  # (DoH 只绕解析门,不绕出网门;证据里连 qname 都没有 —— 审计盲由打标补)
  fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i2.jsonl" -- \
    python3 "$CLI" "$DOH_URL" ext.c2.evil.example 443 > "$WORK/i2.out" 2>&1
  check "I2 DoH 解析成功但白名单外目标 connect EPERM" \
    grep -q '"event":"connect","action":"deny","dst":"203.0.113.10:443"' "$WORK/ev-i2.jsonl"
  check "I2' 客户端 connect: 1 Operation not permitted" \
    grep -q "connect: 1 Operation not permitted" "$WORK/i2.out"

  # I3 共享 CDN 死角:IP 门放行,C2 vhost 由 SNI 门拦死(OpenSSL 路径,shutdown 掐握手)
  fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i3.jsonl" -- \
    python3 "$CLI" "$DOH_URL" c2.evil.example 8443 --tls > "$WORK/i3.out" 2>&1
  check "I3 IP 门放行的共享 CDN 上,SNI 门拒未申报 C2 vhost" \
    grep -q '"event":"sni","action":"deny","dst":"127.0.0.1:8443","host":"c2.evil.example"' "$WORK/ev-i3.jsonl"
  check "I3' connect 已过、TLS 握手被连级重置(拒在应用层域门)" \
    bash -c "grep -q 'connect: OK' '$WORK/i3.out' && grep -q 'tls: ConnectionResetError' '$WORK/i3.out'"

  # I3b 正向对照:白名单内 SNI 正常走通 + sni allow 行
  fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i3b.jsonl" -- \
    python3 "$CLI" "$DOH_URL" c2.evil.example 8443 --tls --sni allowed.example > "$WORK/i3b.out" 2>&1
  check "I3b 白名单内 SNI 正常走通(HTTP 200)" grep -q "tls: HTTP/1.0 200 OK" "$WORK/i3b.out"
  check "I3b' 证据含 sni allow 行" \
    bash -c "grep -q '\"event\":\"sni\",\"action\":\"allow\"' '$WORK/ev-i3b.jsonl' && grep -q '\"host\":\"allowed.example\"' '$WORK/ev-i3b.jsonl'"

  # I4 FW_DOH=deny:进了白名单的 DoH 端点也强制拒(1.1.1.1 在 allow-i.txt 里)
  FW_DOH=deny fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i4.jsonl" -- \
    python3 -c "import socket
try: socket.create_connection(('1.1.1.1', 443), timeout=5); print('connected?!')
except OSError as e: print('connect:', e.errno, e.strerror)" > "$WORK/i4.out" 2>&1
  check "I4 FW_DOH=deny 下白名单内的已知 DoH 端点也被拒(note 打标)" \
    grep -q '"host":"1.1.1.1","note":"ip-literal,doh-endpoint"' "$WORK/ev-i4.jsonl"

  # I5 已知 DoH 域名解析:deny 行自带 doh-endpoint 打标(审计归因,不拦不误)
  fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i5.jsonl" -- \
    python3 -c "import socket
try: socket.getaddrinfo('dns.google', 443)
except OSError: pass" > /dev/null 2>&1
  check "I5 已知 DoH 域名 resolve deny 带 doh-endpoint 打标" \
    bash -c "grep -q '\"host\":\"dns.google\"' '$WORK/ev-i5.jsonl' && grep -q 'doh-endpoint' '$WORK/ev-i5.jsonl'"

  # I6 curl --doh-url 真端到端:DoH 解析全部成功,目标连接被 SNI 门掐
  # (curl 在 step1 设 SNI、step2 才 SSL_set_fd → 走待杀名单路径,SSL_set_fd 钩拦截)
  rc=0
  fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i6.jsonl" -- \
    curl -sk -o /dev/null --doh-url "$DOH_URL" --doh-insecure \
    https://c2.evil.example:8443/ > "$WORK/i6.out" 2>&1 || rc=$?
  check "I6 curl 真 DoH 端到端被 SNI 门掐(rc≠0)" test "$rc" -ne 0
  check "I6' 证据含 sni deny c2.evil.example(DoH qname 面外可见)" \
    bash -c "grep -q '\"event\":\"sni\",\"action\":\"deny\"' '$WORK/ev-i6.jsonl' && grep -q '\"host\":\"c2.evil.example\"' '$WORK/ev-i6.jsonl'"

  # I7 GnuTLS 同门:ctypes dlsym(handle) 绕过 interposition,必须 PLT 编译型 fixture
  if ls /usr/lib/x86_64-linux-gnu/libgnutls.so.30 >/dev/null 2>&1; then
    cat > "$WORK/gnutls_sns.c" <<'EOF'
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
    if gcc -O2 -Wall -o "$WORK/gnutls_sns" "$WORK/gnutls_sns.c" -Wl,-l:libgnutls.so.30 2>/dev/null; then
      fw --mode enforce --allow "$WORK/allow-i.txt" --evidence "$WORK/ev-i7.jsonl" -- \
        "$WORK/gnutls_sns" c2.evil.example > "$WORK/i7.out" 2>&1
      check "I7 GnuTLS 路径:SNI 拒设(sns=-1,SNI 不落 session)" grep -q "sns=-1" "$WORK/i7.out"
      check "I7' 证据 note=gnutls-sni-gate" \
        bash -c "grep -q '\"host\":\"c2.evil.example\"' '$WORK/ev-i7.jsonl' && grep -q '\"note\":\"gnutls-sni-gate\"' '$WORK/ev-i7.jsonl'"
    else
      echo "  SKIP: 场景I7(libgnutls 链接失败)"
    fi
  else
    echo "  SKIP: 场景I7(无 libgnutls.so.30)"
  fi

  # I8 桥:sni 事件 → canonical net(qname/dst 透传)
  python3 "$ROOT/fabric/fw2fabric.py" --evidence "$WORK/ev-i3.jsonl" \
    --out "$WORK/events-i.jsonl" --host ci-runner --session ci-e2e-1 >/dev/null 2>&1
  check "I8 fw2fabric 把 sni deny 转 canonical net(qname 在场)" \
    bash -c "grep -q '\"type\": \"net\"' '$WORK/events-i.jsonl' && grep -q 'c2.evil.example' '$WORK/events-i.jsonl'"

  kill "$DOH_PID" 2>/dev/null || true
  DOH_PID=""
else
  echo "  SKIP: 场景I(无 openssl CLI,生成不了自签证书)"
fi

echo "== J. 证据链(--chain,07 号接生产流):入链/封存/改账检出/rc 透传 =="
CHLOG="$ROOT/../07-evidence-chain/chainlog"
KEYJ="$WORK/fw-chain-key.hex"
printf '%s' "$(python3 -c 'import os;print(os.urandom(32).hex())')" > "$KEYJ"
# J1 audit 空白名单跑一条外联(127.0.0.1:9 拒连)→ 证据入链 + 封存
fw --mode audit --evidence "$WORK/ev-j.jsonl" --chain -- \
  bash -c 'curl -s -m 2 http://127.0.0.1:9/nope || true' >/dev/null 2>&1 || true
check "J1 证据链文件生成" test -f "$WORK/ev-j.jsonl.chained.jsonl"
check "J1' 封存点生成" test -f "$WORK/ev-j.jsonl.chained.jsonl.seal.json"
[ "$(grep -c . "$WORK/ev-j.jsonl" 2>/dev/null || echo 0)" -ge 1 ] \
  && ok "J1\" 证据非空(audit 记录拒连)" || bad "J1\" 证据为空"
check "J2 裸验链通过" python3 "$CHLOG/verify.py" "$WORK/ev-j.jsonl.chained.jsonl"
# J3 外部封存(HMAC)正向
python3 "$CHLOG/verify.py" "$WORK/ev-j.jsonl.chained.jsonl" --seal \
  --seal-file "$WORK/ext-j.seal.json" --seal-key "$KEYJ" >/dev/null 2>&1
check "J3 外部封存点(HMAC)正向核验" python3 "$CHLOG/verify.py" \
  "$WORK/ev-j.jsonl.chained.jsonl" --check-seal --seal-file "$WORK/ext-j.seal.json" --seal-key "$KEYJ"
# J4 改账被外部 seal 抓出
printf '{"event":"forged","note":"chain-invalid-appended"}\n' >> "$WORK/ev-j.jsonl.chained.jsonl"
rcj=0; python3 "$CHLOG/verify.py" "$WORK/ev-j.jsonl.chained.jsonl" --check-seal \
  --seal-file "$WORK/ext-j.seal.json" --seal-key "$KEYJ" >/dev/null 2>&1 || rcj=$?
[ "$rcj" -ne 0 ] && ok "J4 改账被外部封存点抓出(rc=$rcj)" || bad "J4 改账未被检出"
# J5 rc 透传 + 空证据入链(无出网事件也成链,seq 0)
rcj=0
fw --mode audit --evidence "$WORK/ev-j2.jsonl" --chain -- bash -c 'exit 3' >/dev/null 2>&1 || rcj=$?
[ "$rcj" -eq 3 ] && ok "J5 命令 rc 透传(3)" || bad "J5 rc 不透传(得 $rcj)"
check "J5' 空证据也成链" python3 "$CHLOG/verify.py" "$WORK/ev-j2.jsonl.chained.jsonl"

echo
echo "== 结果: $PASS passed, $FAIL failed(证据文件: $WORK/ev-*.jsonl)"
if [[ "${KEEP_E2E_WORK:-}" = "1" ]]; then echo "E2E_WORK=$WORK"; fi
[[ $FAIL -eq 0 ]]
