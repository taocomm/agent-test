#!/usr/bin/env bash
# 07-evidence-chain 测试:合成事件全流程 + 03 号真数据往返 + 判伪三连
set -Eeuo pipefail
BASE="$(cd "$(dirname "$0")/.." && pwd)"
CHAIN="$BASE/chainlog/chain_tee.py"
VERIFY="$BASE/chainlog/verify.py"
PASS=0 FAIL=0
D="$(mktemp -d /tmp/chain-test-XXXXXX)"
trap 'rm -rf "$D"' EXIT

ok()  { PASS=$((PASS + 1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "== A) 合成事件:接链/验链/无损往返 =="
for i in 1 2 3 4 5 6 7 8; do
    printf '{"seq_id":%d,"event":"file_write","path":"/tmp/f%d"}\n' "$i" "$i"
done | python3 "$CHAIN" > "$D/a.chained.jsonl" 2>"$D/a.err"
python3 "$VERIFY" "$D/a.chained.jsonl" 2>/dev/null && ok "验链通过" \
    || bad "验链失败"
for i in 1 2 3 4 5 6 7 8; do
    printf '{"seq_id":%d,"event":"file_write","path":"/tmp/f%d"}\n' "$i" "$i"
done > "$D/a.orig.jsonl"
python3 "$VERIFY" "$D/a.chained.jsonl" --unwrap > "$D/a.roundtrip.jsonl" \
    2>/dev/null
# unwrap 对 JSON 行是语义还原(键序/空白可与原文不同),raw 行逐字节还原
if python3 - "$D/a.orig.jsonl" "$D/a.roundtrip.jsonl" <<'EOF'
import json, sys
def load(p):
    out = []
    for l in open(p, encoding="utf-8"):
        l = l.strip()
        if not l:
            continue
        try:
            out.append(("j", json.loads(l)))
        except json.JSONDecodeError:
            out.append(("r", l))
    return out
sys.exit(0 if load(sys.argv[1]) == load(sys.argv[2]) else 1)
EOF
then
    ok "unwrap 往返语义一致"
else
    bad "unwrap 往返有损"
fi
grep -q "__chainraw__" "$D/a.chained.jsonl" \
    && bad "合法 JSON 不应落 raw" || ok "合法 JSON 原样进 data"

echo "== B) 非 JSON 行落 raw 兜底 =="
printf 'Attaching 3 probes\n{"event":"exec","cmd":"ls"}\n\nnot json either\n' \
    | python3 "$CHAIN" > "$D/b.chained.jsonl" 2>/dev/null
python3 "$VERIFY" "$D/b.chained.jsonl" 2>/dev/null && ok "杂行/空行也能成链" \
    || bad "非 JSON 行处理失败"
[ "$(python3 "$VERIFY" "$D/b.chained.jsonl" --unwrap 2>/dev/null | wc -l)" -eq 3 ] \
    && ok "unwrap 还原 3 条原行(空行已剥)" || bad "unwrap 行数不对"

echo "== C) 03 号真数据:events.jsonl 全量接链 =="
REAL=/home/agent_codex/wk09/playbooks/03-run-ledger/runs/strace-20261104-005629/events.jsonl
if [ -f "$REAL" ]; then
    python3 "$CHAIN" < "$REAL" > "$D/real.chained.jsonl" 2>"$D/real.err"
    n_real=$(grep -c . "$REAL" || true)
    n_chain=$(grep -c . "$D/real.chained.jsonl" || true)
    [ "$n_real" -eq "$n_chain" ] && ok "真数据 $n_real 条全部入链" \
        || bad "入链条数不符 $n_real vs $n_chain"
    python3 "$VERIFY" "$D/real.chained.jsonl" 2>/dev/null \
        && ok "真数据链验证通过" || bad "真数据链验证失败"
    python3 "$VERIFY" "$D/real.chained.jsonl" --unwrap 2>/dev/null \
        > "$D/real.roundtrip.jsonl"
    if python3 - "$REAL" "$D/real.roundtrip.jsonl" <<'EOF'
import json, sys
def load(p):
    out = []
    for l in open(p, encoding="utf-8"):
        l = l.strip()
        if not l:
            continue
        try:
            out.append(("j", json.loads(l)))
        except json.JSONDecodeError:
            out.append(("r", l))
    return out
sys.exit(0 if load(sys.argv[1]) == load(sys.argv[2]) else 1)
EOF
    then
        ok "真数据往返语义一致"
    else
        bad "真数据往返有损"
    fi
else
    bad "找不到 03 号真数据($REAL),跳过 C 组"
fi

echo "== D) 判伪三连(改字/删行/封存后加行)==="
if bash "$BASE/demo/tamper_demo.sh" > "$D/demo.log" 2>&1; then
    ok "tamper_demo 全流程符合预期"
else
    bad "tamper_demo 失败:"; tail -5 "$D/demo.log"
fi
grep -q '改第 3 行' "$D/demo.log" && grep -q '✅ 判伪演示全部符合预期' "$D/demo.log" \
    && ok "演示日志完整" || bad "演示日志不完整"

echo "== E) seal 升级:外部封存点 + HMAC 签名(2026-11-08 接生产流)==="
head -4 "$D/a.chained.jsonl" > "$D/e.chained.jsonl"
KEY="$D/key.hex"; printf '%s' "$(python3 -c 'import os;print(os.urandom(32).hex())')" > "$KEY"
# E1 签名 seal:写 seal 带 mac
python3 "$VERIFY" "$D/e.chained.jsonl" --seal --seal-key "$KEY" 2>/dev/null
check_e1() { python3 -c "import json,sys;s=json.load(open('$D/e.chained.jsonl.seal.json'));sys.exit(0 if 'mac' in s else 1)"; }
check_e1 && ok "E1 签名封存点含 mac" || bad "E1 seal 无 mac"
# E2 正向核验(带密钥)
python3 "$VERIFY" "$D/e.chained.jsonl" --check-seal --seal-key "$KEY" 2>/dev/null \
    && ok "E2 签名 seal 正向核验过" || bad "E2 签名 seal 核验失败"
# E3 fail-closed:带 mac 的 seal 不给密钥 → exit 2
rc3=0; python3 "$VERIFY" "$D/e.chained.jsonl" --check-seal 2>/dev/null || rc3=$?
[ "$rc3" -eq 2 ] && ok "E3 带 mac 的 seal 无密钥核验 exit 2(fail-closed)" \
    || bad "E3 期望 exit 2,实得 $rc3"
# E4 错钥 → exit 1
printf '%s' "$(python3 -c 'import os;print(os.urandom(32).hex())')" > "$D/wrong.hex"
python3 "$VERIFY" "$D/e.chained.jsonl" --check-seal --seal-key "$D/wrong.hex" 2>/dev/null \
    && bad "E4 错钥竟通过" || ok "E4 错钥被拒(exit $?)"
# E5 外部封存点(--seal-file):seal 写到别处(模拟 outbox/另一台机),同机改账抓得住
mkdir -p "$D/external"
python3 "$VERIFY" "$D/e.chained.jsonl" --seal --seal-file "$D/external/seal.json" \
    --seal-key "$KEY" 2>/dev/null
python3 "$VERIFY" "$D/e.chained.jsonl" --check-seal --seal-file "$D/external/seal.json" \
    --seal-key "$KEY" 2>/dev/null && ok "E5a 外部 seal 正向核验" || bad "E5a 外部 seal 核验失败"
printf '{"v":1,"seq":5,"data":{"event":"forged"}}\n' >> "$D/e.chained.jsonl"
python3 "$VERIFY" "$D/e.chained.jsonl" --check-seal --seal-file "$D/external/seal.json" \
    --seal-key "$KEY" 2>/dev/null && bad "E5b 改账后外部 seal 竟通过" \
    || ok "E5b 外部封存点抓住同机改账(链合法伪造也逃不掉)"
# E6 字节级 tripwire:语义不变的空白重写 → file_bytes 失配
head -4 "$D/a.chained.jsonl" > "$D/f.chained.jsonl"
python3 "$VERIFY" "$D/f.chained.jsonl" --seal 2>/dev/null
python3 - "$D/f.chained.jsonl" <<'EOF'
import json, sys
p = sys.argv[1]
# chain_tee 输出用默认分隔符(', ', ': '),改用紧凑分隔符才真的改变节字(非语义重写)
lines = [json.dumps(json.loads(l), ensure_ascii=False, separators=(",", ":")) + "\n" for l in open(p, encoding="utf-8")]
open(p, "w", encoding="utf-8").writelines(lines)
EOF
python3 "$VERIFY" "$D/f.chained.jsonl" 2>/dev/null \
    && ok "E6a 空白重写验链仍过(语义无损)" || bad "E6a 空白重写竟破坏验链"
python3 "$VERIFY" "$D/f.chained.jsonl" --check-seal 2>/dev/null \
    && bad "E6b 字节 tripwire 未报" \
    || ok "E6b 封存点抓住非语义字节改动(file_bytes 失配)"
# E7 无密钥的老式 seal 回归(向后兼容)
head -4 "$D/a.chained.jsonl" > "$D/g.chained.jsonl"
python3 "$VERIFY" "$D/g.chained.jsonl" --seal 2>/dev/null
python3 "$VERIFY" "$D/g.chained.jsonl" --check-seal 2>/dev/null \
    && ok "E7 旧式无签名 seal 回归通过" || bad "E7 旧式 seal 被破坏"

# E8 v2 格式:链记录 ts 改写(等长、语义不变字节量)被验链抓出 —— v1 盲点已关
head -4 "$D/a.chained.jsonl" > "$D/h.chained.jsonl"
python3 - "$D/h.chained.jsonl" <<'EOF'
import json, sys
p = sys.argv[1]
lines = []
for l in open(p, encoding="utf-8"):
    r = json.loads(l)
    r["ts"] = r["ts"].replace("2026-", "2099-")   # 等长改写,外层元数据不在 v1 哈希内
    lines.append(json.dumps(r, ensure_ascii=False) + "\n")
open(p, "w", encoding="utf-8").writelines(lines)
EOF
rc8=0; python3 "$VERIFY" "$D/h.chained.jsonl" 2>/dev/null || rc8=$?
[ "$rc8" -eq 1 ] && ok "E8 v2 链记录 ts 改写被验链抓出" || bad "E8 v2 ts 盲点仍在(rc=$rc8)"
# E9 v1 旧格式向后兼容(02 号世界 fixture 同构):step() 直建 v1 记录仍验得过
python3 - "$D/i.chained.jsonl" "$BASE/chainlog" <<'EOF'
import json, sys
sys.path.insert(0, sys.argv[2])
from chain_tee import GENESIS, step
prev, out = GENESIS, []
for i in range(1, 4):
    data = {"seq_id": i, "event": "legacy-v1"}
    rec = {"v": 1, "seq": i, "ts": "2026-11-05T00:00:00.000+00:00",
           "prev": prev, "hash": step(prev, data), "data": data}
    out.append(json.dumps(rec, ensure_ascii=False) + "\n")
    prev = rec["hash"]
open(sys.argv[1], "w").writelines(out)
EOF
python3 "$VERIFY" "$D/i.chained.jsonl" 2>/dev/null \
    && ok "E9 v1 旧格式验链兼容(02 号世界不受影响)" || bad "E9 v1 兼容被破坏"

echo
echo "== F) 非对称 seal:RSA-PKCS#1v1.5-SHA256,sealer ≠ verifier(2026-11-08)=="
if command -v openssl >/dev/null; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$D/priv.pem" 2>/dev/null
  openssl pkey -in "$D/priv.pem" -pubout -out "$D/pub.pem" 2>/dev/null
  openssl pkey -in "$D/priv.pem" -traditional -out "$D/priv-pkcs1.pem" 2>/dev/null
  head -4 "$D/a.chained.jsonl" > "$D/r.chained.jsonl"
  # F1 签发(PKCS#8 私钥):seal 含 sig_alg+sig、无 mac
  python3 "$VERIFY" "$D/r.chained.jsonl" --seal --seal-priv "$D/priv.pem" 2>/dev/null
  python3 -c "import json,sys;s=json.load(open('$D/r.chained.jsonl.seal.json'));sys.exit(0 if s.get('sig_alg')=='rsa-sha256-pkcs1v15' and 'sig' in s and 'mac' not in s else 1)" \
      && ok "F1 RSA seal 含 sig_alg/sig 且与 HMAC 互斥" || bad "F1 seal 字段不符"
  # F2 正向核验(公钥)
  python3 "$VERIFY" "$D/r.chained.jsonl" --check-seal --seal-pub "$D/pub.pem" 2>/dev/null \
      && ok "F2 RSA seal 公钥正向核验过" || bad "F2 RSA seal 核验失败"
  # F3 fail-closed:带 sig 的 seal 不给公钥 → exit 2
  rc3=0; python3 "$VERIFY" "$D/r.chained.jsonl" --check-seal 2>/dev/null || rc3=$?
  [ "$rc3" -eq 2 ] && ok "F3 带 sig 的 seal 无公钥核验 exit 2(fail-closed)" \
      || bad "F3 期望 exit 2,实得 $rc3"
  # F4 PKCS#1 传统形态私钥同构
  python3 "$VERIFY" "$D/r.chained.jsonl" --seal-file "$D/r2.seal.json" --seal \
      --seal-priv "$D/priv-pkcs1.pem" 2>/dev/null
  python3 "$VERIFY" "$D/r.chained.jsonl" --check-seal --seal-file "$D/r2.seal.json" \
      --seal-pub "$D/pub.pem" 2>/dev/null && ok "F4 PKCS#1 传统私钥同构可用" \
      || bad "F4 PKCS#1 形态失败"
  # F5 sig 翻一字节 → exit 1
  python3 - "$D" <<'EOF'
import json, base64, sys
p = sys.argv[1]
s = json.load(open(f"{p}/r.chained.jsonl.seal.json"))
b = bytearray(base64.b64decode(s["sig"])); b[10] ^= 1
s["sig"] = base64.b64encode(bytes(b)).decode()
json.dump(s, open(f"{p}/r-forged.seal.json", "w"))
EOF
  rc5=0; python3 "$VERIFY" "$D/r.chained.jsonl" --check-seal --seal-file "$D/r-forged.seal.json" --seal-pub "$D/pub.pem" 2>/dev/null || rc5=$?
  [ "$rc5" -eq 1 ] && ok "F5 sig 篒改一字节被拒" || bad "F5 期望 exit 1,实得 $rc5"
  # F6 错误公钥(另一对密钥)→ exit 1
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$D/priv2.pem" 2>/dev/null
  openssl pkey -in "$D/priv2.pem" -pubout -out "$D/pub2.pem" 2>/dev/null
  rc6=0; python3 "$VERIFY" "$D/r.chained.jsonl" --check-seal --seal-pub "$D/pub2.pem" 2>/dev/null || rc6=$?
  [ "$rc6" -eq 1 ] && ok "F6 错误公钥被拒" || bad "F6 期望 exit 1,实得 $rc6"
  # F7 改 seal 字段(last_hash)→ 签名失配
  python3 - "$D" <<'EOF'
import json, sys
p = sys.argv[1]
s = json.load(open(f"{p}/r.chained.jsonl.seal.json")); s["last_hash"] = "f" * 64
json.dump(s, open(f"{p}/r-field.seal.json", "w"))
EOF
  rc7=0; python3 "$VERIFY" "$D/r.chained.jsonl" --check-seal --seal-file "$D/r-field.seal.json" --seal-pub "$D/pub.pem" 2>/dev/null || rc7=$?
  [ "$rc7" -eq 1 ] && ok "F7 seal 字段篡改被签名抓住" || bad "F7 期望 exit 1,实得 $rc7"
  # F8 openssl 互操作:我们的签名是标准 PKCS#1v1.5(外部工具可验)
  python3 - "$D" "$BASE" <<'EOF'
import json, base64, sys
sys.path.insert(0, sys.argv[2] + "/chainlog")
import verify
s = json.load(open(f"{sys.argv[1]}/r.chained.jsonl.seal.json"))
open(f"{sys.argv[1]}/payload.bin", "wb").write(verify.seal_payload(s))
open(f"{sys.argv[1]}/sig.bin", "wb").write(base64.b64decode(s["sig"]))
EOF
  openssl dgst -sha256 -verify "$D/pub.pem" -signature "$D/sig.bin" "$D/payload.bin" >/dev/null 2>&1 \
      && ok "F8 openssl 互操作 Verified OK(标准签名格式)" || bad "F8 openssl 验签失败"
  # F9 互斥与误用:--seal-key 与 --seal-priv 同给 / --seal-priv 无 --seal
  rc9=0; python3 "$VERIFY" "$D/r.chained.jsonl" --seal --seal-key "$D/key.hex" --seal-priv "$D/priv.pem" 2>/dev/null || rc9=$?
  [ "$rc9" -eq 2 ] && ok "F9a 两通道同给 exit 2" || bad "F9a 期望 exit 2,实得 $rc9"
  rc9b=0; python3 "$VERIFY" "$D/r.chained.jsonl" --seal-priv "$D/priv.pem" 2>/dev/null || rc9b=$?
  [ "$rc9b" -eq 2 ] && ok "F9b --seal-priv 无 --seal exit 2" || bad "F9b 期望 exit 2,实得 $rc9b"
else
  echo "  SKIP: F 组(无 openssl CLI)"
fi

echo
echo "=== $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
