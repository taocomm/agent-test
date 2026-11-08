#!/usr/bin/env bash
# tamper_demo — 现场演示账本的判伪能力:改一个字节/删一行/封存后加一行,全都逃不掉
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CHAIN="$HERE/chainlog/chain_tee.py"
VERIFY="$HERE/chainlog/verify.py"
D="$(mktemp -d /tmp/chain-demo-XXXXXX)"
trap 'rm -rf "$D"' EXIT
cd "$D"

echo "== 1) 生成 5 条事件并接链 =="
for i in 1 2 3 4 5; do
    printf '{"event":"exec","cmd":"cmd-%d"}\n' "$i"
done | python3 "$CHAIN" > events.chained.jsonl
python3 "$VERIFY" events.chained.jsonl

echo "== 2) 还原原事件流(无损往返)==="
python3 "$VERIFY" events.chained.jsonl --unwrap > unwrapped.jsonl
diff <(for i in 1 2 3 4 5; do printf '{"event":"exec","cmd":"cmd-%d"}\n' "$i"; done) \
     unwrapped.jsonl && echo "✅ 往返一致"

echo "== 3) 改第 3 行 payload 一个字符 =="
python3 - events.chained.jsonl <<'EOF'
import json, sys
p = sys.argv[1]
lines = open(p).readlines()
r = json.loads(lines[2]); r["data"]["cmd"] = "cmd-999"   # 假账
lines[2] = json.dumps(r, ensure_ascii=False) + "\n"
open(p, "w").writelines(lines)
EOF
if python3 "$VERIFY" events.chained.jsonl 2>msg.txt; then
    echo "❌ 篡改没被抓到!"; exit 1
fi
cat msg.txt

echo "== 4) 删一行 =="
sed '3d' <(for i in 1 2 3 4 5; do printf '{"event":"exec","cmd":"cmd-%d"}\n' "$i"; done) \
    | python3 "$CHAIN" > events2.chained.jsonl
python3 - events2.chained.jsonl <<'EOF'
import sys
p = sys.argv[1]
lines = open(p).readlines()
del lines[1]                       # 抽掉第 2 条账
open(p, "w").writelines(lines)
EOF
if python3 "$VERIFY" events2.chained.jsonl 2>msg2.txt; then
    echo "❌ 删行没被抓到!"; exit 1
fi
cat msg2.txt

echo "== 5) 封存后偷偷加一行(尾账伪造)==="
for i in 1 2 3; do printf '{"event":"exec","cmd":"cmd-%d"}\n' "$i"; done \
    | python3 "$CHAIN" > events3.chained.jsonl
python3 "$VERIFY" events3.chained.jsonl --seal
python3 - events3.chained.jsonl <<'EOF'
import json, sys, hashlib
p = sys.argv[1]
lines = open(p).readlines()
last = json.loads(lines[-1])
# 伪造者从尾哈希续链,加一条假账(能骗过裸验链,骗不过封存点)
fake = {"event": "exec", "cmd": "innocent-looking"}
h = hashlib.sha256((last["hash"] + "\n" + json.dumps(
    fake, sort_keys=True, ensure_ascii=False, separators=(",", ":")
)).encode()).hexdigest()
lines.append(json.dumps({"v": 1, "seq": 4, "ts": "fake", "prev": last["hash"],
                         "hash": h, "data": fake}, ensure_ascii=False) + "\n")
open(p, "w").writelines(lines)
EOF
if python3 "$VERIFY" events3.chained.jsonl; then
    echo "(裸验链被骗过 —— 符合预期,续链伪造本来就能造出合法链)"
fi
if python3 "$VERIFY" events3.chained.jsonl --check-seal 2>msg3.txt; then
    echo "❌ 封存点没抓到加行!"; exit 1
fi
cat msg3.txt

echo
echo "✅ 判伪演示全部符合预期:改字/删行/封存后加行 全部定位并报错"
