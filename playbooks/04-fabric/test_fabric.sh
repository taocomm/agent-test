#!/usr/bin/env bash
# 端到端联调(localhost,无需 root):hub + 2 个"主机" node + 时间线查询
set -Eeuo pipefail
cd "$(dirname "$0")"
HUB_PORT=8765
DB=/tmp/fabric-test-$.db
SESS=$(cat /proc/sys/kernel/random/uuid)

cleanup() {
  [ -n "${HUB_PID:-}" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "${HUB2_PID:-}" ] && kill "$HUB2_PID" 2>/dev/null || true
  rm -f "$DB" "/tmp/fabric-chain-$$.db" "/tmp/fabric-chain-2-$$.db"
  rm -rf "${EXDIR:-}" "${CHAINDB:-}"; rm -f "${CHAINDB:-}.seal.json"
}
trap cleanup EXIT

# 1) 起 hub(按 PID 管理,不用 pkill)
python3 hub/hub.py --port $HUB_PORT --db "$DB" &
HUB_PID=$!
for i in $(seq 1 20); do curl -s "http://127.0.0.1:$HUB_PORT/health" >/dev/null && break; sleep 0.2; done
echo "[test] hub 就绪 (pid=$HUB_PID), session=$SESS"

# 2) 造两台"主机"的事件(hostA: agent 收到 prompt 并写文件;hostB: 同 session 派生 exec+外联)
mkdir -p /tmp/fabric-test
cat > /tmp/fabric-test/hostA.jsonl <<EOF
{"ts":"2026-11-02T21:00:01+08:00","type":"llm","pid":100,"comm":"claude","host_hdr":"api.anthropic.com","model":"claude-sonnet-4"}
{"ts":"2026-11-02T21:00:05+08:00","type":"file","pid":130,"comm":"python","path":"/home/u/project/src/a.py","action":"write-open"}
EOF
cat > /tmp/fabric-test/hostB.jsonl <<EOF
{"ts":"2026-11-02T21:00:09+08:00","type":"exec","pid":210,"ppid":1,"comm":"bash","argv":"bash -c npm install"}
{"ts":"2026-11-02T21:00:12+08:00","type":"net","pid":211,"comm":"npm","src":"10.0.2.5:52100","dst":"151.101.1.12:443"}
EOF

# 3) node 上报(读到 EOF 即退)
python3 node/node.py --hub "http://127.0.0.1:$HUB_PORT" --host nodeA --session "$SESS" --file /tmp/fabric-test/hostA.jsonl
python3 node/node.py --hub "http://127.0.0.1:$HUB_PORT" --host nodeB --session "$SESS" --file /tmp/fabric-test/hostB.jsonl

# 4) 查时间线 + 网页
echo '--- /timeline ---'
curl -s "http://127.0.0.1:$HUB_PORT/timeline?session=$SESS" | python3 -m json.tool --no-ensure-ascii
echo '--- / (HTML 头) ---'
curl -s "http://127.0.0.1:$HUB_PORT/" | head -3
# 5) 链账本(--chain,07 号接生产流):入链/验链/跨机封存/改账检出/重启续接
CHLOG="$(pwd)/../07-evidence-chain/chainlog"
VERIFY="$CHLOG/verify.py"
CHAINDB="/tmp/fabric-chain-$$.jsonl"
EXDIR="/tmp/fabric-chain-ext-$$"          # 模拟另一台机/outbox 的封存副本
mkdir -p "$EXDIR"
PASS5=0; FAIL5=0
ok5()  { PASS5=$((PASS5+1)); echo "  PASS: $1"; }
bad5() { FAIL5=$((FAIL5+1)); echo "  FAIL: $1"; }

HUB2_PORT=8766
python3 hub/hub.py --port $HUB2_PORT --db "/tmp/fabric-chain-$$.db" --chain "$CHAINDB" \
  2>"/tmp/fabric-hub2-$$.log" &
HUB2_PID=$!
for i in $(seq 1 20); do curl -s "http://127.0.0.1:$HUB2_PORT/health" >/dev/null && break; sleep 0.2; done
python3 node/node.py --hub "http://127.0.0.1:$HUB2_PORT" --host nodeA --session "$SESS" --file /tmp/fabric-test/hostA.jsonl 2>/dev/null
python3 node/node.py --hub "http://127.0.0.1:$HUB2_PORT" --host nodeB --session "$SESS" --file /tmp/fabric-test/hostB.jsonl 2>/dev/null
seq_val=$(curl -s "http://127.0.0.1:$HUB2_PORT/chain" | python3 -c 'import json,sys;print(json.load(sys.stdin)["seq"])')
[ "$seq_val" -eq 4 ] && ok5 "入链 4 条(/chain seq=$seq_val)" || bad5 "入链条数不符(seq=$seq_val)"
python3 "$VERIFY" "$CHAINDB" 2>/dev/null && ok5 "hub 账本验链通过" || bad5 "hub 账本验链失败"

# 外部封存(HMAC):seal 副本放“另一台机”,hub 机改账逃不掉
printf '%s' "$(python3 -c 'import os;print(os.urandom(32).hex())')" > "$EXDIR/key.hex"
python3 "$VERIFY" "$CHAINDB" --seal --seal-file "$EXDIR/seal.json" --seal-key "$EXDIR/key.hex" 2>/dev/null
python3 "$VERIFY" "$CHAINDB" --check-seal --seal-file "$EXDIR/seal.json" --seal-key "$EXDIR/key.hex" 2>/dev/null \
  && ok5 "外部封存点(HMAC)正向核验过" || bad5 "外部封存点核验失败"

# 攻击模拟:hub 机上链合法重写(改 payload + 重算全链)——裸验链 PASS,外部 seal 才是唯一反证
python3 - "$CHAINDB" "$CHLOG" <<'EOF'
import json, os, sys
sys.path.insert(0, sys.argv[2])
from chain_tee import GENESIS, step2
p = sys.argv[1]
recs = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
recs[0]["data"]["pid"] = 999                     # 改第一条 payload(等长无关,链重算即可续)
prev = GENESIS
for r in recs:
    r["prev"] = prev
    r["hash"] = step2(prev, r["ts"], r["data"])
    prev = r["hash"]
open(p, "w", encoding="utf-8").write("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in recs))
EOF
python3 "$VERIFY" "$CHAINDB" 2>/dev/null \
  && ok5 "链合法重写裸验链 PASS(数学上合法的新链)" || bad5 "链合法重写竟未过裸验链"
rc=0; python3 "$VERIFY" "$CHAINDB" --check-seal --seal-file "$EXDIR/seal.json" --seal-key "$EXDIR/key.hex" \
  2>/dev/null || rc=$?
[ "$rc" -ne 0 ] && ok5 "外部封存点抓住 hub 机改账(跨机封存)" || bad5 "改账未被外部 seal 检出"

# 重启续接:同一账本路径起新 hub,从盘面恢复链状态再追加
kill "$HUB2_PID" 2>/dev/null; wait "$HUB2_PID" 2>/dev/null || true
printf '{"ts":"2026-11-02T21:00:20+08:00","type":"exec","pid":300,"comm":"tail"}\n' > /tmp/fabric-test/hostC.jsonl
python3 hub/hub.py --port $HUB2_PORT --db "/tmp/fabric-chain-2-$$.db" --chain "$CHAINDB" \
  2>"/tmp/fabric-hub2b-$$.log" &
HUB2_PID=$!
for i in $(seq 1 20); do curl -s "http://127.0.0.1:$HUB2_PORT/health" >/dev/null && break; sleep 0.2; done
grep -q "账本续接" "/tmp/fabric-hub2b-$$.log" && ok5 "重启续接账本(启动全量验算)" \
  || bad5 "重启未续接账本"
python3 node/node.py --hub "http://127.0.0.1:$HUB2_PORT" --host nodeC --session "$SESS" --file /tmp/fabric-test/hostC.jsonl 2>/dev/null
seq_val=$(curl -s "http://127.0.0.1:$HUB2_PORT/chain" | python3 -c 'import json,sys;print(json.load(sys.stdin)["seq"])')
[ "$seq_val" -eq 5 ] && ok5 "续接后追加(seq=5)" || bad5 "续接后追加条数不符(seq=$seq_val)"
python3 "$VERIFY" "$CHAINDB" 2>/dev/null && ok5 "续接后验链通过" || bad5 "续接后验链失败"
rm -rf "$EXDIR" "$CHAINDB" "$CHAINDB.seal.json" /tmp/fabric-test /tmp/fabric-hub2-$$.log /tmp/fabric-hub2b-$$.log

echo "[test] PASS(链账本组: $PASS5 passed, $FAIL5 failed)"
[ "$FAIL5" -eq 0 ]
