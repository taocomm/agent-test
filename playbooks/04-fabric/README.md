# 04-fabric — 跨主机 Agent 行为关联(framework)

**一句话**:把各台机器上的 agent 行为事件按 session 聚到一个 hub,网页上看一条会话怎么跨机接力
(A 机收 prompt → B 机 exec → C 机外联)。

## 架构

```
 hostA: agent 会话(session=abc)                 hostB: agent 派生的任务
 ┌─────────────────────────┐                   ┌─────────────────────────┐
 │ 采集器(03-run-ledger 的  │                   │  采集器 → events.jsonl   │
 │ bpftrace/Tetragon 等)   │                   │  node/node.py --follow  │
 │      → events.jsonl     │                   └───────────┬─────────────┘
 │ node/node.py --follow   │        HTTP batch POST /ingest  │
 └────────────┬────────────┘  ◄──────────────────────────────┘
              ▼
      ┌──────────────┐   GET /timeline?session=abc
      │ hub/hub.py   │──► JSON(跨主机时间线)
      │ (sqlite)     │   GET /            → 网页查看器
      └──────────────┘
```

**关联键**:`session`(主要)+ `host` + `pid/ppid`(主机内谱系)。session 经环境变量
`AGENT_SESSION_ID` 随进程树传播——这是 v0 的核心假设,三通道方案见 `design.md`。

## 快速开始(本沙箱已验证,无需 root)

```bash
./test_fabric.sh          # 一键端到端:起 hub → 两个"主机"的 node 上报 → 查时间线
                          # (含链账本组:入链/跨机封存/改账检出/重启续接, 8 断言)
# 手动:
python3 hub/hub.py --port 8765 &
python3 node/node.py --hub http://127.0.0.1:8765 --host nodeA --file events.jsonl
./node/session-run.sh claude -p "..."     # 给 agent 会话发 session id
open http://127.0.0.1:8765/
```

## 证据链(--chain,07 号接生产流,2026-11-08)

```bash
python3 hub/hub.py --port 8765 --db fabric.db --chain /var/lib/fabric/chain.jsonl
```

- 每条入库事件同步追加进 07 号 SHA-256 哈希链(v2 格式,flush+fsync);
- 启动时对已有账本全量重算验算,破损拒绝启动(fail-closed);重启自动续接;
- `GET /chain` 返回 `{path, seq, head}`;
- **跨机封存**:账本副本 + 封存点交另一台机/outbox,
  `07-evidence-chain/chainlog/verify.py <副本> --seal-file <外部seal> --seal-key <hex>`;
  hub 机上把账本连封存点整体重写(含链合法重写)与外部副本核对即暴露——
  裸验链抓不住续链/重写,外部封存是唯一反证(02 号 v8/v10 实验的产品化)。
- 不加 `--chain` 时行为与旧版逐字节一致。

## 与 03 的关系

- **采集器直接复用 03**:`03-run-ledger` 的 `report.py` 产出 `events.jsonl`(canonical schema),
  本目录 `node.py` 只管搬运;Tetragon/logira 等任何能出 JSONL 的采集器都能接;
- 事件 schema 见 `schema/events.schema.json`(两目录共享同一份)。

## 状态

- hub/node/session-run 已在 localhost 联调通过(`test_fabric.sh`);
- 链账本已接生产流(hub `--chain` 侧账本 + 跨机封存,test_fabric.sh 链账本组 8/8,2026-11-08);
- `design.md` 的 SSH/K8s 传播通道未实测;deploy/ 下的编排文件是骨架待调;
- 已知盲区:采集层若是 tracepoint 系,对 io_uring 类行为隐身(见 01-evasion-bench)。
