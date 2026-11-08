# design — session 传播与关联设计

## 问题

单机监控看到的是碎片:A 机的 `claude`、B 机一个 `curl`、C 机一次 `git push`。
要串成"这条 agent 会话",必须有一个**随任务传播、不可伪造(至少不可无意伪造)的关联键**。

## v0 关联键

```
session  = AGENT_SESSION_ID(UUID,随进程树环境变量传播)
host     = hostname / K8s pod 名
pid/ppid = 主机内谱系(03-run-ledger 已采集)
```

## 传播通道(按部署形态)

### 1. 环境变量(本骨架已实现:`node/session-run.sh`)

```bash
export AGENT_SESSION_ID=$(uuidgen)
exec claude -p "..."
```

- 子进程、ssh 子进程、容器 exec 默认继承;
- 弱点:agent 自主开新会话(daemon/setsid)会丢;伪造成本为零——**定位是"归因"不是"鉴权"**。

### 2. SSH AcceptEnv(跳板机形态)

```ssh-config
# /etc/ssh/sshd_config
AcceptEnv AGENT_SESSION_ID
```
```bash
ssh -o SendEnv=AGENT_SESSION_ID nodeB
```
- 适合"人/agent 通过跳板机到各机器"的拓扑;sshd 侧还能记下 session↔跳板登录 的对应关系,
  hub 里作为独立事件源(SSH_AUTH_SOCK 的登录审计)。

### 3. K8s downward API(pod 形态)

```yaml
env:
  - name: AGENT_SESSION_ID
    valueFrom:
      fieldRef: { fieldPath: metadata.labels['agent-session'] }
```
- session 从调度层注入 pod,和 audit log 的 pod label 天然对齐;
- 更进一步:pod annotation 里带"发起这条会话的人/prompt 摘要哈希",hub 时间线上直接可读。

## hub 侧关联

- `GET /timeline?session=X` 把三台机器的事件按 ts 排序输出,就是 v0 的"跨机接力"视图;
- v1:若 session 丢失(setsid/新终端),用 `(host, 根 pid 时间邻域)` 做启发式兜底关联,
  在时间线上标"疑似同会话"。

## 已知盲区(诚实清单)

1. **采集层盲区继承自 01-evasion-bench**:tracepoint 系采集器对 io_uring 类行为全盲——
   fabric 只是把"各机器各自看到的碎片"拼起来,不解决单机盲区;
2. 时钟偏移:跨机 ts 排序前先 NTP 校验,v1 用逻辑时钟/事件因果(ppid 链 + ssh 流向)辅助;
3. session 伪造:恶意 agent 可以报别人的 session id。v0 接受;v1 给 node 配预共享密钥
   (hub 校验 HMAC),并把"node 身份"作为事件的一部分。
