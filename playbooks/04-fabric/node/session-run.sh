#!/usr/bin/env bash
# 给一条 agent 会话发 session id,随进程树环境变量传播(通道1,见 design.md)
# 用法: session-run.sh <agent 命令...>
set -Eeuo pipefail
export AGENT_SESSION_ID="${AGENT_SESSION_ID:-$(cat /proc/sys/kernel/random/uuid)}"
echo "[session-run] AGENT_SESSION_ID=$AGENT_SESSION_ID" >&2
exec "$@"
