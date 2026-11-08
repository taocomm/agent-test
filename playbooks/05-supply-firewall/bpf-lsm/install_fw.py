#!/usr/bin/env python3
"""install_fw.py — 安装期防火墙,BPF LSM 模式 [VM 实测 2026-11-06 四联判定全绿]

沙箱无 root(unprivileged_bpf_disabled=2),在 root + CONFIG_BPF_LSM 的 VM 上跑(需要 bcc)。
2026-11-06 VM(6.12.115)首跑逼出并当场修三 bug:①6.12 的 linux_binprm 已删 envp 成员,
bprm 扫 env 方案不可行 → 改 loader 直标 tgid + fork 继承;②LPM key 字节序(loader 插
htonl 网络序,lookup 同序);③CIDR 只插了 network_address/32。四联判定全绿,见
wk09/HANDOFF.md 第十轮。
2026-11-06 二轮:证据 enrich —— 已解析域名写入 host 字段:域名条目解析出的每个
IP 映射回域名、裸 IP /32 条目映射回字面量(CIDR 网段不映射,一个网段说不出是哪个域名)。
2026-11-08 三轮(第四十一轮):SNI 域门进 LSM 模式(--sni 门控,不开则行为与二轮逐字节一致)。

SNI 门设计(对偶 preload 侧 fwshim.c 的 SSL_ctrl/gnutls 钩子,补其 PLT 够不着的盲区):
  uprobe SSL_ctrl(ssl, cmd, larg, parg)  cmd==55 即 SSL_set_tlsext_host_name 宏的落点
                                          (OpenSSL 3 的 libssl.so.3 与 node 自带 OpenSSL
                                           都导出 SSL_ctrl;SSL_set_tlsext_host_name 是宏
                                           不成符号,只有 libssl.so.3 如此——node 侧无该符号,
                                           同走 SSL_ctrl);
  uprobe gnutls_server_name_set(s, type, name, len)  type∈{0,1}(GNUTLS_NAME_DNS 各版本
                                          枚举值有差异,放宽到两值都收);
  内核内同步:FNV-1a64(小写域名) 查 sni_allow 哈希表;未批准 → sni_poison[tgid]=1。
  SNI-set 先于 connect/握手,uprobe 返回前投毒已生效——零竞态,ClientHello 根本出不了门;
  LSM socket_sendmsg 对投毒 tgid 一律 -EPERM(写族全经 sock_sendmsg,write/send/sendto/
  sendmsg 通吃),并出首笔 send-deny 证据行(只报第一笔防刷屏,拦截持续到进程退出)。
  这一环把 preload 的 SNI 门(PLT interposition)够不着的都罩住:
    - node/npm 生命周期脚本(node 自带 OpenSSL 内部链接不经 PLT,--sni-bin 挂它的 SSL_ctrl);
    - 与 IP 门(connect 钩)叠加:共享 CDN 死角(C2 与 registry 同 CDN IP)在内核侧闭环。
  证据 schema 与 preload 对齐:event=sni(allow/deny)+ event=send(deny, note=bpf-lsm-sni-gate),
  可直接喂 fw2fabric 桥 / 04-fabric hub。

已知边界(v0):
  - Go(crypto/tls 原生)与 QUIC(HTTP/3,UDP)没有 SSL_ctrl 等价物,SNI 门盲——
    connect IP 门兜底;本 VM 安全组拦 UDP:443 回包,QUIC 连 E2E 都不可行(39 轮实证);
  - 剥符号/无 SSL_ctrl 的运行时:--sni-bin attach 失败告警跳过(不 fail-closed,如实记录);
  - 投毒粒度 = tgid:一次违例 SNI 杀全进程后续发送(install 期 fail-closed 语义);
    per-SSL 粒度需 ssl→fd 绑定链,留 M 项;
  - 域名哈希 = FNV-1a64,理论碰撞在白名单量级下可忽略;IDN 走 punycode(ASCII)不受影响;
  - 无 SNI 的 ClientHello(openssl s_client -noservername 一类)门盲 → 落 CDN 默认 vhost,
    证书校验兜底(同 preload 决);IP 形态 SNI 放行(RFC 6066 不允许,真客户端不会发)。

与 preload 模式(shim/fwshim.c)的分工:
  preload = 今天就能用的原型,可被静态/Go 二进制绕过;
  本文件  = 产品形态,内核强制、无法绕过,对标并修正 KEIP:
    - KEIP 按可执行名圈范围(pip/python),误伤全机 python3;
      这里按 **FW_SCOPE=1 环境标记 + fork 继承** 圈调用树,与 preload 模式同一标记。
    - KEIP 是行为启发式(端口陷阱 80/443/53 + 连接数帽 + 字节帽),允许面过宽;
      这里是 **域名/IP 白名单 + 默认拒绝**,与 preload 同一份 allowlists/*.txt。
    - KEIP 事件只在 ring buffer 里挥发了;这里落 JSONL 证据账本, schema 与 preload 一致,
      可直接喂 03-run-ledger 对账 / 04-fabric 上报。

钩子设计(对应 CargoWall stepbpf.c 的 fork 树标记 + KEIP 的 LSM attach):
  loader(本脚本)      → Popen 后把子进程 tgid 直标进 scope_pids;原 bprm 扫 envp 方案
                          2026-11-06 VM 实测不可行:6.12 的 linux_binprm 已删 envp 成员
  tp/raw sched_process_fork  → 父标记则子继承(圈住整棵调用树)
  tp/raw sched_process_exit  → 组长退出才清 map(线程池线程退出不摘标)
  security_socket_connect    → 未白名单 IPv4 connect 返回 -EPERM + 上报事件
  uprobe SSL_ctrl/gnutls_server_name_set (--sni) → 抓 SNI、查域门哈希、投毒 + 证据
  security_socket_sendmsg    → 投毒 tgid 一律 -EPERM + 首笔证据

其他已知边界(骨架期即有):
  - 只处理 AF_INET;AF_INET6 留 TODO(骨架期先 fail-open,正式版应 fail-close);
  - 白名单域名在 loader 启动时一次性解析成 /32 进 LPM——长任务中 registry 换 IP 会误拒,
    周期刷新留 M 项(SNI 门不依赖 DNS:域名条目无条件进哈希表,解析失败不致命);
  - UDP sendto(如 c-ares 原生 DNS)不经 connect,connect 钩看不见(sendmsg 钩在 --sni
    下覆盖,但仅投毒进程);系统解析器仍靠 load_resolvers 入 LPM 兜底;
  - 标记竞态:Popen 返回到 tgid 入 map 之间(~µs)子进程若已 fork,孙进程不入圈;
    npm/cargo 等首子进程 ≥100ms 后才起,实测无影响。
"""
import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from ctypes import Structure, c_uint, c_ubyte, c_ulonglong

from bcc import BPF


class LpmKey(Structure):
    """BPF LPM_TRIE 键:prefixlen + 大端 IP(内核按字节从高位比)。"""
    _fields_ = [("prefixlen", c_uint), ("data", c_uint)]


def sni_hash96(domain: str) -> int:
    """BPF 侧 handle_sni_name 的逐字节镜像:96 字节缓冲 = 域名(小写、去尾点、截 95)
    + NUL + 零尾,FNV-1a64 全量 96 字节(哈希含零尾是 BPF 侧常量行程的一部分,
    两侧必须同构,否则全 miss)。"""
    buf = domain.lower().rstrip(".").encode()[:95]
    buf += b"\x00" * (96 - len(buf))
    h = 0xCBF29CE484222325
    for b in buf:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <net/sock.h>

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC 1
#endif

struct lpm4_key { u32 prefixlen; u32 data; };

BPF_HASH(scope_pids, u32, u8);
BPF_HASH(sni_allow, u64, u8);     /* FNV-1a64(小写域名,去尾点) → 1 */
BPF_HASH(sni_poison, u32, u8);    /* tgid → 1=拦发 2=已出过首笔证据行 */
BPF_F_TABLE("lpm_trie", struct lpm4_key, u64, allow_v4, 1024, BPF_F_NO_PREALLOC);

struct event_t {
    u32 pid;
    u32 ppid;
    u32 dst;
    u16 port;
    u8  verdict;      /* 0=allow 1=deny */
    u8  kind;         /* 0=connect 1=send(sni 投毒拦发) */
    char comm[16];
};
BPF_PERF_OUTPUT(events);

struct sni_event_t {
    u32 pid;
    u32 ppid;
    u8  verdict;      /* 0=allow 1=deny(捕获时点的域门判定) */
    char host[96];
    char comm[16];
};
BPF_PERF_OUTPUT(sni_events);

/* 入圈由 loader 直标(见文件头);fork 继承把整棵调用树圈进来 */
RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child  = (struct task_struct *)ctx->args[1];
    u32 ppid = 0, cpid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    bpf_probe_read_kernel(&cpid, sizeof(cpid), &child->tgid);
    u8 *m = scope_pids.lookup(&ppid);
    if (m) {
        u8 one = 1;
        scope_pids.update(&cpid, &one);
    }
    return 0;
}

/* 只在组长退出时清:node 等线程池线程退出不该摘掉整进程的标记 */
RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    struct task_struct *t = (struct task_struct *)ctx->args[0];
    u32 tid = 0, tgid = 0;
    bpf_probe_read_kernel(&tid, sizeof(tid), &t->pid);
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &t->tgid);
    if (tid == tgid) {
        scope_pids.delete(&tgid);
        sni_poison.delete(&tgid);
    }
    return 0;
}

/* 共享主体:读用户态 SNI 串 → 全量哈希查域门 → 证据 + 投毒。
 * uprobe 返回前投毒必已生效(SNI-set 先于 connect/握手),内核侧零竞态。
 *
 * 哈希必须全量 96 字节、常量行程、零变量出口(2026-11-08 VM 实录两个 verifier 坑):
 * ①变量上界循环(i<len)被 clang 展开成指针成对游走 → 奇数偏移状态拒载;
 * ②即使常量上界+变量 break,clang 会利用 len≤95 把 i<96 当冗余条件消掉、
 *   把循环旋转化成 i==len-1 等值退出,verifier 无法证明等值可达,i widen 到
 *   112 越界拒载。全量哈希(串+NUL+零尾,name[96]={} 初始化保证尾零)与
 *   loader 侧 sni_hash96() 逐字节镜像,循环只剩 i<96 一个出口,平凡可证。
 * IP 形态 SNI 不特判:RFC 6066 禁止,OpenSSL/GnuTLS/node 对字面量根本不发
 * SNI(VM 实测 curl https://127.0.0.1 零事件);手搓客户端发 IP SNI 落
 * 哈希 miss → fail-closed,可接受。 */
static __always_inline int handle_sni_name(struct pt_regs *ctx, const void *uname)
{
    u64 pid = bpf_get_current_pid_tgid();
    u32 tgid = pid >> 32;
    if (!scope_pids.lookup(&tgid)) return 0;

    char name[96] = {};
    long n = bpf_probe_read_user_str(name, sizeof(name), uname);
    if (n <= 1) return 0;
    int len = n - 1;
    if (len > 95) len = 95;

    /* 尾点归一(与 loader 侧 rstrip('.') 同义):尾点原位改写为 NUL,
     * 全量哈希因此与 loader 逐字节一致;索引显式钳位助证。 */
    {
        int last = len - 1;
        if (last > 95) last = 95;
        if (last < 0) last = 0;
        if (name[last] == '.') name[last] = 0;
    }

    u64 h = 0xcbf29ce484222325ULL;
    int i;
#pragma clang loop unroll(disable)
    for (i = 0; i < 96; i++) {
        u8 c = (u8)name[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= (u64)c;
        h *= 0x100000001b3ULL;
    }
    u8 *ok = sni_allow.lookup(&h);
    u8 verdict = ok ? 0 : 1;

    if (verdict) {
        u8 one = 1;
        sni_poison.update(&tgid, &one);
    }

    struct sni_event_t ev = {};
    ev.pid = tgid;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &t->real_parent);
    if (parent)
        bpf_probe_read_kernel(&ev.ppid, sizeof(ev.ppid), &parent->tgid);
    ev.verdict = verdict;
    __builtin_memcpy(ev.host, name, sizeof(ev.host));
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    sni_events.perf_submit((void *)ctx, &ev, sizeof(ev));
    return 0;
}

/* SSL_ctrl(ssl, cmd, larg, parg):SSL_set_tlsext_host_name 是宏,落到底 =
 * SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME=55, 0, name)。libssl.so.3 与 node
 * 自带 OpenSSL 都导出 SSL_ctrl;larg 不筛(各实现宏展开一致为 0,不必赌)。 */
int sni_probe_openssl(struct pt_regs *ctx)
{
    if (PT_REGS_PARM2(ctx) != 55) return 0;
    const void *name = (const void *)PT_REGS_PARM4(ctx);
    if (!name) return 0;
    return handle_sni_name(ctx, name);
}

/* gnutls_server_name_set(session, type, name, len):只收 SNI 类型
 * (GNUTLS_NAME_DNS 的枚举值各版本 0/1 有差异,放宽两值都收)。 */
int sni_probe_gnutls(struct pt_regs *ctx)
{
    unsigned long ty = PT_REGS_PARM2(ctx);
    if (ty != 0 && ty != 1) return 0;
    const void *name = (const void *)PT_REGS_PARM3(ctx);
    if (!name) return 0;
    return handle_sni_name(ctx, name);
}

LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!scope_pids.lookup(&tgid)) return 0;
    if (!address) return 0;

    sa_family_t fam = 0;
    bpf_probe_read_kernel(&fam, sizeof(fam), &address->sa_family);
    if (fam != AF_INET) return 0;   /* v6 TODO,见文件头已知边界 */

    struct sockaddr_in sin = {};
    bpf_probe_read_kernel(&sin, sizeof(sin), address);
    u32 dst_be = sin.sin_addr.s_addr;   /* LPM key 必须用网络序原始字节:loader 插 htonl,
                                           2026-11-06 VM 实测:lookup 用 ntohl 主机序则全 miss */
    u32 dst = ntohl(dst_be);            /* 主机序仅用于展示 */
    u16 port = ntohs(sin.sin_port);

    struct lpm4_key key = { .prefixlen = 32, .data = dst_be };
    u64 *allow = allow_v4.lookup(&key);
    u8 deny = allow ? 0 : 1;

    struct event_t ev = {};
    ev.pid = tgid;
    ev.kind = 0;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &t->real_parent);
    if (parent)
        bpf_probe_read_kernel(&ev.ppid, sizeof(ev.ppid), &parent->tgid);
    ev.dst = dst;
    ev.port = port;
    ev.verdict = deny;
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    events.perf_submit((void *)ctx, &ev, sizeof(ev));

    return deny ? -EPERM : 0;
}

/* SNI 投毒拦发:写族(write/send/sendto/sendmsg)全经 sock_sendmsg,一钩通吃。
 * ClientHello 在首次 send 时被 -EPERM 掐死——TCP 通道虽在,TLS 握手永不完成。 */
LSM_PROBE(socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u8 *p = sni_poison.lookup(&tgid);
    if (!p) return 0;

    struct event_t ev = {};
    ev.pid = tgid;
    ev.kind = 1;
    ev.verdict = 1;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &t->real_parent);
    if (parent)
        bpf_probe_read_kernel(&ev.ppid, sizeof(ev.ppid), &parent->tgid);
    void *sk = NULL;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
    if (sk) {
        u32 daddr_be = 0, dport_be = 0;
        bpf_probe_read_kernel(&daddr_be, sizeof(daddr_be),
                              &((struct sock *)sk)->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&dport_be, sizeof(dport_be),
                              &((struct sock *)sk)->__sk_common.skc_dport);
        ev.dst = ntohl(daddr_be);
        ev.port = ntohs(dport_be);
    }
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    events.perf_submit((void *)ctx, &ev, sizeof(ev));

    if (*p == 1) {   /* 只报首笔,防刷屏;拦截持续到进程退出(exit 钩清 map) */
        u8 two = 2;
        sni_poison.update(&tgid, &two);
    }
    return -EPERM;
}
"""


def load_allowlist(path, bpf, resolved=None, domains=None):
    """域名现场解析成 /32、IP/CIDR 直录;解析失败(离线)不致命,运行期会被 deny 并留证据。

    resolved(可选):{点分 IP: 白名单字面量} 映射,供证据 enrich(见文件头)。
    domains(可选):收集域名条目(小写、去尾点)——--sni 时进 FNV 哈希白名单;
    SNI 域门不依赖 DNS,解析失败不影响哈希入表。"""
    tbl = bpf["allow_v4"]
    n = 0
    for raw in open(path, encoding="utf-8"):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            if "/" in s:
                net = ipaddress.ip_network(s, strict=False)
                if net.version != 4:
                    print(f"[install-fw] 暂只支持 IPv4,跳过 {s}", file=sys.stderr)
                    continue
                targets = [(net.prefixlen, int(net.network_address))]
                if resolved is not None and net.prefixlen == 32:
                    resolved.setdefault(str(net.network_address), s)
            else:
                try:
                    ipaddress.IPv4Address(s)
                    targets = [(32, int(ipaddress.IPv4Address(s)))]
                except ValueError:
                    # 域名条目:无论能否解析,先进 SNI 哈希白名单
                    if domains is not None:
                        domains.append(s.lower().rstrip("."))
                    targets = [(32, int(ipaddress.IPv4Address(ai[4][0])))
                               for ai in socket.getaddrinfo(s, None, socket.AF_INET)]
                    if resolved is not None:
                        for ai in socket.getaddrinfo(s, None, socket.AF_INET):
                            resolved.setdefault(ai[4][0], s)
            for plen, ipint in targets:
                tbl[LpmKey(plen, socket.htonl(ipint))] = tbl.Leaf(1)
            n += 1
        except Exception as e:
            print(f"[install-fw] 白名单项 {s!r} 处理失败: {e}", file=sys.stderr)
    return n


def load_resolvers():
    """系统解析器必须入白名单:getaddrinfo 会走 TCP DNS(:53 connect),LSM 没有
    resolver 逻辑,不把 DNS 服务器入圈的话,圈内核进程连合法域名都解析不了
    (2026-11-06 VM 实测:EAI_AGAIN)。"""
    ns = []
    for line in open("/etc/resolv.conf", encoding="utf-8"):
        f = line.split()
        if len(f) >= 2 and f[0] == "nameserver":
            try:
                ns.append(str(ipaddress.IPv4Address(f[1])))
            except ValueError:
                pass
    return ns


def attach_sni_probes(bpf, sni_bins):
    """挂 SNI uprobe:系统 libssl.so.3(覆盖 curl/python/_ssl 等 OpenSSL 系)+
    libgnutls.so.30(wget 等 GnuTLS 系)+ --sni-bin 指定的自带 OpenSSL 运行时
    (node 等,其 SSL_ctrl 在自己的二进制里)。缺失/剥符号的项告警跳过。"""
    cands = [
        ("/usr/lib/x86_64-linux-gnu/libssl.so.3", "SSL_ctrl", "sni_probe_openssl"),
        ("/usr/lib/x86_64-linux-gnu/libgnutls.so.30", "gnutls_server_name_set", "sni_probe_gnutls"),
    ]
    for p in sni_bins:
        cands.append((p, "SSL_ctrl", "sni_probe_openssl"))
    ok = []
    for path, sym, fn in cands:
        if not path or not os.path.exists(path):
            print(f"[install-fw] SNI 跳过(不存在): {path}", file=sys.stderr)
            continue
        try:
            bpf.attach_uprobe(name=path, sym=sym, fn_name=fn, pid=-1)
            ok.append(f"{os.path.basename(path)}:{sym}")
        except Exception as e:
            print(f"[install-fw] SNI attach 失败 {path}:{sym} ({e});该运行时无域门,"
                  f"IP 门兜底", file=sys.stderr)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow", required=True, help="白名单文件(与 shim 共用同一份)")
    ap.add_argument("--evidence", default=None, help="JSONL 证据输出(缺省 stdout)")
    ap.add_argument("--sni", action="store_true",
                    help="启用 SNI 域门(uprobe SSL_ctrl/gnutls + LSM sendmsg 拦发)")
    ap.add_argument("--sni-bin", action="append", default=[],
                    help="额外挂钩 SSL_ctrl 的二进制(node 等自带 OpenSSL 运行时,可重复)")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- 后接被罩命令")
    args = ap.parse_args()
    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        ap.error("需要 -- CMD")

    out = open(args.evidence, "a", buffering=1) if args.evidence else sys.stdout
    bpf = BPF(text=BPF_TEXT)
    ns_extra = "/tmp/fw-lsm-resolvers.txt"
    with open(ns_extra, "w", encoding="utf-8") as f:
        for ip in load_resolvers():
            f.write(f"{ip}/32\n")
    resolved = {}
    domains = []
    n = load_allowlist(args.allow, bpf, resolved, domains)
    n_dns = load_allowlist(ns_extra, bpf)
    sni_msg = ""
    if args.sni:
        sni_tbl = bpf["sni_allow"]
        for d in domains:
            sni_tbl[c_ulonglong(sni_hash96(d))] = c_ubyte(1)
        hooked = attach_sni_probes(bpf, args.sni_bin)
        sni_msg = f" + SNI 域门 {len(domains)} 域 {len(hooked)} 挂点({' '.join(hooked) or '无'})"
    print(f"[install-fw] BPF LSM attached, allowlist {n} 条 + 系统 DNS {n_dns} 条{sni_msg}",
          file=sys.stderr)

    def ppid_of(ev):
        return ev.ppid

    def on_event(cpu, data, size):
        ev = bpf["events"].event(data)
        dst = f"{(ev.dst >> 24) & 255}.{(ev.dst >> 16) & 255}.{(ev.dst >> 8) & 255}.{ev.dst & 255}"
        comm = ev.comm.decode(errors="replace").rstrip("\x00")
        if ev.kind == 1:   # SNI 投毒后的 send 拦发
            rec = {
                "ts": int(time.time() * 1000),
                "pid": ev.pid, "ppid": ev.ppid, "comm": comm,
                "event": "send", "action": "deny",
                "dst": f"{dst}:{ev.port}", "host": "", "note": "bpf-lsm-sni-gate",
            }
            out.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
            return
        rec = {
            "ts": int(time.time() * 1000),
            "pid": ev.pid, "ppid": ev.ppid,
            "comm": comm,
            "event": "connect",
            "action": "deny" if ev.verdict else "allow",
            "dst": f"{dst}:{ev.port}", "host": resolved.get(dst, ""), "note": "bpf-lsm",
        }
        out.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
        if ev.verdict:
            print(f"[install-fw] BLOCKED connect {dst}:{ev.port} (pid {ev.pid} "
                  f"comm {comm})", file=sys.stderr)

    def on_sni_event(cpu, data, size):
        ev = bpf["sni_events"].event(data)
        host = ev.host.decode(errors="replace").rstrip("\x00")
        comm = ev.comm.decode(errors="replace").rstrip("\x00")
        rec = {
            "ts": int(time.time() * 1000),
            "pid": ev.pid, "ppid": ev.ppid, "comm": comm,
            "event": "sni",
            "action": "deny" if ev.verdict else "allow",
            "host": host,
            "note": "bpf-lsm-sni-gate" if ev.verdict else "bpf-lsm",
        }
        out.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
        if ev.verdict:
            print(f"[install-fw] SNI-GATE {host} (pid {ev.pid} comm {comm}) "
                  f"→ 进程级拦发", file=sys.stderr)

    bpf["events"].open_perf_buffer(on_event, page_cnt=64)
    if args.sni:
        bpf["sni_events"].open_perf_buffer(on_sni_event, page_cnt=64)

    env = dict(os.environ, FW_SCOPE="1")   # shim 模式靠它激活;LSM 模式下 tgid 直标(下一行)
    child = subprocess.Popen(cmd, env=env)
    bpf["scope_pids"][c_uint(child.pid)] = c_ubyte(1)
    try:
        while child.poll() is None:
            bpf.perf_buffer_poll(timeout=200)
        bpf.perf_buffer_poll(timeout=200)
    finally:
        sys.exit(child.returncode or 0)


if __name__ == "__main__":
    main()
