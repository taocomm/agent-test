# design — AI 供应链"安装期防火墙"(方向5)

一句话:包管理器 install 期是任意代码执行窗口,把出网白名单强制加在这段调用树上,白名单外一律阻断 + 落证据账本。对标 KEIP(pip 专用 PoC)与 CargoWall(cargo/GH Actions 专用),泛化到 npm/cargo/uvx 等生态,主战场是自托管 CI。

## 1. 为什么是 install 期

- 2026-06 Atomic Arch 一次性投放 1500 个恶意包(见 wk09 报告 §4),install 期被实锤为真实攻击窗口;
- npm lifecycle scripts / cargo build.rs / pip setup.py 与构建后端,都是**包作者代码在本机拿到任意执行**的时刻,且发生在"开发者以为自己在装东西"的低警惕上下文;
- 传统答案(不跑脚本 `--ignore-scripts`)在真实项目里撑不住(很多包真要编译),npm 11 已经自己动手:install-scripts 准入制(默认不跑未批准脚本)。**但 npm 管的是"脚本跑不跑",没人管"整个 install 调用树能碰哪些网络"**——脚本准入绕不过的(依赖包的传递性 postinstall、构建期下载、被批准脚本的恶意行为),网络面兜底。这就是本项目的位置。

## 2. 先前工作与本项目的差异化

| | KEIP (Otsmane-Ahmed) | CargoWall (code-cargo) | 本项目 |
|---|---|---|---|
| 生态 | pip 专用 | cargo 专用(GH Actions) | 多生态,允许面按生态配置 |
| 圈范围方式 | **可执行名匹配**(bprm 里找 "pip"/"python")+ 父继承 | GH Actions step 边界 + fork 树标记 | **FW_SCOPE=1 env 标记 + fork 继承**:不看名字(全机 python3 不被误伤),不依赖 CI 语义 |
| 判定 | 行为启发式:端口陷阱 80/443/53、单 PID 连接数帽、收发比 | SNI 解析 + step 白名单 | **域名白名单,默认拒绝**(registry 之外的 connect 一律非法,无需猜行为) |
| IPv4/6 | v6 只查端口不查地址 | 有 SNI 层 | v4 全查 + v6 字面量比对(preload);bpf 骨架 v6 TODO |
| 证据 | ring buffer 挥发 | 自有上报 | **JSONL 账本,O_APPEND 落盘**,schema 与 preload/bpf 两种模式一致,可接 03 对账、04 上报 |
| 运行形态 | BCC,需 root | eBPF + GH Action | 两级:LD_PRELOAD(无 root,今天可用)/ BPF LSM(内核强制,VM) |

KEIP 的三个具体短板(源码级,`keip_pip_monitor.py`):名字圈范围(监视期内全机 python3 都被罩住——CI 上会把无关进程一并误伤/审计);启发式允许面(443 的 C2 天然过检);localhost 永久放行(postinstall 可以随意打本机服务)。本项目对应修正:env 圈树、默认拒绝 + 显式白名单、localhost 也要在白名单里。

## 3. 架构:两级模式

```
                    ┌─ 模式1: LD_PRELOAD(shim/fwshim.c)─────────┐
fw-run --allow npm.txt -- npm ci                                       │
  └─ 注入 FW_SCOPE=1 + LD_PRELOAD → 调用树全部继承                       │
       getaddrinfo/gethostbyname 家族/getaddrinfo_a: 域名白名单判定,
                   enforce 下未申报域名各自掐在解析器;解析结果统一入已批准缓存
       connect:    IP ∈ (白名单 ∪ 已批准解析缓存)? 否则 EPERM            │
       证据: JSONL(O_APPEND,单 write;enforce 与 audit 同构)           │
                    └─ audit 模式 = 同一套路只记不拦(白名单调参用)      │
                                                                        │
                    ┌─ 模式2: BPF LSM(bpf-lsm/install_fw.py)[VM] ──────┤
fw-run-bpf --allow npm.txt -- npm ci                                    │
  └─ 内核 security_bprm_check 扫 envp 发现 FW_SCOPE=1 → 标记 tgid        │
       sched_process_fork 继承 / sched_process_exit 回收                 │
       security_socket_connect: LPM 白名单,未命中 -EPERM + ringbuf       │
       证据: perf → 同一份 JSONL schema                                  │
```

- 模式1 价值:**零特权、零部署**,任何开发机/CI runner 当场可用;弱点诚实列出(§5)。
- 模式2 价值:内核强制、Go/静态二进制也罩住;与模式1 共用白名单文件与证据 schema,升级即换 runner,账本不断。
- 范围标记 `FW_SCOPE=1` 是两种模式的统一接口:谁能拿到 env,谁就在圈内;double-fork/setsid 甩不掉(环境变量随 exec 继承)。边界诚实说明:标记强度 = wrapper 的 env 卫生(比如用户手动 `FW_SCOPE=1` 起的进程也会入圈——这更接近 feature 而非 bug)。

## 4. 证据账本

每事件一行 JSON:`ts/pid/ppid/comm/argv/event(resolve|connect|session)/action(allow|deny|audit-deny|resolve-failed)/dst/host/note`。

- ppID 链在场 → 账本本身可回放"哪次 install 的哪个脚本发起",不必依赖 npm 自己的日志;
- enforce 的 deny 行同时打 stderr,CI 日志里立即可见;
- 抗篡改边界:O_APPEND 单 write 只保证行完整性,不防同权限进程改写——升级项是 host 侧只增存储
  或接 04-fabric 即时外送(**桥已就位:`fabric/fw2fabric.py` 把本证据转 canonical schema,
  落盘喂 node/node.py 或直 POST hub /ingest,2026-11-04 全链路实测)**;
- 与 03-run-ledger 的分工:03 管"agent 干了什么 vs 它自报了什么"(对账),05 管"install 树不被允许干什么"(管制)。05 的证据文件格式刻意保持 03 可读。

## 5. 诚实边界

preload 模式(LD_PRELOAD)的绕过面,全列表(2026-11-08 实测修订):

1. **静态/Go/musl 二进制**:不走 libc PLT,connect/getaddrinfo 拦不到。实测修订:rustc 默认
   gnu 目标产物是 glibc 动态链接,**build.rs 本体落在罩内**(cargo-evil demo 实证);
   罩不住的是 build.rs 里下载再执行的静态/musl/Go 恶意件——那才是模式2的硬靶;
2. **c-ares/原生 UDP DNS**:node 的 `dns.resolve`、Go 的原生解析器直接发 UDP,不经 connect;
   恶意回传可以走 DNS 隧道。模式2 也要加 sock_create/sendmsg 钩子才闭合;
3. **DoH/DoT(加密解析)——解析面绕过,不是出网绕过**:getaddrinfo 门对它无效,但 enforce
   默认拒绝下 DoH 查询本身是到解析器 IP 的 connect,白名单外照样 EPERM(场景 I1/I2 实证:
   解析器不在白名单 → connect EPERM;解析器在、目标不在 → DoH 拿到 IP 后 connect 照拒)。
   审计面才是真盲:qname 在 TLS 里不可见 → 已知公共解析器 IP/域名证据打 note=doh-endpoint
   (2026-11-08 起),`FW_DOH=deny` 可强制拒(白名单内也拒,场景 I4);
4. **共享 CDN IP(SNI 门已堵,2026-11-08)**:registry 在 Cloudflare 后面时,已批准缓存里
   必有 CDN IP;C2 落在同一 CDN 时 connect 层放行——**IP 门唯一放行死角**(DoH/硬编码解析
   只是它的马甲)。解法:hook libssl `SSL_ctrl` / gnutls `gnutls_server_name_set`,
   ClientHello 出门前按 SNI 比白名单,enforce 下 shutdown(fd)/拒设 SNI(场景 I3/I6/I7 实证,
   含 curl --doh-url 真端到端)。覆盖边界:curl/python(OpenSSL 系)罩内;GnuTLS 路径拿不到
   fd,退化为拒设 SNI(ClientHello 无 SNI,靠 CDN 默认 vhost/证书校验兜底),弱于 OpenSSL;
   **node 的 BoringSSL 对 preload 盲,但导出 SSL_ctrl 符号 → BPF LSM SNI 域门 --sni-bin
   直挂,npm 生命周期脚本 HTTPS 盲区已闭环(2026-11-08,场景组 L3/L4/L4b,comm=MainThread)**;
   QUIC(HTTP/3)的 SNI 在 UDP 里,LSM sendmsg 钩只对已投毒 tgid 生效,未覆盖——与 1/2
   剩余部分同归后置故事;
5. **setuid/文件能力二进制**:内核剥 LD_PRELOAD;
6. **已有连接的复用**:fd 传入/Unix socket 转发这类骚操作未覆盖;
7. **res_* 原生解析 API**(MX/TXT 等非地址查询):误拦面大,不钩——套接字对端仍由 connect 层兜底;
8. **getaddrinfo_a 轮询 gai_error 的程序**:解析结果不入缓存(gai_suspend 路径已缓存);
   构建工具链几乎不碰该 API,残余误拒面可忽略。

模式2 在骨架期只处理 AF_INET(fail-open),v6/UDP 闭合前同样不宣称完备。

### 5.1 SNI 门的工程注记(2026-11-08 实测)

- **真函数解析**:python 的 `_ssl` 以 RTLD_LOCAL dlopen 加载 libssl,`dlsym(RTLD_NEXT)`
  返回 NULL(不守卫直接调就是段错误)——必须回落 `dlopen("libssl.so.N")` 拿句柄;
- **curl 的 fd 时序**:curl 在 step1 设 SNI、step2 才 `SSL_set_fd`,SSL_ctrl 时刻
  `SSL_get_fd` 返回 -1——待杀名单记下待拒 ssl,fd 落上时(SSL_set_fd 钩)或握手发起时
  (SSL_connect 钩)再拦死;
- **node 的 BoringSSL** 内部链接不经 PLT,SSL_ctrl 钩子天然拦不到 npm 生命周期脚本;
  但 node 的 connect/getaddrinfo 走 libc(2026-11-04 pi 审计实证),IP 门有效;
- **ctypes dlsym(handle) 直调绕过 interposition**——验 GnuTLS 钩子必须 PLT 编译型
  fixture(`-Wl,-l:libgnutls.so.30`,无需 dev 包头文件)。

### 5.2 BPF LSM SNI 域门的工程注记(2026-11-08 VM 实测,三跑 27/27)

- **挂点**:libssl.so.3 与 node 自带 BoringSSL 都导出 `SSL_ctrl`——`SSL_set_tlsext_host_name`
  是宏,落底为 `SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME=55, 0, name)`,按 cmd==55 筛;
  GnuTLS 挂 `gnutls_server_name_set`(type∈{0,1})。uprobe pid=-1 全局挂 + `--sni-bin`
  对 node 这类自带 TLS 库的二进制补挂;
- **零竞态设计**:SNI-set 先于 connect/握手,uprobe 返回前内核内完成白名单判定,未批准 →
  `sni_poison[tgid]=1`;LSM `socket_sendmsg` 对投毒 tgid 一律 -EPERM——ClientHello 出不了
  门,不存在 preload 版的 fd 时序问题(curl step1/step2 分离,见 5.1);
- **verifier 三坑**(全部实录):①变量上界循环被 clang 展开成指针成对游走 → 奇数偏移状态
  拒载;②常量上界+变量 break 也不够——clang 利用 len≤95 把 i<96 当冗余条件消掉、循环
  旋转化成 i==len-1 等值退出,verifier 无法证明等值可达,i widen 越界拒载;③治本 = 全量
  96 字节哈希(串+NUL+零尾,`name[96]={}` 保证尾零)+ 常量行程 + `unroll(disable)`,
  循环只剩 i<96 一个出口,verifier 平凡可证;loader 侧 sni_hash96() 逐字节镜像同构;
- **IP 形态 SNI 不特判**:RFC 6066 禁止,OpenSSL/GnuTLS/node 对字面量根本不发 SNI(VM
  实测 curl https://127.0.0.1 零事件);手搓客户端发 IP SNI 落哈希 miss → fail-closed,
  可接受(preload 版特判保留,更严);
- **粒度与盲区**:投毒粒度 = tgid(fail-closed,deny 后该进程剩余生命周期出网全拒);
  Go crypto/tls 与 QUIC 无 SSL_ctrl 等价物 → IP 门兑底(VM 安全组拦 UDP:443,QUIC 连
  E2E 不可行,39 轮实证);无 SNI 的 ClientHello 盲(证书校验兑底);剥符号二进制 attach
  失败告警跳过;node 证据行 comm=MainThread(主线程 pthread_setname_np,非 node)。

## 6. CI 接入(M2 形态)

```yaml
# GitHub Actions / 自托管 runner 通用形态
- run: |
    playbooks/05-supply-firewall/shim/fw-run \
      --mode enforce --allow allowlists/npm.txt \
      -- npm ci
```

- 首跑用 `--mode audit` 收一周证据 → 人工定白名单(镜像源、私有 registry)→ 切 enforce;
- deny 即构建红 + 证据 artifact 上传(事后取证);
- 自托管 runner 常驻机的做法:runner 进程本身常罩(不信任工作区代码),这是与 CargoWall "step 边界"的差异——我们罩"整棵 npm ci 树"而不是"某个 workflow step"。

## 7. 里程碑

- **M1 npm 支持** ✅:shim enforce/audit 双模式 E2E 实测(含恶意包 demo、范围对照);npm 11 install-scripts 准入与网络面的互补关系已写入 §1;
- **M2 多生态 + 一行接入** ✅(2026-11-04,沙箱可做部分):①legacy 解析器家族(gethostbyname 家族/getaddrinfo_a)钩住——域名门无绕过、解析结果统一入缓存,**DNS 刷新(长任务 registry 换 IP)误拒正解落地**;②cargo(build.rs)与 uv(setup.py 构建后端)双生态实测,rustc 动态链接实证收窄 §5.1;③GH Action 复合 action + workflow 样例(**沙箱无 runner,YAML 未真机跑**);④证据接 04-fabric(fw2fabric 桥全链路实测)。遗留:bpf-lsm on VM 对拍、GH Actions 真机;
- **M3 误报调优**:生态默认白名单沉淀(`allowlists/*.txt` 起步即此);~~SNI 解析补 DOH 盲区~~
  **✅ 已落地为 preload 版 SNI 门 + DoH 打标(2026-11-08,比 CargoWall 的 eBPF 解析便宜:
  我们本来就在 LD_PRELOAD 里,hook libssl 即可,工程注记见 §5.1)**;证据集群视图(桥已就位,hub 侧视图待做)。
