# 05 — AI 供应链"安装期防火墙"(方向5)

包管理器 install 期 = 任意代码执行窗口。给这段调用树强制出网白名单:白名单外 connect 一律阻断 + 落证据账本。设计论证见 `design.md`;点子出处 `../../ebpf-agent-ideas-2026-11.md` 方向5。

## 状态矩阵(2026-11-08,M3/链账本轮,本沙箱无 root)

| 组件 | 状态 |
|---|---|
| `shim/fwshim.c` LD_PRELOAD 拦截器(getaddrinfo + **gethostbyname 家族/getaddrinfo_a** + connect + **SSL_ctrl/gnutls_server_name_set SNI 门**,域名/IP/CIDR 白名单,DoH 端点打标,JSONL 证据) | ✅ 编译零告警,**E2E 48/48 真跑通过** |
| `shim/fw-run` 启动器(enforce/audit 双模式,**白名单/证据路径自动绝对化**;`--chain` 运行后证据套 07 号哈希链+封存点) | ✅ 实测 |
| legacy 解析器家族钩子(gethostbyname{,2}{,_r}、getaddrinfo_a+gai_suspend) | ✅ **ctypes 直调 libc 实测**:未申报域名掐在解析器,解析结果入缓存喂 connect(DNS 刷新不误拒) |
| `demo/cargo-evil`(build.rs 构建期外联样本,本机无害) | ✅ enforce 下 connect 得 os error 1、resolve 掐在解析器;**实证 rustc 默认输出落在 preload 罩内** |
| `demo/pypi-evil`(setup.py 构建后端外联样本,本机无害) | ✅ enforce 下同样双拦;uv 构建隔离子进程继承 env,实测罩内 |
| `demo/evil-pkg` / `demo/benign-pkg`(npm postinstall 样本) | ✅ 同 M1 |
| `demo/doh-server.py` | ✅ 本机假 DoH 解析器 + 假共享 CDN(同实例同 IP):`ext.` 前缀 qname 返白名单外 IP(TEST-NET-3),其余返 127.0.0.1 模拟 C2 与白名单服务共 CDN |
| `demo/doh-client.py` | ✅ 恶意 postinstall 风格 DoH 样本:绕过 getaddrinfo 门的 HTTPS 解析 + 可选 TLS/SNI,逐步落行供断言 |
| `test/test_fw.sh` E2E(11 组场景 A-J) | ✅ **56/56** |
| `ci/install-fw-action`(GH Action 复合 action)+ `ci/github-actions-example.yml` + `ci/gh-smoke-standalone.yml` | ✅ **GH Actions 真机实测**(2026-11-07,ubuntu-latest 托管 runner,run 42369109907):deny-connect 红(设计内,空白名单 fail-closed,shim `BLOCKED connect`,curl exit 7)、allow-domain 绿(resolve→connect 双 allow,52ms),证据 artifact 同 schema;无 root 托管 runner 照常工作 |
| `fabric/fw2fabric.py` 证据 → 04-fabric 桥 | ✅ **全链路实测**:ev.jsonl → 桥 → node.py → hub /timeline(deny 事件 + qname + host/session 归属全对);LSM connect 事件 qname 透传(host enrich 后重测,2026-11-06);sni 事件同型透传(2026-11-08) |
| `bpf-lsm/install_fw.py` BPF LSM 模式(内核强制) | ✅ **VM 实测**(2026-11-06,6.12.115):四联判定全绿(EPERM/ECONNREFUSED/HTTP 404/静态 Go 拒),首跑逼出三 bug(bprm envp 不可行→loader 直标/LPM 字节序/CIDR prefixlen);**host enrich 同日二轮实测**:域名条目解析出的 IP 与裸 IP /32 把白名单字面量写进证据 host 字段(deny/解析器行留空),对账/fabric 侧从此能答"这个连接属于哪个申报域名" |
| `bpf-lsm/install_fw.py` **SNI 域门**(`--sni`:SSL_ctrl cmd==55 + gnutls_server_name_set uprobe → 内核内哈希白名单 → 未批准投毒 tgid,LSM sendmsg 拦发) | ✅ **VM 实测**(2026-11-08,三跑 27/27):preload 版 npm/node SNI 盲区闭环(--sni-bin 挂 node 自带 SSL_ctrl,comm=MainThread);ClientHello 出不了门(零竞态);fabric 桥 sni 行透传重验 |
| `bpf-lsm/test_sni_lsm.sh` E2E(场景组 L,9 例 27 断言) | ✅ **27/27 三连跑**(curl/node/npm run/python allow+deny + GnuTLS 捕获 + 圈外对照 + IP 门回归 + 服务端零请求计数) |

## 快速开始(无 root 即可)

```bash
cd playbooks/05-supply-firewall
gcc -O2 -Wall -Wextra -shared -fPIC -o shim/fwshim.so shim/fwshim.c -ldl -lpthread

# 上线前调参:audit 一周,看证据里冒出什么再定白名单
shim/fw-run --mode audit --allow allowlists/npm.txt -- npm install <pkg>

# 强制模式:白名单外 connect → EPERM,证据落 runs/fw-<ts>.jsonl
shim/fw-run --mode enforce --allow allowlists/npm.txt -- npm ci

# cargo / uv(pypi)同构;构建后端子进程随 env 继承入罩
shim/fw-run --mode enforce --allow allowlists/cargo.txt -- cargo build --release
shim/fw-run --mode enforce --allow allowlists/pypi.txt  -- uv pip install -r requirements.txt
```

CI 一行接入(复合 action,证据自动 artifact):

```yaml
- uses: ./playbooks/05-supply-firewall/ci/install-fw-action
  with: { mode: enforce, allowlist: playbooks/05-supply-firewall/allowlists/npm.txt, command: npm ci }
- if: always()   # 无论成败上传证据
  uses: actions/upload-artifact@v4
  with: { name: install-fw-evidence, path: install-fw-evidence.jsonl }
```

完整样例见 `ci/github-actions-example.yml`;独立测试仓形态(runbook 任务 2,已真机验证)见 `ci/gh-smoke-standalone.yml`——注意两种布局下 action.yml 的 ROOT 解析不同,见文件头注。首跑 `--mode audit` 收一周证据 → 人工定白名单 → 切 enforce。

复现攻击样本演练(全部动作无害、只碰本机):

```bash
bash test/test_fw.sh        # 10 组场景 E2E,自带本地采集器;场景G 需代理预取一次 setuptools
```

预期:evil 包 postinstall 连 `127.0.0.1:9999` 得 **EPERM**(而非 ECONNREFUSED,区分"被防火墙掐"与"没人听");解析 `c2.evil.example` 被掐在解析器;**cargo build.rs 与 uv setup.py 里的外联同样被拦**;证据账本 deny 行带 pid/ppid/comm/argv,可回放是哪次 install 的哪个脚本发起;证据经 `fabric/fw2fabric.py` 直上 04-fabric hub 出跨机时间线。

## 文件

| 文件 | 说明 |
|---|---|
| `shim/fwshim.c` | LD_PRELOAD 拦截器。FW_SCOPE=1 才激活(零影响系统其余进程);FW_MODE=enforce/audit;FW_ALLOW 白名单;FW_EVIDENCE JSONL。拦截 getaddrinfo、gethostbyname{,2}{,_r}、getaddrinfo_a(+gai_suspend 缓存)、connect |
| `shim/fw-run` | 启动器,注入 env + LD_PRELOAD 后 exec;白名单/证据路径自动绝对化(install 期子进程会换 cwd);`--chain` 运行后证据入 07 号哈希链+封存点(FW_CHAIN_KEY=hex 文件时 HMAC 签名) |
| `allowlists/{npm,cargo,pypi}.txt` | 生态默认白名单起步(M3 沉淀) |
| `demo/evil-pkg` `demo/benign-pkg` | npm postinstall 拦截/放行样本(本机无害) |
| `demo/cargo-evil` | build.rs 构建期外联样本:域名解析 + 本机 connect(本机无害) |
| `demo/pypi-evil` | setup.py 构建后端外联样本(本机无害) |
| `ci/install-fw-action/action.yml` | GH Action 复合 action:编译 shim → 注入 env/LD_PRELOAD → 跑受罩命令 |
| `ci/github-actions-example.yml` | workflow 样例(含证据 artifact 上传) |
| `ci/gh-smoke-standalone.yml` | 独立测试仓形态冒烟 workflow(2026-11-07 真机验证;两种布局的 ROOT 解析差异见头注) |
| `fabric/fw2fabric.py` | 证据 → canonical schema 桥:resolve/connect → type=net(域名进 qname),session → raw;落盘喂 node.py 或直 POST hub |
| `bpf-lsm/install_fw.py` | BCC + LSM(loader 直标 tgid + fork 继承圈树,6.12 已删 bprm envp)+ socket_connect LPM 强制 + 同 schema 证据(host 字段带已解析域名);自动放行 /etc/resolv.conf 解析器 |
| `test/test_fw.sh` | E2E:A 放行 / B 拦截 / C 范围对照 / D audit / E legacy 解析器 / F cargo / G uv / H fabric 桥 / I DoH 与共享 CDN(SNI 门) / J 证据链(--chain:入链/外部封存/改账检出/rc 透传) |

## 与 npm 11 install-scripts 准入的关系(实测发现)

npm 11.19 默认**不跑**未批准的 install scripts(`npm install-scripts approve` 准入)。它管"脚本跑不跑",本项目管"**整棵 install 调用树能碰哪些网络**"——脚本被批准后的恶意行为、传递依赖脚本、构建期下载,都由网络面兜底。两层正交,测试里为此走"装一次→approve→重装"三步舞(见 test_fw.sh 的 `npm_preflight_approve`)。

## 本轮实测发现(2026-11-04,M2)

1. **rustc 默认输出是 glibc 动态链接**——build.rs 编译出的原生二进制落在 LD_PRELOAD 罩内,resolve/connect 全被拦(实证)。design.md §5.1 的悲观预估收窄:罩不住的不是 build.rs 本身,而是 build.rs 里下载再执行的静态/musl/Go 二进制(那才是 BPF LSM 模式的硬靶)。
2. **fw-run 必须绝对化白名单/证据路径**:npm 在包目录跑 postinstall、cargo 在包目录跑 build.rs,相对路径在子进程 cwd 下打不开 → fail-closed 会误拦良性构建。已修,fw-run 内 `readlink -f`。
3. **cargo 捕获 build.rs 的 stdout**(只在 `-vv` 下回显)——判定恶意行为要么 `-vv`,要么以证据 JSONL 为准(推荐后者,comm=`build-script-bu` 15 字符截断可精确定位)。
4. **Python 3.13 的 `socket.gethostbyname` 内部走 setipaddr→getaddrinfo**,不碰 legacy 符号——验 gethostbyname 钩子必须 ctypes 直调 libc(测试里就是这么做的)。钩住 legacy 家族的真实意义在遗留 C 代码与其它脚本生态。
5. uv 构建隔离(isolated build env)的子进程继承 env:LD_PRELOAD/FW_SCOPE 原样入罩,`uv pip install --offline` 可用缓存预取的 setuptools 模拟"CI 镜像预装工具链"。

## 已知边界(preload 模式,完整论证在 design.md §5)

静态/Go 二进制绕过(不走 libc)→ BPF LSM 模式的存在理由;c-ares 原生 UDP DNS 盲 → 后续加
sendmsg 钩子;**DoH/DoT(2026-11-08 起)**:解析面绕过但非出网绕过 —— enforce 默认拒绝下
解析器 IP 白名单外照样 connect EPERM,真盲是审计面(qname 在 TLS 里)→ 已知公共解析器
IP/域名证据打 note=doh-endpoint、`FW_DOH=deny` 强制拒(白名单内也拒);**共享 CDN IP 死角
已由 SNI 门堵上**(SSL_ctrl/gnutls_server_name_set,握手前判白名单,未申报即 shutdown/拒设)
—— 覆盖 curl/python(OpenSSL 系)与 GnuTLS 客户端;node 的 BoringSSL 对 preload 盲
(npm 生命周期脚本 HTTPS),**已由 BPF LSM SNI 域门闭环**(2026-11-08,--sni-bin 挂
node 自带 SSL_ctrl,场景组 L);QUIC(HTTP/3)的 SNI 在 UDP 里未覆盖,与 Go crypto/tls
(无 SSL_ctrl 等价物)同归 IP 门兜底 + 后置故事;res_* 原生解析 API(MX/TXT 类查询,误拦面大)不钩;
getaddrinfo_a 轮询 gai_error 的程序解析结果不缓存(gai_suspend 路径已缓存,构建工具链几乎
不碰该 API)。**当前不宣称对恶意样本完备,宣称:无特权可部署、默认拒绝可执行、每一次被拦
都有可回放证据。**

另:白名单文件缺失/不可读时 fail-closed(全部拒绝,实测确认)——宁误拒不漏拦,CI 里表现为构建失败 + stderr 提示,而非静默放行。

## BPF LSM SNI 域门(2026-11-08,VM 6.12.115,三跑 27/27)

preload SNI 门的内核侧对偶:同一个故事(共享 CDN IP 死角 → 按 SNI 判),换到内核执行,
**把 preload 版最大的盲区(npm/node 生命周期脚本 HTTPS)一并堵上**——node 的 BoringSSL
不走 PLT,preload 钩不到,但它导出 `SSL_ctrl` 符号,BPF uprobe 直接挂符号地址即可。

**机制**(`install_fw.py --sni`):

1. uprobe 捕 SNI:libssl.so.3 与 node 自带 BoringSSL 的 `SSL_ctrl`(cmd==55 即
   SSL_set_tlsext_host_name 落底)+ libgnutls.so.30 的 `gnutls_server_name_set`(type 0/1);
   `--sni-bin <路径>` 对自带 TLS 库的二进制(node 等)补挂;
2. 内核内同步:FNV-1a64(小写)查哈希白名单,未批准 → `sni_poison[tgid]=1`;
3. LSM `socket_sendmsg`:投毒 tgid 的写族一律 -EPERM——SNI-set 先于握手,故
   **ClientHello 出不了门,零竞态**(preload 版的 fd 时序问题在内核侧不存在);
4. 证据行:`event=sni`(allow note=bpf-lsm / deny note=bpf-lsm-sni-gate)+ 拦发行
   `event=send`;schema 与 preload 对齐,fw2fabric 桥零改动透传(sni→net/qname、send→raw)。

**实测**(场景组 L,`test_sni_lsm.sh`,9 例 27 断言):curl/node/npm run/python 的
allow+deny 双向、GnuTLS fixture 捕获行、圈外对照、IP 门回归、服务端零请求计数
(doh-server 假共享 CDN 记路径)全绿;三连跑稳定。关键教训(verifier 三坑、IP SNI 不特判、
node comm=MainThread)沉淀在 design.md §5.2。

**边界**:Go crypto/tls 与 QUIC 无 SSL_ctrl 等价物 → IP 门兜底;无 SNI 的 ClientHello 盲
(证书校验兜底);投毒粒度 = tgid(fail-closed);剥符号二进制 attach 失败告警跳过。

## DoH/SNI 门实测发现(2026-11-08)

1. **DoH 在 enforce 下不是出网绕过**(此前 §5.3 表述过重):解析器不在白名单 → connect EPERM;
   解析器在白名单 → DoH 拿到 IP 后 connect 照拒(场景 I1/I2)。真空洞是**共享 CDN IP**:
   registry 在 Cloudflare 后面时已批准缓存里必有 CDN IP,C2 落同一 CDN 时 IP 门放行 ——
   SNI 门(SSL_ctrl/gnutls 钩子)是唯一解,DoH 只是这个洞的马甲之一;
2. **curl 设 SNI 与 SSL_set_fd 分属 step1/step2** —— SSL_ctrl 时刻拿不到 fd,直接 shutdown
   不可行;待杀名单记下待拒 ssl,fd 落上时(SSL_set_fd 钩)再拦死。python 则 fd 已在,
   SSL_ctrl 时即可掐;
3. **python 的 libssl 是 RTLD_LOCAL dlopen 加载** —— `dlsym(RTLD_NEXT)` 返回 NULL,不守卫
   就是段错误;必须回落 `dlopen("libssl.so.N")`;
4. **ctypes dlsym(handle) 直调绕过 interposition**(验 GnuTLS 钩子必须 PLT 编译型 fixture,
   `-Wl,-l:libgnutls.so.30` 无需 dev 包);curl 8.14 带 nghttp3,QUIC 的 SNI 在 UDP 里,
   sendto 未钩,预声明边界。

## 里程碑

- **M1 npm 支持** ✅;
- **M2 多生态 + 一行接入** ✅:cargo/uv 实测、GH Action 形态、DNS 刷新(legacy 解析器家族)修复、证据接 04-fabric;GH Actions 真机 2026-11-07 实测(ubuntu-latest,deny/allow 双 job 判定全中,run 42369109907),bpf-lsm on VM 2026-11-06 实测(四联判定全绿);
- **M3 误报调优**:生态默认白名单沉淀、~~SNI 解析补 DOH 盲区~~ **✅ preload 版 SNI 门 + DoH 打标(2026-11-08,场景组 I)**、**✅ 内核版 SNI 域门(2026-11-08,场景组 L,npm/node 盲区闭环)**、证据集群视图(桥已就位)。
