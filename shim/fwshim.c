/*
 * fwshim.c — 安装期出网防火墙,LD_PRELOAD 拦截器
 *
 * 范围:仅当环境变量 FW_SCOPE=1 时激活(由 fw-run 注入,随 fork/exec 继承);
 *       没有该变量时完全惰性,零开销、零日志 —— 防火墙只罩住被审计的那次安装调用树。
 * 白名单:FW_ALLOW 文件,每行一个:域名 / *.后缀通配 / IPv4 字面量 / IPv4 CIDR / IPv6 字面量
 * 证据:FW_EVIDENCE 指向 JSONL 追加写文件(O_APPEND 单 write,进程内串行)
 * 模式:FW_MODE=enforce(默认,拦) | audit(只记不拦,用于白名单调参)
 *
 * 拦截点:
 *   getaddrinfo — 域名白名单判定;enforce 下未申报域名直接 EAI_NONAME(掐在解析器);
 *                 IP 字面量节点放行解析(不缓存),由 connect 层按 IP 白名单判;
 *   connect     — AF_INET/AF_INET6 目的地址比对"已批准 IP 缓存 ∪ 白名单 IP/CIDR",
 *                 未命中 enforce 返回 EPERM;
 *   gethostbyname{,_r}/gethostbyname2{,_r}/getaddrinfo_a(+gai_suspend)
 *               — 同一套域名判定与缓存。缺了它们,Python socket.gethostbyname、
 *                 遗留 C 代码、异步解析会绕过域名门,且其解析结果进不了已批准
 *                 缓存 → 长任务里 registry 换 IP(DNS 刷新)即被误拒。
 *
 * 已知边界(design.md 有完整论证):静态链接/Go 二进制走原生 syscall 绕过;
 * c-ares 原生 UDP DNS 不经 libc;这两条是 BPF LSM 模式(bpf-lsm/)存在的理由。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_HOSTS 64
#define MAX_IPENTS 64
#define MAX_PERM4 4096
#define MAX_PERM6 256
#define HOST_LEN 128

struct host_ent { char host[HOST_LEN]; int wild; };      /* wild = "*.foo" 前缀 */
struct v4ent   { uint32_t addr, mask; };

static struct host_ent g_hosts[MAX_HOSTS]; static int g_nhosts;
static struct v4ent   g_v4[MAX_IPENTS];    static int g_nv4;
static struct in6_addr g_v6[MAX_IPENTS];   static int g_nv6;

static uint32_t g_perm4[MAX_PERM4]; static int g_nperm4;
static struct in6_addr g_perm6[MAX_PERM6]; static int g_nperm6;

static int g_active;          /* FW_SCOPE=1 */
static int g_enforce = 1;     /* FW_MODE=audit -> 0 */
static int g_evfd = -1;
static char g_self[64];       /* comm */
static char g_argv[256];      /* /proc/self/cmdline 截断 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static int (*real_gai)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static struct hostent *(*real_ghbn)(const char *);
static struct hostent *(*real_ghbn2)(const char *, int);
static int (*real_ghbn_r)(const char *, struct hostent *, char *, size_t,
                          struct hostent **, int *);
static int (*real_ghbn2_r)(const char *, int, struct hostent *, char *, size_t,
                           struct hostent **, int *);
static int (*real_gai_a)(int, struct gaicb **, int, struct sigevent *);
static int (*real_gai_suspend)(const struct gaicb *const *, int, const struct timespec *);

static void init_reals(void)
{
    real_connect     = dlsym(RTLD_NEXT, "connect");
    real_gai         = dlsym(RTLD_NEXT, "getaddrinfo");
    real_ghbn        = dlsym(RTLD_NEXT, "gethostbyname");
    real_ghbn2       = dlsym(RTLD_NEXT, "gethostbyname2");
    real_ghbn_r      = dlsym(RTLD_NEXT, "gethostbyname_r");
    real_ghbn2_r     = dlsym(RTLD_NEXT, "gethostbyname2_r");
    real_gai_a       = dlsym(RTLD_NEXT, "getaddrinfo_a");
    real_gai_suspend = dlsym(RTLD_NEXT, "gai_suspend");
}

/* ---------- 小工具 ---------- */

static int json_escape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 8 < outsz; p++) {
        if (*p == '"' || *p == '\\') { out[o++] = '\\'; out[o++] = *p; }
        else if (*p == '\n')  { out[o++]='\\'; out[o++]='n'; }
        else if (*p == '\r')  { out[o++]='\\'; out[o++]='r'; }
        else if (*p == '\t')  { out[o++]='\\'; out[o++]='t'; }
        else if (*p < 0x20)   { o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", *p); }
        else out[o++] = (char)*p;
    }
    out[o] = 0;
    return (int)o;
}

static void read_proc_meta(void)
{
    FILE *f;
    char buf[512];
    if (g_self[0] == 0) {
        f = fopen("/proc/self/comm", "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f)) {
                buf[strcspn(buf, "\n")] = 0;
                snprintf(g_self, sizeof(g_self), "%.*s", (int)sizeof(g_self) - 1, buf);
            }
            fclose(f);
        }
    }
    if (g_argv[0] == 0) {
        f = fopen("/proc/self/cmdline", "r");
        if (f) {
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            /* NUL 分隔改空格 */
            for (size_t i = 0; i < n; i++) if (buf[i] == 0) buf[i] = ' ';
            buf[n] = 0;
            snprintf(g_argv, sizeof(g_argv), "%.*s", (int)sizeof(g_argv) - 1, buf);
        }
    }
}

static pid_t read_ppid(void)
{
    FILE *f = fopen("/proc/self/stat", "r");
    if (!f) return 0;
    char buf[512];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
    fclose(f);
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    p += 2;                                 /* 跳过 ") ",停在 state 字段 */
    p += 1;                                 /* state 是单个字母,跳过 */
    while (*p == ' ') p++;
    return (pid_t)strtol(p, NULL, 10);      /* ppid */
}

/* ---------- 证据账本 ---------- */

static void emit(const char *event, const char *action,
                 const char *host, const struct sockaddr *sa, const char *note)
{
    if (g_evfd < 0) return;
    char line[1024], esch[256], esargv[320], esnote[128], dst[96];
    dst[0] = 0;

    if (sa && sa->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)sa;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip));
        snprintf(dst, sizeof(dst), "%s:%u", ip, (unsigned)ntohs(a->sin_port));
    } else if (sa && sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)sa;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
        snprintf(dst, sizeof(dst), "[%s]:%u", ip, (unsigned)ntohs(a->sin6_port));
    }

    json_escape(host ? host : "", esch, sizeof(esch));
    json_escape(g_argv, esargv, sizeof(esargv));
    json_escape(note ? note : "", esnote, sizeof(esnote));

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms = (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    int n = snprintf(line, sizeof(line),
        "{\"ts\":%ld,\"pid\":%d,\"ppid\":%d,\"comm\":\"%s\",\"argv\":\"%s\","
        "\"event\":\"%s\",\"action\":\"%s\",\"dst\":\"%s\",\"host\":\"%s\",\"note\":\"%s\"}\n",
        ms, (int)getpid(), (int)read_ppid(), g_self, esargv, event, action, dst, esch, esnote);
    if (n > 0) {
        pthread_mutex_lock(&g_lock);
        if (write(g_evfd, line, (size_t)n) < 0) { /* 证据写失败不折腾宿主 */ }
        pthread_mutex_unlock(&g_lock);
    }

    if (g_enforce && strcmp(action, "deny") == 0) {
        fprintf(stderr, "[install-fw] BLOCKED %s %s %s%s%s (pid %d comm %s)\n",
                event, dst[0] ? dst : "", host ? host : "", note && note[0] ? " " : "",
                note && note[0] ? note : "", (int)getpid(), g_self);
    }
}

/* ---------- 白名单 ---------- */

static void parse_allow_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[install-fw] cannot open allowlist %s: %s\n", path, strerror(errno));
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == 0) continue;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) *--e = 0;

        struct in_addr a4; struct in6_addr a6;
        char *slash = strchr(s, '/');
        /* 先截掉 /len 再验 IPv4:inet_pton 不吃 CIDR 串;
         * 旧写法两分支都拿原串 s 验,IPv4/len 永远落到域名桶(VM 实测 S3 抓出) */
        char tmp[64];
        long hostlen = slash ? (long)(slash - s) : (long)strlen(s);
        snprintf(tmp, sizeof(tmp), "%.*s", (int)hostlen, s);
        if (inet_pton(AF_INET, tmp, &a4) == 1) {
            if (g_nv4 < MAX_IPENTS) {
                uint32_t bits = slash ? (uint32_t)atoi(slash + 1) : 32;
                if (bits > 32) bits = 32;
                uint32_t mask = bits ? ~((1u << (32 - bits)) - 1) : 0;
                g_v4[g_nv4].addr = ntohl(a4.s_addr) & mask;
                g_v4[g_nv4].mask = mask;
                g_nv4++;
            }
        } else if (inet_pton(AF_INET6, s, &a6) == 1) {
            if (g_nv6 < MAX_IPENTS) g_v6[g_nv6++] = a6;
        } else if (g_nhosts < MAX_HOSTS) {
            int wild = (s[0] == '*' && s[1] == '.');
            snprintf(g_hosts[g_nhosts].host, HOST_LEN, "%s", wild ? s + 2 : s);
            g_hosts[g_nhosts].wild = wild;
            g_nhosts++;
        }
    }
    fclose(f);
}

static int host_allowed(const char *h)
{
    for (int i = 0; i < g_nhosts; i++) {
        if (!g_hosts[i].wild) {
            if (strcasecmp(h, g_hosts[i].host) == 0) return 1;
        } else {
            size_t hl = strlen(g_hosts[i].host), nl = strlen(h);
            if (nl >= hl && strcasecmp(h + nl - hl, g_hosts[i].host) == 0 &&
                (nl == hl || h[nl - hl - 1] == '.'))
                return 1;
        }
    }
    return 0;
}

static int v4_permitted(uint32_t ip)   /* 主机序 */
{
    for (int i = 0; i < g_nv4; i++)
        if ((ip & g_v4[i].mask) == g_v4[i].addr) return 1;
    for (int i = 0; i < g_nperm4; i++)
        if (g_perm4[i] == ip) return 1;
    return 0;
}

static int v6_permitted(const struct in6_addr *a)
{
    for (int i = 0; i < g_nv6; i++)
        if (memcmp(a, &g_v6[i], 16) == 0) return 1;
    for (int i = 0; i < g_nperm6; i++)
        if (memcmp(a, &g_perm6[i], 16) == 0) return 1;
    return 0;
}

/* 已批准缓存只增不减:同域名的 DNS 刷新(换 IP)随新解析自动入缓存。
 * 缓存与白名单判定同一把锁,connect 读时无需二次加锁(整数/16字节读原子性足够)。 */
static void cache_raw_v4(uint32_t ip)   /* 主机序 */
{
    for (int i = 0; i < g_nperm4; i++) if (g_perm4[i] == ip) return;
    if (g_nperm4 < MAX_PERM4) g_perm4[g_nperm4++] = ip;
}

static void cache_raw_v6(const struct in6_addr *a)
{
    for (int i = 0; i < g_nperm6; i++) if (!memcmp(a, &g_perm6[i], 16)) return;
    if (g_nperm6 < MAX_PERM6) g_perm6[g_nperm6++] = *a;
}

static void cache_addrs(const struct addrinfo *res)
{
    pthread_mutex_lock(&g_lock);
    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(struct sockaddr_in)) {
            cache_raw_v4(ntohl(((const struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr));
        } else if (ai->ai_family == AF_INET6 && ai->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            const struct in6_addr *a = &((const struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
            if (IN6_IS_ADDR_V4MAPPED(a))
                cache_raw_v4(ntohl(*(const uint32_t *)(a->s6_addr + 12)));
            else
                cache_raw_v6(a);
        }
    }
    pthread_mutex_unlock(&g_lock);
}

static void cache_hostent(const struct hostent *he)
{
    if (!he || !he->h_addr_list) return;
    pthread_mutex_lock(&g_lock);
    for (char **a = he->h_addr_list; *a; a++) {
        if (he->h_addrtype == AF_INET && he->h_length == 4)
            cache_raw_v4(ntohl(((const struct in_addr *)*a)->s_addr));
        else if (he->h_addrtype == AF_INET6 && he->h_length == 16)
            cache_raw_v6((const struct in6_addr *)*a);
    }
    pthread_mutex_unlock(&g_lock);
}

/* ---------- 生命周期 ---------- */

__attribute__((constructor(101)))
static void fwshim_init(void)
{
    const char *scope = getenv("FW_SCOPE");
    g_active = scope && strcmp(scope, "1") == 0;
    if (!g_active) return;

    const char *mode = getenv("FW_MODE");
    if (mode && strcmp(mode, "audit") == 0) g_enforce = 0;

    const char *allow = getenv("FW_ALLOW");
    if (allow && allow[0]) parse_allow_file(allow);

    const char *ev = getenv("FW_EVIDENCE");
    if (ev && ev[0]) {
        g_evfd = open(ev, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (g_evfd < 0)
            fprintf(stderr, "[install-fw] cannot open evidence %s: %s\n", ev, strerror(errno));
    }
    read_proc_meta();
    emit("session", "start", NULL, NULL, g_enforce ? "enforce" : "audit");
}

__attribute__((destructor))
static void fwshim_fini(void)
{
    if (g_active && g_evfd >= 0) {
        emit("session", "end", NULL, NULL, NULL);
        close(g_evfd);
        g_evfd = -1;
    }
}

/* ---------- 被拦截的符号 ---------- */

/* gethostbyname 家族的域名判定:同一套白名单;enforce 下未申报域名返回 0(调用方
 * 置 h_errno=HOST_NOT_FOUND 并返回失败)。IP 字面量放行(connect 层裁决)。
 * 注意 h_errno 只对非 _r 变体有意义,_r 变体走 *h_errnop 参数。 */
static int legacy_name_check(const char *name)
{
    if (!g_active) return 1;
    read_proc_meta();
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, name, &a4) == 1 || inet_pton(AF_INET6, name, &a6) == 1)
        return 1;
    if (host_allowed(name)) return 1;
    if (g_enforce) {
        emit("resolve", "deny", name, NULL, "legacy-resolver");
        h_errno = HOST_NOT_FOUND;
        return 0;
    }
    emit("resolve", "audit-deny", name, NULL, "legacy-resolver");
    return 1;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res)
{
    if (!real_gai) init_reals();
    if (!g_active || !node || !node[0]) return real_gai(node, service, hints, res);

    read_proc_meta();
    struct in_addr a4; struct in6_addr a6;
    int numeric = inet_pton(AF_INET, node, &a4) == 1 || inet_pton(AF_INET6, node, &a6) == 1;
    int allowed = numeric
        ? (inet_pton(AF_INET, node, &a4) == 1
              ? v4_permitted(ntohl(a4.s_addr))
              : v6_permitted(&a6))
        : host_allowed(node);

    if (numeric) {
        /* IP 字面量:放行解析,缓存与否由 connect 层裁决(常见于硬编码 C2) */
        emit("resolve", allowed ? "allow" : (g_enforce ? "deny" : "audit-deny"),
             node, NULL, numeric ? "ip-literal" : NULL);
        int r = real_gai(node, service, hints, res);
        if (r == 0 && allowed && res) cache_addrs(*res);
        return r;
    }

    if (!allowed && g_enforce) {
        emit("resolve", "deny", node, NULL, "blocked-at-resolver");
        return EAI_NONAME;   /* 掐在解析器,不给真实地址 */
    }

    int r = real_gai(node, service, hints, res);
    if (r == 0) {
        emit("resolve", allowed ? "allow" : (g_enforce ? "deny" : "audit-deny"),
             node, NULL, NULL);
        if (allowed && res) cache_addrs(*res);
        else if (res && *res) {
            /* audit 模式:未批准域名也给解析结果,但绝不进缓存 */
        }
    } else {
        emit("resolve", "resolve-failed", node, NULL, gai_strerror(r));
    }
    return r;
}

int connect(int fd, const struct sockaddr *sa, socklen_t len)
{
    if (!real_connect) init_reals();
    if (!g_active || !sa) return real_connect(fd, sa, len);

    if (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) {
        read_proc_meta();
        const struct sockaddr_in  *a4 = (const struct sockaddr_in *)sa;
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)sa;
        uint16_t port = sa->sa_family == AF_INET
            ? ntohs(a4->sin_port) : ntohs(a6->sin6_port);

        int ok;
        if (sa->sa_family == AF_INET) {
            ok = v4_permitted(ntohl(a4->sin_addr.s_addr));
        } else if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
            uint32_t v4;
            memcpy(&v4, a6->sin6_addr.s6_addr + 12, 4);
            ok = v4_permitted(ntohl(v4));
        } else {
            ok = v6_permitted(&a6->sin6_addr);
        }
        /* port 0 是 getaddrinfo AF_UNSPEC 辅助探测,不算出网意图 */
        const char *note = port == 0 ? "port0-probe" : NULL;
        if (!ok && port != 0) {
            emit("connect", g_enforce ? "deny" : "audit-deny", NULL, sa, NULL);
            if (g_enforce) { errno = EPERM; return -1; }
        } else {
            emit("connect", "allow", NULL, sa, note);
        }
    }
    return real_connect(fd, sa, len);
}

/* ---------- legacy 解析器家族:同策略、同缓存 ----------
 * 不钩它们:①Python socket.gethostbyname / 遗留 C 代码绕过域名门;
 * ②解析结果进不了已批准缓存 → 长任务里 registry 换 IP(DNS 刷新)被误拒。 */

struct hostent *gethostbyname(const char *name)
{
    if (!real_ghbn) init_reals();
    if (!g_active || !name || !name[0]) return real_ghbn(name);
    if (!legacy_name_check(name)) return NULL;
    struct hostent *h = real_ghbn(name);
    if (h) cache_hostent(h);
    return h;
}

struct hostent *gethostbyname2(const char *name, int af)
{
    if (!real_ghbn2) init_reals();
    if (!g_active || !name || !name[0]) return real_ghbn2(name, af);
    if (!legacy_name_check(name)) return NULL;
    struct hostent *h = real_ghbn2(name, af);
    if (h) cache_hostent(h);
    return h;
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen,
                    struct hostent **result, int *h_errnop)
{
    if (!real_ghbn_r) init_reals();
    if (!g_active || !name || !name[0])
        return real_ghbn_r(name, ret, buf, buflen, result, h_errnop);
    if (!legacy_name_check(name)) {
        if (result)  *result = NULL;
        if (h_errnop) *h_errnop = HOST_NOT_FOUND;
        return HOST_NOT_FOUND;
    }
    int r = real_ghbn_r(name, ret, buf, buflen, result, h_errnop);
    if (r == 0 && result && *result) cache_hostent(*result);
    return r;
}

int gethostbyname2_r(const char *name, int af, struct hostent *ret, char *buf, size_t buflen,
                     struct hostent **result, int *h_errnop)
{
    if (!real_ghbn2_r) init_reals();
    if (!g_active || !name || !name[0])
        return real_ghbn2_r(name, af, ret, buf, buflen, result, h_errnop);
    if (!legacy_name_check(name)) {
        if (result)  *result = NULL;
        if (h_errnop) *h_errnop = HOST_NOT_FOUND;
        return HOST_NOT_FOUND;
    }
    int r = real_ghbn2_r(name, af, ret, buf, buflen, result, h_errnop);
    if (r == 0 && result && *result) cache_hostent(*result);
    return r;
}

/* 异步解析:enforce 下任一未申报域名整批 EAI_NONAME(fail-closed);放行项的结果
 * 在 gai_suspend 返回后入缓存。轮询 gai_error 不经 suspend 的程序拿不到缓存,
 * 属残余边界(构建工具链几乎不碰 getaddrinfo_a)。 */
int getaddrinfo_a(int mode, struct gaicb **list, int nitems, struct sigevent *sevp)
{
    if (!real_gai_a) init_reals();
    if (!g_active || !list || nitems <= 0) return real_gai_a(mode, list, nitems, sevp);
    read_proc_meta();
    struct in_addr a4; struct in6_addr a6;
    for (int i = 0; i < nitems; i++) {
        const char *n = list[i] ? list[i]->ar_name : NULL;
        if (!n || !n[0]) continue;
        if (inet_pton(AF_INET, n, &a4) == 1 || inet_pton(AF_INET6, n, &a6) == 1) continue;
        if (host_allowed(n)) {
            emit("resolve", "allow", n, NULL, "getaddrinfo_a");
        } else if (g_enforce) {
            emit("resolve", "deny", n, NULL, "getaddrinfo_a");
            return EAI_NONAME;
        } else {
            emit("resolve", "audit-deny", n, NULL, "getaddrinfo_a");
        }
    }
    return real_gai_a(mode, list, nitems, sevp);
}

int gai_suspend(const struct gaicb *const *list, int nitems, const struct timespec *timeout)
{
    if (!real_gai_suspend) init_reals();
    int r = real_gai_suspend(list, nitems, timeout);
    if (g_active && g_enforce && r == 0 && list) {
        for (int i = 0; i < nitems; i++)
            if (list[i] && list[i]->ar_result) cache_addrs(list[i]->ar_result);
    }
    return r;
}
