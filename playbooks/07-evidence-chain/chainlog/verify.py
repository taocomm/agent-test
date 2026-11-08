#!/usr/bin/env python3
"""verify — 验证 chain_tee 产物,可选还原原事件流 / 写读封存点。

用法:
  verify.py <chained.jsonl>                # 验链,干净 exit 0
  verify.py <chained.jsonl> --unwrap       # 验链 + 还原原事件流到 stdout
  verify.py <chained.jsonl> --seal         # 验链 + 写封存点(缺省 <file>.seal.json)
  verify.py <chained.jsonl> --check-seal   # 验链 + 与封存点核对(防增删)
  verify.py <chained.jsonl> --seal-file P  # 封存点读写到 P(跨机封存:副本放别处)
  verify.py <chained.jsonl> --seal-key K   # 封存点带 HMAC-SHA256 签名(防伪造封存点)
  verify.py <chained.jsonl> --seal-priv K  # 封存点带 RSA 私钥签名(--seal 时;sealer ≠ verifier)
  verify.py <chained.jsonl> --seal-pub P   # 核验 RSA 签名(--check-seal 时;核验方只持公钥)

判伪能力:改内容(seq N 哈希失配)、删行(seq 断档)、加行/换序(封存点
尾哈希失配)、字节级触碰(file_bytes 失配——即使语义未变也报)。发现第一处
破坏即报行号与原因,exit 1。

seal 签名(lure-v11/v15/v17 行为级结论的产品化),两条互斥通道:
  HMAC(--seal-key):共享密钥,核验方必须持同一密钥;密钥与账本/封存点分机存放。
  RSA(--seal-priv / --seal-pub,2026-11-08):签名 payload = "seal-v2|seq|last_hash|
  file_bytes"(RSA-PKCS#1v1.5-SHA256,纯 stdlib 实现)。核验方只持公钥——公钥泄漏
  不构成伪造能力,验签机被整体攻陷也核得住(与 v11「seal 覆盖字节不担保来源」同源
  的分轨:seal 签名管封存点真伪,链哈希管账本字节)。私钥在采集/封存侧,永不随账本走。
  带 sig 的 seal 不给 --seal-pub = fail-closed exit 2;--seal-key 与 --seal-priv 互斥。
"""
import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone

GENESIS = "0" * 64

# ---- RSA-PKCS#1v1.5-SHA256 封存点签名(纯 stdlib;无 cryptography/openssl 依赖)----
SHA256_DI = bytes.fromhex("3031300d060960864801650304020105000420")  # DigestInfo 前缀
RSA_OID = bytes.fromhex("2a864886f70d010101")                        # 1.2.840.113549.1.1.1


def _pem_der(text):
    b64 = "".join(l for l in text.splitlines() if l.strip() and not l.startswith("-----"))
    return base64.b64decode(b64)


def _asn1(buf):
    """读一个 TLV → (tag, content, 余下字节)"""
    tag = buf[0]
    ln = buf[1]
    i = 2
    if ln & 0x80:
        nbytes = ln & 0x7F
        ln = int.from_bytes(buf[i:i + nbytes], "big")
        i += nbytes
    return tag, buf[i:i + ln], buf[i + ln:]


def _seq_items(der):
    """der = 一个 SEQ TLV → 返回其子 TLV 列表 [(tag, content), ...]"""
    t, c, _ = _asn1(der)
    if t != 0x30:
        raise ValueError("期望 SEQUENCE")
    items, buf = [], c
    while buf:
        it, cc, buf = _asn1(buf)
        items.append((it, cc))
    return items


def _rsa_key_from_pkcs1(seq_der):
    """RSAPrivateKey SEQ{ver,n,e,d,p,q,dp,dq,qinv} → (n,e,d);RSAPublicKey SEQ{n,e} → (n,e,None)"""
    ints = [int.from_bytes(c, "big") for t, c in _seq_items(seq_der) if t == 0x02]
    if len(ints) >= 9:                    # 私钥:ver=0, n, e, d, p, q, dp, dq, qinv
        return ints[1], ints[2], ints[3]
    if len(ints) == 2:                    # 公钥:n, e
        return ints[0], ints[1], None
    raise ValueError(f"RSA 密钥整数项数异常: {len(ints)}")


def load_rsa_key(pem_text):
    """公钥(SubjectPublicKeyInfo)或私钥(PKCS#8 / PKCS#1)→ (n, e, d);公钥 d=None"""
    der = _pem_der(pem_text)
    head = pem_text.strip().splitlines()[0]
    if "BEGIN RSA PRIVATE KEY" in head:                      # PKCS#1 私钥
        return _rsa_key_from_pkcs1(der)
    items = _seq_items(der)
    if "BEGIN PUBLIC KEY" in head:                           # SubjectPublicKeyInfo: SEQ{SEQ{OID,NULL}, BITSTRING}
        (t1, algid), (t2, bit) = items[0], items[1]
        if t1 != 0x30 or t2 != 0x03:
            raise ValueError("公钥 PEM 结构不符")
        if _asn1(algid)[1] != RSA_OID:   # algid children 首个 TLV = OID
            raise ValueError("非 RSA 公钥")
        n, e, _ = _rsa_key_from_pkcs1(bit[1:])  # BITSTRING 首字节 = 未用位数(0)
        return n, e, None
    if "BEGIN PRIVATE KEY" in head:                          # PKCS#8: SEQ{ver, SEQ{OID,NULL}, OCTETSTRING}
        (t3, octet) = items[2]
        if t3 != 0x04:
            raise ValueError("私钥 PEM 结构不符")
        return _rsa_key_from_pkcs1(octet)
    raise ValueError(f"不支持的 PEM 形态: {head}")


def _em_padded(payload: bytes, k: int) -> bytes:
    di = SHA256_DI + hashlib.sha256(payload).digest()
    return b"\x00\x01" + b"\xff" * (k - len(di) - 3) + b"\x00" + di


def rsa_sign(payload: bytes, key) -> bytes:
    n, _e, d = key
    if d is None:
        raise ValueError("签名需要私钥")
    k = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(_em_padded(payload, k), "big"), d, n).to_bytes(k, "big")


def rsa_verify(payload: bytes, sig: bytes, key) -> bool:
    n, e, _d = key
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    return hmac.compare_digest(em, _em_padded(payload, k))


def seal_payload(s) -> bytes:
    return f"seal-v2|{s.get('seq')}|{s.get('last_hash')}|{s.get('file_bytes')}".encode()


def canonical(data) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))


def expected_hash(prev: str, data) -> str:
    return hashlib.sha256((prev + "\n" + canonical(data)).encode()).hexdigest()


def fail(path, lineno, why):
    print(f"❌ 篡改 @ {path}:{lineno}: {why}", file=sys.stderr)
    sys.exit(1)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    path = unwrap = seal = check_seal = None
    seal_file = key_file = priv_file = pub_file = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--unwrap":
            unwrap = True
        elif a == "--seal":
            seal = True
        elif a == "--check-seal":
            check_seal = True
        elif a == "--seal-file":
            seal_file = args[i + 1]
            i += 1
        elif a == "--seal-key":
            key_file = args[i + 1]
            i += 1
        elif a == "--seal-priv":
            priv_file = args[i + 1]
            i += 1
        elif a == "--seal-pub":
            pub_file = args[i + 1]
            i += 1
        elif path is None:
            path = a
        else:
            print(f"❌ 未知参数 {a}", file=sys.stderr)
            sys.exit(2)
        i += 1
    if path is None:
        print(__doc__)
        sys.exit(2)
    if key_file and priv_file:
        print("❌ --seal-key 与 --seal-priv 互斥(共享密钥通道与非对称通道二选一)", file=sys.stderr)
        sys.exit(2)
    if priv_file and not seal:
        print("❌ --seal-priv 只在 --seal(写封存点)时有意义", file=sys.stderr)
        sys.exit(2)
    if pub_file and not check_seal:
        print("❌ --seal-pub 只在 --check-seal(核验封存点)时有意义", file=sys.stderr)
        sys.exit(2)
    key = None
    if key_file:
        with open(key_file, "rb") as f:
            key = f.read().strip()
        if not key:
            print(f"❌ --seal-key 文件为空: {key_file}", file=sys.stderr)
            sys.exit(2)
    priv = pub = None
    try:
        if priv_file:
            priv = load_rsa_key(open(priv_file, encoding="utf-8").read())
        if pub_file:
            pub = load_rsa_key(open(pub_file, encoding="utf-8").read())
    except (OSError, ValueError, IndexError) as e:
        print(f"❌ RSA 密钥加载失败: {e}", file=sys.stderr)
        sys.exit(2)

    prev, n = GENESIS, 0
    try:
        fh = open(path, encoding="utf-8")
    except OSError as e:
        print(f"❌ 打不开 {path}: {e}", file=sys.stderr)
        sys.exit(2)
    with fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                fail(path, lineno, "不是 JSON(链记录被破坏)")
            if rec.get("seq") != n:
                fail(path, lineno,
                     f"seq 断档: 期望 {n} 实得 {rec.get('seq')}(删行/重排)")
            if rec.get("prev") != prev:
                fail(path, lineno,
                     f"prev 链接断: 期望 {prev[:16]}… 实得 {str(rec.get('prev'))[:16]}…")
            if rec.get("v") == 2:
                # v2:ts 入哈希(链记录元数据不可被静默改写);v1 旧格式不含 ts
                exp = hashlib.sha256(
                    (prev + "\n" + str(rec.get("ts")) + "\n"
                     + canonical(rec.get("data"))).encode()).hexdigest()
            else:
                exp = expected_hash(prev, rec.get("data"))
            if rec.get("hash") != exp:
                fail(path, lineno,
                     f"hash 失配(data 被改): 期望 {exp[:16]}… 实得 "
                     f"{str(rec.get('hash'))[:16]}…")
            prev = rec["hash"]
            if unwrap:
                data = rec.get("data")
                out = (json.dumps(data, ensure_ascii=False)
                       if not isinstance(data, dict) or "__chainraw__" not in data
                       else data["__chainraw__"])
                sys.stdout.write(out + "\n")
    print(f"✅ {path}: {n} 条事件链完整,head={prev[:16]}…", file=sys.stderr)

    seal_path = seal_file if seal_file else path + ".seal.json"
    if seal:
        s = {"seq": n, "last_hash": prev,
             "ts": datetime.now(timezone.utc).isoformat(),
             "file_bytes": os.path.getsize(path)}
        if key:
            s["mac"] = hmac.new(
                key, f"v1|{n}|{prev}|{s['file_bytes']}".encode(),
                hashlib.sha256).hexdigest()
        if priv:
            s["sig_alg"] = "rsa-sha256-pkcs1v15"
            s["sig"] = base64.b64encode(rsa_sign(seal_payload(s), priv)).decode()
        with open(seal_path, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=1)
        tag = "(HMAC 签名)" if key else ("(RSA 签名)" if priv else "")
        print(f"🔒 封存点 → {seal_path}" + tag, file=sys.stderr)
    if check_seal:
        if not os.path.exists(seal_path):
            print(f"❌ 无封存点 {seal_path}", file=sys.stderr)
            sys.exit(2)
        with open(seal_path, encoding="utf-8") as f:
            s = json.load(f)
        sig_ok = False
        if "sig" in s:
            if not pub:
                print("❌ seal 带 RSA 签名,核验必须 --seal-pub 提供公钥"
                      "(fail-closed:无公钥无法排除伪造封存点)", file=sys.stderr)
                sys.exit(2)
            try:
                sig = base64.b64decode(s["sig"])
            except Exception:
                fail(path, n, "seal sig 不是合法 base64")
            if not rsa_verify(seal_payload(s), sig, pub):
                fail(path, n,
                     "seal RSA 签名失配: 封存点被伪造/篡改或公钥不符"
                     "—— 按 seal 零行处理,上报不修复")
            sig_ok = True
        if "mac" in s:
            if not key:
                print("❌ seal 带 MAC,核验必须 --seal-key 提供同一密钥"
                      "(fail-closed:无密钥无法排除伪造封存点)", file=sys.stderr)
                sys.exit(2)
            exp_mac = hmac.new(
                key, f"v1|{s.get('seq')}|{s.get('last_hash')}|{s.get('file_bytes')}".encode(),
                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(exp_mac, s["mac"]):
                fail(path, n,
                     "seal MAC 失配: 封存点被伪造/篡改或密钥不符"
                     "—— 账本与封存点都不可信,按零行处理")
        if s.get("seq") != n or s.get("last_hash") != prev:
            fail(path, n,
                 f"封存点失配: seal=({s.get('seq')},{str(s.get('last_hash'))[:16]}…) "
                 f"file=({n},{prev[:16]}…) —— 账本在封存后被动过(增/删/换)")
        fb = s.get("file_bytes")
        if fb is not None and fb != os.path.getsize(path):
            fail(path, n,
                 f"file_bytes 失配: seal={fb} file={os.path.getsize(path)}"
                 "(字节层面被动过;语义未变也报,非语义差异须解释)")
        print(f"✅ 封存点核对一致({n} 条"
              + (",RSA 验签过" if sig_ok else "")
              + (",HMAC 验签过" if "mac" in s else "") + ")", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
