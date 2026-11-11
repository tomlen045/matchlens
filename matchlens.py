#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
matchlens — sshd_config Match 块透视镜。回答三个问题：谁的规则、谁说了算、还健不健康。

零依赖单文件 CLI（stdlib only）：解析 sshd_config（含 Include 指令、注释、
Match 全零/全一缩进风格），手工实现 OpenSSH 的生效语义，把散落在全局段
+N个Match块里的几十条指令折叠成「一个用户视角」的生效视图。

生效语义（已用本机真 sshd -T 二进制对拍验证，脚本见 verify_sshd_semantics.sh，
OpenSSH_10.3p1 实测）：
- 全局段：first-value-wins（同键重复赋值取第一条）
- 命中的 Match 块自上而下依次应用，块内赋值【覆盖】全局与先前块
  （实测：全局 PasswordAuthentication no + Match User alice 内 yes
   => sshd -T -C user=alice 给出 passwordauthentication yes）
- 块内重复键取第一条（块内 first-value-wins）

子命令：
    parse [path]         结构透视：全局段 + 每个 Match 块（条件串+指令表+行号），含 Include 展开
    effsim <user>        以指定用户视角模拟生效配置（全局+所有命中块按覆盖链折叠）
    effsim <user> --host <fqdn> --addr <ip>   三条件全开模拟（未给的维度按不命中+提示）
    audit [path]         全量体检（exit 0 干净 / 1 有 CRIT 或 WARN / 2 环境错误）
    ask <user> <key>     单键三段式：全局值 → 命中块 → 生效值 + sshd -T 一键核对命令
    selftest             不变量自测（ML-01 起）
    --json               机器可读输出（配合 parse/effsim/audit/ask）

只读承诺（ML-01）：parse/effsim/audit/ask 绝不写任何文件；
唯一写盘 = selftest 的临时目录。

Match 语义参照 OpenSSH 9.x/10.x sshd_config(5)：
- Match 全部条件满足才命中；User/Group/Host/Address/LocalAddress/LocalPort/RDomain
- Match 块内可用指令是全局子集（详见 man 页 MATCH 节）
"""
import argparse
import fnmatch
import glob as _globmod
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path

VERSION = "1.1.0"
TOOL = "matchlens"

DEFAULT_PATHS = [
    "/etc/ssh/sshd_config",
    "/usr/local/etc/sshd_config",
    "/opt/homebrew/etc/sshd_config",
]

# Match 块内允许的指令（OpenSSH 9.x/10.x sshd_config(5) MATCH 节，ASCII 序）
MATCH_ALLOWED = {
    "AcceptEnv", "AllowAgentForwarding", "AllowGroups", "AllowStreamLocalForwarding",
    "AllowTcpForwarding", "AllowUsers", "AuthenticationMethods", "AuthorizedKeysCommand",
    "AuthorizedKeysCommandUser", "AuthorizedKeysFile", "AuthorizedPrincipalsCommand",
    "AuthorizedPrincipalsCommandUser", "AuthorizedPrincipalsFile", "Banner",
    "CASignatureAlgorithms", "ChannelTimeout", "ChrootDirectory", "ClientAliveCountMax",
    "ClientAliveInterval", "DenyGroups", "DenyUsers", "DisableForwarding", "ExposeAuthInfo",
    "FingerprintHash", "ForceCommand", "GatewayPorts", "GSSAPIAuthentication",
    "HostCertificate", "HostKey", "HostKeyAlgorithms", "IgnoreRhosts",
    "Include", "IPQoS", "KbdInteractiveAuthentication", "KerberosAuthentication",
    "LogLevel", "MaxAuthTries", "MaxSessions", "PasswordAuthentication",
    "PermitEmptyPasswords", "PermitListen", "PermitOpen", "PermitRootLogin",
    "PermitTTY", "PermitTunnel", "PermitUserRC", "PubkeyAcceptedAlgorithms",
    "PubkeyAuthentication", "RekeyLimit", "RevokedKeys", "RDomain", "SetEnv",
    "StreamLocalBindMask", "StreamLocalBindUnmask", "TrustedUserCAKeys",
    "X11DisplayOffset", "X11Forwarding", "X11MaxDisplays",
}

# audit 重点盯防的安全键
SECURITY_KEYS = ["PasswordAuthentication", "PermitRootLogin", "PermitEmptyPasswords",
                 "KbdInteractiveAuthentication", "ChallengeResponseAuthentication",
                 "AllowTcpForwarding", "AllowAgentForwarding", "PermitTTY", "X11Forwarding"]

CRIT, WARN, INFO = "CRIT", "WARN", "INFO"

DEFAULTS = {
    "PasswordAuthentication": "yes",
    "PermitRootLogin": "prohibit-password",
    "PermitEmptyPasswords": "no",
    "AllowTcpForwarding": "yes",
    "AllowAgentForwarding": "yes",
    "PermitTTY": "yes",
    "X11Forwarding": "no",
    "MaxAuthTries": "6",
}


# ------------------------------------------------------------ include ---

def expand_includes(path, depth=0, _seen=None):
    """读文件并把 Include 指令内联展开（glob 支持，环形/深度保护，缺文件 INFO 不炸）。
    返回 [(lineno, text, origin)]，origin=来源文件路径。"""
    if _seen is None:
        _seen = set()
    rp = Path(os.path.realpath(os.path.expanduser(str(path))))
    out = []
    try:
        lines = rp.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    key = str(rp)
    if key in _seen or depth > 8:
        out.append((0, "# matchlens: circular Include or depth>8, stopped: %s" % key, "matchlens"))
        return out
    _seen.add(key)
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            out.append((i, raw, str(rp)))
            continue
        parts = s.split()
        if parts[0] == "Include" and len(parts) >= 2:
            base_dir = rp.parent
            for pat in parts[1:]:
                p = pat if os.path.isabs(pat) else str(base_dir / pat)
                hits = sorted(_globmod.glob(p))
                if hits:
                    for h in hits:
                        out.extend(expand_includes(h, depth + 1, _seen))
                else:
                    out.append((i, "# matchlens: Include %s -> no match" % pat, "matchlens"))
        else:
            out.append((i, raw, str(rp)))
    return out


# ------------------------------------------------------------ parsing ---

COND_KEYS = {"User", "Group", "Host", "LocalAddress", "LocalPort", "Address", "RDomain"}

VALID_KEYS = {
    "AcceptEnv", "AddressFamily", "AllowAgentForwarding", "AllowGroups",
    "AllowStreamLocalForwarding", "AllowTcpForwarding", "AllowUsers", "AuthenticationMethods",
    "AuthorizedKeysCommand", "AuthorizedKeysCommandUser", "AuthorizedKeysFile",
    "AuthorizedPrincipalsCommand", "AuthorizedPrincipalsCommandUser",
    "AuthorizedPrincipalsFile", "Banner", "CASignatureAlgorithms", "ChallengeResponseAuthentication",
    "ChrootDirectory", "Ciphers", "ClientAliveCountMax", "ClientAliveInterval", "Compression",
    "DebianBanner", "DenyGroups", "DenyUsers", "DisableForwarding", "ExposeAuthInfo",
    "FingerprintHash", "ForceCommand", "GatewayPorts", "GSSAPIAuthentication",
    "GSSAPICleanupCredentials", "HostbasedAcceptedAlgorithms", "HostbasedAuthentication",
    "HostbasedUsesNameFromPacketOnly", "HostCertificate", "HostKey", "HostKeyAlgorithms",
    "IgnoreRhosts", "IgnoreUserKnownHosts", "Include", "IPQoS", "KbdInteractiveAuthentication",
    "KerberosAuthentication", "KerberosGetAFSToken", "KerberosOrLocalPasswd",
    "KerberosTicketCleanup", "KexAlgorithms", "ListenAddress", "LogLevel", "LoginGraceTime",
    "MACs", "Match", "MaxAuthTries", "MaxSessions", "MaxStartups", "PasswordAuthentication",
    "PermitEmptyPasswords", "PermitListen", "PermitOpen", "PermitRootLogin", "PermitTTY",
    "PermitTunnel", "PermitUserEnvironment", "PermitUserRC", "PidFile", "Port",
    "PrintMotd", "PubkeyAcceptedAlgorithms", "PubkeyAuthentication", "RekeyLimit",
    "RevokedKeys", "RDomain", "SetEnv", "StreamLocalBindMask", "StreamLocalBindUnmask",
    "StrictModes", "Subsystem", "SyslogFacility", "TCPKeepAlive", "TrustedUserCAKeys",
    "UseDNS", "UsePAM", "VersionAddendum", "X11DisplayOffset", "X11Forwarding", "X11MaxDisplays",
    "X11UseLocalhost",
}

MULTI_VALUE_KEYS = {"HostKey", "ListenAddress", "Port", "AcceptEnv", "SetEnv", "Subsystem",
                    "AllowUsers", "DenyUsers", "AllowGroups", "DenyGroups", "PermitOpen",
                    "PermitListen", "HostKeyAlgorithms", "CASignatureAlgorithms"}


def parse_criteria(rest):
    """解析 Match 条件串 → (criteria dict, errors list)。
    criteria: {key: [patterns]}; 条件值支持逗号分隔多值（all/any/none 是保留词）。"""
    crit, errors = {}, []
    toks = rest.split()
    i = 0
    while i < len(toks):
        k = toks[i]
        if k not in COND_KEYS:
            errors.append("未知条件键 %r（合法: %s）" % (k, " ".join(sorted(COND_KEYS))))
            return crit, errors
        if i + 1 >= len(toks):
            errors.append("条件 %s 缺少值" % k)
            return crit, errors
        v = toks[i + 1]
        vals = [x for x in v.split(",") if x]
        if not vals:
            errors.append("条件 %s 值为空" % k)
        for x in vals:
            if x in ("all", "any", "none"):
                errors.append("条件值 %r 是 Match 保留词，不能当 pattern 用" % x)
        crit.setdefault(k, []).extend(vals)
        i += 2
    if not crit and not errors:
        errors.append("Match 条件串为空")
    return crit, errors


def parse_config(path):
    """解析 sshd_config → 全局段 + Match 块列表 + junk/错误清单。
    返回 dict: {"origin_files", "global": {k: v}, "blocks": [...], "junk": [...]}"""
    lines = expand_includes(path)
    cfg = {"origin_files": [], "global": {}, "blocks": [], "junk": []}
    seen_files = []
    cur = None          # 当前 Match 块 or None=全局
    for lineno, raw, origin in lines:
        if origin not in seen_files:
            seen_files.append(origin)
        s = raw.strip()
        if s.startswith("# matchlens:"):
            cfg["junk"].append({"line": raw, "origin": origin, "reason": s[2:].strip()})
            continue
        if not s or s.startswith("#"):
            continue
        # key = 第一个词；value 支持行内注释剥离（# 前有空格才算）
        body = s
        m = re.search(r"\s+#", s)
        if m and not s.startswith("Match"):
            body = s[: m.start()].strip()
        parts = body.split(None, 1)
        key = parts[0]
        rest = parts[1].strip() if len(parts) > 1 else ""
        if key.startswith("="):
            cfg["junk"].append({"line": raw, "origin": origin, "reason": "键值间用了 = 号（sshd 不认）"})
            continue
        if key != "Match" and key not in VALID_KEYS:
            cfg["junk"].append({"line": raw, "origin": origin,
                                "reason": "未知指令 %r（拼错? OpenSSH sshd -t 也会报）" % key})
            continue
        if key == "Match":
            crit, errs = parse_criteria(rest)
            cur = {"line": lineno, "origin": origin, "criteria": crit,
                   "criteria_errors": errs, "options": {}, "raw": s}
            cfg["blocks"].append(cur)
            continue
        if cur is None:
            # 全局段：重复键 first-value-wins
            if key in MULTI_VALUE_KEYS:
                cfg["global"].setdefault(key, []).append(rest)
            else:
                if key in cfg["global"]:
                    cfg["junk"].append({"line": raw, "origin": origin,
                                        "reason": "全局 %s 重复赋值——sshd 取第一个，此行永不生效" % key})
                else:
                    cfg["global"][key] = rest
        else:
            if key not in MATCH_ALLOWED:
                cur["options"].setdefault("__disallowed__", []).append(
                    {"key": key, "value": rest, "line": lineno, "origin": origin})
            elif key in MULTI_VALUE_KEYS:
                cur["options"].setdefault(key, []).append(rest)
            else:
                if key in cur["options"]:
                    cfg["junk"].append({"line": raw, "origin": origin,
                                        "reason": "块内 %s 重复赋值——块内取第一条，此行永不生效" % key})
                else:
                    cur["options"][key] = rest
    cfg["origin_files"] = seen_files
    return cfg


# ------------------------------------------------------------ matching ---

def _pattern_match(pattern, value):
    """OpenSSH pattern: 逗号分隔；支持 * ?；! 前缀取反；大小写不敏感（对拍 upper）。"""
    value_u = value.upper() if value else ""
    for pat in [p for p in pattern.split(",") if p != ""]:
        p_u = pat.upper()
        negated = p_u.startswith("!")
        if negated:
            p_u = p_u[1:]
        if fnmatch.fnmatchcase(value_u, p_u):
            return not negated
    return False


def _addr_match(pattern, addr):
    """Address 条件：CIDR 段用 ipaddress 精确判；否则走 pattern（含通配）。
    addr 未给时返回 (False, 'no-addr')，上层按不命中+提示处理。"""
    if addr is None:
        return False, "no-addr"
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False, "bad-addr"
    for pat in [p for p in pattern.split(",") if p]:
        if "/" in pat:
            try:
                net = ipaddress.ip_network(pat, strict=False)
                if a in net:
                    return True, "cidr"
            except ValueError:
                continue
        else:
            if _pattern_match(pat, addr):
                return True, "pattern"
    return False, "miss"


def block_matches(block, user=None, host=None, addr=None):
    """判断 Match 块是否命中 (user, host, addr)。
    返回 (hit: bool, detail: dict, unresolved: list[str])"""
    detail, unresolved = {}, []
    hit = True
    for k, pats in sorted(block["criteria"].items()):
        vals = ",".join(pats)
        if k == "User":
            if user is None:
                unresolved.append(k)
                hit = False
                detail[k] = "unresolved(user未给)"
            else:
                ok = _pattern_match(vals, user)
                detail[k] = "%s vs %s -> %s" % (vals, user, ok)
                hit = hit and ok
        elif k == "Group":
            ok = _pattern_match(vals, user or "")
            detail[k] = "%s vs %s -> %s(按主组名近似)" % (vals, user, ok)
            hit = hit and ok
        elif k == "Host":
            if host is None:
                unresolved.append(k)
                hit = False
                detail[k] = "unresolved(host未给,按不命中)"
            else:
                ok = _pattern_match(vals, host)
                detail[k] = "%s vs %s -> %s" % (vals, host, ok)
                hit = hit and ok
        elif k in ("Address", "LocalAddress"):
            ok, how = _addr_match(vals, addr)
            detail[k] = "%s vs %s -> %s(%s)" % (vals, addr, ok, how)
            hit = hit and ok
        elif k in ("LocalPort", "RDomain"):
            unresolved.append(k)
            hit = False
            detail[k] = "unresolved(无-R参数,按不命中)"
    return hit, detail, unresolved


# ------------------------------------------------------------ effective ---

def effective_for(cfg, user, host=None, addr=None, include_blocks=True):
    """以 (user, host, addr) 视角折叠生效配置。

    语义（已用真 sshd -T 对拍验证）：
    - 全局段：first-value-wins（parse_config 已保证单值）
    - 命中的 Match 块自上而下依次应用，块内赋值【覆盖】全局与先前块
    - 块内重复键取第一条（parse_config 已保证单值）
    返回 dict: {"effective": {k: v}, "sources": {k: src}, "unresolved": [...], "hit_blocks": [...]}"""
    eff, sources, unresolved_all, hits = {}, {}, [], []
    # 先全局
    for k, v in cfg["global"].items():
        if k not in eff:
            eff[k] = v
            sources[k] = "global"
    # 再按序应用命中块（覆盖）
    if include_blocks:
        for b in cfg["blocks"]:
            ok, detail, unres = block_matches(b, user, host, addr)
            if unres:
                unresolved_all.extend(unres)
            if ok:
                hits.append({"line": b["line"], "origin": b["origin"], "raw": b["raw"], "detail": detail})
                for k, v in b["options"].items():
                    if k == "__disallowed__":
                        continue
                    eff[k] = v
                    sources[k] = "match@L%d" % b["line"]
    # 补默认值（展示用）
    for k, v in DEFAULTS.items():
        if k not in eff:
            eff[k] = v
            sources[k] = "openssh-default"
    return {"effective": eff, "sources": sources, "unresolved": unresolved_all, "hit_blocks": hits}


# ------------------------------------------------------------ audit ---

def audit(cfg):
    """全量体检 → findings 列表。"""
    F = []

    def add(sev, code, where, msg):
        F.append({"sev": sev, "code": code, "where": where, "msg": msg})

    if not cfg["origin_files"]:
        add(CRIT, "ML-ENV", "-", "配置文件不存在/不可读")
        return F

    g = cfg["global"]

    # ML-02 全局密码认证 + root 登录（经典双开门）
    pa = g.get("PasswordAuthentication")
    prl = g.get("PermitRootLogin")
    if pa is not None and pa.lower() == "yes":
        add(WARN, "ML-02", "global", "PasswordAuthentication yes：密码爆破面暴露（配合 fail2ban/基本密码策略才可接受）")
    if prl is not None and prl.lower() == "yes":
        add(CRIT, "ML-02", "global", "PermitRootLogin yes：root 可直连（钥匙+密码双通道）")
    if pa is None:
        add(INFO, "ML-04", "global", "PasswordAuthentication 未显式配置，按 OpenSSH 默认 yes 跑——建议显式写 no（仅密钥）")

    # Match 块逐块体检
    for b in cfg["blocks"]:
        w = "match@L%d" % b["line"]
        for e in b["criteria_errors"]:
            add(CRIT, "ML-03", w, "条件解析错误：%s——该块永不命中或整段被 sshd -t 拒绝" % e)
        if b["criteria_errors"]:
            continue
        crits = b["criteria"]
        if "User" in crits and "Group" in crits:
            add(WARN, "ML-09", w, "User+Group 双条件：Group 只匹配主组，辅组用户不走该块——确认这是想要的行为")
        # ML-07 Match 内放全局指令 = sshd -t 直接报错
        for d in b["options"].get("__disallowed__", []):
            add(CRIT, "ML-07", w, "Match 块内出现全局指令 %s（L%d，来自 %s）——sshd -t 直接报错，服务起不来" % (d["key"], d["line"], d["origin"]))
        # ML-08 CRIT 安全组合
        opts = b["options"]
        pa_b = opts.get("PasswordAuthentication", "").lower()
        pk_b = opts.get("PubkeyAuthentication", "").lower()
        if pa_b == "no" and pk_b == "no":
            add(CRIT, "ML-08", w, "PasswordAuthentication no + PubkeyAuthentication no：该匹配对象谁也登不进来（含密钥）")
        if opts.get("PermitRootLogin", "").lower() == "yes":
            add(CRIT, "ML-08", w, "Match 块 PermitRootLogin yes：为 root 单独开门")
        if opts.get("PermitEmptyPasswords", "").lower() == "yes":
            add(CRIT, "ML-08", w, "PermitEmptyPasswords yes：空密码放行")
        # ML-10 疲软组合：块内把密码认证开回来
        if pa_b == "yes":
            gv = g.get("PasswordAuthentication", "未配置(默认yes)")
            add(WARN, "ML-10", w, "Match 块把 PasswordAuthentication 开成 yes（全局是 %s）——如果是为个别用户开的临时后门，加注释说明" % gv)
        # ML-05 冗余覆盖行：与全局同值，没改变任何行为
        for k in SECURITY_KEYS:
            if k in opts and k in g and opts[k].lower() == g[k].lower():
                add(INFO, "ML-05", w, "%s=%s 与全局相同——这行没改变任何行为，建议删掉或补注释说明意图" % (k, opts[k]))
        # ML-11 ForceCommand 提示
        if "ForceCommand" in opts:
            add(INFO, "ML-11", w, "ForceCommand 已配置：%s——确认目标 shell 存在且行为符合预期" % opts["ForceCommand"][:60])

    # ML-06 死值（重复赋值/未知指令/=号）
    for j in cfg["junk"]:
        r = j.get("reason", "")
        if "重复赋值" in r or "未知指令" in r or "= 号" in r:
            add(WARN, "ML-06", j["origin"], "%s：%s" % (r, j["line"][:60]))

    # ML-12 Include 缺文件
    for j in cfg["junk"]:
        if "Include" in j.get("reason", "") and "no match" in j.get("reason", ""):
            add(INFO, "ML-12", j["origin"], j["reason"])

    return F


def resolve_path(path):
    """显式路径 > 常见路径探测。返回 (path, err)。"""
    if path:
        p = Path(os.path.expanduser(str(path)))
        if not p.is_file():
            return None, "文件不存在: %s" % p
        return str(p), None
    for cand in DEFAULT_PATHS:
        if Path(cand).is_file():
            return cand, None
    return None, "找不到 sshd_config（试 --file 显式指定，或 macOS: /etc/ssh/sshd_config）"


def fmt_criteria(crit):
    return " ".join("%s %s" % (k, ",".join(v)) for k, v in crit.items())


def print_audit(findings):
    if not findings:
        print("  (clean)  0 findings —— 未发现任何问题")
        return
    order = {CRIT: 0, WARN: 1, INFO: 2}
    for f in sorted(findings, key=lambda x: (order.get(x["sev"], 9), x["code"])):
        print("  [%4s] %s  %s  %s" % (f["sev"], f["code"], f["where"], f["msg"]))


def _multi(v):
    return ",".join(v) if isinstance(v, list) else v


def cmd_parse(args):
    path, err = resolve_path(args.file)
    if err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 2
    cfg = parse_config(path)
    if args.json:
        print(json.dumps(cfg, ensure_ascii=False, indent=2))
        return 0
    print("# %s parse — %s" % (TOOL, path))
    print("# 展开来源文件: %s" % ", ".join(cfg["origin_files"]))
    print("\n== 全局段 (%d keys) ==" % len(cfg["global"]))
    for k, v in cfg["global"].items():
        print("  %s = %s" % (k, _multi(v)))
    if cfg["blocks"]:
        print("\n== Match 块 × %d ==" % len(cfg["blocks"]))
        for b in cfg["blocks"]:
            where = "L%d" % b["line"] + (" (%s)" % b["origin"] if b["origin"] != path else "")
            errs = "  !!条件错误: %s" % "; ".join(b["criteria_errors"]) if b["criteria_errors"] else ""
            print("  [%s] Match %s%s" % (where, fmt_criteria(b["criteria"]), errs))
            for k, v in b["options"].items():
                if k == "__disallowed__":
                    for d in v:
                        print("      !! 全局指令混入: %s (L%d)" % (d["key"], d["line"]))
                else:
                    print("      %s = %s" % (k, _multi(v)))
    if cfg["junk"]:
        print("\n== 可疑/无效行 × %d ==" % len(cfg["junk"]))
        for j in cfg["junk"]:
            print("  [%s] %s: %s" % (j["origin"], j["reason"], j["line"][:70]))
    return 0


def cmd_effsim(args):
    path, err = resolve_path(args.file)
    if err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 2
    cfg = parse_config(path)
    eff = effective_for(cfg, args.user, host=args.host, addr=args.addr)
    if args.json:
        print(json.dumps(eff, ensure_ascii=False, indent=2))
        return 0
    label = args.user + ("@%s" % args.host if args.host else "") + (" via %s" % args.addr if args.addr else "")
    print("# %s effsim — 视角: %s" % (TOOL, label))
    unresolved = sorted(set(eff["unresolved"]))
    if unresolved:
        print("# 未解析条件（按不命中处理）: %s" % ", ".join(unresolved))
        print("# 提示: 补 --host/--addr 可解析 Host/Address 条件; Group/RDomain 无法在此模拟")
    print("\n== 命中 Match 块 × %d ==" % len(eff["hit_blocks"]))
    for h in eff["hit_blocks"]:
        print("  L%d: %s" % (h["line"], h["raw"]))
    print("\n== 生效视图 × %d keys ==" % len(eff["effective"]))
    for k in sorted(eff["effective"]):
        src = eff["sources"].get(k, "?")
        mark = "  <-默认" if src == "openssh-default" else ""
        print("  %s = %s   [%s]%s" % (k, _multi(eff["effective"][k]), src, mark))
    t_cmd = "sshd -T -C user=%s" % args.user
    if args.host:
        t_cmd += ",host=%s" % args.host
    if args.addr:
        t_cmd += ",addr=%s" % args.addr
    print("\n== 对照真身（推荐每次都跑）==")
    print("  sudo %s   # OpenSSH 真实展开，与本模拟对拍" % t_cmd)
    return 0


def cmd_audit(args):
    path, err = resolve_path(args.file)
    if err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 2
    cfg = parse_config(path)
    findings = audit(cfg)
    if args.json:
        print(json.dumps({"file": path, "findings": findings}, ensure_ascii=False, indent=2))
    else:
        print("# %s audit — %s" % (TOOL, path))
        print("# 来源: %s" % ", ".join(cfg["origin_files"]))
        print("# Match 块: %d | 全局键: %d" % (len(cfg["blocks"]), len(cfg["global"])))
        print_audit(findings)
    bad = sum(1 for f in findings if f["sev"] in (CRIT, WARN))
    return 1 if bad else 0


def cmd_ask(args):
    path, err = resolve_path(args.file)
    if err:
        print("ERROR: %s" % err, file=sys.stderr)
        return 2
    cfg = parse_config(path)
    key = args.key
    canonical = None
    for k in VALID_KEYS:
        if k.lower() == key.lower():
            canonical = k
            break
    if canonical is None:
        print("ERROR: %s 不是合法 sshd_config 指令（见 man sshd_config）" % key, file=sys.stderr)
        return 2
    gval = cfg["global"].get(canonical)
    eff = effective_for(cfg, args.user, host=args.host, addr=args.addr)
    eval_ = eff["effective"].get(canonical)
    src = eff["sources"].get(canonical, "openssh-default")
    hits = eff["hit_blocks"]
    t_cmd = "sudo sshd -T -C user=%s" % args.user
    if args.host:
        t_cmd += ",host=%s" % args.host
    if args.addr:
        t_cmd += ",addr=%s" % args.addr
    t_cmd += " | grep -i '^%s'" % canonical.lower()
    out = {
        "file": path, "user": args.user, "key": canonical,
        "global": gval,
        "hit_blocks": [{"line": h["line"], "raw": h["raw"]} for h in hits],
        "effective": eval_, "source": src, "verify_cmd": t_cmd,
    }
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0
    print("# %s ask — %s → %s" % (TOOL, args.user, canonical))
    print("  全局值      : %s" % (gval if gval is not None else "(未配置)"))
    for h in hits:
        print("  命中块 L%d: %s" % (h["line"], h["raw"]))
    print("  生效值      : %s   [来源: %s]" % (_multi(eval_), src))
    print("\n  一键核对真身:")
    print("  %s" % t_cmd)
    return 0


# ------------------------------------------------------------ selftest ---

def _w(tmp, name, text):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


def selftest():
    """ML-01..ML-14 不变量自测。全绿返回 0。"""
    results = []

    def check(code, desc, fn):
        try:
            fn()
            results.append((True, code, desc, ""))
        except AssertionError as e:
            results.append((False, code, desc, str(e)))
        except Exception as e:
            results.append((False, code, desc, "EXC %s: %s" % (type(e).__name__, e)))

    # ---------- ML-01 只读承诺 ----------
    def t_ml01():
        with tempfile.TemporaryDirectory() as tmp:
            cfgp = _w(tmp, "sshd_config", "PasswordAuthentication no\nMatch User alice\n    PermitTTY no\n")
            before = sorted(os.listdir(tmp))
            cfg = parse_config(cfgp)
            audit(cfg)
            effective_for(cfg, "alice")
            effective_for(cfg, "bob")
            after = sorted(os.listdir(tmp))
            assert before == after, "目录被写: %s" % (set(after) - set(before))

    check("ML-01", "parse/audit/effsim 全程只读不写盘", t_ml01)

    # ---------- ML-02 全局危险双开门 ----------
    def t_ml02():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "PasswordAuthentication yes\nPermitRootLogin yes\n")
            f_ = audit(parse_config(p))
            codes = {f["code"]: f["sev"] for f in f_}
            assert "ML-02" in codes, "ML-02 missing: %s" % f_
            assert codes.get("ML-02") in (CRIT, WARN)

    check("ML-02", "全局 PasswordAuthentication yes + PermitRootLogin yes 出 ML-02", t_ml02)

    # ---------- ML-03 条件错误=永不命中 ----------
    def t_ml03():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "Match User all\n    PermitTTY no\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-03" and f["sev"] == CRIT for f in f_), f_
            cfg = parse_config(p)
            assert cfg["blocks"][0]["criteria_errors"], "criteria_errors should be filled"

    check("ML-03", "保留词 all 当 pattern → ML-03 CRIT", t_ml03)

    # ---------- ML-04 PasswordAuthentication 默认值提示 ----------
    def t_ml04():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "X11Forwarding no\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-04" for f in f_), f_

    check("ML-04", "PasswordAuthentication 未显式配置 → ML-04 提示", t_ml04)

    # ---------- ML-05 冗余覆盖行 ----------
    def t_ml05():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "PasswordAuthentication no\nMatch User alice\n    PasswordAuthentication no\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-05" for f in f_), f_

    check("ML-05", "Match 值与全局相同 → ML-05 冗余提示", t_ml05)

    # ---------- ML-06 死值（重复赋值 first-value-wins）----------
    def t_ml06():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "PasswordAuthentication no\nPasswordAuthentication yes\n")
            cfg = parse_config(p)
            assert cfg["global"]["PasswordAuthentication"] == "no", cfg["global"]
            f_ = audit(cfg)
            assert any(f["code"] == "ML-06" for f in f_), f_

    check("ML-06", "重复赋值取第一个且标 ML-06", t_ml06)

    # ---------- ML-07 Match 内全局指令 ----------
    def t_ml07():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "Match User alice\n    Port 2222\n    PermitTTY no\n")
            cfg = parse_config(p)
            assert cfg["blocks"][0]["options"].get("__disallowed__"), cfg["blocks"]
            f_ = audit(cfg)
            assert any(f["code"] == "ML-07" and f["sev"] == CRIT for f in f_), f_

    check("ML-07", "Match 内 Port=全局指令 → ML-07 CRIT", t_ml07)

    # ---------- ML-08 双 no 登录锁死 ----------
    def t_ml08():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "Match User deploy\n    PasswordAuthentication no\n    PubkeyAuthentication no\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-08" and f["sev"] == CRIT for f in f_), f_

    check("ML-08", "PasswordAuth no + PubkeyAuth no → ML-08 CRIT", t_ml08)

    # ---------- ML-09 Group 主组语义 ----------
    def t_ml09():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "Match User alice Group devs\n    PermitTTY no\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-09" for f in f_), f_

    check("ML-09", "User+Group 双条件 → ML-09 提示", t_ml09)

    # ---------- ML-10 块内 PasswordAuthentication yes ----------
    def t_ml10():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "PasswordAuthentication no\nMatch User tmpuser\n    PasswordAuthentication yes\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-10" for f in f_), f_

    check("ML-10", "块内把密码认证开回来 → ML-10 WARN", t_ml10)

    # ---------- ML-11 ForceCommand 提示 ----------
    def t_ml11():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c", "Match User git\n    ForceCommand /usr/bin/git-shell\n")
            f_ = audit(parse_config(p))
            assert any(f["code"] == "ML-11" for f in f_), f_

    check("ML-11", "ForceCommand → ML-11 INFO", t_ml11)

    # ---------- ML-12 Include 展开 ----------
    def t_ml12():
        with tempfile.TemporaryDirectory() as tmp:
            _w(tmp, "10-hard.conf", "PasswordAuthentication no\n")
            mainp = _w(tmp, "sshd_config", "Include %s/10-hard.conf\nMatch User alice\n    PermitTTY no\n" % tmp)
            cfg = parse_config(mainp)
            assert cfg["global"].get("PasswordAuthentication") == "no", cfg["global"]
            assert len(cfg["blocks"]) == 1, cfg["blocks"]

    def t_ml12b():
        with tempfile.TemporaryDirectory() as tmp:
            mainp = _w(tmp, "sshd_config", "Include %s/absent/*.conf\n" % tmp)
            cfg = parse_config(mainp)
            assert any("no match" in j.get("reason", "") for j in cfg["junk"]), cfg["junk"]

    def t_ml12_wrap():
        t_ml12()
        t_ml12b()

    check("ML-12", "Include 内联展开(命中+缺文件兜底)", t_ml12_wrap)

    # ---------- ML-13 effsim 块覆盖全局 + 块间顺序 ----------
    def t_ml13():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c",
                   "PasswordAuthentication no\n"
                   "Match User alice\n    PasswordAuthentication yes\n"
                   "Match User bob\n    PasswordAuthentication no\n    PermitTTY no\n")
            cfg = parse_config(p)
            ea = effective_for(cfg, "alice")
            eb = effective_for(cfg, "bob")
            ec = effective_for(cfg, "carol")
            assert ea["effective"]["PasswordAuthentication"] == "yes", ea
            assert ea["sources"]["PasswordAuthentication"] == "match@L2", ea["sources"]
            assert eb["effective"]["PasswordAuthentication"] == "no", eb
            assert eb["effective"]["PermitTTY"] == "no", eb
            assert ec["effective"]["PasswordAuthentication"] == "no", ec
            assert ec["sources"]["PasswordAuthentication"] == "global", ec["sources"]

    check("ML-13", "effsim 块覆盖全局+块间顺序+未命中走全局", t_ml13)

    # ---------- ML-14 Host/Address 条件 + 通配 + CIDR ----------
    def t_ml14():
        with tempfile.TemporaryDirectory() as tmp:
            p = _w(tmp, "c",
                   "Match Address 10.213.5.0/24\n    PermitTTY no\n"
                   "Match Host jump*,bastion\n    X11Forwarding yes\n")
            cfg = parse_config(p)
            e1 = effective_for(cfg, "anyuser", addr="10.213.5.77")
            assert e1["effective"]["PermitTTY"] == "no", e1
            e2 = effective_for(cfg, "anyuser", host="jump01")
            assert e2["effective"]["X11Forwarding"] == "yes", e2
            e3 = effective_for(cfg, "anyuser", host="web01")
            assert e3["effective"]["X11Forwarding"] == "no", e3
            e4 = effective_for(cfg, "anyuser", addr="192.168.1.1")
            assert e4["effective"]["PermitTTY"] == "yes", e4

    check("ML-14", "Host/Address(CIDR+通配) 命中与不命中", t_ml14)

    # ---------- 汇总 ----------
    passed = sum(1 for r in results if r[0])
    print("# %s selftest %s — %d/%d passed" % (TOOL, VERSION, passed, len(results)))
    for ok, code, desc, err in results:
        mark = "PASS" if ok else "FAIL"
        line = "%s %s %s" % (mark, code, desc)
        if err:
            line += "\n      -> %s" % err
        print(line)
    return 0 if passed == len(results) else 1


def main():
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description="matchlens — sshd_config Match 块透视镜（零依赖，只读）")
    ap.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("parse", help="结构透视：全局段+Match块+可疑行")
    p.add_argument("file", nargs="?", help="sshd_config 路径（缺省自动探测）")
    p.add_argument("--json", action="store_true", help="机器可读输出")
    p.set_defaults(fn=cmd_parse)

    p = sub.add_parser("effsim", help="以用户视角模拟生效配置")
    p.add_argument("user")
    p.add_argument("--host")
    p.add_argument("--addr")
    p.add_argument("--file")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_effsim)

    p = sub.add_parser("audit", help="全量体检（exit 0/1）")
    p.add_argument("file", nargs="?", help="sshd_config 路径（缺省自动探测）")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("ask", help="单键三段式：全局→命中块→生效值")
    p.add_argument("user")
    p.add_argument("key")
    p.add_argument("--host")
    p.add_argument("--addr")
    p.add_argument("--file")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_ask)

    sub.add_parser("selftest", help="不变量自测 ML-01 起")
    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(selftest())
    if not args.cmd:
        ap.print_help()
        return 0
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
