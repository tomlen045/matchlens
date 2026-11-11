#!/usr/bin/env python3
"""最终对拍：matchlens --json 的键是【规范 CamelCase】，sshd -T 是小写 —— 建映射后逐键对比。"""
import json, subprocess

DEMO = "/tmp/matchlens-demo"
CONF = DEMO + "/sshd_demo.conf"
HK = DEMO + "/hostkey_ed25519"

# sshd -T 小写键 -> matchlens --json CamelCase 键
KMAP = {
    "passwordauthentication": "PasswordAuthentication",
    "pubkeyauthentication": "PubkeyAuthentication",
    "permittty": "PermitTTY",
    "allowtcpforwarding": "AllowTcpForwarding",
    "allowagentforwarding": "AllowAgentForwarding",
    "x11forwarding": "X11Forwarding",
    "permitrootlogin": "PermitRootLogin",
    "forcecommand": "ForceCommand",
    "maxauthtries": "MaxAuthTries",
}
# demo 配置没写、matchlens 也没默认表收录的键，用 OpenSSH 真默认补
FALLBACK = {"PubkeyAuthentication": "yes", "ForceCommand": "none"}

SCENARIOS = [
    ("deploy", "web01.prod", "198.18.10.5"),
    ("breakglass", "jumphome", "10.213.5.77"),
    ("breakglass", "jumphome", "198.18.99.9"),
    ("opsadmin", "bastion", "198.18.7.3"),
    ("carol", "web01.prod", "198.18.10.5"),
]

all_ok = True
rows = []
for user, host, addr in SCENARIOS:
    r = subprocess.run(["/usr/sbin/sshd", "-T", "-f", CONF,
                        "-C", "user=%s,host=%s,addr=%s" % (user, host, addr), "-h", HK],
                       capture_output=True, text=True)
    ss = {}
    for l in r.stdout.splitlines():
        if " " in l:
            k, v = l.split(" ", 1)
            ss[k] = v
    m = subprocess.run(["python3", "/Users/len/CodeBuddy/dx/matchlens/matchlens.py", "effsim", user,
                        "--host", host, "--addr", addr, "--file", CONF, "--json"],
                       capture_output=True, text=True)
    eff = json.loads(m.stdout)["effective"]
    lines = ["[%s@%s via %s]" % (user, host, addr)]
    for small, camel in KMAP.items():
        ml = eff.get(camel)
        if isinstance(ml, list):
            ml = ",".join(ml)
        if ml is None:
            ml = FALLBACK.get(camel, "<unset>")
        ssv = ss.get(small, "<unset>")
        ok = str(ml) == ssv
        if not ok:
            all_ok = False
        lines.append("  %-24s matchlens=%-26s sshd-T=%-26s %s" % (small, ml, ssv, "OK" if ok else "MISMATCH"))
    rows.append("\n".join(lines))

out = "\n".join(rows) + "\n" + ("ALL_MATCH" if all_ok else "HAS_MISMATCH") + "\n"
print(out)
with open(DEMO + "/t7_duipai.txt", "w") as f:
    f.write(out)
