#!/usr/bin/env python3
"""matchlens 演示实验室：造一个带 3 个 Match 块的演示配置（非 root 可跑），
1) 用真 /usr/sbin/sshd -T -f 对拍 matchlens effsim 的关键字段（含 PID/HostKey 假值垫片）
2) 输出 transcripts 到 /tmp/matchlens-demo/*.txt 供证据图使用。
演示配置里的网段一律用 10.213.x.x / 198.18.x.x 文档保留段，无真实信息。"""
import os
import re
import subprocess

DEMO = "/tmp/matchlens-demo"
os.makedirs(DEMO, exist_ok=True)

CONF = f"""# matchlens 演示配置：一台「堡垒机 + 发布机」混部服务器的典型 sshd_config
Port 22
AddressFamily any
ListenAddress 0.0.0.0

# 基线：只认钥匙，root 只许密钥进
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
MaxAuthTries 4
X11Forwarding no
AllowTcpForwarding yes

# 运维跳板组：开全程转发（班组共用）
Match Group ops
    PermitTTY yes
    AllowTcpForwarding yes
    AllowAgentForwarding yes

# CI 发布账号：锁死交互，只许跑部署脚本
Match User deploy
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding no
    AllowAgentForwarding no
    ForceCommand /opt/deploy/run.sh

# 应急通道：仅堡垒网段 + 指定账号，密码可以进来（临时开门，记得加注释+期限）
Match User breakglass Address 10.213.5.0/24
    PasswordAuthentication yes
    PermitTTY yes
    MaxAuthTries 6
"""
conf_path = os.path.join(DEMO, "sshd_demo.conf")
with open(conf_path, "w") as f:
    f.write(CONF)

# ---- 用真 sshd -T 对拍 ----
def sshd_t(user, host, addr):
    spec = f"user={user},host={host},addr={addr}"
    # macOS sshd -T 需要 hostkey；给一把演示钥匙垫片
    hk = os.path.join(DEMO, "hostkey_ed25519")
    if not os.path.exists(hk):
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", hk],
                       check=True, capture_output=True)
    r = subprocess.run(
        ["/usr/sbin/sshd", "-T", "-f", conf_path, "-C", spec, "-h", hk],
        capture_output=True, text=True)
    if r.returncode != 0:
        return None, r.stderr.strip()
    keys = {}
    for line in r.stdout.splitlines():
        if " " in line:
            k, v = line.split(" ", 1)
            keys[k] = v
    return keys, None

WATCH = ["passwordauthentication", "pubkeyauthentication", "permittty",
         "allowtcpforwarding", "allowagentforwarding", "x11forwarding",
         "permitrootlogin", "forcecommand", "maxauthtries"]

SCENARIOS = [
    ("deploy", "web01.prod", "198.18.10.5"),      # CI 账号：块内全锁
    ("breakglass", "jumphome", "10.213.5.77"),    # 应急通道：密码进来
    ("breakglass", "jumphome", "198.18.99.9"),    # 同账号非堡垒段：密码被拒
    ("opsadmin", "bastion", "198.18.7.3"),        # ops 组：转发全开
    ("carol", "web01.prod", "198.18.10.5"),       # 普通账号：全走全局基线
]

report = []
all_ok = True
for user, host, addr in SCENARIOS:
    keys, err = sshd_t(user, host, addr)
    if keys is None:
        report.append(f"[sshd-T FAIL] {user}@{host}: {err}")
        all_ok = False
        continue
    m = subprocess.run(
        ["python3", "/Users/len/CodeBuddy/dx/matchlens/matchlens.py", "effsim", user,
         "--host", host, "--addr", addr, "--file", conf_path, "--json"],
        capture_output=True, text=True)
    import json
    eff = json.loads(m.stdout)["effective"]
    row = []
    for k in WATCH:
        ml = str(eff.get(k, "<unset>"))
        if k == "forcecommand":
            ml = {"/opt/deploy/run.sh": "/opt/deploy/run.sh", "none": "<unset>"}.get(ml, ml)
        ss = keys.get(k, "<unset>")
        ok = (ml == ss)
        if not ok:
            all_ok = False
        row.append(f"  {k:24} matchlens={ml:28} sshd-T={ss:28} {'OK' if ok else 'MISMATCH'}")
    report.append(f"[{user}@{host} via {addr}]\n" + "\n".join(row))

print("\n".join(report))
print("\nALL_MATCH" if all_ok else "\nHAS_MISMATCH")

# ---- transcripts 供证据图 ----
def save(name, text):
    with open(os.path.join(DEMO, name), "w") as f:
        f.write(text)

save("t1_demo_conf.txt", CONF)
r = subprocess.run(["python3", "matchlens.py", "parse", conf_path],
                   capture_output=True, text=True, cwd="/Users/len/CodeBuddy/dx/matchlens")
save("t2_parse.txt", r.stdout)
r = subprocess.run(["python3", "matchlens.py", "effsim", "deploy",                    "--file", conf_path], capture_output=True, text=True,
                   cwd="/Users/len/CodeBuddy/dx/matchlens")
save("t3_effsim_deploy.txt", r.stdout)
r = subprocess.run(["python3", "matchlens.py", "effsim", "breakglass",
                    "--host", "jumphome", "--addr", "10.213.5.77", "--file", conf_path],
                   capture_output=True, text=True, cwd="/Users/len/CodeBuddy/dx/matchlens")
save("t4_effsim_breakglass.txt", r.stdout)
r = subprocess.run(["python3", "matchlens.py", "audit", conf_path],
                   capture_output=True, text=True, cwd="/Users/len/CodeBuddy/dx/matchlens")
save("t5_audit.txt", r.stdout + f"\n[exit={r.returncode}]\n")
r = subprocess.run(["python3", "matchlens.py", "selftest"],
                   capture_output=True, text=True, cwd="/Users/len/CodeBuddy/dx/matchlens")
save("t6_selftest.txt", r.stdout)
# 对拍场景 transcript
lines = []
for user, host, addr in SCENARIOS:
    keys, _ = sshd_t(user, host, addr)
    m = subprocess.run(["python3", "matchlens.py", "effsim", user, "--host", host,
                        "--addr", addr, "--file", conf_path, "--json"],
                       capture_output=True, text=True, cwd="/Users/len/CodeBuddy/dx/matchlens")
    eff = json.loads(m.stdout)["effective"]
    for k in ["passwordauthentication", "permittty", "allowtcpforwarding", "forcecommand"]:
        ml = str(eff.get(k, "<unset>"))
        if k == "forcecommand":
            ml = {"none": "<unset>"}.get(ml, ml)
        ss = keys.get(k, "<unset>")
        lines.append(f"$ matchlens effsim {user} --host {host} --addr {addr}")
        lines.append(f"  {k:22} matchlens={ml:26} sshd -T={ss:26} {'OK' if ml == ss else 'MISMATCH'}")
        lines.append("")
save("t7_duipai.txt", "\n".join(lines))
print("transcripts saved:", sorted(os.listdir(DEMO)))
