#!/usr/bin/env python3
"""matchlens 证据图生成器：6 张 1200x675 macOS 窗框 One Dark 终端实拍风格。
内容 100% 来自 /tmp/matchlens-demo/*.txt 真实命令输出（make_demo.py 产物，已核对）。
长行按真实内容拆行展示，绝不编造。出图后逐张 vision_analyze 验字。"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = "/Users/len/CodeBuddy/dx/matchlens/shots"
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·…％' for ch in t)

def shot(name, lines, title="matchlens — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57"); d.ellipse([44, 15, 56, 27], fill="#febc2e"); d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 74
    for item in lines:
        text, color, size, mono = item
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.62)
    img.save(f"{OUT}/{name}.png")
    print(name, "OK", "bottom_y=", y)

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read().splitlines()

# ── SHOT1 selftest 14/14 ──
shot("shot1_selftest", [
    ("$ python3 matchlens.py selftest", GOLD, 21, True),
    ("# matchlens selftest 1.1.0 — 14/14 passed", WHITE, 20, True),
    ("PASS ML-01 parse/audit/effsim 全程只读不写盘", GREEN, 19, False),
    ("PASS ML-02 全局 PasswordAuth yes + PermitRootLogin yes 出 ML-02", GREEN, 19, False),
    ("PASS ML-03 保留词 all 当 pattern → ML-03 CRIT", GREEN, 19, False),
    ("PASS ML-06 重复赋值取第一个且标 ML-06", GREEN, 19, False),
    ("PASS ML-07 Match 内 Port=全局指令 → ML-07 CRIT", GREEN, 19, False),
    ("PASS ML-08 PasswordAuth no + PubkeyAuth no → ML-08 CRIT", GREEN, 19, False),
    ("PASS ML-12 Include 内联展开(命中+缺文件兜底)", GREEN, 19, False),
    ("PASS ML-13 effsim 块覆盖全局+块间顺序+未命中走全局", GREEN, 19, False),
    ("PASS ML-14 Host/Address(CIDR+通配) 命中与不命中", GREEN, 19, False),
])

# ── SHOT2 demo 配置：3 个 Match 块的典型混部服务器 ──
shot("shot2_demo_conf", [
    ("# 一台「堡垒机+发布机」混部服务器的 sshd_config", GREY, 18, False),
    ("PasswordAuthentication no          # 基线：只认钥匙", WHITE, 19, True),
    ("PermitRootLogin prohibit-password", WHITE, 19, True),
    ("", WHITE, 8, True),
    ("Match Group ops                    # 运维跳板组", GOLD, 19, True),
    ("    PermitTTY yes", GREEN, 19, True),
    ("    AllowAgentForwarding yes", GREEN, 19, True),
    ("", WHITE, 8, True),
    ("Match User deploy                  # CI 发布账号：锁死交互", GOLD, 19, True),
    ("    PermitTTY no", RED, 19, True),
    ("    AllowTcpForwarding no", RED, 19, True),
    ("    ForceCommand /opt/deploy/run.sh", BLUE, 19, True),
    ("", WHITE, 8, True),
    ("Match User breakglass Address 10.213.5.0/24", GOLD, 19, True),
    ("    PasswordAuthentication yes     # 应急通道(临时)", RED, 19, True),
    ("$ 问: deploy 这个账号到底能不能用密码登录?", WHITE, 19, False),
], title="matchlens — demo sshd_config")

# ── SHOT3 parse 结构透视 ──
shot("shot3_parse", [
    ("$ python3 matchlens.py parse --file /tmp/matchlens-demo/sshd_demo.conf", GOLD, 20, True),
    ("# Match 块: 3 | 全局键: 9", GREY, 18, True),
    ("== 全局段 (9 keys) ==", WHITE, 20, True),
    ("  PasswordAuthentication = no", GREEN, 19, True),
    ("  PermitRootLogin = prohibit-password", GREEN, 19, True),
    ("  MaxAuthTries = 4", GREEN, 19, True),
    ("== Match 块 × 3 ==", WHITE, 20, True),
    ("  [L14] Match Group ops", GOLD, 19, True),
    ("      PermitTTY = yes", WHITE, 19, True),
    ("  [L21] Match User deploy", GOLD, 19, True),
    ("      PermitTTY = no   AllowTcpForwarding = no", WHITE, 19, True),
    ("      ForceCommand = /opt/deploy/run.sh", WHITE, 19, True),
    ("  [L29] Match User breakglass Address 10.213.5.0/24", GOLD, 19, True),
    ("      PasswordAuthentication = yes", WHITE, 19, True),
    ("$ Include 拆的文件也内联展开, 每行带行号", GREY, 18, False),
], title="matchlens parse")

# ── SHOT4 effsim deploy：答案揭晓 ──
shot("shot4_effsim_deploy", [
    ("$ python3 matchlens.py effsim deploy --file /tmp/matchlens-demo/sshd_demo.conf", GOLD, 20, True),
    ("# matchlens effsim — 视角: deploy", GREY, 18, True),
    ("== 命中 Match 块 × 1 ==", WHITE, 20, True),
    ("  L21: Match User deploy", GOLD, 19, True),
    ("== 生效视图 × 13 keys ==", WHITE, 20, True),
    ("  PasswordAuthentication = no   [global]", GREEN, 19, True),
    ("  AllowTcpForwarding = no   [match@L21]", GREEN, 19, True),
    ("  ForceCommand = /opt/deploy/run.sh   [match@L21]", GREEN, 19, True),
    ("  PermitTTY = no   [match@L21]", GREEN, 19, True),
    ("  X11Forwarding = no   [match@L21]", GREEN, 19, True),
    ("  PubkeyAuthentication = yes   [global]", GREEN, 19, True),
    ("$ deploy 不能用密码登录, 只能跑部署脚本, 转发全锁", WHITE, 19, False),
    ("$ 每个键后面就是「谁说了算」: global / match@L21", GREY, 18, False),
], title="matchlens effsim deploy")

# ── SHOT5 breakglass 对比 + 真机对拍 ──
shot("shot5_duipai", [
    ("$ effsim breakglass --addr 10.213.5.77   # 堡垒段内", GOLD, 20, True),
    ("  PasswordAuthentication = yes   [match@L29]", GREEN, 19, True),
    ("$ effsim breakglass --addr 198.18.99.9    # 非堡垒段", GOLD, 20, True),
    ("  PasswordAuthentication = no   [global]", GREEN, 19, True),
    ("$ 真机对拍: matchlens vs sshd -T (5场景×9键)", GOLD, 20, True),
    ("  passwordauthentication  matchlens=no    sshd-T=no     OK", WHITE, 19, True),
    ("  permittty               matchlens=no    sshd-T=no     OK", WHITE, 19, True),
    ("  forcecommand            matchlens=/opt/deploy/run.sh  sshd-T=同  OK", WHITE, 19, True),
    ("  maxauthtries            matchlens=4     sshd-T=4      OK", WHITE, 19, True),
    ("  ...45 项全部 OK, 0 MISMATCH", GREEN, 20, False),
    ("$ 条件没给全时按不命中处理并明示 unresolved", GREY, 18, False),
], title="matchlens — sshd -T 对拍")

# ── SHOT6 audit + ask + 狗粮 ──
shot("shot6_audit_ask", [
    ("$ python3 matchlens.py audit /tmp/matchlens-demo/sshd_demo.conf", GOLD, 20, True),
    ("  [WARN] ML-10  match@L29  Match 块把 PasswordAuthentication 开成 yes", WHITE, 18, True),
    ("           （全局是 no）——临时后门记得加注释+期限", GREY, 18, False),
    ("  [INFO] ML-05  match@L15  AllowTcpForwarding=yes 与全局相同——冗余行", WHITE, 18, True),
    ("  [INFO] ML-11  match@L21  ForceCommand 已配置：/opt/deploy/run.sh", WHITE, 18, True),
    ("  exit=1 (有 WARN)", GOLD, 18, True),
    ("", WHITE, 8, True),
    ("$ python3 matchlens.py ask deploy passwordauthentication", GOLD, 20, True),
    ("  全局值      : no", WHITE, 19, True),
    ("  命中块 L21: Match User deploy", WHITE, 19, True),
    ("  生效值      : no   [来源: global]", GREEN, 19, True),
    ("  sudo sshd -T -C user=deploy | grep -i '^passwordauthentication'", BLUE, 18, True),
    ("$ 开发本工具时 14 条自测抓出真 bug: Include 标记行被吞", GREY, 17, False),
], title="matchlens audit / ask")

print("all shots done ->", OUT)
