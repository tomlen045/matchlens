# matchlens 🔍

**sshd_config Match 块透视镜，零依赖单文件。** 回答三个问题：**谁的规则、谁说了算、还健不健康。**

服务器 sshd_config 攒到几百行、拆了 3 个 Include 文件、埋了 5 个 Match 块之后，
「deploy 这个账号到底能不能用密码登录」就再也没人能一口答出来了——全局基线说 no，
Match 块里藏着 yes，两个都「生效」其实只有一个说了算。matchlens 把这道题变成一条命令。

```
$ matchlens effsim deploy
# matchlens effsim — 视角: deploy

== 命中 Match 块 × 1 ==
  L21: Match User deploy

== 生效视图 × 13 keys ==
  PasswordAuthentication = no   [global]
  ForceCommand = /opt/deploy/run.sh   [match@L21]
  AllowTcpForwarding = no   [match@L21]
  ...
```

matchlens 是自研运维透镜套件的又一件：

> **porteye**（谁在听）→ **callhome**（谁打电话回家）→ **authguard**（谁想进来）
> → **envlens**（SSH 客户端怎么连）→ **hostlens**（known_hosts 记了谁）→ **keyvaultdog**（我的私钥台账）
> → **authkeylens**（服务端谁被允许进门）→ **matchlens**（进门的规则到底怎么算）

authkeylens 管的是 authorized_keys 这份「名单」，matchlens 管的是 sshd_config 这部
「门禁法」——谁走哪个门、哪个门对谁静悄悄关着，一条命令看完。

## 解决什么问题

- 「deploy 能用密码登录吗？」答不上来 → **effsim**：以任意用户视角折叠全局+N个Match块，每个键标出谁说了算（global / match@L21 / openssh-default）
- 改了 Match 块不放心，想立刻验证 → **真机对拍**：effsim 的每个值都和 `sshd -T -C user=...` 同格式，一条命令交叉核对（本机已做过 5 场景 × 9 键全对拍，45/45 OK）
- 配置越攒越乱没人敢动 → **audit**：13 条不变量全量体检（死值/永不命中块/块内混入全局指令/双 no 锁死/临时后门），exit code 直接给结论
- 只关心一个键 → **ask**：`matchlens ask deploy passwordauthentication` 三段式回答：全局值 → 命中块 → 生效值 + sshd -T 一键核对命令
- Include 拆文件后没人知道全局还剩什么 → **parse**：把 Include 内联展开，全局段 + 每个 Match 块（条件串+行号+来源文件）一张表看完

## 30 秒上手

```bash
# 结构透视（缺省自动探测 /etc/ssh/sshd_config；macOS/Linux 通用）
python3 matchlens.py parse

# 以 deploy 用户视角看生效配置（补 --host/--addr 可解析 Host/Address 条件）
python3 matchlens.py effsim deploy
python3 matchlens.py effsim deploy --host jumphome --addr 10.213.5.77

# 全量体检（发现 CRIT/WARN 时 exit 1，挂 cron/CI 直接用）
python3 matchlens.py audit

# 单键三段式
python3 matchlens.py ask deploy passwordauthentication

# 机器可读（cron/监控管道）
python3 matchlens.py audit --json
```

## 生效语义（真机对拍，不是拍脑袋）

matchlens 的折叠规则用本机真 `/usr/sbin/sshd -T` 二进制做过对拍验证
（OpenSSH_10.3p1，5 场景 × 9 键 = 45 项全 OK，对拍脚本 `duipai.py`）：

1. **全局段：first-value-wins** —— 同键重复赋值取第一条（后面的行永不生效，audit 会标出来）
2. **Match 块覆盖全局** —— 命中的块自上而下依次应用，块内赋值覆盖全局与先前块。
   实测：全局 `PasswordAuthentication no` + `Match User alice` 内 `yes`
   ⇒ `sshd -T -C user=alice` 给出 `passwordauthentication yes`
3. **块内重复键取第一条**（块内 first-value-wins）

最常见的翻车就是把规则 1 记成全局：以为 Match 块「也要抢第一批次」，实际它是覆盖；
反过来以为块内写了两遍会取最后一遍，实际取第一遍。

## 13 条不变量（ML-01 起）

| 编号 | 级别 | 抓什么 |
|---|---|---|
| ML-01 | 承诺 | parse/effsim/audit/ask 只读不写盘（唯一写盘=selftest 临时目录） |
| ML-02 | CRIT/WARN | 全局密码认证开着 / root 可直连 |
| ML-03 | CRIT | Match 条件串错误（保留词 all 当 pattern / 缺值）= 永不命中的管理盲区 |
| ML-04 | INFO | PasswordAuthentication 未显式配置（默认 yes 裸奔） |
| ML-05 | INFO | Match 块与全局同值的冗余行（没改变任何行为，建议删） |
| ML-06 | WARN | 死值：全局/块内重复赋值、未知指令（拼错）、`=` 号赋值 |
| ML-07 | CRIT | Match 块内混入全局指令（Port/ListenAddress...）—— sshd -t 直接报错，服务起不来 |
| ML-08 | CRIT | 双 no 登录锁死（PasswordAuth no + PubkeyAuth no）/ root 单独开门 / 空密码放行 |
| ML-09 | WARN | User+Group 双条件：Group 只匹配主组，辅组用户不走该块 |
| ML-10 | WARN | Match 块把 PasswordAuthentication 开回来（临时后门没注释） |
| ML-11 | INFO | ForceCommand 已配置（确认目标 shell 存在且行为符合预期） |
| ML-12 | INFO | Include 指向不存在的文件 |
| ML-13/14 | 语义 | effsim 覆盖链正确（块覆盖全局+块间顺序）/ Host 通配+Address CIDR 命中判定 |

```bash
$ python3 matchlens.py selftest
# matchlens selftest 1.1.0 — 14/14 passed
```

## Match 块内能写什么（速查）

只有 sshd_config(5) MATCH 节列出的指令能出现在 Match 块里。最常用的一批：

```
PermitTTY  PermitRootLogin  PasswordAuthentication  PubkeyAuthentication
PermitEmptyPasswords  AllowTcpForwarding  AllowAgentForwarding  X11Forwarding
ForceCommand  ChrootDirectory  MaxAuthTries  MaxSessions  PermitOpen  PermitListen
AuthorizedKeysFile  AuthorizedKeysCommand  AuthenticationMethods  SetEnv  Include ...
```

写了全集之外的（Port、ListenAddress、HostKey…）= ML-07 CRIT，`sshd -t` 会直接拒绝启动——
改配置不看这条，重启就是一次生产事故。

## 设计取舍（一句大实话）

- **Group 条件按「主组名」近似匹配**：sshd 真身按用户属组（含辅组）判，纯 stdlib 拿不到
  可靠的属组展开，matchlens 用用户名对拍主组 pattern 近似——所以 audit 对 User+Group
  双条件块永远提示人工复核，effsim 对 Group 块给出「近似」标注。真身以 `sshd -T` 为准，
  这也是每条命令都附 -T 对照命令的原因：**matchlens 给你 90 分的快速答案，-T 给你 100 分的官方答案**
- **LocalPort/RDomain 条件无法在无 -R 场景解析**：按不命中处理并明示 unresolved
- **本工具不解密 Known_hosts、不改任何文件**：hostlens 管 known_hosts，matchlens 管 sshd_config，各管各的

## 套件叙事：SSH 门禁全家桶

```
出门:  envlens(客户端怎么连) → hostlens(对方是谁记过账吗) → keyvaultdog(我的钥匙台账)
进门:  matchlens(门禁法怎么算) → authkeylens(名单上都有谁) → authguard(门口的监控录像)
在听:  porteye(哪些门开着) → callhome(谁从里面往外打电话)
```

## 仓库结构

```
matchlens.py              主程序（零依赖，Python 3.8+，stdlib only）
selftest_matchlens.py     独立自测入口（同 selftest 子命令）
make_demo.py              演示实验室：造 3-Match 块演示配置 + 7 份真机 transcript
duipai.py                 真机对拍：5 场景 × 9 键 vs /usr/sbin/sshd -T
verify_sshd_semantics.sh  语义取证：最小配置验证「块覆盖全局」
make_shots.py             证据图生成器（1200×675 macOS 终端实拍风）
shots/                    6 张证据图
```

## License

MIT
