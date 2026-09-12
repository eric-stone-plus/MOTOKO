# MOTOKO 工具编排注册表（Tool Registry）

全景图景：host + Kali 容器全部安全工具在攻击图里的编排状态。
**编排 = 有规则点火进图；登记 = 已在图景、无安全触发器（人工/反射器按需调用）。**

更新时间：2026-09-11（第一轮 run 前编排）

## 路由

| 路由 | 机制 | 工具 |
|---|---|---|
| host | executor 默认（resolve_tool 多目录） | httpx/nuclei/katana/… |
| container | action `"runtime": "container"` → `podman exec kali-recon <argv>` | kali 工具 |

容器管理：`motoko kali status|start|stop`（podman 生命周期，CLI-only）。
容器工具输出同样进 obs/ 走 parser；无 parser 的进 dead_letter（R6-1 已落盘）。

## Host 工具（22）

### 已编排（规则点火）

| 工具 | 规则 | 触发条件 | 输出 parser |
|---|---|---|---|
| httpx | R-BOOT-URL-001 | url 或 host 资产 | httpx.py |
| nuclei | R-BOOT-SCAN-001（category=scan，配额优先） | 存活 2xx/3xx/401/403/405 | nuclei.py |
| katana | R-CTX-CRAWL-001 | 200 且 host 未爬 | katana.py |
| ffuf | R-CTX-FFUF-403-001 | 401/403 | ffuf.py |
| sqlmap | R-VULN-SQLI-VERIFY-001 | class 含 sqli | sqlmap.py |
| dalfox | R-VULN-XSS-VERIFY-001 | class 含 xss | dalfox.py |
| arjun | R-TECH-PARAM-001 | has_param | arjun.py |
| jsluice | R-CTX-JS-001 | JS 上下文 | jsluice.py |
| wpscan | R-TECH-WORDPRESS-001 | tech wordpress | 待写 |
| subfinder | R-RECON-SUB-001 | url 且 host 未枚举 | lines.py |
| amass | R-RECON-SUB-001（第二 action） | 同上 | lines.py |
| gau | R-RECON-GAU-001 | url 且 host 未枚举 | lines.py |
| nmap | R-RECON-NMAP-001 | 存活 web 且 host 未扫 | nmap.py（services） |

### 登记（R7 降级：无 parser / 需人工）

| 工具 | 降级理由 | 恢复条件 |
|---|---|---|
| strix | R7-1：LLM agent 自动点火不可控（P0） | CLI `motoko strix` 人工深挖 |
| whatweb/nikto | R7-2：parser 待写，零回灌烧槽 | R8 parser 后恢复 |
| sslscan | R7-2：同上 | R8 |
| theHarvester | R7-2：同上 + CN 源裁剪 | R8 |
| netexec/smbclient/enum4linux-ng | R7-2：nmap service 入图后再开 | 图上出现 service=smb 后 R8 |

### 登记（无安全自动触发器）

| 工具 | 理由 | 触发途径 |
|---|---|---|
| naabu | 端口扫描与 nmap 重叠（nmap -sV 已编） | 规则可加（网段资产） |
| dnsx | 解析验证（subfinder 输出处理） | 与 SUB 链合并可加 |
| anew | 去重管道工具（非独立扫描） | 管道辅助 |
| gf | 模式匹配过滤器（非独立扫描） | 管道辅助 |
| qsreplace | URL 变形辅助（非独立扫描） | 管道辅助 |
| hydra | 弱口令爆破需要凭证/字典配置 | 服务发现后人工触发 |
| searchsploit | 本地 exploitdb 查询；{tech0} 渲染缺 | 人工/反射器 |

## Kali 容器工具（26）

### 已编排

| 工具 | 规则 | 触发 | parser |
|---|---|---|---|
| netexec | R-ACCESS-SMB-001 | service=smb | 待写 |
| smbclient | R-ACCESS-SMB-002 | service=smb | 待写 |
| enum4linux-ng | R-ACCESS-SMB-003 | service=smb | 待写 |
| nmap | R-RECON-NMAP-001 | 存活 web host | 待写 |
| sslscan | R-TLS-SSLSCAN-001 | https | 待写 |
| theHarvester | R-OSINT-HARVESTER-001 | url 且 host 未枚举 | 待写 |

### 登记（无安全自动触发器 / 需特殊上下文）

| 工具 | 理由 |
|---|---|
| masscan | 大网段快速端口发现——需网段目标（scope 内 IP 段） |
| testssl.sh | 与 sslscan 重叠（保留作深度 TLS 审计备选） |
| nikto/feroxbuster/gobuster/dirsearch/whatweb/wpscan/nuclei/ffuf/sqlmap（容器版） | 与 host 版重复——host 优先，容器版是冗余备份 |
| impacket-scripts | SMB/LDAP/MSSQL 协议攻击——需服务+凭证上下文 |
| responder | 内网 LLMNR/NBT-NS 毒化——需内网位置，单独授权 |
| bettercap | 内网嗅探/MITM——需内网位置，单独授权 |
| metasploit-framework | 利用框架——具体项目目标单独授权（sliver 同待遇） |
| hashcat | 离线破解——需先拿到 hash |
| hydra（容器版） | 与 host 版重复 |
| seclists/wordlists | 词表数据（ffuf 词表在 host ~/.motoko/wordlists/） |
| exploitdb/searchsploit | 知识库——人工查询 |

## 迭代纪律（用户确认）

1. run 前编排只是第一轮。
2. **每个 wave 实战后走 loop**：波次数据 + 代码 → qwen/kimi 独立审计 → grok 裁决 → 修复 → 测试 → 下一波。
3. 动态发现的问题（爆炸/饿死/断链）即时适配调优，新规则/parser/路由变更同样进下一轮 loop。
4. 归档：每轮修复落 plans/waves/（r6-land 起）。
