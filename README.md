# nettool（网络管理工具）

一台机器同时接了多个路由器 / 多条宽带时，用它把「哪些流量走哪条线」管起来，并顺手把 DNS、网卡配置和连通性排查一起做了。
Go 编写，单个二进制、无外部运行依赖，所有操作都在内嵌的 Web 后台完成，也都有对应的 RESTful 接口。

---

## 功能一览

| 页签 | 干什么 | 主要接口 |
| --- | --- | --- |
| **SOCKS5 代理** | 随时启停的 SOCKS5 代理，外发流量绑定到指定网卡 IP（也就是指定走哪个路由器），实时看连接与流量 | `/api/status`、`/api/proxy`、`/api/stats`、`/api/egress-ip`、`/api/interfaces` |
| **路由管理** | 按网段或域名下发系统路由指向某个网关，带台账、启动对账、定时重解析、暂停/恢复 | `/api/routes*`、`/api/system-routes` |
| **网卡配置** | 改本机网卡的 IP / 掩码 / 网关 / DNS，并按连上的 Wi-Fi 自动套用配置档 | `/api/net/*` |
| **DNS 服务** | 本机 DNS 解析器：UDP/TCP/DoT/DoH 上游、按域名分流、缓存、静态记录 | `/api/dns*` |
| **Ping** | ICMP 连通性测试，可指定源 IP —— 同一个目标换条线路试，结果一目了然 | `/api/diag/ping` |
| **路由追踪** | traceroute，逐跳看流量实际经过哪些路由器，同样可指定源 IP | `/api/diag/traceroute` |

所选页签记忆在 localStorage 中，刷新后回到上次那页。

贯穿全局的几件事：

- **Web 后台登录认证**：`-user` / `-pass` 开启 HTTP Basic Auth，保护控制台与全部 API；两个都留空则不鉴权。
- **按上次的状态启动**：SOCKS5 代理和 DNS 服务的开关状态跟着配置一起存盘，进程重启（升级、崩溃、机器重启）后照着上次退出前的样子恢复——上次开着就自动起来，上次点过「停止」就保持停止，不用每次再去后台点一次。全新安装（还没有配置文件）时两者都不启动，避免装好就抢端口；`-start-proxy` / `-start-dns` 则是无条件启动，不看上次状态。
- **配置各自独立成 JSON**：路由台账、Wi-Fi 配置档、DNS 配置、代理配置四份文件互不干扰，一律先写临时文件再原子替换，掉电不会留下半个文件。
- **系统服务模板**：`deploy/` 下有 Linux systemd 与 OpenWrt procd 两份配置，开机自启 + 崩溃自动重启。

---

## 一、SOCKS5 代理

### 启停与状态

- 程序启动后按**上次退出前的开关状态**恢复：上次是开着的就自动开始监听，上次点过「停止代理」就只加载配置、不监听。第一次运行（还没有 `proxy.json`）时不启动，在 Web 后台点「启动代理」即可，之后这个选择就会被记住。想无条件开机即启加 `-start-proxy`。
- 端口、出口 IP、代理 DNS 也一并存在 `proxy.json` 里（默认与路由台账同目录，可用 `-proxy-config-file` 指定）。命令行 `-socks-port` / `-outbound-ip` / `-dns` 只在真填了的时候覆盖存档，留空则沿用上次的值。
- 「停止代理」不只是关监听口，还会主动断开当前所有隧道连接——点了停止就是真的停，不会有残留连接继续跑流量。
- 代理停止时仍可修改端口与出口 IP（保存后不会被动拉起，按钮文案相应变成「保存配置」）；代理运行中保存则自动带新配置重启（「保存并重启代理」）。
- 界面显示运行状态、代理启动时刻与已运行时长（停止时为 `-`），以及不受代理开关影响的程序运行时长。
- 接口：`POST /api/proxy {"action":"start"|"stop"}`；`GET /api/status` 返回 `running` / `proxy_state` / `started_at` / `uptime_seconds`。

### 流量统计与实时监控

- 精确统计全局上下行流量、历史连接数，并提供 2 秒自动刷新的实时活跃连接监控仪表盘。
- 每条连接显示**实际访问的目标**：客户端用 `--socks5-hostname` 交给代理解析时显示 `域名:端口 (解析到的IP)`，客户端本地解析后直接给 IP 时显示 `IP:端口`。目标是在 SOCKS5 握手时借 `RuleSet` 钩子按客户端地址回填的（Accept 那一刻还不知道要连哪儿），握手完成前显示「握手中…」。
- 列表按连接建立时间排序，不会每 2 秒行序乱跳。

### 出口网关强制绑定

- 允许指定代理外发流量绑定的本地网卡 IP，强制经由指定路由器网关转发。
- Web 后台自动读取本机可用网卡（网卡名、IP/掩码、对应网关）供下拉选择，并提供「刷新」按钮随时重新探测；亦可切换为「手动输入」填写任意 IP。
- 网关按 **IP 逐个解析**而非按网卡：同一块网卡上的多个地址可能分属不同上游路由器（macOS 的多个网络服务 / Linux 的策略路由）。macOS 读取 `scutil` 中各网络服务的 `Router`，Linux 用 `ip route get <目标> from <本机IP>` 查询实际生效网关，取不到时回落到该网卡的默认路由。
- ⚠️ 注意：显示的网关是系统对该地址配置的上游路由器。在 macOS 上，同一网卡的多个 IP 只有优先级最高的那条默认路由生效，**仅绑定源 IP 并不会自动改走另一个网关**；确需分流时请配合「路由管理」按目标网段指定网关。
- 对应接口：`GET /api/interfaces`，返回 `{"interfaces": [{name, ip, cidr, mac, gateway, loopback}], "outbound_ip": "当前生效出口IP"}`。
- 出口 IP 强制校验：必须是本机网卡上真实存在的 IPv4 地址，否则启动时直接报错退出、`POST /api/status` 返回 `400` 并列出可用的本机 IP；校验失败不会影响正在运行的代理服务。

### 代理自己的 DNS

`-dns`，或后台「代理 DNS」：客户端用 `--socks5-hostname` 时域名是交给**代理**解析的，代理默认用系统 DNS。在被污染的网络里系统 DNS 会返回假地址，这时哪怕流量出口在国外也连不上（实测 `www.google.com` 系统 DNS 解析出 `203.0.113.10` → 超时；境外 DNS 解析出 `203.0.113.20` → 0.4 秒 204）。填一个境外 DNS（如 `8.8.8.8`，只填 IP 会自动补 `:53`）即可，**DNS 查询本身也从绑定的出口 IP 发出去**，所以查询不经过被污染的线路。留空则维持系统解析。

### 实际出口公网 IP 探测

后台点「检测」会真的经由本机 SOCKS5 端口请求一次 `https://myip.ipip.net/`（等价于 `curl --socks5-hostname 127.0.0.1:<port> 'https://myip.ipip.net/'`），用来确认绑定是否真的生效。接口 `GET /api/egress-ip`；代理停止时该接口返回 `409` 并提示先启动代理。

---

## 二、路由管理（多路由器网关调度）

自定义托管路由增删 + 操作系统内核路由实时审计，两张表都在同一页。

### 按域名添加

- 填域名会当场解析 A 记录，为每个 IPv4 下发一条 `/32` 主机路由。一个域名解析出多个 IP 时全部下发，并在界面里归为一组，可整组删除。
- **定时自动重新解析**：CDN 域名的 IP 会轮换（实测 `myip.ipip.net` 一小时内 A 记录全变），默认每 **5 分钟**自动重新解析一遍，与最新 A 记录对齐——新增缺失的、撤下已不再解析到的。间隔由 `-domain-refresh` 控制（`0` 关闭），也可在界面点「重新解析」手动触发。
  - 只有真的发生变化才写日志，不会每轮刷屏。
  - **DNS 解析失败时保持现状**，绝不会因为一次抖动把路由全撤了；失败原因记在域名记录上，界面可见。
  - **新 IP 一条都没下发成功时不撤旧 IP**，避免该域名直接断流，留到下一轮重试。
  - 域名本身是独立记录（台账 `domains` 段），即使当前一条路由都没有也仍在托管、仍会被定时刷新；界面用琥珀色行显示这类「托管中但无生效路由」的域名及其最近错误。
- 相关接口：`POST /api/routes/refresh {"domain":"example.com"}`；`DELETE /api/routes {"domain":"example.com"}` 取消托管并删除其全部路由。
- **多个域名共用同一个 IP**：不同域名解析到同一地址时（CDN 上很常见），这条路由由它们共同持有，台账里记成 `domains: [...]`；取消托管其中一个域名不会删掉这条路由，只有最后一个持有者退出时才真正下发删除。界面上共用的行会注明「与 xxx 共用同一条路由」。

### 暂停 / 恢复

单条路由、整个域名、以及「全部暂停 / 全部恢复」都支持。暂停会把路由从内核撤下但保留台账记录（状态显示「已暂停」），恢复时重新下发；内核里本来就没有该条时按已暂停处理，不算失败。接口 `POST /api/routes/pause`。

### 路由台账与启动对账

解决「哪些是本程序改的」这个问题：

- 每次增删都写入 JSON 台账，记录 `destination / gateway / domain / resolved_at / created_at`；先写临时文件再原子替换。
- 路径由 `-state-file` 指定，留空则依次尝试 `/var/lib/nettool/routes.json` → `~/.nettool/routes.json` → 当前目录，全部不可写则本次运行不持久化（并明确告警）。
- 启动时读台账并与内核路由表逐条比对，日志与界面标出每条是「生效中 / 已失效 / 状态未知」；机器重启导致路由丢失时，可在界面点「重新下发失效路由」（`POST /api/routes/restore`，同时会纠正作用域并在响应里返回 `rescoped`），或用 `-restore-routes` 启动参数自动重建。
- **作用域自动纠偏（macOS）**：`-ifscope` 的作用域网卡是添加那一刻按「网关挂在哪块网卡上」算出来存进台账的。网关后来换了网卡（典型：把 Wi-Fi 的默认网关也设成同一个路由器，系统就把它的邻居项挪到了 Wi-Fi 上），旧作用域里再也解析不到网关，这条路由会变成**黑洞**——内核里看着还在（状态显示「生效中」），走它的流量却发不出去。所以在启动对账、每轮域名刷新、以及 Wi-Fi 配置档切换完 5 秒后，都会比一遍作用域，不一致就按新网卡撤旧下新；网关当前哪块网卡都够不着时不动它（可能只是网线拔了），下一轮再说。下发失败不写台账，下轮自动重试。界面每条路由会显示当前作用域网卡。
- Linux 上下发时额外打 `proto 210` 标记，即使台账丢失也能用 `ip route show proto 210` 认出本程序加的路由；界面会把「内核有标记但台账没有」的列为孤儿路由。busybox 的 `ip` 不认 `proto` 时会自动去掉标记重试。
- 目标写法统一归一化为 CIDR，各平台命令按主机/网段分别拼装（macOS `-host` vs `-net`、Windows 按前缀算掩码），由 `internal/route` 的单元测试覆盖。

---

## 三、网卡配置与 Wi-Fi 自动切换

### 网卡配置（IP / 掩码 / 网关 / DNS）

- 「网卡配置」页列出本机每张网卡的配置入口、当前方式（DHCP / 手动）、IP、掩码、网关、手工 DNS，并可直接改成 DHCP 或手动指定。
- 各平台的写入方式：macOS `networksetup`（以「网络服务」为单位，一块网卡可能对应多个服务）、Linux `nmcli`（以 NetworkManager 连接为单位，改完自动 `connection up`）、Windows `netsh`。掩码可填 `255.255.255.0` 或 `24`，会按平台自动换算（nmcli 用 `ip/prefix`）。
- 下发前校验：IP / 网关 / DNS 必须是合法 IPv4，网关必须与 IP 同网段（否则配下去必然不通），掩码必须连续。命令拼装由 `internal/netconfig` 的单元测试覆盖三个平台。
- ⚠️ 修改网卡配置需要 root，且会让该网卡短暂断线；如果 Web 后台正是经由这张网卡访问的，页面会断开。界面上有二次确认。
- 接口：`GET /api/net/interfaces`、`POST /api/net/apply {service, device, method, ip, mask, gateway, dns[]}`。

### 按 Wi-Fi 自动切换配置档

- 为每个 Wi-Fi 存一份配置档（应用到哪张网卡 + DHCP/手动 + IP/掩码/网关/DNS），程序定期检查当前连的是哪个 Wi-Fi，**换网后自动套用**对应配置档。间隔由 `-wifi-watch` 控制（默认 `30s`，`0` 关闭）。
- **默认档（其他 Wi-Fi）**：勾「作为默认档」存一份兜底配置，连到没有单独配置的 Wi-Fi 时套用它（典型用法：公司/家里用固定 IP，其他地方一律 DHCP）。默认档只能有一个，新存的会顶掉旧的；不填名字就叫「其他 Wi-Fi」；它是兜底用的，不会绑定到某个具体网络的指纹上。没有默认档时，陌生 Wi-Fi 保持现状不动。
- 匹配顺序：SSID 精确匹配 → 网络指纹匹配 → 默认档。没连 Wi-Fi 时哪一档都不套用。界面上会给当前命中的那一档打「当前命中」标记。
- 只在「换了网络」时才切换，且**当前配置已经和配置档一致就跳过**，不会无谓地把网卡断一下；启动那次只记录当前网络、不自动下发，需要的话点「立即应用」。
- 「换没换网」以后台轮询自己处理过的网络为准：界面刷新只读状态、不会顺手把换网这件事记成已处理（否则界面轮询比 `-wifi-watch` 快时会把切换吃掉）。下发失败的那一轮不算已处理，下一轮会重试。
- 配置档可单独停用/启用、立即应用、删除；每次下发的成功或失败都记在配置档上，界面可见。
- **macOS 14 起系统默认不给读 SSID**（需要给程序所在终端授予「定位服务」权限），这时会退回用系统给该网络的指纹（`ProfileID`）来识别：新建配置档时勾上「绑定当前这个 Wi-Fi」即可，SSID 那栏就当成你自己起的名字。SSID 能读到时优先按 SSID 匹配。
- 配置档存成独立 JSON（默认与路由台账同目录的 `net-profiles.json`，可用 `-net-profile-file` 指定）。
- 接口：`GET /api/net/wifi`、`POST /api/net/wifi/profiles`（新增/修改/仅改启用开关）、`DELETE /api/net/wifi/profiles {ssid}`、`POST /api/net/wifi/apply {ssid}`。

---

## 四、本地 DNS 服务（多形态上游 + 按域名分流）

- 「DNS 服务」页可随时启停一个本机 DNS 解析器（**UDP + TCP 同时监听**），局域网里的机器把 DNS 指向本机 IP 即可使用。开关状态存在 `dns.json` 里，程序启动时按上次退出前的状态恢复（第一次运行不启动）；加 `-start-dns` 则无条件启动。
- **四种上游形态**：普通 `udp`（53）、`tcp`（53）、**DoT**（DNS over TLS，853）、**DoH**（DNS over HTTPS，RFC 8484）。地址支持直接粘 `tls://1.1.1.1@one.one.one.one`、`https://dns.google/dns-query`、`udp://223.5.5.5` 等写法，类型自动识别；只填 IP 会按类型补默认端口。
- **按域名分流**：每个上游可以写一串域名（含子域），只有命中的查询才交给它；没写域名的上游作为兜底。命中时按**最长后缀**优先——`mail.example.com` 的规则会盖过 `example.com`。这套分流和「路由管理」里按域名指定网关的思路一致：把国内域名留给运营商 DNS，其余走 DoH/DoT。
- **两种查询策略**：`顺序`（前一个失败才轮到下一个，默认）与 `并发`（一起发，谁先回用谁——上游混着境内境外时能省掉超时等待）。UDP 应答带 TC 标记时自动改用 TCP 重问一次。
- **DoT/DoH 的 bootstrap**：上游写域名时可以指定一个用来解析它的普通 DNS（必须填 IP）。本机很可能正把这个服务设成系统解析器，不给 bootstrap 就会变成自己问自己。解析结果缓存 5 分钟。DoT 填 IP 时必须另给证书域名（或写成 `IP@域名`），否则拒绝保存——不校验证书的 DoT 等于没加密。
- **缓存**：按 `域名+类型+类` 缓存，命中时**按已缓存时长扣减 TTL** 再返回，不会让客户端以为记录比实际新；TTL 取应答里最小的那个并夹到配置的上下限之间，NXDOMAIN/空应答按 30 秒负缓存，SERVFAIL 一律不缓存（免得一次抖动被记住）。条数超限时先清过期项。
- **静态解析记录**：本地写死的 `域名 → IP`，优先于所有上游，支持 `*.dev.local` 这样的通配（只匹配子域，不匹配 `dev.local` 本身）。给内网机器起名、或把某个域名钉到指定 IP 上很方便。
- **测试解析**：走真实的分流规则和上游但不写缓存，可指定上游，DNS 服务没启动时也能测，用来验证上游填对没有。
- 界面显示累计查询 / 缓存命中 / 解析失败 / 缓存条目，每个上游的调用次数、失败次数、平均耗时与最近错误，以及最近 60 条查询（客户端、域名、类型、来源=缓存/静态/上游/失败、结果、耗时），停在该页时每 3 秒刷新。
- 配置存成独立 JSON（默认与路由台账同目录的 `dns.json`，可用 `-dns-config-file` 指定）；改配置时服务在跑会带新配置重启，**新配置起不来会自动回滚到旧配置**继续服务。
- ⚠️ 监听 53 端口需要 root，且不能和系统自带的解析器（systemd-resolved、dnsmasq 等）抢；被占用时可以先改成 5353 验证。
- 接口：`GET/POST /api/dns`（读取/保存整份配置）、`POST /api/dns/power {"action":"start"|"stop"}`、`GET /api/dns/stats`、`DELETE /api/dns/stats`（清空统计与缓存）、`POST /api/dns/query {name, type, upstream}`。

---

## 五、连通性诊断（Ping / 路由追踪）

前面几件事都在决定「流量走哪条线」，这两页用来验证它到底走没走成。

- **指定源 IP**：两者都能从某个本机 IPv4 发包（下拉框里就是「SOCKS5 出口」那张网卡列表，带网关信息）。同一个目标换不同源 IP 跑一遍，两条线路的差别一眼就看出来了；留空则按系统默认选路。源 IP 必须是本机真实存在的地址，否则接口直接返回 `400` 并列出可用 IP。
- **后台任务 + 增量刷新**：点开始后接口立刻返回任务 ID，前端每秒取一次增量，ping 的每一包、traceroute 的每一跳都是边跑边显示，不用等全部跑完。停在该页时才轮询，切走自动停。页面刷新后按类型接回最近一次任务，结果还在。
- **随时停止**：「停止」会取消后台任务并断开套接字。ping 的次数填 `0` 就是一直探到手动停（兜底上限 30 分钟，免得页面关了还在后台发包）。

### Ping

- 目标填 IP 或域名（域名当场解析成 IPv4）。可调次数、间隔、单包超时、负载大小。
- 每包显示序号、回应方、结果（成功 / 超时 / 不可达 / 出错）、回包 TTL、时刻与 RTT；顶部四张卡片汇总已发送/已回应、丢包率、平均延迟以及最小/最大/抖动。
- 持续 ping 时明细只保留最近 500 条，但汇总是整轮累计的，不受截断影响。
- 接口：`POST /api/diag/ping {target, source_ip, count, interval_ms, timeout_ms, size}`，`count` 传负数表示一直 ping。

### 路由追踪（Traceroute）

- 逐跳加大 TTL，让沿途每个路由器各回一个 Time Exceeded，从而把整条路径问出来；收到目标回的 echo reply 就说明到了，该行标「目标」。
- 每跳显示各次探测的耗时与最快值，同一跳出现多个响应者（负载均衡）会分行列出；可选反查域名。
- 中间设备不回 ICMP 时显示 `*`，属正常现象；**连续 5 跳无响应会提前结束**，免得对着一堵墙把 30 跳跑完。
- 接口：`POST /api/diag/traceroute {target, source_ip, max_hops, probes, timeout_ms, resolve_names}`。

### 权限说明

ICMP 套接字有两条路：非特权的 ICMP 数据报套接字与需要 root 的原始套接字。ping 优先用前者（macOS 默认可用，Linux 需要当前用户的 gid 在 `net.ipv4.ping_group_range` 内），traceroute 优先用后者——**Linux 上非特权套接字收不到中间路由器的回包**，那样整趟都会是超时，这种情况界面会明确提示。两条都打不开时接口返回 `403` 并说明原因。

### 共用接口

`GET /api/diag/job?id=<任务ID>` 或 `?kind=ping|traceroute`（取该类最近一次，没有则返回 `{"found":false}`）；`POST /api/diag/stop {"id":"..."}`。内存里保留最近 20 次诊断记录。

---

## 项目结构

按业务分包，`main.go` 只做命令行参数解析与装配，各业务互不依赖对方的内部实现。

```text
nettool/
├── go.mod            # Go 模块配置文件
├── main.go           # 入口：解析参数 → 装配各业务 → 起 Web 服务
├── internal/
│   ├── proxy/        # SOCKS5 代理
│   │   ├── server.go     # 启停、出口 IP 绑定、配置
│   │   ├── resolver.go   # 代理侧域名解析、目标记录
│   │   └── stats.go      # 连接与流量统计
│   ├── route/        # 路由台账（多路由器网关调度）
│   │   ├── model.go      # 路由/域名的数据模型
│   │   ├── manager.go    # 增删改、暂停/恢复
│   │   ├── domain.go     # 域名解析、定时重新解析
│   │   ├── state.go      # 台账持久化、启动对账、重新下发
│   │   ├── oscmd.go      # 各平台路由命令拼装与执行
│   │   └── kernel.go     # 内核路由表解析（用于对账）
│   ├── dnsserver/    # 本地 DNS 服务
│   │   ├── settings.go   # 配置模型与校验（上游写法归一化）
│   │   ├── engine.go     # 查询引擎：分流、缓存、UDP/TCP/DoT/DoH 上游
│   │   ├── cache.go      # 应答缓存
│   │   ├── stats.go      # 查询统计
│   │   ├── message.go    # DNS 报文工具
│   │   ├── server.go     # 监听与生命周期、测试解析
│   │   └── config.go     # 配置持久化
│   ├── netconfig/    # 网卡配置与 Wi-Fi 自动切换
│   │   ├── nic.go        # 配置模型、校验、下发命令拼装
│   │   ├── nicread.go    # 读取三平台的当前网卡配置
│   │   ├── wifi.go       # 当前 SSID / 网络指纹识别
│   │   ├── profile.go    # Wi-Fi 配置档存取
│   │   └── watcher.go    # 按 SSID 自动切换
│   ├── netdiag/      # 连通性诊断（ping / traceroute）
│   │   ├── netdiag.go    # 参数校验、诊断任务与结果模型
│   │   ├── icmp.go       # ICMP 套接字：收发与回包匹配
│   │   ├── ping.go       # ping 的探测循环与统计
│   │   └── traceroute.go # 逐跳 TTL 探测与反查
│   ├── netiface/     # 本机网卡枚举与网关探测
│   ├── netutil/      # 跨包共用的小工具（域名校验、状态文件原子写入）
│   └── api/          # HTTP 管理接口 + 前端托管
│       ├── server.go     # 路由注册与 Basic Auth
│       ├── route.go      # /api/routes*
│       ├── proxy.go      # /api/status、/api/proxy、/api/stats、/api/egress-ip
│       ├── net.go        # /api/net/*
│       ├── dns.go        # /api/dns/*
│       └── diag.go       # /api/diag/*
├── Makefile          # 多平台一键编译脚本
├── deploy/
│   ├── nettool.service  # Linux Systemd 服务模板
│   └── nettool.init     # OpenWrt Procd 初始化脚本模板
├── static/
│   └── index.html    # 嵌入式响应式 Web 管理前端（六个页签）
└── README.md         # 项目说明文档
```

---

## 编译（使用 Makefile）

一键编译所有平台（输出至 `build/` 目录）：

```bash
make all-platforms
```

按指定平台单独编译：

- `make linux` （Linux AMD64）
- `make windows` （Windows AMD64）
- `make darwin` （macOS Intel & ARM）
- `make router` （路由器/嵌入式设备：ARMv7, ARM64, MIPS, MIPSLE）

---

## 运行与参数

```bash
sudo ./nettool -socks-port 8091 -api-port 8090 -user admin -pass my_secure_password
```

**代理**

- `-socks-port`: SOCKS5 代理监听端口（留空沿用配置文件里的值，默认 `8091`）
- `-start-proxy`: 启动时**无条件**开启 SOCKS5 代理；不加则按上次退出前的开关状态恢复（第一次运行为不启动，在 Web 后台点「启动代理」）
- `-outbound-ip`: SOCKS5 代理外发流量绑定的本地网卡 IP（留空沿用配置文件里的值）
- `-dns`: 代理解析域名用的上游 DNS（如 `8.8.8.8`），查询从 `-outbound-ip` 绑定的地址发出；留空沿用配置文件里的值，要改回系统 DNS 在 Web 后台清空即可
- `-proxy-config-file`: 代理配置文件路径（留空则与路由台账同目录的 `proxy.json`）

**Web 后台**

- `-api-port`: Web 管理后台与 API 端口（默认 `8090`）
- `-user` / `-pass`: Web 控制台登录用户名与密码（留空则不启用认证）

**路由**

- `-state-file`: 路由台账文件路径（留空自动选择可写位置）
- `-restore-routes`: 启动时自动重新下发台账中已失效的路由
- `-domain-refresh`: 域名路由自动重新解析间隔，默认 `5m`，设为 `0` 关闭

**网卡与 Wi-Fi**

- `-wifi-watch`: 检查当前 Wi-Fi 的间隔，用于按 SSID 自动切换网卡配置，默认 `30s`，设为 `0` 关闭
- `-net-profile-file`: Wi-Fi 网卡配置档文件路径（留空则与路由台账同目录的 `net-profiles.json`）

**DNS 服务**

- `-start-dns`: 启动时**无条件**开启本地 DNS 服务；不加则按上次退出前的开关状态恢复（第一次运行为不启动，在 Web 后台点「启动 DNS」）
- `-dns-listen`: 监听地址（留空沿用配置文件里的值，默认 `0.0.0.0`）
- `-dns-port`: 监听端口（留空沿用配置文件里的值，默认 `53`，需要 root）
- `-dns-upstream`: 上游列表，逗号分隔，如 `223.5.5.5,tls://dns.alidns.com,https://doh.pub/dns-query`；**仅在配置文件里还没有上游时生效**，否则每次带参数启动都会冲掉后台调好的列表
- `-dns-config-file`: DNS 服务配置文件路径（留空则与路由台账同目录的 `dns.json`）

> Ping 与路由追踪没有命令行参数，全部在 Web 后台按次发起。

---

## 部署为系统服务

### Linux (Systemd)

1. 将编译好的二进制文件复制到 `/usr/local/bin/`：
   ```bash
   sudo cp build/nettool-linux-amd64 /usr/local/bin/nettool
   sudo chmod +x /usr/local/bin/nettool
   ```
2. 将 `deploy/nettool.service` 复制到 `/etc/systemd/system/`：
   ```bash
   sudo cp deploy/nettool.service /etc/systemd/system/
   ```
3. 修改服务文件中的密码及参数（如需）：
   ```bash
   sudo nano /etc/systemd/system/nettool.service
   ```
4. 启动并设置开机自启：
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now nettool
   sudo systemctl status nettool
   ```

### OpenWrt 路由器

1. 将对应架构的二进制文件（如 `nettool-router-mipsle`）通过 SCP 上传至路由器 `/usr/bin/nettool`，并赋予执行权限：
   ```bash
   chmod +x /usr/bin/nettool
   ```
2. 将 `deploy/nettool.init` 复制到路由器 `/etc/init.d/nettool`：
   ```bash
   chmod +x /etc/init.d/nettool
   ```
3. 启停与开机自启配置：
   ```bash
   /etc/init.d/nettool enable
   /etc/init.d/nettool start
   ```

---

## 测试

### SOCKS5 代理

```bash
# 传递域名给代理解析
curl --socks5-hostname 127.0.0.1:8091 'https://myip.ipip.net/'
# 本地解析后把 IP 交给代理
curl --socks5 127.0.0.1:8091 'https://myip.ipip.net/'
curl 'https://myip.ipip.net/' -x socks5://127.0.0.1:8091
```

### 本地 DNS 服务

```bash
# 先不占用 53，用 5353 起来验证（配好上游后在后台点「启动 DNS」，或加 -start-dns）
sudo ./nettool -dns-port 5353 -dns-upstream '223.5.5.5,https://doh.pub/dns-query' -start-dns

dig +short @127.0.0.1 -p 5353 www.baidu.com A     # UDP
dig +tcp +short @127.0.0.1 -p 5353 example.com A  # TCP
# 第二次同样的查询应当直接命中缓存（后台「最近查询」里来源显示「缓存」，TTL 会随时间递减）

# 不启动服务也能测某个上游通不通
curl -s -X POST http://127.0.0.1:8090/api/dns/query \
  -H 'Content-Type: application/json' \
  -d '{"name":"www.example.com","type":"A","upstream":"腾讯DoH"}'
```

### 连通性诊断

```bash
# 从指定网卡 IP ping，起完任务用返回的 id 取结果
curl -s -X POST http://127.0.0.1:8090/api/diag/ping \
  -H 'Content-Type: application/json' \
  -d '{"target":"1.1.1.1","source_ip":"192.168.1.10","count":4}'
curl -s 'http://127.0.0.1:8090/api/diag/job?kind=ping'

# traceroute（Linux 需要 root）
curl -s -X POST http://127.0.0.1:8090/api/diag/traceroute \
  -H 'Content-Type: application/json' \
  -d '{"target":"8.8.8.8","max_hops":30,"probes":3,"resolve_names":true}'
curl -s 'http://127.0.0.1:8090/api/diag/job?kind=traceroute'
```

### 单元测试

含 DNS 转发/缓存/分流的端到端用例、三平台命令拼装、ICMP 回包匹配等：

```bash
go test -race ./...
```

---

## 参考文献

- [Go Programming Language](https://golang.org/)
- [Armon go-socks5 Library](https://github.com/armon/go-socks5)
- [golang.org/x/net/icmp](https://pkg.go.dev/golang.org/x/net/icmp)
- [Systemd Service Unit Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [OpenWrt Procd Init Scripts](https://openwrt.org/docs/techref/procd)
