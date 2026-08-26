# LAN Multi-Router & SOCKS5 Proxy Manager (Full-Featured with Auth & System Services)

本项目是一个基于 Go 语言编写的高性能工具，专为多路由器局域网（LAN）环境设计。最新版本加入了 **Web 后台登录认证（Basic Auth）** 以及 **Linux Systemd / OpenWrt 系统服务配置模板**，满足生产环境的长期稳定运行与安全管控需求。

---

## 核心功能特性

1. **Web 管理后台登录认证**：
   - 支持通过 `-user` 和 `-pass` 参数启用 HTTP Basic Auth 认证，保护 Web 控制台及所有 RESTful API 免受未授权访问。
2. **系统服务集成 (Service Deployment)**：
   - 提供标准 **Linux (Systemd)** 与 **OpenWrt (Procd)** 服务配置文件模板，支持开机自启与崩溃自动重启。
3. **流量统计与实时监控**：
   - 精确统计全局上下行流量、历史连接数，并提供 2 秒自动刷新的实时活跃连接监控仪表盘。
4. **代理可随时启停（默认关闭）**：
   - 程序启动后 **不会** 自动开启 SOCKS5 代理，只加载配置；在 Web 后台点「启动代理」才开始监听。想开机即启动加 `-start-proxy`。
   - 「停止代理」不只是关监听口，还会主动断开当前所有隧道连接——点了停止就是真的停，不会有残留连接继续跑流量。
   - 代理停止时仍可修改端口与出口 IP（保存后不会被动拉起，按钮文案相应变成「保存配置」）；代理运行中保存则自动带新配置重启（「保存并重启代理」）。
   - 界面显示运行状态、代理启动时刻与已运行时长（停止时为 `-`），以及不受代理开关影响的程序运行时长。
   - 接口：`POST /api/proxy {"action":"start"|"stop"}`；`GET /api/status` 返回 `running` / `proxy_state` / `started_at` / `uptime_seconds`。
5. **SOCKS5 出口网关强制绑定**：
   - 允许指定代理外发流量绑定的本地网卡 IP，强制经由指定路由器网关转发。
   - Web 后台自动读取本机可用网卡（网卡名、IP/掩码、对应网关）供下拉选择，并提供「刷新」按钮随时重新探测；亦可切换为「手动输入」填写任意 IP。
   - 网关按 **IP 逐个解析**而非按网卡：同一块网卡上的多个地址可能分属不同上游路由器（macOS 的多个网络服务 / Linux 的策略路由）。macOS 读取 `scutil` 中各网络服务的 `Router`，Linux 用 `ip route get <目标> from <本机IP>` 查询实际生效网关，取不到时回落到该网卡的默认路由。
   - ⚠️ 注意：显示的网关是系统对该地址配置的上游路由器。在 macOS 上，同一网卡的多个 IP 只有优先级最高的那条默认路由生效，**仅绑定源 IP 并不会自动改走另一个网关**；确需分流时请配合下方「自定义路由」按目标网段指定网关。
   - 对应接口：`GET /api/interfaces`，返回 `{"interfaces": [{name, ip, cidr, mac, gateway, loopback}], "outbound_ip": "当前生效出口IP"}`。
   - 出口 IP 强制校验：必须是本机网卡上真实存在的 IPv4 地址，否则启动时直接报错退出、`POST /api/status` 返回 `400` 并列出可用的本机 IP；校验失败不会影响正在运行的代理服务。
   - **实际出口公网 IP 探测**：后台点「检测」会真的经由本机 SOCKS5 端口请求一次 `https://myip.ipip.net/`（等价于 `curl --socks5-hostname 127.0.0.1:<port> 'https://myip.ipip.net/'`），用来确认绑定是否真的生效。接口 `GET /api/egress-ip`；代理停止时该接口返回 `409` 并提示先启动代理。
6. **双路由表展示与管理**：
   - 自定义托管路由增删 + 操作系统内核路由实时审计。
   - **支持按域名添加**：填域名会当场解析 A 记录，为每个 IPv4 下发一条 `/32` 主机路由。一个域名解析出多个 IP 时全部下发，并在界面里归为一组，可整组删除。
   - **定时自动重新解析**：CDN 域名的 IP 会轮换（实测 `myip.ipip.net` 一小时内 A 记录全变），默认每 **5 分钟**自动重新解析一遍，与最新 A 记录对齐——新增缺失的、撤下已不再解析到的。间隔由 `-domain-refresh` 控制（`0` 关闭），也可在界面点「重新解析」手动触发。
     - 只有真的发生变化才写日志，不会每轮刷屏。
     - **DNS 解析失败时保持现状**，绝不会因为一次抖动把路由全撤了；失败原因记在域名记录上，界面可见。
     - **新 IP 一条都没下发成功时不撤旧 IP**，避免该域名直接断流，留到下一轮重试。
     - 域名本身是独立记录（台账 `domains` 段），即使当前一条路由都没有也仍在托管、仍会被定时刷新；界面用琥珀色行显示这类"托管中但无生效路由"的域名及其最近错误。
   - 相关接口：`POST /api/routes/refresh {"domain":"example.com"}`；`DELETE /api/routes {"domain":"example.com"}` 取消托管并删除其全部路由。
   - **多个域名共用同一个 IP**：不同域名解析到同一地址时（CDN 上很常见），这条路由由它们共同持有，台账里记成 `domains: [...]`；取消托管其中一个域名不会删掉这条路由，只有最后一个持有者退出时才真正下发删除。界面上共用的行会注明「与 xxx 共用同一条路由」。
   - **暂停 / 恢复**：单条路由、整个域名、以及「全部暂停 / 全部恢复」都支持。暂停会把路由从内核撤下但保留台账记录（状态显示「已暂停」），恢复时重新下发；内核里本来就没有该条时按已暂停处理，不算失败。接口 `POST /api/routes/pause`。
   - **路由台账与启动对账**（解决"哪些是本程序改的"）：
     - 每次增删都写入 JSON 台账，记录 `destination / gateway / domain / resolved_at / created_at`；先写临时文件再原子替换。
     - 路径由 `-state-file` 指定，留空则依次尝试 `/var/lib/lan-proxy/routes.json` → `~/.lan-proxy/routes.json` → 当前目录，全部不可写则本次运行不持久化（并明确告警）。
     - 启动时读台账并与内核路由表逐条比对，日志与界面标出每条是「生效中 / 已失效 / 状态未知」；机器重启导致路由丢失时，可在界面点「重新下发失效路由」（`POST /api/routes/restore`），或用 `-restore-routes` 启动参数自动重建。
     - Linux 上下发时额外打 `proto 210` 标记，即使台账丢失也能用 `ip route show proto 210` 认出本程序加的路由；界面会把"内核有标记但台账没有"的列为孤儿路由。busybox 的 `ip` 不认 `proto` 时会自动去掉标记重试。
   - 目标写法统一归一化为 CIDR，各平台命令按主机/网段分别拼装（macOS `-host` vs `-net`、Windows 按前缀算掩码），由 `main_test.go` 覆盖。
7. **两个标签页分区**：
   - 「SOCKS5 代理」页：流量统计、监听端口与出口网卡绑定、实时连接监控（每 2 秒刷新，切走后自动暂停轮询）。
   - 「路由管理」页：自定义路由增删 + 系统完整路由表；网关输入框会用探测到的网关做候选。所选标签页记忆在 localStorage 中。
8. **Makefile 一键交叉编译**：
   - 支持 Linux、Windows、macOS 以及各类主流路由器架构（ARM、MIPS、MIPSLE）。

---

## 项目结构

```text
lan_router_socks5/
├── go.mod            # Go 模块配置文件
├── main.go           # 主程序源码（含安全认证中间件）
├── Makefile          # 多平台一键编译脚本
├── deploy/
│   ├── lan-proxy.service  # Linux Systemd 服务模板
│   └── lan-proxy.init     # OpenWrt Procd 初始化脚本模板
├── static/
│   └── index.html    # 嵌入式响应式 Web 管理前端
└── README.md         # 项目说明文档
```

---

## 编译指南 (使用 Makefile)

### 1. 一键编译所有平台（输出至 `build/` 目录）
```bash
make all-platforms
```

### 2. 按指定平台单独编译
- `make linux` （Linux AMD64）
- `make windows` （Windows AMD64）
- `make darwin` （macOS Intel & ARM）
- `make router` （路由器/嵌入式设备：ARMv7, ARM64, MIPS, MIPSLE）

---

## 运行与认证参数

启动时可指定账号密码以启用登录保护：

```bash
sudo ./lan_proxy -socks-port 1080 -api-port 8080 -user admin -pass my_secure_password
```

- `-socks-port`: SOCKS5 代理监听端口（默认 `1080`，代理默认不启动）
- `-start-proxy`: 启动时立即开启 SOCKS5 代理（默认 `false`，即启动后代理处于停止状态，在 Web 后台点「启动代理」）
- `-outbound-ip`: SOCKS5 代理外发流量绑定的本地网卡 IP
- `-api-port`: Web 管理后台与 API 端口（默认 `8080`）
- `-user`: Web 控制台登录用户名（留空则不启用认证）
- `-pass`: Web 控制台登录密码（留空则不启用认证）
- `-state-file`: 路由台账文件路径（留空自动选择可写位置）
- `-restore-routes`: 启动时自动重新下发台账中已失效的路由
- `-domain-refresh`: 域名路由自动重新解析间隔，默认 `5m`，设为 `0` 关闭

---

## 将程序配置为系统后台服务

### 1. Linux (Systemd) 部署指南
1. 将编译好的二进制文件复制到 `/usr/local/bin/`：
   ```bash
   sudo cp build/lan_proxy-linux-amd64 /usr/local/bin/lan_proxy
   sudo chmod +x /usr/local/bin/lan_proxy
   ```
2. 将 `deploy/lan-proxy.service` 复制到 `/etc/systemd/system/`：
   ```bash
   sudo cp deploy/lan-proxy.service /etc/systemd/system/
   ```
3. 修改服务文件中的密码及参数（如需）：
   ```bash
   sudo nano /etc/systemd/system/lan-proxy.service
   ```
4. 启动并设置开机自启：
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now lan-proxy
   sudo systemctl status lan-proxy
   ```

### 2. OpenWrt 路由器部署指南
1. 将对应的路由器架构二进制文件（如 `lan_proxy-router-mipsle`）通过 SCP 上传至路由器 `/usr/bin/lan_proxy`，并赋予执行权限：
   ```bash
   chmod +x /usr/bin/lan_proxy
   ```
2. 将 `deploy/lan-proxy.init` 复制到路由器 `/etc/init.d/lan_proxy`：
   ```bash
   chmod +x /etc/init.d/lan_proxy
   ```
3. 启停与开机自启配置：
   ```bash
   /etc/init.d/lan_proxy enable
   /etc/init.d/lan_proxy start
   ```

---

## 测试

### 传递域名socks5代理
curl --socks5-hostname 127.0.0.1:8091 'https://myip.ipip.net/'
### 传递本地解析后的ip做代理
curl --socks5 127.0.0.1:8091 'https://myip.ipip.net/'
curl 'https://myip.ipip.net/' -x socks5://127.0.0.1:8091


---

## 参考文献

- [Go Programming Language](https://golang.org/)
- [Armon go-socks5 Library](https://github.com/armon/go-socks5)
- [Systemd Service Unit Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [OpenWrt Procd Init Scripts](https://openwrt.org/docs/techref/procd)
