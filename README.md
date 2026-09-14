# MCTier 信令服务器

MCTier 联机工具的 WebSocket 信令服务器，用 Rust + Tokio 编写。它负责在玩家之间交换
WebRTC 的 Offer / Answer / ICE Candidate，帮助客户端建立 P2P 连接，并提供大厅隔离、
房主管理、公开大厅广场、屏幕共享与文件共享的信令转发。

服务器只转发信令，不中转游戏流量。语音、屏幕共享和文件传输的数据都走客户端之间的
P2P 通道，因此服务器带宽占用很低，1 核 512MB 的小机器即可承载。

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [环境变量](#环境变量)
- [反向代理与 HTTPS/WSS](#反向代理与-httpswss)
- [服务管理](#服务管理)
- [客户端配置](#客户端配置)
- [本地开发](#本地开发)
- [信令协议](#信令协议)
- [安全说明](#安全说明)
- [故障排查](#故障排查)
- [系统要求](#系统要求)
- [开源协议](#开源协议)

## 功能特性

- **大厅隔离**：以 `SHA256(大厅名)` 作为大厅 ID，进入已有大厅时单独校验密码。输错密码明确拒绝，不会创建同名房间。
- **房主管理**：踢人、禁言、转让房主、设置人数上限。房主退出时自动把房主转移给剩余玩家。
- **公开大厅广场**：房主可将大厅设为公开并填写简介，其他玩家在广场中浏览后一键加入，并自动同步房主使用的 EasyTier 节点。
- **用户共享节点**：玩家可投稿自己的 EasyTier 节点供他人使用。投稿时先探测可达性，入库后由服务器周期性巡检，**失效超过 1 天的节点自动移除**，列表按在线状态与延迟排序。
- **屏幕共享信令**：支持共享列表同步、观众计数，以及链式中继（`screen-share-relay`），让观众可以从其他观众处转发画面，减轻共享者上行压力。
- **文件共享信令**：共享的添加、移除与列表同步。
- **版本准入**：低于最低版本要求的客户端会被拒绝并收到下载地址提示，避免旧客户端因协议不兼容出现异常。
- **防伪造校验**：转发前校验消息的 `from` 与该连接注册的 `clientId` 是否一致，未注册的连接不能发送信令。
- **断线重连保护**：同一 `clientId` 用新连接重连后，旧连接的延迟断开不会误删新连接的会话记录。

## 快速开始

### 一键部署（推荐）

```bash
# 1. 拉取源码
git clone https://github.com/pmh1314520/MCTier-Signaling-Server.git
cd MCTier-Signaling-Server

# 2. 运行部署脚本
chmod +x deploy.sh
sudo ./deploy.sh
```

脚本会自动检查并安装 Docker 与 Docker Compose，构建镜像，启动服务并配置自动重启。

部署完成后，信令容器监听在 `127.0.0.1:8445`（**仅本机**）。
对外提供服务需要你自己在宿主机上配一层反向代理，见
[反向代理与 HTTPS/WSS](#反向代理与-httpswss)。

### 手动部署

```bash
# 1. 安装 Docker
curl -fsSL https://get.docker.com | bash
systemctl enable --now docker

# 2. 按需修改配置
cp .env.example .env

# 3. 启动服务
docker compose up -d --build

# 4. 查看日志
docker compose logs -f
```

容器默认只绑定回环地址，因此**不需要**在防火墙放行 `8445`；
需要放行的是你自己反向代理监听的端口（通常是 `443`）。

## 环境变量

所有配置都通过环境变量提供，可写在 `.env` 文件里（参考 `.env.example`）。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND_ADDRESS` | `0.0.0.0:8445` | 监听地址和端口 |
| `RUST_LOG` | `info` | 日志级别：`error`/`warn`/`info`/`debug`/`trace` |
| `MINIMUM_CLIENT_VERSION` | `3.0.0` | 允许连接的最低客户端版本，低于此版本会被拒绝 |
| `CLIENT_DOWNLOAD_URL` | MCTier 官网 | 版本过低时提示给客户端的下载地址 |
| `MAX_CONNECTIONS` | `4096` | 最大并发 WebSocket 连接数，超出后新连接被直接拒绝 |
| `MAX_CONNECTIONS_PER_SOURCE` | 未设置（不启用） | 可选的每个真实来源并发上限；只有显式设置正整数（例如 `128`）才启用。同一 NAT 下的用户会共享该额度 |
| `TRUSTED_PROXIES` | 空 | 逗号分隔的反代 IP 白名单。仅信任这些直接上游的转发头；不能填所有来源或任意内网网段 |
| `COMMUNITY_NODES_FILE` | `community_nodes.json` | 用户投稿共享节点的存档路径。Docker 部署下为 `/app/data/community_nodes.json`，已挂载命名卷，容器重建后投稿不丢失 |
| `COMMUNITY_NODE_CAPACITY` | `200` | 共享节点列表容量上限 |
| `COMMUNITY_NODE_ALLOW_PRIVATE_TARGETS` | `false` | 是否允许探测回环/内网/保留地址。默认只探测公网地址，避免投稿接口被当作内网端口扫描器（SSRF）。仅同内网自建部署才需开启 |

修改环境变量后需要强制重建容器才会生效：

```bash
docker compose up -d --force-recreate
```

## 反向代理与 HTTPS/WSS

本仓库**只提供信令容器**，不内置 Nginx 与 Certbot：证书、域名和网关属于部署环境的
私有配置，塞进 compose 往往会和服务器上已有的网关抢 80/443 端口。
反向代理与 TLS 请按你自己的习惯处理（nginx / caddy / 云厂商负载均衡都可以）。

当前 Compose 默认发布 `127.0.0.1:8445:8445`，避免公网绕过 TLS 反向代理；反代位于其他容器时使用私有 Docker 网络，并通过防火墙限制直连来源。

必须透传 WebSocket 升级头。信令走的是 WebSocket，
少了 `Upgrade` / `Connection` 这两个头，握手会直接失败（客户端表现为连不上信令）。

nginx 的最小配置示例：

```nginx
location /signaling {
    proxy_pass http://127.0.0.1:8445;
    proxy_http_version 1.1;

    # WebSocket 握手必需
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    proxy_set_header Host $host;
    # 单层边缘反代覆盖客户端自带的转发头，不接受客户端自报 IP
    proxy_set_header X-Forwarded-For $remote_addr;

    # 大厅内长时间无消息时不要掐断连接（服务器侧有 60s 空闲回收与心跳）
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

caddy 的等价写法（自动签发证书，不需要额外配 TLS）：

```caddy
mctier.example.com {
    reverse_proxy /signaling* 127.0.0.1:8445
}
```

配好之后客户端填 `wss://mctier.example.com/signaling`。

在 Compose 同目录的 `.env` 中设置 `TRUSTED_PROXIES` 为**信令容器实际看到的代理 IP**。例如实际来源是 `172.20.0.1` 才填写 `TRUSTED_PROXIES=172.20.0.1`；不要照抄其他服务器的地址。可以结合连接日志与 `docker network inspect mctier-network` 确认。直接运行且代理来源为回环地址时，可填写 `127.0.0.1,::1`。

只有受信任代理的 `X-Forwarded-For`（或 `X-Real-IP`）会被使用。多层代理从右向左跳过已配置的可信节点，取最近的非可信来源；格式错误、重复头或缺失真实 IP 的可信代理请求返回 HTTP 429。未配置白名单时，头信息会被忽略，不能为了绕过来源限制而信任任意客户端转发头。

未完成 HTTP 握手的连接使用独立池，默认最多 128 个、每个真实来源最多 16 个，10 秒超时回收；成功升级的 WebSocket 仍受 `MAX_CONNECTIONS` 全局上限约束，未注册连接仍在 15 秒后回收。已建立连接默认不启用单来源限制；只有显式设置有效的 `MAX_CONNECTIONS_PER_SOURCE` 才按真实来源限制连接数，来源额度按 IPv4 地址或 IPv6 /64 网段归并。消息限速按每条连接独立计算，不会把代理下所有玩家合并。公网边缘仍需配置连接/握手速率限制与云厂商抗 DDoS，应用层限制无法抵御链路带宽被打满。

如果部署环境已经正确恢复真实客户端 IP，可以显式设置 `MAX_CONNECTIONS_PER_SOURCE`；如果多个用户经过同一 EdgeOne/OpenResty/Docker 网关而无法恢复真实地址，应保持该变量为空，让 `MAX_CONNECTIONS` 继续提供全局保护，同时修正代理信任链。不要仅为消除 429 而信任任意转发头或关闭全部连接保护。

如果客户端提示无法完成注册，且握手返回 `429 source connection capacity reached`，表示来源连接名额已满，不代表 DNS 解析失败。新版日志会显示 `tcp_peer`、`quota_source`、`trusted_proxy` 和拒绝原因（最多每 5 秒一条）。若不同玩家都被计入同一代理地址，必须修正 `TRUSTED_PROXIES`；若经过 CDN，多层代理也须正确传递和验证真实来源，不能只把 Docker 网关列入白名单而继续按 CDN 节点计数。不要信任任意客户端传来的转发头，也不要为消除报错直接关闭全部连接保护。

使用腾讯 EdgeOne 与 1Panel/OpenResty 的部署，请按 [EdgeOne 真实来源与注册失败排查](docs/edgeone-signaling-proxy.md) 配置两层代理。连接成功日志中的 `quota_source` 应为玩家出口 IP（IPv6 为 /64 网段），用于确认配置是否真正生效。

可先检查当前容器配置：

```bash
docker exec mctier-signaling sh -c 'printenv | grep -E "^(TRUSTED_PROXIES|MAX_CONNECTIONS|MAX_CONNECTIONS_PER_SOURCE)="'
docker logs --tail=300 mctier-signaling 2>&1 | grep -E '拒绝 WebSocket 握手|WebSocket 连接已建立'
```

仅修改 `.env` 后，应执行 `docker compose up -d --force-recreate mctier-signaling`，普通重启不会加载新环境变量。代理 IP 必须来自实际部署信息，不能照抄示例。修改源码后仍需重新构建镜像。

源码和环境配置更新后执行：

```bash
docker compose up -d --build --force-recreate mctier-signaling
```

本次增加了 `src/connection_guard.rs`，部署必须同步整个 `src` 目录，不能只替换 `main.rs`。

### 不想加反向代理（仅内网测试）

把 `docker-compose.yml` 里的端口改成直接对外，然后放行 `8445/tcp`：

```yaml
ports:
  - "8445:8445"
```

此时客户端填 `ws://你的服务器IP:8445`。**这是明文连接**，大厅密码等信令内容不加密，
只适合内网自用，不要这样暴露到公网。

## 服务管理

```bash
# 查看日志
docker compose logs -f mctier-signaling

# 重启 / 停止
docker compose restart
docker compose down

# 更新到最新代码
git pull
docker compose up -d --build
```

## 客户端配置

在 MCTier 客户端的设置中填写信令服务器地址：

```
# 经反向代理（推荐，公网部署请用这个）
wss://你的域名/signaling

# 容器直连（仅内网测试；需先把端口改为 8445:8445，明文不加密）
ws://你的服务器IP:8445
```

EasyTier 节点服务器可以继续使用官方节点，也可以自建：

```
wss://mctiers.pmhs.top
```

## 本地开发

需要 Rust 1.83 或更高版本。

```bash
# 检查编译
cargo check

# 本地运行（可用环境变量覆盖配置）
RUST_LOG=debug BIND_ADDRESS=127.0.0.1:8445 cargo run

# 构建发布版本
cargo build --release
```

编译产物在 `target/release/mctier-signaling-server`。

## 信令协议

所有消息都是 JSON 文本帧，用 `type` 字段区分类型。客户端连接后必须先发送 `register`，
在收到 `register-success` 之前发送的其他信令都会被拒绝。

### 连接与大厅

| 消息类型 | 方向 | 说明 |
| --- | --- | --- |
| `register` | 客户端 → 服务器 | 携带 `clientId`、`playerName`、`lobbyName`、`lobbyPassword`、`clientVersion` |
| `register-success` | 服务器 → 客户端 | 返回 `lobbyId`、`hostId`、`maxPlayers`、`isPublic`、`mutedPlayers` |
| `register-error` | 服务器 → 客户端 | 注册失败原因（大厅人数已满、旧版本字段缺失等） |
| `version-too-old` | 服务器 → 客户端 | 版本过低，附带 `minimumVersion` 和 `downloadUrl` |
| `players-list` | 服务器 → 客户端 | 当前大厅玩家列表 |
| `player-joined` / `player-left` | 服务器 → 客户端 | 玩家进出通知 |

### WebRTC 与聊天

`offer`、`answer`、`ice-candidate` 在同一大厅内按 `to` 字段定向转发；
`chat-message` 在大厅内广播，被禁言的玩家发送的消息会被丢弃。

### 房主管理

`kick-player`、`mute-player`、`transfer-host`、`set-lobby-options` 只接受房主发送，
对应的结果通过 `kicked`、`player-mute-changed`、`host-changed`、`lobby-options-changed` 通知大厅成员。

### 公开大厅广场

客户端发送 `public-lobby-list-request`，服务器返回 `public-lobby-list-response`，
其中每个条目包含大厅名、当前人数、人数上限、房主名、简介以及房主使用的 EasyTier 节点，不包含密码。

### 用户共享节点

客户端发送 `community-node-list-request`，服务器返回 `community-node-list-response`，
条目包含节点名、地址、投稿者、投稿时间、最近一次探测成功时间、在线状态与延迟。

投稿使用 `community-node-submit`（字段：`name`、`address`、可选 `submitter`），
服务器回 `community-node-submit-result`（`ok` / `message` / 成功时附 `node`）。两类消息都**不要求先注册**，
玩家在进入大厅前也能浏览和投稿。

节点存活判定与自动淘汰：

- 投稿时立即探测一次，**不可达的地址直接拒绝入库**，避免死地址进入公共列表；
- 入库后每 5 分钟巡检一轮，探测成功即刷新 `lastOkAt`；
- `lastOkAt` 距今**超过 1 天**即自动移除，并立即写回存档；
- 短暂不可达只把 `online` 置为 `false`，不会立刻删除，避免一次网络抖动误删正常节点；
- 探测以 TCP 握手为准；`udp://` 节点在 TCP 不通时退化为 UDP 探测（收到 ICMP 端口不可达才判失效）；
- 同一来源 IP 的投稿有 30 秒冷却，地址会归一化后去重（协议/主机大小写、缺省端口视为同一节点）；
- 投稿地址先解析成 IP 再校验，**只探测公网可路由的单播地址**：回环、私有网段、链路本地
  （含 `169.254.169.254` 云元数据）、CGNAT、文档/保留段以及它们的 IPv6 映射写法一律拒绝，
  防止有人借投稿接口把服务器变成内网端口扫描器；解析结果直接用于连接，不留 DNS Rebinding 窗口。

### 屏幕共享与文件共享

`screen-share-start` / `screen-share-stop` / `screen-share-update` 维护共享列表和观众计数；
`screen-share-offer` / `screen-share-answer` / `screen-share-ice-candidate` 完成媒体协商；
`screen-share-relay` 用于链式中继的上下游协商。文件共享对应
`file-share-added` / `file-share-removed` 和列表请求响应。

## 安全说明

部署前请了解以下几点：

- **大厅密码即访问凭证**。大厅 ID 只由名称决定；服务端单独校验已有大厅的密码，错误时不下发聊天令牌或成员信息。名称和密码中的分隔符不会改变大厅归属。请使用不易猜测的密码。大厅随最后一位成员离开而销毁，并非永久保留的账号或房间。
- **公开广场只接受无密码大厅**。广场列表不再下发任何密码（`PublicLobbyInfo` 结构里没有密码字段），
  带密码的大厅也不允许公开——两条一起才能真正闭合：只去掉列表里的密码字段，
  带密码的大厅仍会被公开且陌生人无从加入；只禁止带密码大厅公开，历史数据仍可能残留密码。
  因此"公开"等同于"任何看到广场的人都能进"，请据此决定是否公开。这两条都有单测覆盖。
- **服务器没有账号体系**。协议 v3 使用公钥签名证明客户端身份，但不限制用户生成新身份；密码和大厅成员校验仍是访问权限边界，域名保密不能替代鉴权。
- **公网部署必须用 WSS**。明文 WS 会把信令内容（包括大厅密码）暴露在链路上。
  当前 Compose 已默认使用回环映射；直连测试或跨容器访问时，请显式改成受限的 `8445:8445` 映射或私有 Docker 网络。
- **反向代理需要配置可信来源和真实 IP 头**。连接额度与投稿冷却按解析后的真实来源隔离，普通客户端伪造转发头无效。
- **不要提交敏感文件**。`.gitignore` 已排除 `.env` 与各类证书私钥，请勿手动强制添加。

## 故障排查

### 无法连接到信令服务器

先确认容器在运行（`docker compose ps`），再按下面的顺序排查：

1. **容器本身通不通**（绕过反向代理，直接在服务器上测）：

   ```bash
   nc -vz 127.0.0.1 8445
   ```

2. **反向代理有没有透传 WebSocket 升级头**。这是最常见的原因：普通 HTTP 反代配置
   缺少 `Upgrade` / `Connection`，页面能打开但信令握不上手。参考
   [反向代理与 HTTPS/WSS](#反向代理与-httpswss) 的示例配置。

3. **防火墙 / 安全组放行的是反向代理的端口**（通常 `443`），而不是 `8445`——
   容器默认只监听回环，放行 8445 没有意义。
   仅当你把端口改成 `8445:8445` 直连时才需要放行它：

   ```bash
   # Ubuntu / Debian
   sudo ufw allow 8445/tcp

   # CentOS / RHEL
   sudo firewall-cmd --permanent --add-port=8445/tcp && sudo firewall-cmd --reload
   ```

云服务器还需要在厂商控制台的安全组里放行对应端口。

### 客户端提示版本过低

服务器的 `MINIMUM_CLIENT_VERSION` 高于客户端版本。升级客户端，或调低该环境变量后重建容器。

### 查看详细日志

```bash
docker compose logs --tail=100 mctier-signaling

# 需要更详细的信息时把日志级别调成 debug
RUST_LOG=debug docker compose up -d
```

### 测试连接是否通畅

```bash
# 容器直连（在服务器本机执行）
nc -vz 127.0.0.1 8445

# 经反向代理的 WebSocket 握手：正常应返回 101 Switching Protocols
curl -i -N \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://你的域名/signaling
```

返回 `200` 或 `404` 说明请求被反向代理当成普通 HTTP 处理了，
即升级头没有透传；返回 `502` 说明代理连不上容器。

## 系统要求

- 操作系统：Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- CPU：1 核及以上
- 内存：512MB 及以上
- 磁盘：1GB 及以上
- 带宽：1Mbps 及以上（仅转发信令，占用很低）

## 技术栈

- Rust + Tokio：异步运行时
- tokio-tungstenite：WebSocket 实现
- serde / serde_json：消息序列化
- sha2：大厅 ID 哈希
- Docker + Docker Compose：容器化部署（反向代理与证书由部署者自行处理）

## 开源协议

本项目采用 MCTier 自定义开源协议，详见 [LICENSE](LICENSE)：

- 禁止商业用途
- 允许二次开发
- 必须标明原作者
- 二次开发必须开源

## 相关项目

- MCTier 主项目：https://github.com/pmh1314520/MCTier

## 联系方式

- 作者：青云制作_彭明航
- QQ：2124691573
- QQ 交流群：1075096452
- GitHub：https://github.com/pmh1314520/MCTier
- Gitee：https://gitee.com/peng-minghang/mctier
