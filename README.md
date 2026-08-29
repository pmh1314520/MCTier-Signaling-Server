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
- [配置 HTTPS/WSS](#配置-httpswss)
- [服务管理](#服务管理)
- [客户端配置](#客户端配置)
- [本地开发](#本地开发)
- [信令协议](#信令协议)
- [安全说明](#安全说明)
- [故障排查](#故障排查)
- [系统要求](#系统要求)
- [开源协议](#开源协议)

## 功能特性

- **大厅隔离**：以 `SHA256(大厅名:密码)` 作为大厅 ID，只有大厅名和密码都一致的客户端才会进入同一个大厅，互不干扰。
- **房主管理**：踢人、禁言、转让房主、设置人数上限。房主退出时自动把房主转移给剩余玩家。
- **公开大厅广场**：房主可将大厅设为公开并填写简介，其他玩家在广场中浏览后一键加入，并自动同步房主使用的 EasyTier 节点。
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

部署完成后，信令服务器监听在 `ws://你的服务器IP:8445`。

### 手动部署

```bash
# 1. 安装 Docker
curl -fsSL https://get.docker.com | bash
systemctl enable --now docker

# 2. 按需修改配置
cp .env.example .env

# 3. 启动服务（HTTP/WS 模式）
docker compose -f docker-compose-http.yml up -d --build

# 4. 查看日志
docker compose -f docker-compose-http.yml logs -f
```

记得在防火墙和云厂商安全组放行 `8445/tcp`。

## 环境变量

所有配置都通过环境变量提供，可写在 `.env` 文件里（参考 `.env.example`）。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `BIND_ADDRESS` | `0.0.0.0:8445` | 监听地址和端口 |
| `RUST_LOG` | `info` | 日志级别：`error`/`warn`/`info`/`debug`/`trace` |
| `MINIMUM_CLIENT_VERSION` | `2.1.0` | 允许连接的最低客户端版本，低于此版本会被拒绝 |
| `CLIENT_DOWNLOAD_URL` | MCTier Releases 页面 | 版本过低时提示给客户端的下载地址 |

修改环境变量后需要重建容器才会生效：

```bash
docker compose -f docker-compose-http.yml up -d
```

## 配置 HTTPS/WSS

默认部署是 HTTP/WS 模式。如果客户端需要走 `wss://`，或者你希望用域名而不是 IP，
可以用仓库里的 `docker-compose.yml`，它额外带了 Nginx 反向代理和 Certbot 自动续期。

前提条件：拥有一个域名、域名已解析到服务器 IP、服务器放行 80 和 443 端口。

### 1. 修改 Nginx 配置中的域名

```bash
sed -i 's/your-domain.com/mctier.example.com/g' nginx.conf
```

### 2. 申请 SSL 证书

```bash
mkdir -p certbot/conf certbot/www

# 先只启动 Nginx 用于域名验证
docker compose up -d nginx

# 申请 Let's Encrypt 免费证书
docker compose run --rm certbot certonly \
  --webroot --webroot-path=/var/www/certbot \
  --email your-email@example.com \
  --agree-tos --no-eff-email \
  -d mctier.example.com
```

### 3. 启动全部服务

```bash
# 停掉 HTTP 模式
docker compose -f docker-compose-http.yml down

# 启动 HTTPS 模式
docker compose up -d
```

现在客户端可以使用 `wss://mctier.example.com/signaling` 连接。

HTTPS 模式下信令容器的 8445 端口不再直接对公网暴露，只允许 Nginx 通过内部网络访问。

### 使用已有的 SSL 证书

如果你已经有证书，把文件放到对应目录再启动即可：

```bash
mkdir -p certbot/conf/live/your-domain.com/
# 放入 fullchain.pem（完整证书链）和 privkey.pem（私钥）
docker compose up -d
```

## 服务管理

HTTP 模式把下面命令中的 `docker compose` 换成 `docker compose -f docker-compose-http.yml` 即可。

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
# HTTP/WS 模式
ws://你的服务器IP:8445

# HTTPS/WSS 模式
wss://你的域名/signaling
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
其中每个条目包含大厅名、当前人数、人数上限、房主名、简介、加入密码以及房主使用的 EasyTier 节点。

### 屏幕共享与文件共享

`screen-share-start` / `screen-share-stop` / `screen-share-update` 维护共享列表和观众计数；
`screen-share-offer` / `screen-share-answer` / `screen-share-ice-candidate` 完成媒体协商；
`screen-share-relay` 用于链式中继的上下游协商。文件共享对应
`file-share-added` / `file-share-removed` 和列表请求响应。

## 安全说明

部署前请了解以下几点：

- **大厅密码即访问凭证**。大厅 ID 由大厅名和密码哈希得出，任何知道这两者的人都能进入大厅，请使用不易猜测的密码。
- **公开大厅会暴露密码**。设为公开的大厅，其密码会随广场列表下发给所有查询者，这是"一键加入"的实现方式。不想被陌生人加入就不要设为公开。
- **服务器本身没有账号体系**。它不做身份认证，任何能连上端口的客户端都可以注册。如果只想给朋友用，建议用防火墙限制来源 IP，或放在只有你们知道的域名后面。
- **建议使用 WSS**。HTTP/WS 模式下信令内容（包括大厅密码）以明文传输，公网部署请配置 HTTPS/WSS。
- **不要提交敏感文件**。`.gitignore` 已排除 `.env`、`certbot/` 和各类证书私钥，请勿手动强制添加。

## 故障排查

### 无法连接到信令服务器

先确认容器在运行（`docker compose ps`），再检查端口是否放行：

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
docker compose -f docker-compose-http.yml logs --tail=100 mctier-signaling

# 需要更详细的信息时把日志级别调成 debug
RUST_LOG=debug docker compose -f docker-compose-http.yml up -d
```

### 测试连接是否通畅

```bash
# 检查端口
nc -vz 你的服务器IP 8445

# HTTPS 模式检查 Nginx
curl -I https://你的域名
```

### SSL 证书申请失败

确认域名已正确解析到服务器 IP、80 端口可从外网访问、服务器时间准确。需要重新申请时：

```bash
rm -rf certbot/conf/live/your-domain.com \
       certbot/conf/archive/your-domain.com \
       certbot/conf/renewal/your-domain.com.conf

docker compose run --rm certbot certonly \
  --webroot --webroot-path=/var/www/certbot \
  --email your-email@example.com \
  --agree-tos --no-eff-email \
  -d your-domain.com
```

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
- Docker + Docker Compose：容器化部署
- Nginx + Let's Encrypt：反向代理与证书（可选）

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
