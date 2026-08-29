# MCTier 信令服务器 Docker 镜像
# 基于 Rust 官方镜像构建

# 构建阶段
FROM rust:1.83-slim as builder

# 安装必要的构建工具
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制 Cargo 配置文件
COPY Cargo.toml Cargo.lock ./

# 复制源代码
COPY src ./src

# 构建发布版本
RUN cargo build --release

# 运行阶段
FROM debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# 创建非 root 用户
RUN useradd -m -u 1000 mctier

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/release/mctier-signaling-server /app/mctier-signaling-server

# 更改所有权
RUN chown -R mctier:mctier /app

# 切换到非 root 用户
USER mctier

# 暴露端口
EXPOSE 8445

# 设置环境变量
ENV RUST_LOG=info
ENV BIND_ADDRESS=0.0.0.0:8445

# 启动服务
CMD ["/app/mctier-signaling-server"]
