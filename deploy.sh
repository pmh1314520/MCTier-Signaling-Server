#!/bin/bash

# MCTier 信令服务器一键部署脚本
# 作者：青云制作_彭明航
# 版本：2.1.0（仅部署信令容器；反向代理与证书由部署者自行处理）

set -e

# 全局变量
DOCKER_COMPOSE_CMD=""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[信息]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[成功]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

print_error() {
    echo -e "${RED}[错误]${NC} $1"
}

# 打印欢迎信息
print_welcome() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   MCTier 信令服务器一键部署脚本${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

# 检查是否为 root 用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 root 用户或 sudo 运行此脚本"
        exit 1
    fi
}

# 检查 Docker 是否已安装
check_docker() {
    print_info "检查 Docker 是否已安装..."
    if ! command -v docker &> /dev/null; then
        print_warning "Docker 未安装，正在安装..."
        install_docker
    else
        print_success "Docker 已安装: $(docker --version)"
    fi
}

# 安装 Docker
install_docker() {
    print_info "开始安装 Docker..."
    curl -fsSL https://get.docker.com | bash
    systemctl start docker
    systemctl enable docker
    print_success "Docker 安装完成"
}

# 检查 Docker Compose 是否已安装
check_docker_compose() {
    print_info "检查 Docker Compose 是否已安装..."
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_warning "Docker Compose 未安装，正在安装..."
        install_docker_compose
    else
        print_success "Docker Compose 已安装"
        
        # 检测使用哪个命令
        if command -v docker-compose &> /dev/null; then
            DOCKER_COMPOSE_CMD="docker-compose"
        else
            DOCKER_COMPOSE_CMD="docker compose"
        fi
        print_info "使用命令: $DOCKER_COMPOSE_CMD"
    fi
}

# 安装 Docker Compose
install_docker_compose() {
    print_info "开始安装 Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    print_success "Docker Compose 安装完成"
    DOCKER_COMPOSE_CMD="docker-compose"
}

# 启动服务
start_services() {
    print_info "构建并启动信令服务器..."
    print_warning "首次构建需要 5-10 分钟下载依赖包，请耐心等待..."
    
    $DOCKER_COMPOSE_CMD up -d --build
    
    if [ $? -eq 0 ]; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败"
        exit 1
    fi
}

# 检查服务状态
check_services() {
    print_info "检查服务状态..."
    sleep 5
    
    $DOCKER_COMPOSE_CMD ps
    
    echo ""
    print_info "检查信令服务器健康状态..."
    
    # 等待服务完全启动
    for i in {1..30}; do
        if docker exec mctier-signaling timeout 1 bash -c '</dev/tcp/localhost/8445' 2>/dev/null; then
            print_success "信令服务器运行正常"
            break
        fi
        
        if [ $i -eq 30 ]; then
            print_warning "无法连接到信令服务器，请检查日志"
        else
            sleep 2
        fi
    done
}

# 显示部署信息
show_deployment_info() {
    # 获取服务器 IP 地址
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   部署完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    print_info "信令容器已监听: 127.0.0.1:8445（仅本机）"
    echo ""
    print_warning "容器只绑定回环地址，公网访问需要你自己在宿主机配置反向代理与 TLS。"
    print_info "反向代理需要把 WebSocket 升级头透传给 127.0.0.1:8445（Upgrade / Connection）。"
    print_info "客户端最终填写的地址形如: wss://your-domain.com/signaling"
    print_info "仅内网测试、不加反代时，可把 compose 里的端口改为 8445:8445（明文 WS，勿用于公网）。"
    echo ""
    print_info "常用命令："
    echo "  查看日志: $DOCKER_COMPOSE_CMD logs -f"
    echo "  重启服务: $DOCKER_COMPOSE_CMD restart"
    echo "  停止服务: $DOCKER_COMPOSE_CMD down"
    echo "  更新服务: $DOCKER_COMPOSE_CMD up -d --build"
    echo ""
    print_success "请在 MCTier 客户端设置中配置信令服务器地址"
    echo ""
}

# 主函数
main() {
    print_welcome
    
    # 检查是否为 root 用户
    check_root
    
    # 检查并安装 Docker
    check_docker
    
    # 检查并安装 Docker Compose
    check_docker_compose
    
    # 启动服务
    start_services
    
    # 检查服务状态
    check_services
    
    # 显示部署信息
    show_deployment_info
}

# 运行主函数
main
