#!/usr/bin/env bash
set -euo pipefail

# ====== 请把下面的 URL 改成你自己仓库的 RAW 链接 ======
SCRIPT_URL="https://raw.githubusercontent.com/janelai2022/nas_tools/main/NaiveProxy/do.sh"

# ====== 全局变量 ======
INSTALL_DIR="/opt/naive"
SCRIPT_PATH="${INSTALL_DIR}/naive.sh"
BIN_LINK="/usr/local/bin/naive"
ENV_FILE="/etc/naive.env"
CADDY_BIN="/usr/local/bin/caddy"
CADDY_DIR="/etc/caddy"
CADDYFILE="${CADDY_DIR}/Caddyfile"
SERVICE_NAME="naive.service"

# ====== 基础工具 ======
need_pkgs() {
  apt-get update -y
  apt-get install -y curl tar git ca-certificates iproute2 jq netcat-openbsd
  apt-get install -y dnsutils || true
  apt-get install -y ufw || true
  apt-get install -y nano || true
}

# ====== 自安装为 /usr/local/bin/naive ======
self_install() {
  mkdir -p "$INSTALL_DIR"
  # 用 SCRIPT_URL 自我复制到本地（避免 pipe 执行时 $0 不是文件）
  if [[ -n "${SCRIPT_URL}" ]]; then
    curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
  else
    # 退路：把当前内容写入（某些环境用不上）
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || true
    chmod +x "$SCRIPT_PATH" || true
  fi
  ln -sf "$SCRIPT_PATH" "$BIN_LINK"
}

# ====== 读取/写入 ENV ======
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi
}
save_env() {
  cat >"$ENV_FILE" <<EOF
DOMAIN="${DOMAIN}"
PORT="${PORT}"
PROXY_USER="${PROXY_USER}"
PROXY_PASS="${PROXY_PASS}"
ACME_EMAIL="${ACME_EMAIL}"
EOF
}

# ====== Go/xcaddy 安装 ======
ensure_go_xcaddy() {
  if ! command -v go >/dev/null 2>&1; then
    local GO_VER="1.22.7"
    echo "安装 Go ${GO_VER}…"
    cd /tmp && curl -fsSLO "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
    echo 'export PATH=/usr/local/go/bin:$PATH' >/etc/profile.d/go_path.sh
    export PATH=/usr/local/go/bin:$PATH
  fi
  if ! command -v xcaddy >/dev/null 2>&1; then
    echo "安装 xcaddy…"
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    export PATH="$(go env GOPATH)/bin:$PATH"
    echo "export PATH=$(go env GOPOPATH)/bin:\$PATH" >/etc/profile.d/xcaddy_path.sh || true
  fi
}

# ====== 编译 Caddy（forwardproxy 插件）======
build_caddy() {
  local PLUGINS="--with github.com/caddyserver/forwardproxy"
  mkdir -p /opt/caddy-bin && cd /opt/caddy-bin
  echo "编译 Caddy（plugins: ${PLUGINS}）…"
  xcaddy build latest ${PLUGINS}
  install -m 0755 caddy "$CADDY_BIN"
}

# ====== 写 Caddyfile ======
write_caddyfile() {
  mkdir -p "$CADDY_DIR" /var/www/html /var/lib/caddy
  chown -R caddy:caddy /var/www/html /var/lib/caddy || true

  cat >/var/www/html/index.html <<'HTML'
<!doctype html><meta charset="utf-8"><title>Welcome</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;padding:40px;line-height:1.6}</style>
<h1>It works.</h1><p>Static content served by Caddy.</p>
HTML

  cat >"$CADDYFILE" <<EOF
{
  email ${ACME_EMAIL}
}

${DOMAIN}:${PORT} {
  tls   # 交由 Caddy 自动申请/续签（Let's Encrypt/ZeroSSL）
  route {
    forward_proxy {
      basic_auth ${PROXY_USER} ${PROXY_PASS}
      hide_ip
      hide_via
      probe_resistance
    }
    root * /var/www/html
    file_server
  }
}
EOF

  chown -R caddy:caddy "$CADDY_DIR"
}

# ====== systemd ======
write_service() {
  cat >/etc/systemd/system/${SERVICE_NAME} <<'SERVICE'
[Unit]
Description=Caddy (NaiveProxy - forwardproxy)
Documentation=https://caddyserver.com/docs/
After=network-online.target
Wants=network-online.target

[Service]
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
}

# ====== 伪外部探针 & DNS 预检 ======
precheck_dns_ports() {
  local PUB_IP DNS_IP
  PUB_IP="$(curl -4 -fsS ifconfig.me || true)"
  if [[ -z "${PUB_IP}" ]]; then
    echo "[错误] 无法获取公网IP，请检查网络。" ; return 1
  fi
  DNS_IP="$(dig +short "${DOMAIN}" A || true)"
  echo "本机公网IP: ${PUB_IP}"
  echo "域名解析IP: ${DNS_IP:-<空>}"
  if [[ -z "${DNS_IP}" || "${DNS_IP}" != "${PUB_IP}" ]]; then
    cat <<EOF
[提示] 你的域名未正确指向当前 VM 公网 IP。
  - 请在 DNS 面板添加/修改 A 记录：
      主机名: ${DOMAIN}
      值(IP): ${PUB_IP}
  - 修改后等几分钟再运行安装。
EOF
    return 1
  fi

  # UFW 若启用则放行
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw allow "${PORT}"/tcp || true
  fi

  echo "[预检] 探测 80/443（仅作先验参考）……"
  local ok80="false" ok443="false"
  if curl -I --connect-timeout 3 -m 5 -sS "http://${DOMAIN}" >/dev/null 2>&1; then
    ok80="true"
  else
    if nc -z -w3 "${DOMAIN}" 80 >/dev/null 2>&1; then ok80="true"; fi
  fi
  if nc -z -w3 "${DOMAIN}" 443 >/dev/null 2>&1; then ok443="true"; fi
  echo "  80/TCP 可达：$ok80"
  echo "  443/TCP 可达：$ok443"
  if [[ "$ok80" != "true" || "$ok443" != "true" ]]; then
    cat <<EOF
[提醒] 预检显示 80/443 可能外部不可达（或当前未监听）。这不一定是错误；
       如安装后 Caddy 首签失败，多数是 VPC 未放行 80/443。

[可复制的 gcloud 命令（在你本地有权限环境执行；将 <PROJECT>/<NETWORK> 替换）]
  gcloud config set project <PROJECT>
  gcloud compute firewall-rules create allow-http  --allow tcp:80  --network=<NETWORK> --direction=INGRESS --priority=1000 --target-tags=http-https || true
  gcloud compute firewall-rules create allow-https --allow tcp:443 --network=<NETWORK> --direction=INGRESS --priority=1000 --target-tags=http-https || true
  gcloud compute firewall-rules create allow-naive --allow tcp:${PORT} --network=<NETWORK> --direction=INGRESS --priority=1000 --target-tags=naive || true

[Console 路径]
  Google Cloud Console → VPC 网络 → 防火墙 → “创建防火墙规则”
  建三条：
    * allow-http  : TCP 80
    * allow-https : TCP 443
    * allow-naive : TCP ${PORT}
  并把实例附上相应网络标签（如 http-https / naive）
EOF
  fi
}

# ====== 安装 / 更新 ======
install_or_update() {
  echo "........... Naiveproxy 安装向导 .........."
  read -rp "域名（FQDN，例如 t26.netor.xyz）: " DOMAIN
  read -rp "代理监听端口（默认 2443，回车取默认）: " PORT
  PORT="${PORT:-2443}"
  read -rp "代理用户名: " PROXY_USER
  read -rp "代理密码（强密码）: " PROXY_PASS
  read -rp "ACME 邮箱（证书联系邮箱）: " ACME_EMAIL

  need_pkgs
  precheck_dns_ports || { echo "[中止] 预检未通过。"; return 1; }
  ensure_go_xcaddy
  build_caddy
  id -u caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
  write_caddyfile
  write_service
  save_env

  systemctl enable --now "${SERVICE_NAME}" || true
  sleep 2
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "✅ 安装/更新完成，服务已启动。"
  else
    echo "⚠️ 服务未成功启动，常见原因：GCP VPC 未放行 80/443 → ACME 首签失败。"
    echo "   放行端口后重试：systemctl restart ${SERVICE_NAME}"
    echo "   查看日志：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  fi
}

# ====== 显示信息 ======
show_info() {
  load_env
  echo "........... Naiveproxy 配置信息 .........."
  echo "域名: ${DOMAIN:-<未配置>}"
  echo "端口: ${PORT:-<未配置>}"
  echo "用户: ${PROXY_USER:-<未配置>}"
  echo "邮箱: ${ACME_EMAIL:-<未配置>}"
  echo "URL : https://${PROXY_USER:-user}:${PROXY_PASS:-pass}@${DOMAIN:-example}:${PORT:-2443}"
  echo
  echo "........... NaiveProxy 服务状态（按 q 退出） .........."
  systemctl --no-pager -l status "${SERVICE_NAME}" || true
}

# ====== 修改配置（nano 打开 Caddyfile，保存后 reload） ======
edit_config() {
  nano "$CADDYFILE"
  systemctl reload "${SERVICE_NAME}" || systemctl restart "${SERVICE_NAME}" || true
  echo "[完成] 已重载/重启。"
}

# ====== 优化：启用 BBR + fq ======
optimize_bbr() {
  echo "........... 启用 BBR/FQ .........."
  sysctl -w net.core.default_qdisc=fq
  sysctl -w net.ipv4.tcp_congestion_control=bbr
  {
    grep -q "^net.core.default_qdisc" /etc/sysctl.conf && sed -i 's/^net\.core\.default_qdisc.*/net.core.default_qdisc=fq/' /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    grep -q "^net.ipv4.tcp_congestion_control" /etc/sysctl.conf && sed -i 's/^net\.ipv4\.tcp_congestion_control.*/net.ipv4.tcp_congestion_control=bbr/' /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
  } || true
  sysctl -p || true
  echo "✅ BBR/FQ 已设置。"
}

# ====== 证书详情 ======
cert_info() {
  echo "........... 证书目录 & 文件 .........."
  # Caddy 的默认证书目录（root: /var/lib/caddy/.local/share/caddy/certificates）
  local CERT_BASE="/var/lib/caddy/.local/share/caddy/certificates"
  if [[ -d "$CERT_BASE" ]]; then
    find "$CERT_BASE" -type f -maxdepth 4 -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort
  else
    echo "未找到证书目录：$CERT_BASE"
  fi
  echo
  echo "提示：Caddy 会自动在到期前续签；如遇签发失败，常见为 80/443 未放行。"
}

# ====== 证书续签（触发重试：重启服务） ======
cert_renew() {
  systemctl restart "${SERVICE_NAME}" || true
  echo "已重启服务；如 80/443 可达，Caddy 会自动处理证书校验与续期。"
  echo "查看日志：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
}

# ====== 更新脚本 ======
script_renew() {
  if [[ -z "$SCRIPT_URL" ]]; then
    echo "[错误] 未配置 SCRIPT_URL，无法自更新。"
    return 1
  fi
  curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  ln -sf "$SCRIPT_PATH" "$BIN_LINK"
  echo "✅ 脚本已更新为最新版本。"
}

# ====== 重启 / 启停 / 卸载 ======
restart_service() { systemctl restart "${SERVICE_NAME}" || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; }
start_service()   { systemctl start "${SERVICE_NAME}" || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; }
stop_service()    { systemctl stop "${SERVICE_NAME}" || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; }
uninstall_all() {
  stop_service || true
  systemctl disable "${SERVICE_NAME}" || true
  rm -f /etc/systemd/system/${SERVICE_NAME}
  systemctl daemon-reload
  rm -rf "$CADDY_DIR" /var/www/html /var/lib/caddy
  rm -f "$CADDY_BIN"
  rm -f "$ENV_FILE"
  rm -f "$BIN_LINK"
  rm -rf "$INSTALL_DIR"
  echo "✅ 已卸载。"
}

# ====== 菜单 ======
menu() {
  clear
  cat <<'MENU'
........... Naiveproxy 一键安装脚本 & 管理脚本 Install shell. ..........
1．安装/更新 Install/Update
2．显示信息 Show Info
3．修改配置 Edit
4．优化 Optimize并开启拥塞算法 BBR
5．证书详情 Cert Info
6．证书续签 Cert Renew
7．更新脚本 Shell Renew
8．重启 Start Naive
9．卸载 Uninstall
请选择［1-9］：
MENU
  read -r choice
  case "$choice" in
    1) install_or_update ;;
    2) show_info ;;
    3) edit_config ;;
    4) optimize_bbr ;;
    5) cert_info ;;
    6) cert_renew ;;
    7) script_renew ;;
    8) restart_service ;;
    9) uninstall_all ;;
    *) echo "无效选择" ;;
  esac
  echo
  read -rp "按回车返回菜单..." _
  menu
}

# ====== 主入口 ======
main() {
  # 首次执行：安装命令并提示
  if [[ "${1:-}" != "internal" ]]; then
    need_pkgs
    self_install
    echo "naive 命令安装完毕，请使用 naive 进行操作。"
    # 直接进入菜单体验
    exec "$BIN_LINK" internal
  else
    load_env || true
    menu
  fi
}

main "$@"
