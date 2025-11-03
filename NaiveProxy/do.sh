#!/usr/bin/env bash
set -euo pipefail

# ====== 把下面 URL 改成你自己仓库的 RAW 链接 ======
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

RED="\e[31m"
NC="\e[0m"

finish_msg() {
  # 用红字提示“naive【某选项】完成，请重新执行naive”，然后退出
  echo -e "${RED}naive【$1】完成，请重新执行 naive${NC}"
  exit 0
}

uuid_gen() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    # 退路
    tr -dc 'a-f0-9' </dev/urandom | head -c 8 && echo
  fi
}

# ====== 基础工具 ======
need_pkgs() {
  apt-get update -y
  apt-get install -y curl tar git ca-certificates iproute2 jq netcat-openbsd openssl
  apt-get install -y dnsutils || true
  apt-get install -y ufw || true
  apt-get install -y nano || true
}

# ====== 自安装为 /usr/local/bin/naive ======
self_install() {
  mkdir -p "$INSTALL_DIR"
  if [[ -n "${SCRIPT_URL}" ]]; then
    curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
  else
    cp "$0" "$SCRIPT_PATH" 2>/dev/null || true
    chmod +x "$SCRIPT_PATH" || true
  fi
  ln -sf "$SCRIPT_PATH" "$BIN_LINK"
}

# ====== 读/写 ENV ======
load_env() { [[ -f "$ENV_FILE" ]] && source "$ENV_FILE"; }
save_env() {
  cat >"$ENV_FILE" <<EOF
DOMAIN="${DOMAIN}"
PORT="${PORT}"
PROXY_USER="${PROXY_USER}"
PROXY_PASS="${PROXY_PASS}"
ACME_EMAIL="${ACME_EMAIL}"
EOF
}

# ====== Go / xcaddy ======
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
    echo "export PATH=$(go env GOPATH)/bin:\$PATH" >/etc/profile.d/xcaddy_path.sh || true
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
  id -u caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
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

# ====== systemd 服務 ======
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
  [[ -z "${PUB_IP}" ]] && { echo "[错误] 无法获取公网 IP"; return 1; }
  DNS_IP="$(dig +short "${DOMAIN}" A || true)"
  echo "本机公网IP: ${PUB_IP}"
  echo "域名解析IP: ${DNS_IP:-<空>}"
  if [[ -z "${DNS_IP}" || "${DNS_IP}" != "${PUB_IP}" ]]; then
    cat <<EOF
[提示] 域名未正确指向当前 VM 公网 IP。
  - 请在 DNS 面板设置 A 记录：
      主机名: ${DOMAIN}
      值(IP): ${PUB_IP}
  - 修改后等待数分钟再执行安装。
EOF
    return 1
  fi

  # UFW 若启用则放行
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw allow "${PORT}"/tcp || true
  fi

  echo "[预检] 探测 80/443（仅供参考）……"
  local ok80="false" ok443="false"
  if curl -I --connect-timeout 3 -m 5 -sS "http://${DOMAIN}" >/dev/null 2>&1; then
    ok80="true"
  else
    nc -z -w3 "${DOMAIN}" 80 >/dev/null 2>&1 && ok80="true"
  fi
  nc -z -w3 "${DOMAIN}" 443 >/dev/null 2>&1 && ok443="true"
  echo "  80/TCP 可达：$ok80"
  echo "  443/TCP 可达：$ok443"
  if [[ "$ok80" != "true" || "$ok443" != "true" ]]; then
    cat <<EOF
[提醒] 80/443 可能外部不可达（或暂未监听）。如安装后首次签证书失败，多半是 VPC 未放行 80/443。

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

# ====== 输入校验 ======
validate_domain() {
  # 简单校验：至少一处点、每段仅含字母数字连字符，且不以-开头/结尾
  local d="$1"
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]
}
validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p>=1 && p<=65535 )) || return 1
  (( p != 80 )) || return 1
  return 0
}
validate_email() {
  local m="$1"
  [[ "$m" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

# ====== 安装 / 更新 ======
install_or_update() {
  echo "........... Naiveproxy 安装向导 .........."

  # 3) 域名提示（强化文案）
  while true; do
    read -rp $'请输入一个 正确的域名，一定一定一定要正确，不！能！出！错！\n（例如：n.abc.com）：' DOMAIN
    if validate_domain "$DOMAIN"; then break; else echo -e "${RED}[错误] 域名格式不正确，请重新输入。${NC}"; fi
  done

  # 4) 端口提示（禁用80，默认2443，并提示需自行放开端口/防火墙）
  while true; do
    read -rp $'请输入NaiveProxy端口［1-65535］，不能选择80端口\n（默认端口：2443），设置其它端口时，需自行放开端口，例如增设防火墙规则：' PORT_IN
    PORT="${PORT_IN:-2443}"
    if validate_port "$PORT"; then break; else echo -e "${RED}[错误] 端口无效，请重输（1-65535 且不可为 80）。${NC}"; fi
  done

  # 折衷方案：用户名可留空默认 User；密码可留空自动生成
  read -rp "代理用户名（留空则默认 User）： " PROXY_USER
  PROXY_USER="${PROXY_USER:-User}"
  read -rp "代理密码（留空则随机生成强密码）： " PROXY_PASS
  PROXY_PASS="${PROXY_PASS:-$(uuid_gen)}"

  # 5) 邮箱提示（强化文案）
  while true; do
    read -rp $'请输入一个 证书联系邮箱，邮箱不能乱输，格式要对。\n（例如：name@abc.com）：' ACME_EMAIL
    if validate_email "$ACME_EMAIL"; then break; else echo -e "${RED}[错误] 邮箱格式不正确，请重新输入。${NC}"; fi
  done

  need_pkgs
  precheck_dns_ports || { echo -e "${RED}[中止] 预检未通过。${NC}"; finish_msg "安装/更新（预检失败）"; }

  ensure_go_xcaddy
  build_caddy
  write_caddyfile
  write_service
  save_env

  systemctl enable --now "${SERVICE_NAME}" || true
  sleep 2

  # 输出与原脚本风格一致的信息块
  echo
  echo "........... Naiveproxy 配置信息  .........."
  echo
  echo "* 域名domain   = ${DOMAIN}"
  echo "* 端口port     = ${PORT}"
  echo "* 用户名user   = ${PROXY_USER}"
  echo "* 密码password = ${PROXY_PASS}"
  echo "* 邮箱email    = ${ACME_EMAIL}"
  echo
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "✅ 服务已启动。"
  else
    echo -e "${RED}⚠️ 服务未成功启动，多半为 VPC 未放行 80/443 → ACME 首签失败。${NC}"
    echo "   放行端口后重试：systemctl restart ${SERVICE_NAME}"
    echo "   查看日志：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  fi

  finish_msg "安装/更新"
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
  finish_msg "显示信息"
}

# ====== 修改配置（nano 打开 Caddyfile，保存后 reload） ======
edit_config() {
  nano "$CADDYFILE"
  systemctl reload "${SERVICE_NAME}" || systemctl restart "${SERVICE_NAME}" || true
  echo "[完成] 已重载/重启。"
  finish_msg "修改配置"
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
  finish_msg "优化(BBR)"
}

# ====== 证书详情（多证书清单 + 剩余天数） ======
cert_info() {
  echo "........... 证书详情 Cert Info（多证书）.........."
  local CERT_BASE="/var/lib/caddy/.local/share/caddy/certificates"
  local now_ts crt_list tmpfile
  now_ts="$(date +%s)"
  tmpfile="$(mktemp)"

  if [[ ! -d "$CERT_BASE" ]]; then
    echo "未找到 Caddy 证书目录：$CERT_BASE"
    echo "提示：首次签发未成功时可能尚未生成证书（多为 80/443 未放行）。"
    rm -f "$tmpfile"
    finish_msg "证书详情"
  fi

  mapfile -t crt_list < <(find "$CERT_BASE" -type f -name '*.crt' -print 2>/dev/null)
  if (( ${#crt_list[@]} == 0 )); then
    echo "尚未找到任何 *.crt 证书文件。"
    rm -f "$tmpfile"
    finish_msg "证书详情"
  fi

  printf "%-40s  %-22s  %-24s  %-8s  %s\n" "Domain" "Expires(UTC)" "Issuer" "Days" "Path"
  printf "%-40s  %-22s  %-24s  %-8s  %s\n" "----------------------------------------" "----------------------" "------------------------" "--------" "----"

  for CRT in "${crt_list[@]}"; do
    local SUBJECT ISSUER EDATE exp_ts days_left domain
    SUBJECT="$(openssl x509 -in "$CRT" -noout -subject 2>/dev/null | sed 's/^subject= *//')"
    ISSUER="$(openssl x509 -in "$CRT" -noout -issuer  2>/dev/null | sed 's/^issuer= *//')"
    EDATE="$(openssl x509 -in "$CRT" -noout -enddate 2>/dev/null | cut -d= -f2)"
    domain="$(echo "$SUBJECT" | sed -n 's/.*CN=\([^\/,]*\).*/\1/p')"
    if [[ -z "$domain" ]]; then
      domain="$(echo "$CRT" | sed -n 's#.*/certificates/.*\/\([^/]*\)\.crt$#\1#p')"
      [[ -z "$domain" ]] && domain="(unknown)"
    fi
    exp_ts="$(date -u -d "$EDATE" +%s 2>/dev/null || true)"
    [[ -z "$exp_ts" ]] && continue
    days_left=$(( (exp_ts - now_ts) / 86400 ))
    local issuer_short
    issuer_short="$(echo "$ISSUER" | sed -E 's/.+CN=([^,/]+).*/\1/; s/,.*//')"
    [[ -z "$issuer_short" ]] && issuer_short="$ISSUER"
    printf "%s|%s|%s|%s|%s|%s\n" "$exp_ts" "$domain" "$EDATE" "$issuer_short" "$days_left" "$CRT" >>"$tmpfile"
  done

  if [[ -s "$tmpfile" ]]; then
    sort -n "$tmpfile" | while IFS='|' read -r exp_ts domain EDATE issuer_short days_left path; do
      local mark=""
      if [[ "$days_left" =~ ^-?[0-9]+$ ]] && (( days_left <= 10 )); then mark="⚠️"; fi
      printf "%-40s  %-22s  %-24s  %3s 天  %s %s\n" "$domain" "$(date -u -d "@$exp_ts" '+%Y-%m-%d %H:%M:%S')" "$issuer_short" "$days_left" "$mark" "$path"
    done
  else
    echo "未能解析到任何有效证书。"
  fi

  rm -f "$tmpfile"
  echo
  echo "提示：Caddy 会在到期前自动续签（默认使用 HTTP-01/TLS-ALPN-01）。"
  echo "     若续签失败，最常见原因：GCP VPC 未放行 80/443 或 DNS 未正确指向。"
  echo "     可手动重试：systemctl restart ${SERVICE_NAME}"
  echo "     查日志：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  finish_msg "证书详情"
}

# ====== 证书续签（重启触发重试） ======
cert_renew() {
  systemctl restart "${SERVICE_NAME}" || true
  echo "已重启服务；如 80/443 可达，Caddy 会自动处理签发/续签。"
  echo "查看日志：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  finish_msg "证书续签"
}

# ====== 更新脚本 ======
script_renew() {
  if [[ -z "$SCRIPT_URL" ]]; then
    echo "[错误] 未配置 SCRIPT_URL，无法自更新。"
    finish_msg "更新脚本（失败）"
  fi
  curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  ln -sf "$SCRIPT_PATH" "$BIN_LINK"
  echo "✅ 脚本已更新为最新版本。"
  finish_msg "更新脚本"
}

# ====== 重启 / 启停 / 卸载 ======
restart_service() { systemctl restart "${SERVICE_NAME}" || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; finish_msg "重启"; }
start_service()   { systemctl start "${SERVICE_NAME}"   || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; finish_msg "启动"; }
stop_service()    { systemctl stop "${SERVICE_NAME}"    || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; finish_msg "停止"; }
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
  finish_msg "卸载"
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
  # 每次显示菜单后，用红字提示“naive 命令安装完毕，请使用 naive 进行操作。”
  echo -e "${RED}naive 命令安装完毕，请使用 naive 进行操作。${NC}"
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
    *) echo "无效选择"; finish_msg "无效选择" ;;
  esac
}

# ====== 主入口 ======
main() {
  # 首次执行：安装命令并提示
  if [[ "${1:-}" != "internal" ]]; then
    need_pkgs
    self_install
    echo -e "${RED}naive 命令安装完毕，请使用 naive 进行操作。${NC}"
    exec "$BIN_LINK" internal
  else
    load_env || true
    menu
  fi
}

# ====== 系统/发行版检查 ======
if [[ $EUID -ne 0 ]]; then echo "请用 root 运行（sudo -i）"; exit 1; fi
if [[ -f /etc/os-release ]]; then . /etc/os-release; else echo "无法识别系统发行版"; exit 1; fi
case "${ID:-}" in ubuntu|debian) ;; *) echo "仅支持 Debian/Ubuntu"; exit 1;; esac

main "$@"
