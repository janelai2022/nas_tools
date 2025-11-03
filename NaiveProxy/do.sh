#!/usr/bin/env bash
set -euo pipefail

# ====== 把下面 URL 改成你自己仓库的 RAW 链接（必改） ======
SCRIPT_URL="https://raw.githubusercontent.com/janelai2022/nas_tools/main/NaiveProxy/do.sh"

# ====== 全局变量 ======
INSTALL_DIR="/opt/naive"
SCRIPT_PATH="${INSTALL_DIR}/naive.sh"
WRAPPER_BIN="/usr/local/bin/naive"
ENV_FILE="/etc/naive.env"
CADDY_BIN="/usr/local/bin/caddy"
CADDY_DIR="/etc/caddy"
CADDYFILE="${CADDY_DIR}/Caddyfile"
SERVICE_NAME="naive.service"

RED="\e[31m"; NC="\e[0m"

pause_and_return() {
  echo -e "${RED}naive【$1】完成，请重新执行 naive${NC}"
  read -rp "按回车返回菜单..." _
}

uuid_gen() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    tr -dc 'a-f0-9' </dev/urandom | head -c 32; echo
  fi
}

# ====== 仅装缺少的依赖 ======
install_if_missing() { local pkg="$1" cmd="$2"; command -v "$cmd" >/dev/null 2>&1 || apt-get install -y "$pkg"; }
need_pkgs() {
  apt-get update -y
  install_if_missing curl curl
  install_if_missing tar tar
  install_if_missing git git
  install_if_missing ca-certificates update-ca-certificates || true
  install_if_missing iproute2 ip
  install_if_missing jq jq
  install_if_missing netcat-openbsd nc
  install_if_missing openssl openssl
  install_if_missing dnsutils dig || true
  install_if_missing ufw ufw || true
  install_if_missing nano nano || true
}

# ====== 自安装（下载本体 + 写 wrapper，带校验；修复 tmpf 未定义） ======
self_install() {
  mkdir -p "$INSTALL_DIR"

  # 0) 保护性 trap：只有 tmpf 非空才清理
  local tmpf=""; trap '[[ -n "${tmpf:-}" ]] && rm -f "$tmpf"' EXIT

  # 1) 检查 SCRIPT_URL 是否已被替换
  if [[ "${SCRIPT_URL:-}" == *"<YOUR_GITHUB>"* || "${SCRIPT_URL:-}" == *"<你的GitHub账号>"* || -z "${SCRIPT_URL:-}" ]]; then
    echo -e "${RED}[错误] SCRIPT_URL 仍是占位符或为空，请先替换为你仓库的 RAW 链接。${NC}"
    echo "示例：https://raw.githubusercontent.com/<你的GitHub账号>/nas_tools/main/NaiveProxy/do.sh"
    exit 1
  fi

  # 2) 下载到临时文件并校验
  tmpf="$(mktemp)"
  if ! curl -fsSL "$SCRIPT_URL" -o "$tmpf"; then
    echo -e "${RED}[错误] 无法下载 $SCRIPT_URL，请检查网络/链接是否正确。${NC}"
    exit 1
  fi

  # 3) 防 CRLF、校验体积（避免 404/错误页）
  sed -i 's/\r$//' "$tmpf"
  local sz; sz="$(wc -c <"$tmpf" || echo 0)"
  if (( sz < 8192 )); then
    echo -e "${RED}[错误] 下载到的脚本体积异常（${sz}B < 8KB），多半是 RAW 链接不对或仓库未更新。${NC}"
    exit 1
  fi

  # 4) 落地本体
  install -m 0755 "$tmpf" "$SCRIPT_PATH"

  # 5) 写 wrapper（用绝对路径 + 原样 heredoc，避免变量提前展开）
  cat >"$WRAPPER_BIN" <<'WRAP'
#!/usr/bin/env bash
exec /opt/naive/naive.sh internal "$@"
WRAP
  chmod +x "$WRAPPER_BIN"
}

# ====== 读写 ENV ======
load_env() { [[ -f "$ENV_FILE" ]] && source "$ENV_FILE" || true; }
save_env() {
  cat >"$ENV_FILE" <<EOF
DOMAIN="${DOMAIN}"
PORT="${PORT}"
PROXY_USER="${PROXY_USER}"
PROXY_PASS="${PROXY_PASS}"
ACME_EMAIL="${ACME_EMAIL}"
EOF
}

# ====== 打印配置信息（原脚本风格） ======
print_config_block() {
  echo "* ........... Naiveproxy 配置信息  .........."
  echo "*"
  echo "*"
  echo "* 域名domain   = ${DOMAIN}"
  echo "* 端口port     = ${PORT}"
  echo "* 用户名user   = ${PROXY_USER}"
  echo "* 密码password = ${PROXY_PASS}"
  echo "* 邮箱email    = ${ACME_EMAIL}"
}

# ====== 检测是否已有带 forwardproxy 的 Caddy ======
has_caddy_forwardproxy() {
  if [[ -x "$CADDY_BIN" ]]; then
    "$CADDY_BIN" list-modules | grep -q "caddyserver/forwardproxy" && return 0
  fi
  return 1
}

# ====== 仅在需要时安装 Go/xcaddy 并编译 Caddy ======
ensure_go_xcaddy_if_needed() {
  has_caddy_forwardproxy && return 0
  if ! command -v go >/dev/null 2>&1; then
    local GO_VER="1.22.7"
    echo "安装 Go ${GO_VER}..."
    cd /tmp && curl -fsSLO "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
    echo 'export PATH=/usr/local/go/bin:$PATH' >/etc/profile.d/go_path.sh
    export PATH=/usr/local/go/bin:$PATH
  fi
  if ! command -v xcaddy >/dev/null 2>&1; then
    echo "安装 xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    export PATH="$(go env GOPATH)/bin:$PATH"
  fi
}

build_caddy_if_needed() {
  has_caddy_forwardproxy && { echo "✅ 已存在带 forwardproxy 的 Caddy，跳过编译。"; return; }
  echo "编译 Caddy（带 forwardproxy 插件）..."
  mkdir -p /opt/caddy-bin && cd /opt/caddy-bin
  xcaddy build latest --with github.com/caddyserver/forwardproxy
  install -m 0755 caddy "$CADDY_BIN"
}

# ====== 写入 Caddyfile（tls 采用区块 tls { }） ======
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
  tls {
    # enable automatic HTTPS on a custom port
  }
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

# ====== systemd 服务（允许绑定 80/443） ======
write_service() {
  cat >/etc/systemd/system/${SERVICE_NAME} <<'SERVICE'
[Unit]
Description=Caddy (NaiveProxy)
After=network-online.target
Wants=network-online.target

[Service]
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
Restart=on-failure
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
}

# ====== 输入校验 ======
validate_domain() { [[ "${1:-}" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]; }
validate_port()   { [[ "${1:-}" =~ ^[0-9]+$ ]] && (( ${1:-0} >= 1 && ${1:-0} <= 65535 && ${1:-0} != 80 )); }
validate_email()  { [[ "${1:-}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; }

# ====== 安装/更新 ======
install_or_update() {
  echo "........... Naiveproxy 安装向导 .........."

  while true; do
    read -rp $'请输入一个 正确的域名，一定一定一定要正确，不！能！出！错！\n（例如：n.abc.com）：' DOMAIN
    validate_domain "$DOMAIN" && break || echo -e "${RED}[错误] 域名格式不正确，请重新输入。${NC}"
  done

  while true; do
    read -rp $'请输入NaiveProxy端口［1-65535］，不能选择80端口\n（默认端口：2443），设置其它端口时，需自行放开端口：' PORT_IN
    PORT="${PORT_IN:-2443}"
    validate_port "$PORT" && break || echo -e "${RED}[错误] 端口无效，请重输（1-65535 且不可为80）。${NC}"
  done

  read -rp "代理用户名（留空则默认 User）： " PROXY_USER
  PROXY_USER="${PROXY_USER:-User}"
  read -rp "代理密码（留空则随机生成强密码）： " PROXY_PASS
  PROXY_PASS="${PROXY_PASS:-$(uuid_gen)}"

  while true; do
    read -rp $'请输入一个 证书联系邮箱，邮箱不能乱输，格式要对。\n（例如：name@abc.com）：' ACME_EMAIL
    validate_email "$ACME_EMAIL" && break || echo -e "${RED}[错误] 邮箱格式不正确，请重新输入。${NC}"
  done

  need_pkgs
  ensure_go_xcaddy_if_needed
  build_caddy_if_needed
  write_caddyfile
  write_service
  save_env

  systemctl enable --now "${SERVICE_NAME}" || true
  sleep 2

  echo
  print_config_block
  echo

  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "✅ 服务已启动。"
  else
    echo -e "${RED}⚠️ 服务未成功启动，可能为 80/443 未放行、CF 橙云未关闭或证书验证失败。${NC}"
  fi

  pause_and_return "安装/更新"
}

# ====== 显示信息 ======
show_info() {
  load_env
  print_config_block
  echo
  systemctl --no-pager -l status "${SERVICE_NAME}" || true
  pause_and_return "显示信息"
}

# ====== 其它功能 ======
edit_config()      { nano "$CADDYFILE"; systemctl reload "${SERVICE_NAME}" || systemctl restart "${SERVICE_NAME}"; pause_and_return "修改配置"; }
optimize_bbr()     { sysctl -w net.core.default_qdisc=fq; sysctl -w net.ipv4.tcp_congestion_control=bbr; pause_and_return "优化(BBR)"; }
cert_info()        { find /var/lib/caddy/.local/share/caddy/certificates -type f -name '*.crt' -print 2>/dev/null | xargs -r -I{} bash -lc 'd=$(openssl x509 -in "{}" -noout -enddate|cut -d= -f2); echo "{} -> $d"'; pause_and_return "证书详情"; }
cert_renew()       { systemctl restart "${SERVICE_NAME}"; pause_and_return "证书续签"; }
script_renew()     { curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"; chmod +x "$SCRIPT_PATH"; pause_and_return "更新脚本"; }
restart_service()  { systemctl restart "${SERVICE_NAME}"; systemctl status "${SERVICE_NAME}" --no-pager -l; pause_and_return "重启"; }
uninstall_all()    { systemctl stop "${SERVICE_NAME}" || true; systemctl disable "${SERVICE_NAME}" || true; rm -rf "$INSTALL_DIR" "$CADDY_DIR" "$ENV_FILE" "$WRAPPER_BIN"; echo "✅ 已卸载。"; }

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
    9) uninstall_all ; return ;;
    *) echo "无效选择"; pause_and_return "无效选择" ;;
  esac
  menu
}

# ====== 主入口 ======
main() {
  if [[ "${1:-}" != "internal" ]]; then
    need_pkgs
    self_install
    echo -e "${RED}naive 命令安装完毕，请使用 naive 进行操作。${NC}"
    exit 0
  else
    load_env || true
    menu
  fi
}

[[ $EUID -ne 0 ]] && { echo "请用 root 运行（sudo -i）"; exit 1; }
main "$@"
