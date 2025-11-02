#!/usr/bin/env bash
set -euo pipefail

# ====== 把下面 URL 改成你自己倉庫的 RAW 連結 ======
SCRIPT_URL="https://raw.githubusercontent.com/janelai2022/nas_tools/main/NaiveProxy/do.sh"

# ====== 全局變量 ======
INSTALL_DIR="/opt/naive"
SCRIPT_PATH="${INSTALL_DIR}/naive.sh"
BIN_LINK="/usr/local/bin/naive"
ENV_FILE="/etc/naive.env"
CADDY_BIN="/usr/local/bin/caddy"
CADDY_DIR="/etc/caddy"
CADDYFILE="${CADDY_DIR}/Caddyfile"
SERVICE_NAME="naive.service"

# ====== 基礎工具 ======
need_pkgs() {
  apt-get update -y
  apt-get install -y curl tar git ca-certificates iproute2 jq netcat-openbsd openssl
  apt-get install -y dnsutils || true
  apt-get install -y ufw || true
  apt-get install -y nano || true
}

# ====== 自安裝為 /usr/local/bin/naive ======
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

# ====== 讀/寫 ENV ======
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

# ====== Go / xcaddy ======
ensure_go_xcaddy() {
  if ! command -v go >/dev/null 2>&1; then
    local GO_VER="1.22.7"
    echo "安裝 Go ${GO_VER}…"
    cd /tmp && curl -fsSLO "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
    rm -rf /usr/local/go && tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
    echo 'export PATH=/usr/local/go/bin:$PATH' >/etc/profile.d/go_path.sh
    export PATH=/usr/local/go/bin:$PATH
  fi
  if ! command -v xcaddy >/dev/null 2>&1; then
    echo "安裝 xcaddy…"
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    export PATH="$(go env GOPATH)/bin:$PATH"
    echo "export PATH=$(go env GOPATH)/bin:\$PATH" >/etc/profile.d/xcaddy_path.sh || true
  fi
}

# ====== 編譯 Caddy（forwardproxy 插件）======
build_caddy() {
  local PLUGINS="--with github.com/caddyserver/forwardproxy"
  mkdir -p /opt/caddy-bin && cd /opt/caddy-bin
  echo "編譯 Caddy（plugins: ${PLUGINS}）…"
  xcaddy build latest ${PLUGINS}
  install -m 0755 caddy "$CADDY_BIN"
}

# ====== 寫 Caddyfile ======
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
  tls   # 交由 Caddy 自動申請/續簽（Let's Encrypt/ZeroSSL）
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

# ====== 伪外部探针 & DNS 預檢 ======
precheck_dns_ports() {
  local PUB_IP DNS_IP
  PUB_IP="$(curl -4 -fsS ifconfig.me || true)"
  if [[ -z "${PUB_IP}" ]]; then
    echo "[錯誤] 無法獲取公網 IP，請檢查網絡。" ; return 1
  fi
  DNS_IP="$(dig +short "${DOMAIN}" A || true)"
  echo "本機公網IP: ${PUB_IP}"
  echo "域名解析IP: ${DNS_IP:-<空>}"
  if [[ -z "${DNS_IP}" || "${DNS_IP}" != "${PUB_IP}" ]]; then
    cat <<EOF
[提示] 你的域名未正確指向當前 VM 公網 IP。
  - 請在 DNS 面板添加/修改 A 記錄：
      主機名: ${DOMAIN}
      值(IP): ${PUB_IP}
  - 修改後等數分鐘再執行安裝。
EOF
    return 1
  fi

  # UFW 若啟用則放行
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw allow "${PORT}"/tcp || true
  fi

  echo "[預檢] 探測 80/443（僅作先驗參考）……"
  local ok80="false" ok443="false"
  if curl -I --connect-timeout 3 -m 5 -sS "http://${DOMAIN}" >/dev/null 2>&1; then
    ok80="true"
  else
    if nc -z -w3 "${DOMAIN}" 80 >/dev/null 2>&1; then ok80="true"; fi
  fi
  if nc -z -w3 "${DOMAIN}" 443 >/dev/null 2>&1; then ok443="true"; fi
  echo "  80/TCP 可達：$ok80"
  echo "  443/TCP 可達：$ok443"
  if [[ "$ok80" != "true" || "$ok443" != "true" ]]; then
    cat <<EOF
[提醒] 預檢顯示 80/443 可能外部不可達（或當前未監聽）。這不一定是錯誤；
       如安裝後 Caddy 首簽失敗，多半為 VPC 未放行 80/443。

[可複製的 gcloud 命令（在你本地有權限環境執行；將 <PROJECT>/<NETWORK> 替換）]
  gcloud config set project <PROJECT>
  gcloud compute firewall-rules create allow-http  --allow tcp:80  --network=<NETWORK> --direction=INGRESS --priority=1000 --target-tags=http-https || true
  gcloud compute firewall-rules create allow-https --allow tcp:443 --network=<NETWORK> --direction=INGRESS --priority=1000 --target-tags=http-https || true
  gcloud compute firewall-rules create allow-naive --allow tcp:${PORT} --network=<NETWORK> --direction=INGRESS --priority=1000 --target-tags=naive || true

[Console 路徑]
  Google Cloud Console → VPC 網絡 → 防火牆 → 「創建防火牆規則」
  建三條：
    * allow-http  : TCP 80
    * allow-https : TCP 443
    * allow-naive : TCP ${PORT}
  並把實例附上相應網絡標籤（如 http-https / naive）
EOF
  fi
}

# ====== 安裝 / 更新 ======
install_or_update() {
  echo "........... Naiveproxy 安裝向導 .........."
  read -rp "域名（FQDN，例如 t26.netor.xyz）: " DOMAIN
  read -rp "代理監聽端口（默認 2443，回車取默認）: " PORT
  PORT="${PORT:-2443}"
  read -rp "代理用戶名: " PROXY_USER
  read -rp "代理密碼（強密碼）: " PROXY_PASS
  read -rp "ACME 郵箱（證書聯繫郵箱）: " ACME_EMAIL

  if [[ -z "${DOMAIN}" || -z "${PROXY_USER}" || -z "${PROXY_PASS}" || -z "${ACME_EMAIL}" ]]; then
    echo "[錯誤] 參數不可為空。" ; return 1
  fi

  need_pkgs
  precheck_dns_ports || { echo "[中止] 預檢未通過。"; return 1; }
  ensure_go_xcaddy
  build_caddy
  write_caddyfile
  write_service
  save_env

  systemctl enable --now "${SERVICE_NAME}" || true
  sleep 2
  if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "✅ 安裝/更新完成，服務已啟動。"
  else
    echo "⚠️ 服務未成功啟動，多半為 GCP VPC 未放行 80/443 → ACME 首簽失敗。"
    echo "   放行端口後重試：systemctl restart ${SERVICE_NAME}"
    echo "   查看日誌：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
  fi
}

# ====== 顯示信息 ======
show_info() {
  load_env
  echo "........... Naiveproxy 配置信息 .........."
  echo "域名: ${DOMAIN:-<未配置>}"
  echo "端口: ${PORT:-<未配置>}"
  echo "用戶: ${PROXY_USER:-<未配置>}"
  echo "郵箱: ${ACME_EMAIL:-<未配置>}"
  echo "URL : https://${PROXY_USER:-user}:${PROXY_PASS:-pass}@${DOMAIN:-example}:${PORT:-2443}"
  echo
  echo "........... NaiveProxy 服務狀態（按 q 退出） .........."
  systemctl --no-pager -l status "${SERVICE_NAME}" || true
}

# ====== 修改配置（nano 打開 Caddyfile，保存後 reload） ======
edit_config() {
  nano "$CADDYFILE"
  systemctl reload "${SERVICE_NAME}" || systemctl restart "${SERVICE_NAME}" || true
  echo "[完成] 已重載/重啟。"
}

# ====== 優化：啟用 BBR + fq ======
optimize_bbr() {
  echo "........... 啟用 BBR/FQ .........."
  sysctl -w net.core.default_qdisc=fq
  sysctl -w net.ipv4.tcp_congestion_control=bbr
  {
    grep -q "^net.core.default_qdisc" /etc/sysctl.conf && sed -i 's/^net\.core\.default_qdisc.*/net.core.default_qdisc=fq/' /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    grep -q "^net.ipv4.tcp_congestion_control" /etc/sysctl.conf && sed -i 's/^net\.ipv4\.tcp_congestion_control.*/net.ipv4.tcp_congestion_control=bbr/' /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
  } || true
  sysctl -p || true
  echo "✅ BBR/FQ 已設置。"
}

# ====== 證書詳情（多證書清單 + 剩餘天數） ======
cert_info() {
  echo "........... 證書詳情 Cert Info（多證書）.........."
  local CERT_BASE="/var/lib/caddy/.local/share/caddy/certificates"
  local now_ts crt_list tmpfile
  now_ts="$(date +%s)"
  tmpfile="$(mktemp)"

  if [[ ! -d "$CERT_BASE" ]]; then
    echo "未找到 Caddy 證書目錄：$CERT_BASE"
    echo "提示：首次簽發未成功時可能尚未生成證書（多為 80/443 未放行）。"
    rm -f "$tmpfile"
    return 0
  fi

  mapfile -t crt_list < <(find "$CERT_BASE" -type f -name '*.crt' -print 2>/dev/null)
  if (( ${#crt_list[@]} == 0 )); then
    echo "尚未找到任何 *.crt 證書文件。"
    rm -f "$tmpfile"
    return 0
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
      if [[ "$days_left" =~ ^-?[0-9]+$ ]]; then
        if (( days_left <= 10 )); then mark="⚠️"; fi
      fi
      printf "%-40s  %-22s  %-24s  %3s 天  %s %s\n" "$domain" "$(date -u -d "@$exp_ts" '+%Y-%m-%d %H:%M:%S')" "$issuer_short" "$days_left" "$mark" "$path"
    done
  else
    echo "未能解析到任何有效證書。"
  fi

  rm -f "$tmpfile"
  echo
  echo "提示：Caddy 會在到期前自動續簽（預設使用 HTTP-01/TLS-ALPN-01）。"
  echo "     若續簽失敗，最常見原因：GCP VPC 未放行 80/443 或 DNS 未正確指向。"
  echo "     可手動重試：systemctl restart ${SERVICE_NAME}"
  echo "     查日誌：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
}

# ====== 證書續簽（重啟觸發重試） ======
cert_renew() {
  systemctl restart "${SERVICE_NAME}" || true
  echo "已重啟服務；如 80/443 可達，Caddy 會自動處理簽發/續簽。"
  echo "查看日誌：journalctl -u ${SERVICE_NAME} -n 100 --no-pager"
}

# ====== 更新腳本 ======
script_renew() {
  if [[ -z "$SCRIPT_URL" ]]; then
    echo "[錯誤] 未配置 SCRIPT_URL，無法自更新。"
    return 1
  fi
  curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
  ln -sf "$SCRIPT_PATH" "$BIN_LINK"
  echo "✅ 腳本已更新為最新版本。"
}

# ====== 重啟 / 啟停 / 卸載 ======
restart_service() { systemctl restart "${SERVICE_NAME}" || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; }
start_service()   { systemctl start "${SERVICE_NAME}"   || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; }
stop_service()    { systemctl stop "${SERVICE_NAME}"    || true; systemctl status "${SERVICE_NAME}" --no-pager -l || true; }
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
  echo "✅ 已卸載。"
}

# ====== 選單 ======
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
  # 首次執行：安裝命令並提示
  if [[ "${1:-}" != "internal" ]]; then
    need_pkgs
    self_install
    echo "naive 命令安装完毕，请使用 naive 进行操作。"
    exec "$BIN_LINK" internal
  else
    load_env || true
    menu
  fi
}

# ====== 系統/發行版檢查 ======
if [[ $EUID -ne 0 ]]; then echo "請用 root 运行（sudo -i）"; exit 1; fi
if [[ -f /etc/os-release ]]; then . /etc/os-release; else echo "無法識別系統發行版"; exit 1; fi
case "${ID:-}" in ubuntu|debian) ;; *) echo "僅支持 Debian/Ubuntu"; exit 1;; esac

main "$@"
