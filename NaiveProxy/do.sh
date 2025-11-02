#!/usr/bin/env bash
set -euo pipefail

# ========== 基本参数 ==========
read -rp "域名（FQDN，例如 t26.netor.xyz）: " DOMAIN
read -rp "代理监听端口（默认 2443，回车取默认）: " PORT
PORT="${PORT:-2443}"
read -rp "代理用户名: " PROXY_USER
read -rp "代理密码（强密码）: " PROXY_PASS
read -rp "ACME 邮箱（证书联系邮箱）: " ACME_EMAIL

if [[ $EUID -ne 0 ]]; then echo "请用 root 运行（sudo -i）"; exit 1; fi
if [[ -z "${DOMAIN}" || -z "${PROXY_USER}" || -z "${PROXY_PASS}" || -z "${ACME_EMAIL}" ]]; then
  echo "必要参数不可为空"; exit 1
fi

# ========== 系统/工具 ==========
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) echo "仅支持 Debian/Ubuntu"; exit 1;; esac

apt-get update -y
apt-get install -y curl tar git ca-certificates iproute2 jq netcat-openbsd
apt-get install -y dnsutils || true
apt-get install -y ufw || true

# ========== DNS / 公网IP ==========
PUB_IP="$(curl -4 -fsS ifconfig.me || true)"
if [[ -z "${PUB_IP}" ]]; then echo "无法获取公网IP，请确认网络"; exit 1; fi
DNS_IP="$(dig +short "${DOMAIN}" A || true)"

echo "本机公网IP: ${PUB_IP}"
echo "域名解析IP: ${DNS_IP:-<空>}"
if [[ -z "${DNS_IP}" || "${DNS_IP}" != "${PUB_IP}" ]]; then
  cat <<EOF
[提示] 你的域名未正确指向当前VM公网IP。
  - 请在 DNS 面板添加/修改 A 记录：
      主机名: ${DOMAIN}
      值(IP): ${PUB_IP}
  - 修改后等几分钟再运行本脚本。
EOF
  exit 1
fi

# ========== 本机UFW（如启用则放行）==========
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow "${PORT}"/tcp || true
fi

# ========== 伪外部探针（仅作先验参考） ==========
echo "[预检] 正在探测 80/443 端口可达性（仅供参考）…"

probe_http_ok=false
probe_https_ok=false

# HTTP(80) —— 3秒超时，尝试 HEAD
if curl -I --connect-timeout 3 -m 5 -sS "http://${DOMAIN}" >/dev/null 2>&1; then
  probe_http_ok=true
else
  # 若无服务在80监听，curl 可能报 7/52/56；再用 netcat 以 3 秒探测TCP连通
  if nc -z -w3 "${DOMAIN}" 80 >/dev/null 2>&1; then
    probe_http_ok=true
  fi
fi

# HTTPS(443) —— 3秒超时（证书未申请前可能握手失败；仅用TCP连通判断）
if nc -z -w3 "${DOMAIN}" 443 >/devnull 2>&1; then
  probe_https_ok=true
fi

echo "  80/TCP 可达：$probe_http_ok"
echo "  443/TCP 可达：$probe_https_ok"
if [[ "${probe_http_ok}" != "true" || "${probe_https_ok}" != "true" ]]; then
  cat <<EOF
[提醒] 预检显示 80/443 其中至少一个端口从“外部”可能不可达（或当前无服务监听）。
  - 这不一定是错误（部署前本机未在80/443监听也会导致探测失败）。
  - 如部署后 Caddy 首次签证书失败，多数是 VPC 未放行 80/443。

[可复制的 gcloud 命令（在你本地有权限环境执行；把 <PROJECT>/<NETWORK> 换成实际值）]
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

# ========== 安装 go / xcaddy ==========
if ! command -v go >/dev/null 2>&1; then
  GO_VER="1.22.7"
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
  echo "export PATH=$(go env GOPATH)/bin:\$PATH" >/etc/profile.d/xcaddy_path.sh
fi

# ========== 编译 Caddy + forwardproxy ==========
PLUGINS="--with github.com/caddyserver/forwardproxy"
mkdir -p /opt/caddy-bin && cd /opt/caddy-bin
echo "编译 Caddy（plugins: ${PLUGINS}）…"
xcaddy build latest ${PLUGINS}
install -m 0755 caddy /usr/local/bin/caddy

# ========== 系统用户与目录 ==========
id -u caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
mkdir -p /etc/caddy /var/lib/caddy /var/www/html
chown -R caddy:caddy /var/lib/caddy /var/www/html

cat >/var/www/html/index.html <<'HTML'
<!doctype html><meta charset="utf-8"><title>Welcome</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;padding:40px;line-height:1.6}</style>
<h1>It works.</h1><p>Static content served by Caddy.</p>
HTML

# ========== Caddyfile ==========
cat >/etc/caddy/Caddyfile <<EOF
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
chown -R caddy:caddy /etc/caddy

# ========== systemd ==========
cat >/etc/systemd/system/naive.service <<'SERVICE'
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
systemctl enable --now naive.service || true

sleep 2
echo "=== 初次启动状态 ==="
if systemctl is-active --quiet naive.service; then
  echo "✅ naive.service active (running)"
else
  echo "⚠️ naive.service 未成功启动（多半是 VPC 未放行 80/443 导致 ACME 首签失败）。"
  echo "   放行端口后重试：systemctl restart naive.service"
  echo "   查看日志：journalctl -u naive.service -n 100 --no-pager"
fi

echo
echo "================= 完成 ================="
echo "域名:        ${DOMAIN}"
echo "监听端口:    ${PORT}"
echo "用户名/密码: ${PROXY_USER} / ${PROXY_PASS}"
echo
echo "客户端（naiveproxy / HTTPS 代理）URL："
echo "  https://${PROXY_USER}:${PROXY_PASS}@${DOMAIN}:${PORT}"
