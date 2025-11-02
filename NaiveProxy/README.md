# 🛰️ NaiveProxy 一键安装 & 管理脚本（支持非 80 端口）

本脚本基于 Caddy + ForwardProxy 实现 NaiveProxy 自动化部署，  
支持 **非 80/443 端口** 的代理服务、自动申请 / 续签 TLS 证书、  
并提供 **完整交互式菜单** 管理。

---

## 🚀 功能概览

| 功能 | 说明 |
|------|------|
| ✅ 一键安装 / 更新 | 自动部署 Caddy + ForwardProxy，配置 HTTPS 代理 |
| 🔐 自动签发 / 续签证书 | 使用 Caddy 自动申请 Let's Encrypt / ZeroSSL 证书 |
| 🧠 端口预检 / DNS 检查 | 自动检测 80/443 是否放行及 DNS 是否正确指向 |
| ⚙️ 完整菜单管理 | `naive` 命令支持 1–9 项常用操作 |
| ⚡ 自动优化网络 | 一键启用 BBR 拥塞控制算法 |
| 📜 查看证书详情 | 多证书列出 + 剩余天数 + 过期提醒 |
| 🔁 自更新功能 | 脚本可自更新到最新版本 |
| 🧹 一键卸载 | 可完全移除 Caddy / NaiveProxy 服务 |

---

## 🧩 系统要求

- **操作系统**：Debian / Ubuntu（建议 20.04+）  
- **权限**：root（或使用 `sudo -i`）  
- **环境**：
  - 开放端口：`80`、`443`（用于证书签发）  
  - 你可以自定义代理监听端口（默认 `2443`）  
  - 域名需正确解析到服务器公网 IP  

---

## 🪄 一键安装命令



```bash
curl -fsSL https://raw.githubusercontent.com/janelai2022/nas_tools/main/NaiveProxy/do.sh | bash

运行后出现以下提示即表示脚本已安装完成：

naive 命令安装完毕，请使用 naive 进行操作。

🧭 使用说明

执行：

naive


即可进入交互菜单：

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

📜 功能详解
1. 安装 / 更新

自动安装 Caddy、ForwardProxy 插件；

自动生成配置文件 /etc/caddy/Caddyfile；

自动申请并管理 TLS 证书；

提供伪外部探针检测，提示防火墙或 DNS 问题。

2. 显示信息

查看当前配置、代理 URL、Caddy 服务状态。

3. 修改配置

使用 nano 打开并编辑配置文件；

保存后脚本自动 reload / restart。

4. 优化网络

启用 Linux BBR + fq 拥塞控制算法，提高传输性能。

5. 证书详情（多证书）

自动扫描 Caddy 证书目录：

/var/lib/caddy/.local/share/caddy/certificates


列出每个域名证书的：

过期时间（UTC）

签发者（Issuer）

剩余有效天数

路径

若剩余 ≤10 天，将显示 ⚠️ 警告提示。

6. 证书续签

通过 systemctl restart naive.service 重启服务；

触发 Caddy 重新验证并自动续签证书；

可配合 journalctl -u naive.service -n 100 查看续签日志。

7. 更新脚本

从你仓库的最新版本拉取更新；

自动替换 /usr/local/bin/naive 脚本。

8. 重启 Naive

一键重启代理服务；

可用于配置修改或调试。

9. 卸载

停止服务；

删除 Caddy、配置文件、证书、环境变量及脚本自身。

🔒 安全建议

建议使用 强密码；

不建议将端口号设为 80/443；

如使用 Cloudflare，请关闭 “代理模式 (orange cloud)”；

若证书申请失败，请确认：

域名解析正确；

GCP / 阿里云 / 腾讯云 防火墙放行 80/443；

无端口占用。

🧠 常见路径参考
文件	路径
配置文件	/etc/caddy/Caddyfile
环境变量	/etc/naive.env
网站目录	/var/www/html/
证书目录	/var/lib/caddy/.local/share/caddy/certificates/
服务管理	systemctl status naive.service
🪪 License

MIT License © [你的GitHub账号]

✨ 作者提示

本脚本原始思路来自 imajeason/nas_tools
，
此版本为增强改进版，增加 GCP 适配、伪外部探针预检、
多证书可视化、菜单交互、自动更新、自定义端口、BBR 优化等功能。
