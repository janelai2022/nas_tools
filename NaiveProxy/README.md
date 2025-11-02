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

请将以下命令中的 `<你的GitHub账号>` 替换为你自己的 GitHub 用户名：

```bash
curl -fsSL https://raw.githubusercontent.com/<你的GitHub账号>/nas_tools/main/NaiveProxy/do.sh | bash
