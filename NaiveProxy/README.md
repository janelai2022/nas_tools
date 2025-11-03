# 🌐 NaiveProxy 一键安装与管理脚本

基于 Caddy + ForwardProxy 插件的 HTTPS 代理自动化部署方案，  
支持自定义端口、防火墙检测、证书自动签发/续签、菜单式管理。

---

## 🚀 一键安装命令

请将以下命令中的 `<你的GitHub账号>` 替换为你自己的 GitHub 用户名：

```bash
curl -fsSL https://raw.githubusercontent.com/<你的GitHub账号>/nas_tools/main/NaiveProxy/do.sh | bash
```
安装完成后会出现以下红字提示：
naive 命令安装完毕，请使用 naive 进行操作。

🧭 菜单操作界面

安装完成后执行：
naive



将显示以下菜单：
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


执行任意功能后都会红字提示：

naive【某选项】完成，请重新执行 naive

💡 输入提示说明
项目	新提示文案	校验逻辑
域名	请输入一个 正确的域名，一定一定一定要正确，不！能！出！错！
（例如：n.abc.com）	必须为有效域名格式（含点、字母数字连字符）
端口	请输入 NaiveProxy 端口［1-65535］，不能选择 80 端口
（默认端口：2443），设置其它端口时需自行放开防火墙规则	限制 1–65535，禁止 80
邮箱	请输入一个 证书联系邮箱，邮箱不能乱输，格式要对。
（例如：name@abc.com
）	必须为有效邮箱格式
用户名	可留空（默认为 User）	允许自定义
密码	可留空（自动生成强随机 UUID）	自动保存到 /etc/naive.env
🧠 常见路径参考
项目	路径
配置文件	/etc/caddy/Caddyfile
环境变量	/etc/naive.env
网站根目录	/var/www/html/
证书目录	/var/lib/caddy/.local/share/caddy/certificates/
服务管理	systemctl status naive.service
🧩 故障排查
问题	可能原因	解决方案
安装时报错 acme: no solvers available	80/443 未放行	在 GCP 控制台 → VPC → 防火墙 中放行 80/443
域名解析失败	DNS 未更新或 A 记录错误	确认域名 A 记录指向当前服务器公网 IP
证书未自动续签	Caddy 无法验证	确保 80/443 可访问，再执行 systemctl restart naive.service
curl 一直超时	防火墙或 Cloudflare 未关闭代理	关闭 “橙云 (Proxy)”，仅保留 DNS 模式
🔐 示例配置片段（Caddyfile）
{
  email you@example.com
}

t26.netor.xyz:2443 {
  tls
  route {
    forward_proxy {
      basic_auth User 959b7aac-b0f5-460d-963e-10jh9581d3a4
      hide_ip
      hide_via
      probe_resistance
    }
    root * /var/www/html
    file_server
  }
}

🧱 防火墙规则参考（GCP）

若使用自定义端口（如 2443 或 8964），需在 GCP 控制台添加以下规则：

名称	方向	协议端口	备注
allow-http	入站	TCP:80	ACME 验证使用
allow-https	入站	TCP:443	TLS 验证使用
allow-naive	入站	TCP:自定义端口	NaiveProxy 主代理端口

并在 VM → 编辑 → 网络标签 中添加相应标签（如 http-https、naive）。

🧩 实用命令
# 查看服务状态
systemctl status naive.service --no-pager -l

# 重启服务
systemctl restart naive.service

# 查看证书剩余天数
naive 5

# 编辑配置文件
naive 3

🪪 License

MIT License © 2025
由 Netor Lai
 整理优化，
在 imajeason/nas_tools
 原版基础上改进。
支持 GCP / Oracle / Vultr / 阿里云 / 腾讯云 等主流 VPS 环境。

---

✅ 特点：  
- 所有代码块均有闭合符号，复制按钮范围只含命令。  
- Markdown 已含完整换行格式，可直接上传 GitHub。  
- 完全匹配你新脚本的输入提示与输出格式。  

是否希望我同时帮你生成 README.md 文件的 **中英文双语版本（简体 + English）**？这在 GitHub 展示上会更友好。
