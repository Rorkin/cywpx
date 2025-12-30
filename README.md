# CF-VLESS-SUB

🚀 Cloudflare Workers VLESS 代理 + 订阅管理 + 优选IP自动更新

## ✨ 功能特性

| 功能 | 描述 |
|------|------|
| 🔐 VLESS 代理 | 基于 WebSocket + TLS |
| 📡 多格式订阅 | Base64 / Clash / Sing-Box |
| 🌐 优选IP管理 | 自动获取最快的 CF 节点 |
| ⏰ 定时更新 | Cron 自动更新优选IP |
| 🎛️ 管理面板 | 可视化配置管理 |
| 🔄 手动更新 | 一键刷新优选IP |

## 📦 快速部署

### 1️⃣ 创建 KV 命名空间

```bash
wrangler kv:namespace create "CFKV"
