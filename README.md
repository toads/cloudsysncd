# cloudsysncd

一个基于 Node.js 的轻量文件/文本同步服务。服务端生成一次性 PIN，客户端通过 ECDH + HKDF 协商出共享主密钥，然后使用该密钥解密文件列表、文件内容和文本内容。

当前版本更适合受信任网络内使用，不适合未经加固直接暴露到公网。开源发布前请先阅读 [OPEN_SOURCE_AUDIT.md](./OPEN_SOURCE_AUDIT.md)。

## 功能

- 浏览器端 PIN 配对
- `shared/` 目录文件共享
- 单文件下载和批量下载
- 文本共享接口
- Python 自动轮询下载脚本

## 目录说明

- `server.js`: Express 服务端
- `public/`: 前端页面
- `pin.js`: 本机生成新 PIN
- `share.js`: 把文件复制到 `shared/`
- `shared/sync_download.py`: Python 自动下载客户端
- `data/`: 运行时状态，保存主密钥、已配对设备和本地管理 token，不应提交

## 环境要求

- Node.js 20+
- npm 10+
- Python 3.10+（仅在使用 `shared/sync_download.py` 时需要）

## 快速开始

```bash
npm install
npm start
```

默认监听端口为 `21891`。启动后：

1. 打开浏览器访问 `http://127.0.0.1:21891`
2. 首次启动时服务端会在终端打印 6 位 PIN
3. 在网页输入 PIN 完成配对
4. 把要共享的文件放入 `shared/`，或者使用 `node share.js ...`

## 常用命令

复制文件或目录到共享目录：

```bash
node share.js file1.pdf dir1 another.txt
```

查看当前共享文件：

```bash
node share.js --list
```

清空共享目录：

```bash
node share.js --clear
```

为新设备生成新的 PIN：

```bash
node pin.js
```

## Python 自动下载客户端

安装依赖：

```bash
pip install requests cryptography
```

运行一次：

```bash
SYNCD_SERVER=http://127.0.0.1:21891 python3 shared/sync_download.py --once --dir ./downloads
```

持续轮询：

```bash
SYNCD_SERVER=http://127.0.0.1:21891 python3 shared/sync_download.py --interval 60 --dir ./downloads
```

说明：

- 首次运行会提示输入 6 位 PIN
- 客户端会在下载目录写入 `.syncd_key` 和 `.syncd_state.json`
- 如果下载目录里已有旧版 `.syncd_key` 但没有 `device_id`，升级后首次运行需要重新配对一次
- 这两个文件包含敏感状态，默认已加入 `.gitignore`

## 环境变量

- `PORT`: 服务端监听端口，默认 `21891`
- `SYNCD_SERVER`: Python 客户端访问的服务端地址

如果你要使用自定义 Cloudflare 域名或 `trycloudflare`，还需要先在本机安装 `cloudflared`。

## 部署方案

### 方案 A: 有 Cloudflare 域名

适合已有域名，且希望通过 Cloudflare 做 TLS、隧道和访问控制。

建议做法：

1. 不要把 `server.js` 直接暴露到公网端口。
2. 使用 Cloudflare Tunnel 或反向代理，把公网流量转发到本机 `127.0.0.1:21891`。
3. 在 Cloudflare Access 上加一层访问控制，至少限制邮箱、IP 或一次性身份验证。
4. Python 客户端通过 `SYNCD_SERVER=https://你的域名` 指定地址。
5. 保留 PIN 配对，但不要把 PIN 当作唯一公网安全边界。

上线前建议至少完成：

- 补充设备撤销和密钥轮换能力
- 保持 `tar` 为最新安全版本

### 方案 B: 没有 Cloudflare 域名

没有自定义域名时，可以直接使用 `trycloudflare` 提供的随机域名。

启动本地服务后，单独执行：

```bash
cloudflared tunnel --url http://127.0.0.1:21891
```

Cloudflare 会返回一个随机的 `https://xxxx.trycloudflare.com` 地址。然后：

1. 在浏览器端直接打开这个随机地址
2. 在 Python 客户端里设置 `SYNCD_SERVER=https://xxxx.trycloudflare.com`
3. 随机域名每次重启可能变化，不要写死在代码里

## 开源发布前检查

```bash
git status --short
git ls-files
```

发布前确认：

- `data/` 没有被提交
- `shared/` 里没有样本、报告、HAP、ZIP 等运行态文件
- 仓库里没有写死的公网地址或个人邮箱泄露
- 你已经补充合适的 `LICENSE`

## 已知限制

- 当前服务端已增加逐请求 HMAC 验签，但还没有完整的设备撤销界面和密钥轮换流程
- 浏览器端会把主密钥保存在 IndexedDB
- Python 客户端会把主密钥保存在下载目录
- 客户端解密阶段仍需要在本地持有完整响应内容

这些问题的详细说明见 [OPEN_SOURCE_AUDIT.md](./OPEN_SOURCE_AUDIT.md)。
