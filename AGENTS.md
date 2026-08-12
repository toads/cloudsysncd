# cloudsysncd — Agent 协作指南

> 本文档面向 AI 编码 Agent。阅读者应对本项目一无所知，因此文档力求自包含、准确、可执行。

---

## 项目概述

`cloudsysncd` 是一个基于 Node.js 的轻量级文件/文本同步与共享服务。核心特性包括：

- **浏览器端 PIN 配对**：服务端生成一次性 6 位 PIN，客户端通过 ECDH + HKDF 协商共享主密钥。
- **端到端加密**：文件列表、文件内容、文本内容均使用 AES-256-GCM 加密传输。
- **流式加密大文件**：超过阈值（默认 64MB）的文件使用 chunked AEAD 流式加密，避免服务端内存堆积。
- **多客户端支持**：浏览器前端 + Python 自动轮询下载 CLI。
- **可选云存储加速**：支持 Cloudflare R2 和七牛云 Qiniu，大文件自动上传并返回 Presigned URL，减少服务器出口带宽压力。
- **短链接分享**：可为单个文件生成一次性或有限次数的分享链接。

**当前定位**：受信任网络内的轻量同步工具。未经额外加固不建议直接暴露到公网。

---

## 技术栈与运行时架构

| 层级 | 技术 | 说明 |
|------|------|------|
| 服务端运行时 | Node.js 20+ | Express 单文件服务 (`server.js`) |
| 前端 | 原生 HTML/CSS/JS | `public/index.html` + `public/app.js`，无框架 |
| 客户端 | Python 3.10+ | `syncd_client/cli.py`，依赖 `requests` 和 `cryptography` |
| 打包/构建 | setuptools | `pyproject.toml` 定义 Python 包 `cloudsysncd-sync` |
| 容器化 | Docker + Docker Compose | `Dockerfile` 基于 `node:20-bookworm-slim` |
| 云存储 SDK | `@aws-sdk/client-s3` / `qiniu` | S3-compatible API |
| 加密 | Node.js `crypto` / Web Crypto API / Python `cryptography` | ECDH (P-256)、HKDF-SHA256、AES-256-GCM |

### 核心模块划分

```
server.js              # Express 服务端：配对、鉴权、文件/文本 API、管理接口
pin.js                 # 本地 CLI：生成 PIN、查看/撤销已配对设备
share.js               # 本地 CLI：复制文件到共享目录、软链接分享(--link)、列出/清空共享文件
public/
  index.html           # 单页前端
  app.js               # 浏览器端逻辑：配对、文件浏览/下载、文本收发
lib/
  cloud-storage.js     # 云存储抽象：R2/Qiniu 上传、Presigned URL、配额清理
  chunked-aead.js      # 流式分块加密格式实现
  shared-links.js      # 软链接分享白名单(data/shared-links.json)读写与路径判断
syncd_client/
  __init__.py          # Python 包入口
  cli.py               # Python 轮询下载客户端完整实现
shared/
  sync_download.py     # 兼容旧脚本的包装入口（内部跳转到 syncd_client.cli）
scripts/
  smoke-test.js        # 最小健康检查测试
  integration-test.js  # 端到端配对 + 下载 + 撤销测试
  chunked-test.js      # 5MB chunked AEAD 下载/解密测试
  cloud-smoke.js       # 真实云存储上传 + Presigned URL 测试
  e2e-50mb.js          # 50MB Node server + Python CLI + chunked AEAD 端到端测试
  e2e-qiniu.js         # 5MB Qiniu 端到端测试
  qiniu-usage.js       # 查看 Qiniu 存储用量统计
  qiniu-objects.js     # 列出 Qiniu bucket 对象
```

---

## 关键配置与环境变量

项目通过 `.env` 文件（`dotenv`）和环境变量进行配置。

### 服务端环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | `21891` | 监听端口 |
| `DATA_DIR` | `./data` | 运行时状态目录（保存 masterKey、设备列表、admin token） |
| `SHARED_DIR` | `./shared` | 共享文件目录 |
| `PAIR_SESSION_TTL_MS` | `600000` | PIN 有效期（毫秒） |
| `CHUNKED_THRESHOLD_BYTES` | `67108864` | 超过此大小的文件使用 chunked AEAD |
| `SHARE_ENABLED` | — | 设为 `false` 关闭分享链接功能 |

### 云存储环境变量（可选）

复制 `.env.example` 为 `.env` 后按需填写：

- `STORAGE_PROVIDER=r2|qiniu|false`
- R2: `R2_ENDPOINT`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`
- Qiniu: `QINIU_ACCESS_KEY`, `QINIU_SECRET_KEY`, `QINIU_BUCKET`
- 通用: `STORAGE_FALLBACK_BYTES`, `STORAGE_PRESIGN_EXPIRY_SECONDS`, `STORAGE_HOT_DURATION_MS`, `STORAGE_MAX_BYTES`

### Python 客户端环境变量

| 变量 | 说明 |
|------|------|
| `SYNCD_SERVER` | 服务端地址，默认 `http://127.0.0.1:21891` |
| `SYNCD_VERIFY_TLS` | 是否校验 TLS 证书，`true/false` |

---

## 构建与启动命令

### 本地开发

```bash
npm install          # 安装 Node 依赖
./start.sh           # 生产模式启动（默认端口 21891）
./start.sh --dev     # 开发模式（使用 nodemon 监视 server.js 和 public/）
```

`npm start` 和 `npm run dev` 本质上也是调用 `./start.sh`。

### Docker 启动

```bash
docker compose up --build -d
```

默认映射：
- 端口 `${PORT:-21891}`
- 运行时数据 `./.local/data`
- 共享文件 `./.local/shared`

### Python 客户端安装与使用

```bash
pip install .
# 或保持脚本式调用：pip install requests cryptography

# 运行一次
SYNCD_SERVER=http://127.0.0.1:21891 cloudsysncd-sync --once --dir ./downloads

# 持续轮询
SYNCD_SERVER=http://127.0.0.1:21891 cloudsysncd-sync --interval 60 --dir ./downloads
```

---

## 测试命令

```bash
npm run smoke          # 最小健康检查（临时目录 + 临时端口）
npm run integration    # 完整集成测试（配对 + 下载 + 撤销）
npm test               # smoke + integration
npm run test:chunked   # 验证 5MB chunked AEAD 下载/解密
npm run test:cloud     # 验证真实云存储上传 + Presigned URL（需要配置 .env）
npm run test:e2e       # 50MB 端到端：Node server + Python CLI + chunked AEAD
npm run test:e2e-qiniu # 5MB Qiniu 端到端测试（需要 Qiniu 凭证）
npm run qiniu:usage    # 查看 Qiniu 存储用量统计
npm run qiniu:objects  # 列出 Qiniu bucket 中的对象
```

**注意**：运行 `test:e2e` 前确保 Python 依赖已安装（`pip install requests cryptography`）。

---

## 代码风格与约定

### JavaScript / Node.js

- 使用 **CommonJS**（`require` / `module.exports`），而非 ESM。
- 服务端代码集中在 `server.js`，尽量保持单文件可读性；云存储和 chunked AEAD 逻辑拆分到 `lib/`。
- 字符串引号：项目内混用单引号与双引号，保持与周边代码一致即可。
- 注释与日志输出以 **中文** 为主。
- `console.log` 用于用户可见信息；结构化日志使用 `logEvent(event, fields)`，输出 JSON 到 stdout。
- 加密/安全相关函数优先使用 Node.js 内置 `crypto` 模块。

### Python

- 最低支持 Python 3.10。
- `syncd_client/cli.py` 是一个自包含脚本，尽量减少外部依赖（仅 `requests` 和 `cryptography`）。
- 中文注释和日志输出。
- 状态文件（`.syncd_key`、`.syncd_state.json`）默认写入下载目录，权限设为 `0o600`。

### 前端

- 无构建步骤，`public/app.js` 是原生 ES6+ 浏览器代码。
- 使用 Web Crypto API 进行所有客户端加密操作。
- IndexedDB（`KeyStore`）用于持久化主密钥和设备 ID。
- 样式全部内联在 `index.html` 的 `<style>` 中，无外部 CSS 文件。

---

## 安全模型与关键注意事项

### 配对与鉴权

1. **PIN 配对**：服务端生成 6 位随机 PIN，客户端输入后通过 ECDH (P-256) 协商共享密钥，服务端用 HKDF 派生的传输密钥加密 masterKey 下发。
2. **逐请求鉴权**：配对后所有受保护接口要求 `X-Device-Id`、`X-Auth-Timestamp`、`X-Auth-Nonce`、`X-Auth-Signature`。签名内容为 `HMAC-SHA256(method + path + timestamp + nonce + bodyHash)`。
3. **重放防护**：服务端记录每个设备的 nonce，10 分钟内重复 nonce 返回 `409 Replay detected`。
4. **时间窗**：请求时间戳偏差超过 5 分钟会被拒绝。

### 已知安全边界与限制

- **Python 客户端默认关闭 TLS 校验**（`verify_tls = False`）。这是项目当前明确接受的业务风险，主要用于自签名或局域网场景。如需公网使用，应显式启用 `--verify-tls`。
- **主密钥长期驻留**：服务端 `data/state.json`、浏览器 IndexedDB、Python 客户端 `.syncd_key` 均长期保存同一个 masterKey。目前**没有密钥轮换机制**。
- **设备撤销已实现**：可通过 `node pin.js --revoke <id>` 或管理 API 撤销设备，撤销后该设备的 HMAC 签名将失效。
- **默认监听所有网卡**：`app.listen(PORT)` 未限制 `127.0.0.1`，在可直达的网络环境中会被其他设备访问。
- **不适合直接公网暴露**：README 和 OPEN_SOURCE_AUDIT.md 均强调，公网部署应放在 Cloudflare Tunnel / 反向代理之后，并叠加额外访问控制层。

### 运行时数据隔离

- `data/` 和 `shared/` 是运行态目录，**不应提交到 Git**。
- `.gitignore` 已排除 `data/`、`.local/`、`shared/*`（保留 `shared/sync_download.py`）。
- Docker Compose 默认将运行时目录映射到 `./.local/data` 和 `./.local/shared`，与源码树分离。

---

## 部署流程

### 推荐部署路径

1. **本地/内网**：直接 `./start.sh`。
2. **有 Cloudflare 域名**：使用 Cloudflare Tunnel 转发到 `127.0.0.1:21891`，在 Cloudflare Access 上加访问控制。
3. **无域名**：使用 `cloudflared tunnel --url http://127.0.0.1:21891` 获取随机 `trycloudflare.com` 地址。
4. **Docker**：`docker compose up --build -d`，然后 `curl http://127.0.0.1:21891/healthz` 验证。

### 健康检查

```bash
GET /healthz
```

返回 JSON，包含 `ok`、`service`、`version`、`paired`、`pairedDeviceCount`、`pendingPairExpiresAt`、`uptimeSeconds`。该接口无需鉴权，用于 Docker healthcheck 和 CI smoke test。

---

## 文件与目录快速参考

| 路径 | 作用 | 是否应提交 |
|------|------|------------|
| `server.js` | Express 服务端主文件 | 是 |
| `public/` | 前端静态资源 | 是 |
| `pin.js` | 本地管理 CLI | 是 |
| `share.js` | 文件共享 CLI | 是 |
| `lib/` | 服务端辅助库（云存储、chunked AEAD） | 是 |
| `syncd_client/` | Python 客户端源码 | 是 |
| `scripts/` | 测试与辅助脚本 | 是 |
| `data/` | 运行时状态（masterKey、设备列表、admin token） | **否** |
| `shared/` | 运行时共享文件目录 | **否**（除 `sync_download.py`） |
| `.local/` | Docker Compose 默认映射的运行时目录 | **否** |
| `pyproject.toml` | Python 包配置 | 是 |
| `package.json` | Node 项目配置 | 是 |
| `start.sh` | 统一启动入口 | 是 |
| `.env` | 环境变量（含云存储凭证） | **否** |

---

## 修改前的必读事项

1. **不要回退流式下载**：单文件和批量下载已实现为流式加密响应（`streamEncryptedResponse`、`streamChunkedEncryptedResponse`），不要改为整包缓冲，否则大文件会撑爆服务端内存。
2. **保持 chunked AEAD 格式兼容**：`lib/chunked-aead.js` 的 header 格式（`SYNC` + version + chunkSize）和 Python/浏览器端的解析逻辑必须同步更新。
3. **状态文件格式向后兼容**：`data/state.json` 和 `data/storage-index.json` 的结构变更应做好版本兼容或迁移逻辑。
4. **中文输出优先**：面向用户的日志、错误信息、前端文案保持中文，与现有风格一致。
5. **测试覆盖**：新增服务端接口应补充到 `scripts/integration-test.js`；新增前端功能应在主流浏览器验证配对与下载链路。
