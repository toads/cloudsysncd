# cloudsysncd 开源前安全与合规审计

审计日期：2026-06-30
仓库状态：面向 GitHub 公开发布整理中

## 审计范围

- 当前源码树与可发布包配置
- 服务端、浏览器端、Python 客户端和 TX relay 通道
- 依赖、许可证、运行态数据隔离和默认部署边界

## 结论摘要

当前仓库可以整理后开源，但仍不建议在没有额外访问控制的情况下直接公网暴露。已完成的关键加固包括：

1. 配对后接口使用 `deviceId + timestamp + nonce + HMAC` 做逐请求鉴权。
2. 大文件走流式加密响应，避免服务端整包缓冲。
3. chunked AEAD 增加认证结束帧，客户端会拒绝截断或尾部污染的数据。
4. TX relay 支持独立 access key HMAC，管理接口不会被 relay 代理。
5. 运行态状态文件、分享 token、云存储索引使用私有权限写入。
6. `Dockerfile`、`.gitignore`、`.env.example` 和 npm 包发布白名单已补齐。
7. `LICENSE` 已存在，`package.json` 使用 ISC。

仍需明确接受或后续补齐的边界：

- Python 客户端为了自签名和内网部署兼容，仍允许关闭 TLS 校验；公网使用应显式启用 TLS 校验。
- 服务端、浏览器 IndexedDB、Python 状态目录会长期保存同一个 master key；当前没有主密钥轮换机制。
- 设备撤销已可用，但还没有完整的图形化设备管理和密钥轮换流程。
- HTTP relay fallback 只适合被浏览器明确加入可信不安全源的场景；否则应使用 HTTPS relay。

## 一、敏感信息与运行态数据

`.gitignore` 已覆盖主要运行态与凭证文件：

- `data/`、`.local/`
- `shared/*`，但保留 `shared/sync_download.py`
- `.env*`，但保留 `.env.example`
- `.relay*.env`
- 常见证书和私钥后缀：`*.pem`、`*.key`、`*.p12`、`*.pfx`
- Python 客户端状态：`.syncd_state.json`、`.syncd_key`

发布前仍建议执行：

```bash
git status --short
git ls-files
npm pack --dry-run --json
```

确保没有把本地样本、运行态数据、证书、云厂商凭证或下载目录打进 Git/NPM 包。

## 二、代码安全现状

### 已修复：配对后的逐请求鉴权

保护接口要求携带：

- `X-Device-Id`
- `X-Auth-Timestamp`
- `X-Auth-Nonce`
- `X-Auth-Signature`

签名覆盖 `method + path + timestamp + nonce + body hash`，服务端校验设备状态、时间窗和 nonce 重放。

### 已修复：下载流式化与完整性检查

- 普通大文件使用流式 AES-GCM 或 chunked AEAD。
- chunked AEAD 末尾带认证结束帧，浏览器和 Python 客户端都会校验 chunk 数和 chunk 大小。
- 浏览器下载会校验明文大小，IndexedDB 临时块使用复合 key 避免字典序错序。
- File System Access API 写入失败时不会再尝试用已消费的流做不可靠降级。

### 已修复：TX relay 滥用防护

- relay 请求需要 access key HMAC。
- access key 通过已配对 E2E 信道加密下发给浏览器，不要求用户手工输入。
- relay 不会透传 `x-admin-token`。
- `/api/local/*` 管理接口大小写不敏感地禁止代理。
- 源站本地管理 API 只接受 loopback 请求。

### 已修复：云存储缓存一致性

- 云存储索引记录 `size + mtimeMs` 文件签名。
- 源文件变化后不会继续使用旧对象。
- 对象 key 加随机前缀，避免只由路径哈希决定。
- 同一路径重新上传成功后会清理被替换的旧对象。

### 剩余边界：长期 master key

服务端 `data/state.json`、浏览器 IndexedDB、Python `.syncd_key` 都保存同一个长期 master key。设备撤销能阻断后续 HMAC 请求，但已经泄露的 master key 没有自动轮换能力。

### 剩余边界：默认监听地址

服务端默认 `app.listen(PORT)`，未强制绑定 `127.0.0.1`。推荐生产部署仍放在 Cloudflare Tunnel、反向代理或本机防火墙之后，并叠加访问控制。

## 三、合规与发布

- `LICENSE` 已存在，包声明为 ISC。
- 前端使用系统字体，不依赖浏览器默认不会加载的第三方字体。
- `package.json` 增加 `files` 白名单，降低 `npm pack` 误带运行态文件的概率。
- `package-lock.json` 应保持官方 npm registry 的 resolved URL，避免发布时固定到个人或区域镜像。

## 四、建议的发布前检查

```bash
npm audit --registry=https://registry.npmjs.org --omit=dev --audit-level=moderate
npm test
npm run test:chunked
npm run test:security-relay
npm pack --dry-run --json
```

如果要验证真实 TX relay 链路：

```bash
RELAY_E2E_URL=https://... \
RELAY_E2E_KEY=... \
RELAY_E2E_ACCESS_KEY=... \
npm run test:e2e-relay-tx
```

`test:e2e-relay-tx` 默认不会操作本机 launchd；只有显式设置 `RELAY_E2E_MANAGE_LAUNCHD=true` 才会临时卸载并恢复指定 agent。

## 五、是否可以开源

可以作为“自托管、受控网络内的加密同步工具”开源。若目标是让未知用户直接公网部署，还需要继续补齐主密钥轮换、图形化设备管理、默认 loopback 监听或更严格的默认访问控制。
