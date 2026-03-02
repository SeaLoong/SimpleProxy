# SimpleProxy

**简体中文** | [English](README.EN.md)

轻量级、可配置的本地 HTTP/HTTPS 代理服务器，使用 Rust 编写。支持基于灵活规则的请求拦截、重定向、内容替换和屏蔽，内置 HTTPS MITM 中间人拦截功能。自带中英双语 Web 管理面板。

## 功能特性

- **规则拦截** – 通过精确匹配或正则表达式匹配 URL，执行重定向、替换内容、屏蔽或转发操作
- **HTTPS MITM 拦截** – 透明拦截 HTTPS 流量；自动生成 CA 证书和每个域名的叶子证书
- **Web 管理面板** – 内置中英双语控制面板 `http://127.0.0.1:9000`
- **热重载** – 监听规则文件变更，自动重新加载
- **上游代理** – 支持通过 HTTP 或 SOCKS5 上游代理转发流量（全局或按规则配置）
- **系统代理** – 自动配置系统级代理设置（Windows / macOS / Linux），支持通过 Web 面板实时开关，退出时自动恢复
- **证书管理** – 自动生成 CA、检测系统信任存储状态、面板一键下载证书
- **极简部署** – 单个可执行文件，无运行时依赖

## 快速开始

```bash
# 编译
cargo build --release

# 运行（默认使用当前目录下的 config.json）
./target/release/simple-proxy

# 使用自定义配置文件
./target/release/simple-proxy --config path/to/config.json
```

首次启动时：

1. 在 `ca/` 目录下自动生成 CA 证书
2. 自动打开 Web 管理面板 `http://127.0.0.1:9000`
3. 安装 CA 证书以启用无缝 HTTPS 拦截

## 配置

配置保存在 **config.json** 中（与规则分离）：

```json
{
  "port": 8888,
  "rulesFile": "rules.json",
  "webPort": 9000,
  "autoOpenBrowser": true,
  "systemProxy": false,
  "upstreamProxy": null
}
```

| 字段              | 类型         | 默认值         | 说明                                         |
| ----------------- | ------------ | -------------- | -------------------------------------------- |
| `port`            | number       | `8888`         | 代理服务器监听端口                           |
| `rulesFile`       | string       | `"rules.json"` | 规则 JSON 文件路径（相对于配置文件）         |
| `webPort`         | number       | `9000`         | Web 面板监听端口                             |
| `autoOpenBrowser` | boolean      | `true`         | 启动时自动打开浏览器                         |
| `systemProxy`     | boolean      | `false`        | 启动时自动设置系统代理（可通过面板实时切换） |
| `upstreamProxy`   | string\|null | `null`         | 全局上游代理 URL（`http://`、`socks5://`）   |

如果配置文件不存在，会自动创建默认配置。

## 规则

规则以 JSON 数组形式存储在 **rules.json** 中：

```json
[
  {
    "comment": "将旧页面重定向到新页面",
    "match": "http://example.com/old",
    "type": "redirect",
    "target": "http://example.com/new",
    "statusCode": 302,
    "enabled": true
  },
  {
    "comment": "屏蔽分析脚本",
    "match": "^https?://analytics\\.example\\.com/.*",
    "isRegex": true,
    "type": "block",
    "statusCode": 403,
    "enabled": true
  }
]
```

### 规则字段

| 字段            | 类型    | 必填 | 说明                                                       |
| --------------- | ------- | ---- | ---------------------------------------------------------- |
| `match`         | string  | 是   | URL 匹配模式（精确匹配或正则表达式）                       |
| `type`          | string  | 是   | `redirect` \| `replace` \| `block` \| `proxy` \| `forward` |
| `isRegex`       | boolean | 否   | 将 `match` 作为正则表达式处理                              |
| `target`        | string  | 否   | 目标 URL（用于 `redirect` / `proxy`）                      |
| `statusCode`    | number  | 否   | 返回的 HTTP 状态码                                         |
| `body`          | string  | 否   | 响应体（用于 `replace` / `block`）                         |
| `contentType`   | string  | 否   | Content-Type 响应头（用于 `replace`）                      |
| `file`          | string  | 否   | 本地文件路径（用于 `replace`）                             |
| `headers`       | object  | 否   | 自定义请求头（用于 `proxy` / `forward`）                   |
| `upstreamProxy` | string  | 否   | 按规则指定的上游代理（用于 `forward`）                     |
| `comment`       | string  | 否   | 规则描述                                                   |
| `enabled`       | boolean | 否   | 启用/禁用规则（默认 `true`）                               |

### 规则类型

| 类型       | 行为                                        |
| ---------- | ------------------------------------------- |
| `redirect` | 返回重定向响应，包含 `Location` 头          |
| `replace`  | 返回自定义内容（内联 `body` 或本地 `file`） |
| `block`    | 返回错误响应（默认 403）                    |
| `proxy`    | 将请求转发到指定的 `target` URL             |
| `forward`  | 通过指定的 `upstreamProxy` 转发请求         |

## HTTPS 拦截

SimpleProxy 支持 HTTPS MITM（中间人）拦截：

- 首次运行时，在 `ca/` 目录下生成根 CA 证书和密钥对
- 对于匹配任意规则的域名，终止 TLS 连接并检查请求
- 对于不匹配的域名，使用纯 TCP 隧道透传（不拦截）
- 按域名动态生成叶子证书并缓存

### 安装 CA 证书

**Windows：**

```powershell
# 图形界面：双击 ca/ca.crt → 安装证书 → 本地计算机 → 受信任的根证书颁发机构
# 或通过命令行（以管理员身份运行）：
certutil -addstore Root ca\ca.crt
```

**macOS：**

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca/ca.crt
```

**Linux：**

```bash
sudo cp ca/ca.crt /usr/local/share/ca-certificates/simpleproxy-ca.crt
sudo update-ca-certificates
```

Web 面板会显示 CA 信任状态，并提供下载和重新检查按钮。

## Web 管理面板

内置面板提供以下功能：

- **证书状态** – 显示 CA 是否受信任，提供下载和重新检查按钮
- **系统代理切换** – 实时开关系统代理，无需重启；状态即时反馈
- **配置面板** – 编辑 config.json 中的所有字段并保存
- **规则表格** – 查看、添加、编辑、删除和启用/禁用规则
- **中英双语** – 一键切换中文和英文界面
- **实时持久化** – 修改立即保存到磁盘

访问地址：`http://127.0.0.1:<webPort>`（默认 9000）。

## 命令行

```text
simple-proxy [选项]

选项：
  -c, --config <CONFIG>  配置文件路径 [默认: config.json] [环境变量: CONFIG_FILE]
  -h, --help             显示帮助信息
  -V, --version          显示版本号
```

## 项目结构

```text
src/
  main.rs          – 入口，命令行解析，组件编排
  config.rs        – 配置文件加载与管理
  rule_engine.rs   – 规则加载、匹配、热重载
  proxy.rs         – HTTP/HTTPS 代理服务器（含 MITM 支持）
  cert.rs          – CA 证书管理及按域名生成证书
  upstream.rs      – HTTP 和 SOCKS5 上游代理连接器
  system_proxy.rs  – 系统级代理配置（Win/Mac/Linux）
  web.rs           – Web 面板服务器及嵌入式双语 UI
  lib.rs           – 库导出
config.json        – 应用配置
rules.json         – 拦截规则（JSON 数组）
ca/                – 自动生成的 CA 证书和密钥（已 gitignore）
```

## 编译

```bash
# 调试编译
cargo build

# 发布编译（优化、剥离符号）
cargo build --release

# 运行测试
cargo test

# 代码检查
cargo clippy
```

## 许可证

[MIT](LICENSE)
