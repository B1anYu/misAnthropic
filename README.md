# MisAnthropic

> 检测客户端隐写检查可能依赖的地理指纹信号。基于已公开的第三方逆向分析资料，纯文件系统扫描——**不联网，不上传**。

MisAnthropic 扫描本机环境中可能被用于地域识别的配置痕迹：时区、locale、中国软件残留、镜像源、中国 AI 提供商配置等。它**只读本地文件**，不做任何网络请求，结果也不外传。

## 背景

该工具的检测项基于社区公开的逆向分析资料（如对某些 AI 客户端二进制的反混淆研究）。MisAnthropic 本身：

- **不声称**任何特定产品存在或不存在此类行为；
- **不联网**——所有检查都是 `fs.readdirSync` / `fs.readFileSync` / `process.env`；
- **不上传**——扫描结果只输出到你的终端。

它是一个本地自检工具，帮你了解"本机存在哪些可能被用于地域关联的痕迹"，而非指控任何方。

## 平台

- **原生 Windows** — 扫描本地盘（`C:\…`）
- **WSL2** — 通过 `/mnt/c/` 扫描 Windows 侧
- **纯 Linux** — `/mnt/c` 不可达时自动降级，仅扫描 Linux 侧信号

## 安装与运行

需要 Node.js ≥ 14。

```bash
# 直接运行（无需安装）
node index.js

# 或安装后用命令行
npm install -g .
misanthropic

# 或一次性执行（发布到 npm 后）
npx misanthropic
```

## 用法

```bash
node index.js              # 默认彩色输出
node index.js --json        # 机器可读 JSON
node index.js --summary     # 仅结论
node index.js --no-color    # 纯文本（管道/重定向时自动启用）
node index.js --fix         # 修复指南
node index.js --debug       # 显示未命中的检查项，排查"为什么没检测到"
node index.js --demo-clean  # 无条件预览"干净用户"界面
```

## 检测项

共 12 个检测器，按严重度分级（P0 致命 / P1 严重 / P2 / P3 弱）：

| 检测器 | 检查内容 |
|--------|----------|
| 时区与系统区域 | `/etc/timezone`、`TZ`、大陆时区名单 |
| 语言环境 | `LANG`/locale 含 `zh_CN`、`zh_HK` |
| Windows 侧文件系统 | 中国软件、桌面快捷方式、AppData、中文用户名、WiFi SSID、PowerShell 历史、安装语言（按数量分级） |
| Shell 历史与配置文件 | 镜像源痕迹、典型中国域名、dotfiles |
| 包管理器镜像配置 | npm/pip/apt/docker/go/cargo/gem/yarn/maven/conda/composer 等 |
| 网络指纹 | MAC OUI、中国公共 DNS |
| 硬件与系统 | DMI 厂商、中文输入法、键盘布局 |
| Claude Code 配置 | `ANTHROPIC_BASE_URL` 是否指向中国后端 |
| 其他杂项 | hostname、git 邮箱、gitee insteadOf |
| CC Switch | 安装、db 中指向中国后端的提供商配置 |
| AxonHub | 安装与配置痕迹 |
| WSL 特有信号 | interop、WSLg、GPU 直通 |

部分检测采用**按命中数量分级**（如中国软件 ≥5=P0、≥3=P1、≥1=P2），避免单个弱信号就判 P0。

## 构建产物

`node build.js` 生成三种产物（输出到 `dist/`）：

| 文件 | 说明 |
|------|------|
| `mis.bundle.js` | esbuild 单文件打包，可读 |
| `mis.obfuscated.js` | javascript-obfuscator 重度混淆（控制流平坦化、字符串数组） |
| `mis.xor.js` | XOR 自解压（key=91），可独立执行 |

## 局限

- 检测基于**公开资料和启发式规则**，存在误报与漏报；
- 部分检查依赖外部命令（`npm`/`go`/`docker` 等），命令缺失时该检查静默跳过（用 `--debug` 可见）；
- `/mnt/c` 不可达时（纯 Linux），Windows 侧信号全部跳过；
- 本工具只做**检测**，是否清理痕迹由你决定。`wsl.conf` 禁用 automount 等激进手段虽能阻断信号，但会破坏 VS Code Remote WSL 等功能，**不推荐日常使用**。

## 许可

AGPL-3.0 license
