# nftconf

声明式 **nftables** 配置工具：用简洁配置语言与内核规则集对账（reconcile），
监视文件变更，并以稳定注释标记每条规则的所有权。

## 功能

- **load / unload / status / check** — 实时对账与冲突策略
- **daemon** — inotify 热加载 + **pidfile**（单实例）
- **NAT**（`nat`/`dnat`/`snat`/`masquerade`/`redirect`），且不自动开放 INPUT
- **whitelist / shield** — 默认丢弃的 INPUT 白名单
- **上下文作用域** — 通过 `interface` / `address` 支持多网卡/多地址
- **convert** — 生成汇总的 `nftables.d/*.nft`
- **Docker 演示** — `demo/` 下的 NAT、shield、热加载、pidfile、双网卡实验网

## 快速开始

```bash
sudo apt install meson ninja-build python3 gettext asciidoctor pandoc texinfo nftables
meson setup /build
ninja -C /build
sudo /build/nftconf load -v demo/nftconf.conf   # 需要 root 与 nftables
```

```bash
nftconf load FILE
nftconf daemon FILE --pid /run/nftconf.pid
nftconf stop --pid /run/nftconf.pid
nftconf convert FILE -o nftables.d/out.nft
```

## 仓库结构

| 路径 | 作用 |
|------|------|
| `nftconf.py` | 启动脚本 |
| `nftconf_app/` | Python 包（解析、对账、CLI） |
| `docs/*.adoc` | AsciiDoctor 源（man + info） |
| `guide.md` | Markdown 使用指南 |
| `demo/` | Docker Compose 测试环境 |
| `po/` | gettext 翻译 |
| `debian/` | 打包元数据 |

## 文档

- 手册页：`man nftconf`（`docs/nftconf.1.adoc` → AsciiDoctor）
- Info 手册：`info nftconf`（AsciiDoctor → DocBook → Texinfo）
- 指南：[guide.md](guide.md)
- 英文总览：[README.md](README.md)
- 演示环境：[demo/README.md](demo/README.md)

构建文档需要 `asciidoctor`、`pandoc`、`makeinfo`（由 Meson 调用）。

## 配置示例

```nftconf
table demo
interface eth0
address 203.0.113.10
dest address 10.0.0.50
priority filter

shield on
whitelist tcp 22
nat tcp 8080 to 8080

include conf.d/*.conf
```

完整语法见 [guide.md](guide.md)。

## 构建与测试

使用绝对构建目录 **`/build`**：

```bash
meson setup /build
ninja -C /build
meson test -C /build
```

### 国际化

```bash
ninja -C /build posync
LANGUAGE=zh_CN /build/nftconf -h
```

### 安装辅助

```bash
meson install -C /build
ninja -C /build install-symlinks
ninja -C /build uninstall-symlinks
ninja -C /build look
```

## Docker 演示

```bash
cd demo && docker compose up -d --build
docker compose exec client /demo/scripts/smoke-test.sh
```

## Debian 打包

```bash
dpkg-buildpackage -us -uc
```

## 许可证

Copyright (C) 2026 Lenik <nftconf@bodz.net>

采用 **AGPL-3.0-or-later**。  
本项目反对 AI 剥削与 AI 霸权，反对无脑 MIT 式许可证和政治愚蠢的 BSD 式许可证。  
详见 `LICENSE`。
