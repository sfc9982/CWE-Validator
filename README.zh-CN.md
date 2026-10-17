# CWE Witness

CWE Witness（命令 `cweverify`）用于检查 C 程序的运行证据是否支持其声明的 CWE 弱点。工具会编译样本、使用配置的观察器运行程序，并保存证据和结论，方便复查与复放。

文件名、注释、程序打印的错误信息或一次崩溃都不能单独证明 CWE。`CONFIRMED` 表示本次运行满足配置的证据规则；`NOT_CONFIRMED` 表示未满足，不能据此断言程序安全；`UNSUPPORTED` 表示所需 Profile 或运行环境不可用；`ERROR` 表示验证未能完成。

本项目用于可复现的安全研究和教学。校准程序故意保留漏洞。仅运行可信代码：运行器设置了进程限制，并在 Linux 上提供隔离，但不能作为对抗主动恶意程序的安全边界。

## 快速开始

Linux 上先查看发行版与软件包计划，再安装：

```bash
bash scripts/setup.sh --dry-run
bash scripts/setup.sh --yes
source .venv/bin/activate
cweverify doctor
```

脚本支持 Ubuntu 24.04+/Debian 12+、Fedora、RHEL/Rocky/AlmaLinux/CentOS Stream 9+ 和 Arch/Manjaro 的软件包映射。企业 Linux 使用独立的 Python 3.11 软件包；旧版系统需要自行提供 Python 3.11+。其他发行版可手动装好工具后使用 `--skip-system`，或使用 Docker。`setup-ubuntu.sh` 保留为兼容入口。

Docker 使用方式：

```bash
bash scripts/docker.sh build
bash scripts/docker.sh run doctor
bash scripts/docker.sh run run manifests/calibration/cwe416-trigger.yaml
bash scripts/docker.sh run batch --jobs 1
```

结果保存在主机 `.cwe-witness/`。自有样本通过 `--input-dir /绝对路径/样本包` 只读挂载到 `/inputs`。普通模式使用当前 UID/GID、关闭容器网络；需要 Bubblewrap 路径策略或 strace 时，可显式添加 `--full-isolation`。此选项以容器 root 运行、增加 SYS_ADMIN/SYS_PTRACE 并放宽 seccomp/AppArmor，适用于可信的临时研究环境，输出可能属于 root。宿主内核或 Docker 策略仍可能禁止嵌套隔离。

脚本默认保留系统软件源；可用 `--mirror tsinghua` 选择 PyPI 镜像。`--use-uv` 按锁文件安装，`--no-dev` 仅安装运行依赖。详细参数、发行版限制和 Docker 用法见[环境配置说明](SETUP.md)，实际检查结果见[配置验证记录](SETUP_VALIDATION.md)。

校验并运行内置校准样本：

```bash
cweverify validate manifests/calibration/cwe416-trigger.yaml
cweverify run manifests/calibration/cwe416-trigger.yaml
cweverify batch
```

仅开发 Python 部分：

```bash
uv sync --all-groups
uv run pytest -q
```

项目需要 Python 3.11 或更新版本。样本执行支持 Linux；Windows 用户可通过 WSL2 运行。原生 Windows 仅支持清单校验和报告处理，macOS 原生执行暂不支持。

## 支持范围

内置 Profile 覆盖 CWE-120、125、190、191、369、415、416、476、772、787 和 22。每个 Profile 声明用于支持结论的观察器和证据条件。CWE-772 包含 POSIX 文件描述符和自定义资源检查；CWE-22 使用 Bubblewrap 与 strace。判定能力和限制见[分析方法](ANALYSIS_METHOD.md)。

默认批量清单目录为 `manifests/calibration`，可通过 `cweverify batch --directory PATH` 指定其他目录。运行证据写入 `.cwe-witness/`，该目录已加入 Git 忽略规则。

## 可选目录元数据

运行判定不依赖 CWE 目录。可在 run/batch 命令中通过 `--catalog /路径/catalog.csv` 指定自备 CSV，列名为 `CWE-ID`、`Name` 和 `Description`。默认仅在当前工作目录查找 `699.csv`；不存在时记录 `CATALOG_NOT_FOUND`，不影响运行证据判定。`tests/fixtures/` 中的小型 CSV 是自建测试数据，不是第三方 CWE 数据导出。

## 开发检查

```bash
uv sync --all-groups
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
uv run pytest -q
uv build
```

实际验收结果与尚未执行的环境检查见[验证记录](VALIDATION.md)。

贡献和安全问题报告方式见[贡献指南](CONTRIBUTING.md)与[安全政策](SECURITY.md)。项目代码和合成测试夹具采用 MIT 许可证；不随仓库提供研究语料或第三方 CWE 目录数据。
