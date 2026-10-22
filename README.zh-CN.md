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

CWE-22 在 `observation_mode: adaptive`（默认）下会从文件操作源码中寻找唯一固定目录前缀；找不到时以 `/work` 作为测试边界，并在结果中注明该假设。检测不会自动补造或挂载输入文件。所有 CWE 的自适应观察计划也会记录 AST 候选位点、计划观察器和工具缺口；覆盖率未知会明确标出。设置 `observation_mode: explicit` 可只运行清单指定的 Profile 观察器，`max_supplemental_runs` 默认最多追加三轮观察。

单例清单按原有方式声明源码、CWE、Profile 和输入即可，不必填写 `path_policy` 或为每个位点指定观察器；需要时可覆盖自适应默认值：

```yaml
sample_id: my-cwe22-case
sources: [./case.c]
claimed_cwe: CWE-22
profile: c.path-traversal@1.0.0
entry:
  argv: [user-supplied-path]
# observation_mode: adaptive  # 默认值
# max_supplemental_runs: 3    # 默认最多三轮补充观察
```

## 导入固定回归样例

`import-case` 可将人工审核通过的固定 stdin/argv 与合成夹具接入现有验证器。它不会生成或优化输入，也不会更改基准清单的 CWE、Profile、路径边界、控制条件或观察设置。上游工具的成功标记仅作为来源信息保存，不能形成漏洞结论。JavaScript PoC 不能自动转换为 C 输入；只有明确整理成 C 程序可接受的数据后才能导入。

样例描述文件示例：

```yaml
source_tool: PoCGen
upstream_version: v4
case_id: reviewed-case-01
review_status: approved
review_note: 人工核对输入与目标 C 程序接口及预期诊断。
upstream_success_claim: true
entry:
  stdin: "5\n"
  argv: []
fixtures:
  - source: fixtures/input.txt
    destination: input.txt
```

从现有清单导入并执行：

```bash
cweverify import-case manifests/base.yaml corpus/case.yaml manifests/imported-case.yaml
cweverify validate manifests/imported-case.yaml
cweverify run manifests/imported-case.yaml
```

导入清单记录来源、审核说明及源码、输入和新增夹具的 SHA-256；校验和重放时哈希不匹配会拒绝继续。条件性补建夹具或故障注入仍需作为独立实验保存，不得据此升级原始环境结论。

PoCGen 与 C 检测器的差异及适用范围见 [PoCGen 接入说明](docs/POCGEN_INTEGRATION.zh-CN.md)。

批量清单同样使用自动观察；可在全局配置后按样例覆盖：

```yaml
batch_id: cwe22-corpus
source_directory: ./samples
claimed_cwe: CWE-22
profile: c.path-traversal@1.0.0
entry:
  argv: [user-supplied-path]
overrides:
  nested-case:
    max_supplemental_runs: 1
```

缺少显式边界时采用 `/work` 是检测器的测试约定，不代表宿主机目录或程序自身的安全策略；报告会注明边界来源。补充观察会重复使用原始输入与夹具，不自动生成攻击输入或补建文件。

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
