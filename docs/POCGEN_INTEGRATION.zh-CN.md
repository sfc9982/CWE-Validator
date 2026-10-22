# PoCGen 与 C 回归语料接入

PoCGen 是针对 npm/JavaScript 包漏洞生成并验证 JavaScript PoC 的研究项目。它的目标语言、调用入口和验证栈与本项目不同：PoCGen 输出 JavaScript 调用代码并使用 JavaScript 静态分析和 Node/V8 运行时观察；本项目验证独立 C 程序，通过 stdin、argv 和文件夹具提供输入，并依赖 Clang 与 C 运行时观察器。论文覆盖的漏洞类别中，CWE-22 与本项目现有 Profile 直接重合。论文在 SecBench.js 上报告的结果不能作为 C 检测器的确认率预测。

因此，当前接入的是**样例来源和固定回归输入的导入接口**，不是 PoCGen 的 C 后端，也不会执行其自主生成/优化流程。导入流程只接受人工审核通过的固定输入、argv 和夹具；不解析或转换 JavaScript PoC。不能明确映射到目标 C 程序输入接口的样例应留在上游语料中并标为不支持。

## 使用流程

1. 选定基准 C 清单，人工确认它声明的 CWE、Profile、路径边界和证据要求。
2. 把已审核的固定输入和合成夹具写入样例描述文件，标记 `review_status: approved` 并填写审核说明。
3. 使用 `cweverify import-case` 派生新清单，再运行 `validate`、`run` 或将清单交给现有批量命令。
4. 检查报告中的来源、审核状态及哈希。任何源码、输入或夹具哈希不一致都会在清单校验或重放时失败。

上游工具报告的成功与否只保存在 `upstream_success_claim` 元数据中，独立验证器不读取它来形成判定。导入仅改变派生清单的样例 ID、固定输入和新增夹具；目标 CWE、Profile、路径策略、控制条件、构建和观察策略继承基准清单。

仓库还新增了本地手写 C 回归样例，分别覆盖 CWE-125、787、190、191、369、416、415 和 476。它们用于验证 C 输入、Profile 与证据判定的组合；这些样例不是从 PoCGen 转换或生成的。PoCGen 直接重合的 CWE-22 仍由现有路径校准样例覆盖。

## PoCGen 项目许可

PoCGen 仓库主页和其 `package.json` 当前显示的许可证标识不一致（仓库页面标注 MIT，包元数据声明 ISC）。本项目不复制 PoCGen 代码或依赖；若后续要复制代码、模型提示或其它上游文件，应先核实相应文件的适用许可证和来源。

参考资料：[PoCGen 仓库](https://github.com/sola-st/PoCGen)、[PoCGen 论文](https://arxiv.org/abs/2506.04962)。
