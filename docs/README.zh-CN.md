# 三个操作系统的 DDR 测量

本仓库提供论文 **From DDR Advertisements to Encrypted DNS: System Policies, Upgrade Availability, and Resolver Continuity** 的实验代码、2026 年 10 月测量数据和图表脚本。

实验先在 Windows 11、Android 和 macOS 原生系统上确定 DDR 连接规则，再从新加坡与洛杉矶测点按这些规则验证公网服务器。进一步改变单项规则及其组合，并比较加密升级前后的 DNS 解析功能。

## 主要结果

| 测量项目 | 结果 |
| --- | ---: |
| 端点验证时返回有效、非空 SVCB 的原解析器地址，两测点并集 | 351,897 |
| 符合 Windows DoH 模型 | 84 |
| 符合 Android DoH 模型 | 74 |
| 符合 macOS DoH 模型 | 84 |
| 至少符合一个 DoH 模型 | 112 |
| 同时符合三个 DoH 模型 | 45 |
| 符合 Windows DoT 模型 | 80 |
| 加密升级后稳定丢失 DNS64 合成功能的原解析器 | 4 |
| Mac 原生功能及路由对照 | 16 个场景、96 次查询 |

完整成功包括发现、地址选择、证书检查和有效 DNS 应答；DoH 还要求 HTTP 200。

## 重建图表

在仓库根目录使用 Python 3.11 或更新版本：

```sh
python -m venv .venv
# 按当前终端类型激活虚拟环境。
python -m pip install -r requirements.txt
python scripts/make_figures.py
python zh/scripts/make_figures.py
```

每种语言生成八幅图，包含 PDF 与 PNG。中文字体及具体命令见[图表说明](FIGURES.md)。重绘只读取仓库中的数据。

## 文件说明

- [数据与统计口径](DATA.md)：汇总数据、成功地址列表、逐记录结果和分母定义。
- [测量代码](MEASUREMENT.md)：探测流程、依赖、输入格式和命令。
- [英文说明](../README.md)：仓库结构、作者和资助致谢。

论文用 **R₀** 表示原 DNS 解析器地址、**T** 表示 SVCB 目标名称、**F** 表示加密连接目的地址。历史数据字段 `A` 对应论文中的 R₀；DNS 的 `A` 记录类型仍表示 IPv4 地址记录。`round` 表示同一次测量中的查询重复编号。
