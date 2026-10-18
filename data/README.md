# 基准数据

本目录仅保留修复协议下最新的 16 次正式测量，每版各有 4 次全量、4 次热构建。预热、校准和验证试跑不进入本数据集。测量顺序为 ABBAABBA，A 为 Gradle 7.5.1，B 为 7.6.6。数据集信息见 [dataset.csv](dataset.csv)。

成绩对应测量时的根目录模块布局。源码现位于 `modules/`，Gradle 项目名与依赖拓扑相同。目录迁移后的验证没有混入本次成绩。

## 文件与关联

CSV 均为 UTF-8，第一行为字段名。数值保留源记录精度，缺失或不适用的字段为空。表间以 `measurement_id` 关联测量，以 `sample_id` 关联采样点。采样点编号从 0 开始，进程身份由 PID 和启动时间共同确定。

|文件|内容|
|---|---|
|[measurements.csv](measurements.csv)|每次测量的版本、场景、状态、退出码、耗时、RSS 指标及 daemon 身份|
|[samples.csv](samples.csv)|逐采样点的相对时间、构建或常驻阶段、同步 JVM RSS 总和与 daemon 最大 RSS|
|[rss.csv](rss.csv)|每个采样点实际观测到的各进程 RSS、PID、PPID 和启动时间|
|[processes.csv](processes.csv)|进程角色和观测到的完整命令，用于重建 JVM 与 daemon 归属|
|[gc.csv](gc.csv)|逐行 GC 日志，包括原文、时间、heap 容量、GC 前后用量和可解析的暂停时长|
|[heap.csv](heap.csv)|热构建常驻采样后的 `GC.heap_info` 与 `VM.flags` 原文及可解析数值|
|[pressure.csv](pressure.csv)|每次测量前后的全局 `vm_stat` 原始行|
|[commands.csv](commands.csv)、[context.csv](context.csv)|实际命令的逐参数记录，以及 JDK、缓存目录、离线模式等上下文|
|[cleanup.csv](cleanup.csv)、[signals.csv](signals.csv)|冷 daemon 单元的清理确认、发送的信号和目标身份|
|[fixture.csv](fixture.csv)、[dependencies.csv](dependencies.csv)|源码输入及依赖缓存的逐文件 SHA-256|
|[environment.csv](environment.csv)|主机、JDK、SDK、heap、workers、采样参数和环境探测记录|
|[summary.csv](summary.csv)、[comparison.csv](comparison.csv)|成功轮的中位数、范围、均值、成功次数，以及 B 相对 A 的中位数变化|
|[sources.csv](sources.csv)|被读取的本地原始文件的相对路径、大小与 SHA-256|
|[manifest.csv](manifest.csv)|CSV 的行数、字节数与 SHA-256，覆盖除自身以外的所有 CSV|

命令和诊断文本中的本机绝对路径使用 `${PROJECT}`、`${JDK17}` 和 `${ANDROID_SDK}` 替代。历史模块路径、owner 标记、PID 和启动时间保留。环境文件中的 `uname` 主机名未导出，操作系统与架构由其他字段记录。

## 统计口径

`measurements.csv` 的耗时单位为秒，RSS 指标单位为 MiB。逐进程和逐采样点 RSS 使用 KiB，换算关系为 1024 KiB = 1 MiB。`samples.csv` 中的 `seconds` 从该次 CLI 启动前的单调时钟起点计起，`phase` 区分 `build` 和 `resident`。

RSS 峰值先对同一采样点的全部实验 JVM 求和，再取构建阶段最大值。daemon 峰值单独计算。常驻 RSS 是构建结束后 3 秒窗口的中位数。跨轮次汇总仅使用成功的正式测量，失败状态与退出码仍保留在逐次表中。

同一冷 daemon 单元包含一对全量与热构建，GC 日志因此跨越两次构建。`gc.csv` 通过 `unit_id` 关联，不能将整份日志都计入某一个阶段。`heap.csv` 在热后采样窗口结束后取得，全量结束时未调用 jcmd，因此没有全量结束瞬间的 heap 快照。

本次 8 对热构建开始时都继承了全量后的 daemon 状态，热构建期间 heap 容量都达到 6144 MiB。任务全部 up-to-date 仍会发生配置、状态检查与内存分配。heap 扩展与较高的热构建 RSS 同时出现，但现有数据不能给出各类对象或堆外内存的贡献比例。RSS 范围、GC 时机和主机压缩活动都应一并考虑，单凭 RSS 增长无法判断泄漏。

## 运行与复核

`./run.sh` 生成 1000 个模块，先运行自检，再按相同条件预热两版，完成 ABBAABBA 的 8 对全量＋热构建。配置和依赖解析仅用于预热。原始日志写入新的 `results/` 子目录，通过原始数据与当前 AAR 校验后，将正式数据导出到该运行目录的 `csv/` 子目录。项目 `data/` 保留已归档成绩。

`python3 scripts/verify.py results/运行目录` 校验完整运行的命令、原始采样、daemon 身份、GC 退出顺序、预热、缓存、输入哈希及当前构建产物。它要求运行输入与当前工作区一致。

`python3 scripts/verify_csv.py` 仅凭本目录校验文件哈希、行数、进程关联、同步 RSS、逐次指标及全部汇总，无需本地 `results/`、JDK 或 Android SDK。

`python3 scripts/export_csv.py` 默认选择最新已完成的同协议运行，并将正式 CSV 归档到项目 `data/`。可用 `--source results/运行目录` 指定原件，或用 `--output 目标目录` 指定导出位置。导出前会校验暂存 CSV，`results/` 与 `data/` 分别保存原始日志和 CSV。

统计、进程识别、异常清理和导出测试位于 `tests/`，可用 `PYTHONPATH=scripts python3 -m unittest discover -s tests` 运行。`results/` 保存本地原件，不纳入版本控制。
