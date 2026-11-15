# GhostShredder 👻🔪

**GhostShredder（幽灵粉碎器）** 是一个面向 Windows 的文件/目录占用诊断、解除占用与强制删除工具。

它诞生于一个很具体的问题：一个**空目录**无法删除、无法重命名，常见 Unlocker/Force Deleter 甚至无法定位占用者；最终发现是后台进程把该目录作为 **Current Working Directory (CWD)** 持有。GhostShredder 从这个案例出发，把 Windows 上“删不掉”拆成多类占用与非占用原因，而不是把所有失败都笼统称为“文件被占用”。

> 当前版本：**v0.2.5**（pre-1.0，接口和行为仍可能调整）
>
> 平台：Windows 10/11 x64，Windows PowerShell 5.1+ 推荐。

## 核心能力

- **分析占用**：按类别扫描 CWD、普通文件/目录 Handle、Memory Mapping / IMAGE、SMB Server Open、Filter/Minifilter，并额外执行 DELETE-access probe 与非占用诊断。
- **解除占用**：逐层检测、逐层授权；只在真的发现当前版本可解除的对象时弹确认。
- **强制删除**：尝试 Win32 `FileDispositionInfoEx` / POSIX semantics、扩展路径删除等方式。
- **幽灵粉碎**：以“删除成功”为终止条件。删除失败时，解除已知占用后立即重删，必要时最多追杀 3 轮。
- **下次启动删除**：登记系统重启后的删除操作。
- **停止当前任务**：扫描或删除耗时时可取消；隔离扫描/外部删除子进程可被直接终止。
- **单任务状态机**：任务运行期间禁止重复点击和并发修改同一目标。
- **根目录硬保护**：拒绝对盘符根目录和 UNC share 根目录执行破坏性操作。

## 为什么不是又一个 Unlocker？

GhostShredder 明确区分不同类型的“占用”与“删除失败”：

| 类别 | 例子 | 当前能力 |
|---|---|---|
| A — CWD | 进程把目标目录作为 Current Working Directory | 检测 + 经确认关闭句柄 |
| B — File / Directory Handle | `CreateFile` 打开的普通文件/目录句柄 | 检测 + 经确认关闭句柄 |
| C — Memory Mapping / IMAGE | mmap、映射文件、已加载 EXE/DLL image | 诊断，不远程 Unmap |
| D — SMB Server Open | 远程客户端通过本机 SMB 打开的对象 | 诊断，不主动断会话 |
| E — Filter / Minifilter | 杀软、备份、加密等文件系统过滤器 | 仅诊断上下文，不把“挂载”误判为“占用” |
| F — DELETE-access probe | 测试目标能否取得 DELETE access | 只读探针，不删除 |
| G — 非占用诊断 | 属性、reparse、ACL owner 等 | 用于区分“占用”和其他失败原因 |

详细模型见 [`docs/OCCUPANCY_MODEL.md`](docs/OCCUPANCY_MODEL.md)。

## 结果语义

GhostShredder 不把“没扫到”偷换成“绝对不存在”：

- **发现 N 个**：本次形成正向证据。
- **本次暂未发现**：扫描正常完成，但本次没有命中；不代表未来不会出现，也不代表其他类别没有占用。
- **本次扫描未完成（超时），未形成该类别结论**：扫描没有完成，不输出“有”或“无”的结论。

## 使用方法

1. 下载源码并先阅读 `GhostShredder.ps1`；这是一个需要管理员权限、能够关闭其他进程句柄并永久删除文件的工具。
2. 双击 `Run-GhostShredder.cmd`。
3. UAC 提权后选择目标文件或文件夹。
4. 建议先点 **分析占用**，再根据结果使用 **解除占用 / 强制删除 / 幽灵粉碎**。

`Run-GhostShredder.cmd` 使用 Windows PowerShell 并为该次启动指定 `-ExecutionPolicy Bypass`；它不会修改系统全局 Execution Policy。

也可以直接运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\GhostShredder.ps1
```

或带目标路径：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\GhostShredder.ps1 -TargetPath "D:\path\to\target"
```

## 测试

`tests/` 提供三个可复现实验：

- `Test-CWD-Lock.ps1`：制造 CWD 目录占用；
- `Test-FileHandle-Lock.ps1`：制造普通文件 Handle 占用；
- `Test-MemoryMapping-Lock.ps1`：建立 mapped view 后关闭原始 File/Mapping handle，仅保留映射视图。

测试脚本只应对临时测试目录使用。

## 安全边界

GhostShredder 是**用户态工具，不是内核驱动**。

- 关闭远程进程的 CWD / 文件句柄可能让目标进程继续存活，但后续相对路径或文件访问出现 `ERROR_INVALID_HANDLE` 等异常。
- Memory Mapping / IMAGE 当前只诊断，不通过代码注入远程 Unmap。
- Filter / Minifilter 列表只能说明过滤器挂载在目标卷上，不能据此断言它就是阻塞者。
- SMB 当前只诊断，不自动断开远程客户端会话。
- 受保护进程、内核对象、文件系统内部状态等仍可能超出当前覆盖范围。
- “幽灵粉碎”和“强制删除”是不可逆操作，不经过回收站。

请不要在没有备份或不理解目标用途的情况下对系统目录、程序目录或重要数据使用强制删除。

## 设计原则

1. **先区分占用类型，再决定是否修改。**
2. **检测与授权范围一致。** 新发现的可修改对象需要新的授权；同一操作中已授权对象的重建可按既有授权重试。
3. **删除优先只属于“幽灵粉碎”。** “解除占用”保持逐层、谨慎；“幽灵粉碎”则以目标消失作为终止条件。
4. **不因扫描失败制造结论。** Timeout 是“未完成”，不是“没有占用”，也不是“仍有残留”。
5. **状态修改后立即使旧分析快照失效。** 避免历史观测污染当前确认。

## 项目状态

v0.2.5 已在真实 Windows 11 环境中完成 CWD 锁检测/解除、重复占用处理、幽灵粉碎、逐层授权、取消与防重复点击等交互验证。Handle / Mapping 全局扫描在部分环境中仍可能触发超时，因此当前明确保留“扫描未完成，不下结论”的状态。

这是 pre-1.0 项目，欢迎提交可复现案例、日志和改进建议。提交日志前请先清理个人路径、用户名、PID 之外的敏感信息。

## License

[MIT](LICENSE)
