# GhostShredder 👻🔪

**GhostShredder（幽灵粉碎器）** 是一个面向 Windows 的文件/目录占用诊断、解除占用与强制删除工具。

它诞生于一个很具体的问题：一个**空目录**无法删除、无法重命名，常见 Unlocker/Force Deleter 甚至无法定位占用者；最终发现是后台进程把该目录作为 **Current Working Directory (CWD)** 持有。项目随后扩展到普通文件 Handle、Memory Mapping / IMAGE、SMB、Filter/Minifilter 等多类占用与删除失败诊断。

> 当前公开预览：**v0.3.0-alpha3**
>
> 平台：Windows 10/11 x64，Windows PowerShell 5.1+ 推荐。

## v0.3.0-alpha3 重点

- **多目标队列**：一次添加多个文件与文件夹，所有操作按列表顺序逐项执行。
- **Explorer 拖拽添加**：支持从普通权限 Explorer 直接拖多个项目到管理员 GUI；使用 `WM_DROPFILES` + UIPI 消息白名单兼容跨完整性级别拖放。
- **批量状态与取消**：任务执行时锁定列表和冲突操作；“停止当前任务”中止整个批次。
- **Restart Manager 快速定位普通文件锁**：文件目标先通过 Windows Restart Manager 缩小候选 PID，再对候选进程做精确 Handle 匹配；仅在没有候选时回退全局 Handle 扫描。
- **删除输出编码修复**：外部 `cmd.exe` 删除步骤改用 Unicode 输出，避免中文系统错误信息乱码。

## 核心能力

- **分析占用**：分类扫描 CWD、普通文件/目录 Handle、Memory Mapping / IMAGE、SMB Server Open、Filter/Minifilter，并额外执行 DELETE-access probe 与非占用诊断。
- **解除占用**：逐层检测、逐层授权；只有真的发现当前版本可解除的对象时才弹确认。
- **强制删除**：尝试 Win32 `FileDispositionInfoEx` / POSIX semantics、扩展路径删除等方式。
- **幽灵粉碎**：删除优先；删除失败时解除已知占用后立即重删，必要时最多追杀 3 轮。
- **下次启动删除**：登记系统重启后的删除操作。
- **单任务状态机**：防重复点击、并发扫描/删除和消息泵重入。
- **根目录硬保护**：拒绝对盘符根目录和 UNC share 根目录执行破坏性操作。

## 占用模型

| 类别 | 例子 | 当前能力 |
|---|---|---|
| A — CWD | Current Working Directory | 检测 + 经确认关闭句柄 |
| B — File / Directory Handle | 普通 `CreateFile` 句柄 | Restart Manager 候选定位 + 精确 Handle 检测/关闭 |
| C — Memory Mapping / IMAGE | mmap、映射文件、EXE/DLL image | 诊断，不远程 Unmap |
| D — SMB Server Open | 远程客户端打开项 | 诊断，不主动断会话 |
| E — Filter / Minifilter | 杀软、备份、加密等过滤器 | 仅诊断上下文 |
| F — DELETE-access probe | DELETE access 能力探针 | 只读探针 |
| G — 非占用诊断 | 属性、reparse、ACL owner 等 | 区分占用和其他失败原因 |

详细说明见 [docs/OCCUPANCY_MODEL.md](docs/OCCUPANCY_MODEL.md)。

## 结果语义

GhostShredder 不把“没扫到”偷换成“绝对不存在”：

- **发现 N 个**：本次形成正向证据。
- **本次暂未发现**：扫描正常完成但本次没有命中；仅描述当前观测。
- **本次扫描未完成（超时），未形成该类别结论**：扫描没有完成，因此不输出“有/无”。

## 多目标操作

v0.3 起，顶部使用目标列表而非单路径输入框：

- 文件选择器支持多选；
- 文件夹可逐个添加；
- 可手动输入路径；
- 可一次拖入多个文件/文件夹；
- 精确路径自动去重；
- “移除选中 / 清空列表”只修改队列，不删除磁盘内容；
- 功能按钮默认处理**列表中的全部目标**，严格按顺序执行，不并行关闭句柄或删除。

## 使用

双击：

```text
Run-GhostShredder.cmd
```

或：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\GhostShredder.ps1
```

程序需要管理员权限。建议对不熟悉的目标先使用 **分析占用**。

## 已验证回归场景

v0.3.0-alpha3 已在真实 Windows 11 环境中验证：

1. **CWD 空目录锁**：`cmd.exe` 将目标目录作为当前工作目录；GhostShredder 定位并关闭 CWD handle 后立即删除成功。
2. **普通文件 Handle 锁**：文件返回 `ERROR_SHARING_VIOLATION (32)`；Restart Manager 先定位持有进程，随后精确找到并关闭文件 handle，删除成功。
3. **跨权限 Explorer 拖拽**：普通 Explorer → 管理员 GhostShredder，多个文件/目录可加入目标队列。
4. **任务取消与防重入**：运行期间冲突按钮锁定，隔离扫描/外部删除子进程可终止。

## 安全边界

GhostShredder 是用户态工具，不是内核驱动。

- 关闭远程进程的 CWD / 文件句柄可能使对应程序继续存活，但后续相对路径或文件访问异常。
- Memory Mapping / IMAGE 当前只诊断，不通过代码注入远程 Unmap。
- Filter/Minifilter 挂载不等于它正在阻塞目标。
- SMB 当前只诊断，不自动断开远程会话。
- 受保护进程、内核对象、文件系统内部状态等仍可能超出当前覆盖范围。
- “强制删除 / 幽灵粉碎”不可逆，不经过回收站。

## 测试

`tests/` 包含可复现的 CWD、普通 Handle 与 Memory Mapping 场景。

## License

[MIT](LICENSE)
