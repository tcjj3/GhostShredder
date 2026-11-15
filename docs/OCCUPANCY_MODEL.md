# GhostShredder Occupancy Model

GhostShredder 不把 Windows 上所有“无法删除”都视为同一种锁。当前工程模型分为 A–G 七类。

> 这是 GhostShredder 的工程分类，不是 Windows 内核官方穷举枚举。

## A — Current Working Directory (CWD)

进程把目录设置为当前工作目录时，会持有与该目录相关的状态/句柄。目录可能为空，但仍无法删除或重命名。

GhostShredder 通过读取进程 PEB 中的 CurrentDirectory 信息定位这类占用，并可在用户确认后关闭对应远程句柄。

### 注意

关闭 CWD handle 并不等于让目标进程自动切换到新的工作目录。进程可能继续存活，但相对路径操作随后出现句柄无效等异常。

## B — File / Directory Handle

普通文件或目录可以由 `CreateFile` 等 API 打开。如果打开方没有共享 `FILE_SHARE_DELETE`，后续删除/重命名可能产生 sharing violation。

GhostShredder 在隔离子进程中枚举系统 Handle 并做路径匹配；发现精确命中后，经用户确认可关闭远程句柄。

全局 Handle 名称解析在部分系统/过滤驱动环境中可能非常慢，因此扫描有超时边界。超时只表示“本次扫描未完成”。

## C — Memory Mapping / IMAGE

文件可以被映射进进程地址空间。即使普通 File handle 已关闭，mapped view / executable image 仍可能影响删除行为。

GhostShredder 使用 `VirtualQueryEx` + `GetMappedFileName` 诊断 `MEM_MAPPED` / `MEM_IMAGE` 区域。

当前版本**不会**通过远程线程、代码注入等方式强制 `UnmapViewOfFile`，因此该类别只诊断。

## D — SMB Server Open

当本机作为 SMB Server 时，远程客户端可能保持目标文件打开。此时本机普通进程 Handle 扫描并不能完整表达远端会话状态。

当前版本查询 SMB Server open items，但不主动断开远端会话。

## E — Filter / Minifilter

杀毒、备份、同步、加密、DLP 等软件可能以文件系统 Filter/Minifilter 形式工作。

GhostShredder 只把目标卷上挂载的 Filter 当作**诊断上下文**：

- 挂载 ≠ 正在占用目标；
- 没有额外 ETW/内核调试/驱动证据时，不应把某个 Filter 直接归因为阻塞者。

## F — DELETE-access probe

这是一个只读性质的能力探针：测试是否能够对目标取得 DELETE access，不执行删除。

它可以帮助区分 sharing violation、access denied 等失败类型，但不是完整占用扫描器。

## G — Non-occupancy diagnostics

一些“删不掉”根本不是占用，例如：

- ACL / owner；
- readonly / system / hidden 属性；
- reparse point；
- 路径与文件系统特殊状态；
- 文件系统损坏或驱动私有状态。

因此 GhostShredder 始终区分：

```text
Occupancy / Lock  !=  Deletion Failure
```

## 三态观测语义

每个扫描类别只能产生以下语义之一：

1. **发现 N 个** — 本次有正向证据；
2. **本次暂未发现** — 扫描完成且本次未命中，仅代表当前观测；
3. **本次扫描未完成，未形成该类别结论** — 例如超时，因此不输出“有/无”。

禁止从单一类别的“暂未发现”推导“系统没有其他占用”。

## 解除与粉碎不是同一个目标函数

### 解除占用

逐层检测、逐层授权，只修改明确发现且当前版本支持解除的对象。没有可解除对象时不弹确认、不做修改。

### 幽灵粉碎

以“目标删除成功”为终止条件：

1. 先尝试删除；
2. 失败才解除已知占用；
3. 占用一解除立即重删；
4. 仍失败才继续下一轮检测/解除；
5. 最多进行有限轮次追杀，避免无限循环。
