# GhostShredder v0.3.0-alpha3

这是 v0.3 多目标架构的首个公开预览节点。

## 新增

- 多文件 / 多文件夹目标队列。
- 文件选择器多选、手动路径添加、路径去重、移除选中、清空列表。
- 普通 Explorer 向管理员 GhostShredder 的跨权限拖拽支持。
- 批量顺序执行、逐项状态、停止整个批次。
- 文件目标的 Restart Manager 快速候选 PID 定位。
- 普通 File Handle 定向扫描，降低全局句柄名称解析卡死概率。
- `cmd.exe` 删除错误输出 Unicode 化，修复中文乱码。

## 真机验证

在 Windows 11 x64 上已验证：

- 目录被 `cmd.exe` 作为 CWD 持有：识别 CWD handle → 关闭 → 删除成功。
- 普通文件被进程以不共享删除的 File Handle 打开，返回 `ERROR_SHARING_VIOLATION (32)`：Restart Manager 定位进程 → 精确 Handle 命中 → 关闭 → 删除成功。
- 普通权限 Explorer → 管理员 GhostShredder 拖拽文件/目录成功。

## Alpha 边界

- Mapping / IMAGE 仍只诊断，不远程 Unmap。
- SMB / Filter 仍以诊断为主。
- Restart Manager 是定位加速层，不是“无候选 = 无占用”的证明。
- 全局 Handle/Mapping fallback 在特殊系统对象环境中仍可能超时。

建议继续提交可重复的真实“删不掉”案例。
