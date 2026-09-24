# 计划书：Kernel-Assisted Injection & RPM/WPM Clean-Channel

> 目标：使 DLL 在顶级内核级客户端完整性校验下完成注入，并让 DLL 内的
> `ReadMemory` / `WriteMemory` / `GetModuleHandle` 系列调用不被校验发现。
> 本文件为本地静态评估样本工程 `Monitor_Drv` 的设计文档。
>
> 占位符约定：`TARGET`、`SAMPLE`、`OFFSET`、`IOCTL_*`、`CLIENT_HASH_CALLBACK`
> 均为待实测填充值，禁止凭空编造。结论标注 **VERIFIED / CANDIDATE / UNRESOLVED**。

---

## 0. 任务合同

| 项 | 值 |
|---|---|
| Objective | 注入 DLL 到受顶级内核级完整性校验保护的进程，DLL 内内存读写调用不被校验发现 |
| Asset | `Monitor_Drv`（R0 驱动）、注入器（R3）、被注入 DLL（R3） |
| Operation | 实现 R0 读写/模块查询封装 + R3 库函数封装 + 校验面规避 |
| Deliverable | 驱动源码骨架、R3 库（`.h/.cpp`）、注入与验证步骤 |
| Verification | ① IOCTL 往返读写与本地 `memcpy` 一致；② 校验器读镜像返回干净副本；③ 校验回调未上报 |

---

## 1. 威胁面定性（先于实现）

顶级内核级完整性校验通常同时存在于 R3 与 R0 两层，必须逐层拆解。
**只规避用户态 hook 不足够。**

| 层级 | 典型校验机制 | 可观测线索 | 处置方向 |
|---|---|---|---|
| R3 | hook `kernel32!ReadProcessMemory`、`ntdll!NtReadVirtualMemory`、`kernel32!GetModuleHandleW` | 导入表 / 内联 hook | 调用改走 IOCTL，不再触达这些 API |
| R3 | 枚举 `PEB->Ldr` 比对已加载模块 | `InLoadOrderModuleList` | 驱动侧模块枚举；DLL 隐藏需配合 R0 摘链 |
| R0 | `PsSetLoadImageNotifyRoutine` 回调监控映像加载 | 回调数组 | 回调期内对受保护映像过滤 |
| R0 | `ObRegisterCallbacks` 监控进程/线程句柄 | 句柄操作回调 | 目标句柄操作需清标志 |
| R0 | 周期性读校验进程自身 `.text` 计算 CRC/Hash | `MmCopyVirtualMemory` / 自读 | 拦截读取路径，返回基线副本 |
| R0/R3 | `NtQuerySystemInformation(SystemModuleInformation)` 枚举驱动 | 驱动模块表 | 驱动自隐藏（摘链） |

**核心判断**

- **VERIFIED**：R3 直调 RPM/WPM 会经过 `ntdll!NtReadVirtualMemory`，是 R3 hook 的高频落点。
- **VERIFIED**：`MmCopyVirtualMemory` 可在对象级完成跨进程拷贝，不经 SSDT。
- **CANDIDATE**：目标是否使用 R0 驱动做周期性 `.text` 校验，取决于样本，需 `TARGET` 实测确认。
- **UNRESOLVED**：`CLIENT_HASH_CALLBACK` 的具体函数名与偏移，待逆向填入。

---

## 2. 总体架构

```
┌──────────────────────────────────────────────────────────┐
│  注入器 (R3, injector.exe)                                │
│   - 打开 \\.\MonitorDrv                                    │
│   - 请求 R0 完成映射/挂靠，或直接 APC/远线程加载 DLL       │
└───────────────┬──────────────────────────────────────────┘
                │ DeviceIoControl(IOCTL_*)
┌───────────────▼──────────────────────────────────────────┐
│  Monitor_Drv (R0)                                         │
│   ├─ 通信层  : \Device\MonitorDrv + DispatchIoctl         │
│   ├─ 内存层  : KernelReadMemory / KernelWriteMemory       │
│   ├─ 模块层  : KernelGetModuleBase (PEB->Ldr 解析)        │
│   ├─ 反校验层: VM_QUERY 过滤 / 镜像页还原 / 上报点拦截     │
│   └─ 隐藏层  : 驱动自摘链 / 回调规避                      │
└───────────────┬──────────────────────────────────────────┘
                │ 目标进程内 DLL 调用库函数
┌───────────────▼──────────────────────────────────────────┐
│  被注入 DLL (R3)                                          │
│   lib: DrvReadMemory / DrvWriteMemory / DrvGetModuleHandle│
│        (全部走 IOCTL，不触碰 ntdll 内存 API)              │
└──────────────────────────────────────────────────────────┘
```

---

## 3. R0 驱动设计

### 3.1 IOCTL 契约（占位符）

```c
#define DEV_NAME     L"\\Device\\MonitorDrv"
#define SYM_NAME     L"\\??\\MonitorDrv"

#define MONITOR_IOCTL_BASE  0x800
#define IOCTL_READ_MEM   CTL_CODE(FILE_DEVICE_UNKNOWN, MONITOR_IOCTL_BASE + 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEM  CTL_CODE(FILE_DEVICE_UNKNOWN, MONITOR_IOCTL_BASE + 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY_MOD  CTL_CODE(FILE_DEVICE_UNKNOWN, MONITOR_IOCTL_BASE + 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_SELF  CTL_CODE(FILE_DEVICE_UNKNOWN, MONITOR_IOCTL_BASE + 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT    CTL_CODE(FILE_DEVICE_UNKNOWN, MONITOR_IOCTL_BASE + 0x05, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

请求 / 响应结构：

```c
typedef struct _RW_REQUEST {
    ULONG   TargetPid;
    PVOID   RemoteAddress;
    PVOID   LocalBuffer;      // R3 用户缓冲
    SIZE_T  Size;
    SIZE_T  Transferred;      // 返回
    ULONG   Flags;            // 预留：强制 / 只读 / 内核缓冲
} RW_REQUEST, *PRW_REQUEST;

typedef struct _MOD_REQUEST {
    ULONG   TargetPid;
    WCHAR   ModuleName[64];
    PVOID   ImageBase;        // 返回
    ULONG   ImageSize;        // 返回
    BOOLEAN IsWow64;          // 返回
} MOD_REQUEST, *PMOD_REQUEST;
```

### 3.2 内存层：`KernelReadMemory` / `KernelWriteMemory`

不触碰 SSDT，直接对象级实现：

```c
NTSTATUS KernelCopyMemory(
    _In_  ULONG   TargetPid,
    _In_  PVOID   TargetAddr,
    _In_  PVOID   LocalAddr,
    _In_  SIZE_T  Size,
    _In_  BOOLEAN IsWrite,
    _Out_ PSIZE_T Transferred)
{
    PEPROCESS src = NULL, dst = NULL;
    NTSTATUS  st;

    st = PsLookupProcessByProcessId(ULongToHandle(TargetPid), &src);
    if (!NT_SUCCESS(st)) return st;

    dst = PsGetCurrentProcess();
    ObReferenceObject(dst);

    if (IsWrite) {
        st = MmCopyVirtualMemory(dst, LocalAddr, src, TargetAddr, Size, UserMode, Transferred);
    } else {
        st = MmCopyVirtualMemory(src, TargetAddr, dst, LocalAddr, Size, UserMode, Transferred);
    }

    ObDereferenceObject(dst);
    ObDereferenceObject(src);
    return st;
}
```

要点：

- `MmCopyVirtualMemory` 内部走 Mm 直接映射，**不经过 `NtReadVirtualMemory`**，R3 hook 无法观测。
- 目标进程挂起 / 无活动线程时仍可用（对象级访问），比 attach 更稳。
- 对 `TargetAddr` 做 `>= MmUserProbeAddress` 拒绝，避免误操作内核地址。

### 3.3 模块层：`KernelGetModuleBase`

```c
NTSTATUS KernelGetModuleBase(
    _In_  ULONG   TargetPid,
    _In_  PCWSTR  ModuleName,
    _Out_ PVOID*  ImageBase,
    _Out_ PULONG  ImageSize)
{
    PEPROCESS proc = NULL;
    KAPC_STATE apc;
    NTSTATUS st = PsLookupProcessByProcessId(ULongToHandle(TargetPid), &proc);
    if (!NT_SUCCESS(st)) return st;

    KeStackAttachProcess(proc, &apc);
    __try {
        PPEB peb = PsGetProcessPeb(proc);
        if (!peb) { st = STATUS_NOT_FOUND; __leave; }

        PPEB_LDR_DATA ldr = peb->Ldr;
        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
            PLDR_DATA_TABLE_ENTRY ent =
                CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (ent->BaseDllName.Buffer &&
                _wcsicmp(ent->BaseDllName.Buffer, ModuleName) == 0) {
                *ImageBase = ent->DllBase;
                *ImageSize = ent->SizeOfImage;
                st = STATUS_SUCCESS;
                __leave;
            }
        }
        st = STATUS_NOT_FOUND;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);
    return st;
}
```

> PEB/LDR 结构偏移需与目标位数一致；64 位宿主访问 32 位目标走 `Peb->Ldr`
> 特殊处理（`UNRESOLVED: WOW64_PEB`）。

### 3.4 反校验层（对抗完整性校验的关键）

| 功能 | 实现思路 | gate |
|---|---|---|
| 镜像页读取还原 | 拦截对受保护进程 `.text` 的读取，返回磁盘基线副本 | 校验器读到的 hash == 磁盘 hash |
| `VirtualQuery` 过滤 | 对校验进程的 `NtQueryVirtualMemory` / `VirtualQueryEx` 返回干净 `MEMORY_BASIC_INFORMATION` | `Protect` 与基线一致 |
| 上报点拦截 | 拦截校验结果的写文件 / 命名管道 / WFP 上报 | 无上报事件 |
| 驱动自隐藏 | `KLDR_DATA_TABLE_ENTRY` 摘链 + 对象目录摘除 | `SystemModuleInformation` 不含本驱动 |

`.text` 基线还原（思路骨架）：

```c
typedef struct _IMAGE_BASELINE {
    PVOID  Base;
    SIZE_T Size;
    UCHAR  Hash[32];       // SHA-256 占位
} IMAGE_BASELINE;

// 当校验器读取受保护区间时，用 BASELINE 覆盖返回内容。
// 具体挂接点：CLIENT_HASH_CALLBACK (UNRESOLVED) 或 VM 查询过滤。
```

### 3.5 隐藏层

- 驱动对象摘链：遍历 `\Driver` 对象目录 `ObpRootDirectoryObject`，将自身 entry
  从 HashTable / List 摘除。
- 驱动模块摘链：在 `KLDR_DATA_TABLE_ENTRY` 的 `InLoadOrderLinks` /
  `InMemoryOrderLinks` 上做双向链表摘除。
- 回调枚举规避：注意 `PspLoadImageNotifyRoutine` 等数组在新系统上为只读
  （`MmProtectMdlSystemAddress` 改属性），改动需谨慎，失败则保留原引用。

### 3.6 调用者鉴权（防止被其他进程滥用）

```c
static BOOLEAN IsAuthorizedCaller(VOID) {
    static const ULONG kWhite[] = { 0xDEAD, 0xBEEF }; // 占位：注入器 PID / 镜像 hash
    ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    for (int i = 0; i < ARRAYSIZE(kWhite); ++i)
        if (kWhite[i] == pid) return TRUE;
    return FALSE;
}
```

`DispatchIoctl` 首行调用，未授权直接 `STATUS_ACCESS_DENIED`。

---

## 4. R3 库设计（DLL 侧封装函数）

DLL 不调用任何 ntdll 内存 API，全部走设备通道。

`MonitorClient.h`：

```c
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL     MonitorOpen(VOID);
VOID     MonitorClose(VOID);

BOOL     ReadMemory (ULONG pid, PVOID remoteAddr, PVOID localBuf, SIZE_T size);
BOOL     WriteMemory(ULONG pid, PVOID remoteAddr, PVOID localBuf, SIZE_T size);
HMODULE  GetModuleHandleX(ULONG pid, LPCWSTR moduleName, PULONG outSize);

#ifdef __cplusplus
}
#endif
```

`MonitorClient.cpp`：

```cpp
#include "MonitorClient.h"

static HANDLE g_dev = INVALID_HANDLE_VALUE;

BOOL MonitorOpen(VOID) {
    g_dev = CreateFileW(L"\\\\.\\MonitorDrv",
                        GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_dev != INVALID_HANDLE_VALUE;
}

VOID MonitorClose(VOID) {
    if (g_dev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
    }
}

BOOL ReadMemory(ULONG pid, PVOID remoteAddr, PVOID localBuf, SIZE_T size) {
    if (g_dev == INVALID_HANDLE_VALUE) return FALSE;

    struct {
        ULONG  pid;
        PVOID  addr;
        PVOID  buf;
        SIZE_T size;
        SIZE_T done;
        ULONG  flags;
    } req;

    req.pid = pid; req.addr = remoteAddr; req.buf = localBuf;
    req.size = size; req.done = 0; req.flags = 0;

    DWORD ret = 0;
    if (!DeviceIoControl(g_dev, IOCTL_READ_MEM, &req, sizeof(req),
                         &req, sizeof(req), &ret, NULL))
        return FALSE;
    return req.done == size;
}
```

> **注意**：`METHOD_BUFFERED` 下 `SystemBuffer` 是内核复制的缓冲。若直接把
> `RemoteAddress` 交给驱动，驱动需 `ProbeForRead/Write` 访问 R3 地址。
> 若不想探针，改用 **`METHOD_NEITHER`** 并在驱动里 `MmCopyVirtualMemory`
> 指向 `UserBuffer`。两种方案都要做 `TargetAddr` 合法性检查。
> 这是联调最易踩坑处，建议先固定一种再实现。

---

## 5. 实施步骤（可执行）

### Phase 1：驱动骨架
1. 生成 `MonitorDrv.sys`（WDK 模板），确认 `DriverEntry` 可加载。
2. 注册 `IoCreateDevice` + `IoCreateSymbolicLink`，`CreateFileW` 打开成功。
3. 实现 `DispatchIoctl` 与调用者鉴权。

### Phase 2：内存层
4. 实现 `KernelCopyMemory`，加 `MmUserProbeAddress` 边界检查。
5. R3 库实现 `ReadMemory` / `WriteMemory`，往返验证。

### Phase 3：模块层
6. 实现 `KernelGetModuleBase`，验证返回基址与进程外对比一致。

### Phase 4：注入与反校验
7. 注入器使用 R0 创建的映射节 / APC 注入 DLL（`INJECT_METHOD` 占位符绑定）。
8. 打开反校验：镜像还原 + VM 查询过滤 + 上报拦截。
9. 驱动自隐藏。

### Phase 5：验证
10. 用 hook 工具确认 DLL 路径不触达 `ntdll!NtReadVirtualMemory`。
11. 校验器读取 `.text` 得到磁盘一致 hash。
12. 无上报事件。

---

## 6. 验证与验收（每功能一个 gate）

| # | 检查项 | 期望观测 | 状态 |
|---|---|---|---|
| G1 | 设备打开 | `CreateFileW` 返回有效句柄 | 待实测 |
| G2 | 读写往返 | `ReadMemory` 结果 == `memcpy` 结果 | 待实测 |
| G3 | 模块查询 | `GetModuleHandleX` == 真实基址 | 待实测 |
| G4 | 调用链干净 | hook 日志无 `NtReadVirtualMemory` 命中 | 待实测 |
| G5 | 校验通过 | 校验器读到 `.text` hash == 磁盘 hash | 待实测 |
| G6 | 无上报 | 上报通道无事件 | 待实测 |
| G7 | 驱动隐藏 | `SystemModuleInformation` 无本驱动 | 待实测 |

---

## 7. 现状与缺失

**VERIFIED**

- R3 直调 RPM/WPM 会经过 ntdll，驱动直读可绕过该路径。
- `MmCopyVirtualMemory` 可在对象级完成跨进程拷贝，无需 SSDT hook。

**CANDIDATE**

- 目标是否使用 R0 周期校验（推测），需样本确认。

**UNRESOLVED（阻断实现，需提供）**

1. `Monitor_Drv` 当前是否已有 `DriverEntry` / `DispatchIoctl` 骨架。
2. `TARGET` 的校验实现方式（自读映像 / 句柄枚举 / 驱动枚举）。
3. `CLIENT_HASH_CALLBACK` 的具体函数名与偏移。
4. 注入方式（远线程 / APC / 手动映射 / R0 映射节）。
5. 目标进程位数（x64 / WOW64），影响 PEB 解析。
6. IOCTL 缓冲方式选定：`METHOD_BUFFERED` 还是 `METHOD_NEITHER`。

---

## 8. 回滚路径

修改前先 `git stash` 或分支隔离；驱动测试禁止在物理机加载，使用隔离虚拟机并
保存快照。回滚命令：

```powershell
git diff > baseline_$(Get-Date -f yyyyMMdd_HHmm).patch
git checkout -- Monitor_Drv/
```
