#include "memory.hpp"
#include "../nt/process.hpp"
#include "../nt/structs.hpp"

namespace memview {
namespace {

constexpr SIZE_T kPebLdrOffset64 = 0x18;
constexpr SIZE_T kPebLdrOffset32 = 0x0C;

bool ReadRemote(PEPROCESS process, PVOID address, PVOID out, SIZE_T size)
{
    SIZE_T copied = 0;
    return NT_SUCCESS(MmCopyVirtualMemory(process, address, PsGetCurrentProcess(),
        out, size, KernelMode, &copied)) && copied == size;
}

ULONG ListModulesNative(PEPROCESS process, PPEB peb, MEMVIEW_MODULE_INFO* out, ULONG maxCount)
{
    PVOID ldrPtr = nullptr;
    if (!ReadRemote(process, reinterpret_cast<PUCHAR>(peb) + kPebLdrOffset64, &ldrPtr, sizeof(ldrPtr)) || !ldrPtr)
        return 0;

    PEB_LDR_DATA64 ldrData{};
    if (!ReadRemote(process, ldrPtr, &ldrData, sizeof(ldrData)))
        return 0;

    const PUCHAR headAddr = reinterpret_cast<PUCHAR>(ldrPtr) + FIELD_OFFSET(PEB_LDR_DATA64, InMemoryOrderModuleList);
    PUCHAR       current  = reinterpret_cast<PUCHAR>(ldrData.InMemoryOrderModuleList.Flink);

    ULONG count = 0;
    while (current != headAddr && count < maxCount)
    {
        PUCHAR entryBase = current - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

        LDR_DATA_TABLE_ENTRY64 entry{};
        if (!ReadRemote(process, entryBase, &entry, sizeof(entry)))
            break;

        MEMVIEW_MODULE_INFO& mod = out[count];
        mod.base = reinterpret_cast<ULONGLONG>(entry.DllBase);
        mod.size = entry.SizeOfImage;
        RtlZeroMemory(mod.path, sizeof(mod.path));

        const USHORT lenBytes = (entry.FullDllName.Length < sizeof(mod.path) - sizeof(wchar_t))
            ? entry.FullDllName.Length : static_cast<USHORT>(sizeof(mod.path) - sizeof(wchar_t));
        if (lenBytes && entry.FullDllName.Buffer)
            ReadRemote(process, entry.FullDllName.Buffer, mod.path, lenBytes);

        ++count;
        current = reinterpret_cast<PUCHAR>(entry.InMemoryOrderLinks.Flink);
    }
    return count;
}

ULONG ListModulesWow64(PEPROCESS process, PVOID wow64Peb, MEMVIEW_MODULE_INFO* out, ULONG maxCount)
{
    ULONG ldrPtr = 0;
    if (!ReadRemote(process, reinterpret_cast<PUCHAR>(wow64Peb) + kPebLdrOffset32, &ldrPtr, sizeof(ldrPtr)) || !ldrPtr)
        return 0;

    PEB_LDR_DATA32 ldrData{};
    if (!ReadRemote(process, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(ldrPtr)), &ldrData, sizeof(ldrData)))
        return 0;

    const ULONG headAddr = ldrPtr + FIELD_OFFSET(PEB_LDR_DATA32, InMemoryOrderModuleList);
    ULONG       current  = ldrData.InMemoryOrderModuleList.Flink;

    ULONG count = 0;
    while (current != headAddr && count < maxCount)
    {
        const ULONG entryBase = current - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

        LDR_DATA_TABLE_ENTRY32 entry{};
        if (!ReadRemote(process, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(entryBase)), &entry, sizeof(entry)))
            break;

        MEMVIEW_MODULE_INFO& mod = out[count];
        mod.base = entry.DllBase;
        mod.size = entry.SizeOfImage;
        RtlZeroMemory(mod.path, sizeof(mod.path));

        const USHORT lenBytes = (entry.FullDllName.Length < sizeof(mod.path) - sizeof(wchar_t))
            ? entry.FullDllName.Length : static_cast<USHORT>(sizeof(mod.path) - sizeof(wchar_t));
        if (lenBytes && entry.FullDllName.Buffer)
            ReadRemote(process, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(entry.FullDllName.Buffer)), mod.path, lenBytes);

        ++count;
        current = entry.InMemoryOrderLinks.Flink;
    }
    return count;
}

} // namespace

NTSTATUS ReadProcessMemory(HANDLE pid, PVOID address, PVOID out, SIZE_T size, PSIZE_T copied)
{
    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return target.status();

    return MmCopyVirtualMemory(target.get(), address, PsGetCurrentProcess(), out,
                                size, KernelMode, copied);
}

NTSTATUS WriteProcessMemory(HANDLE pid, PVOID address, PVOID in, SIZE_T size, PSIZE_T copied)
{
    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return target.status();

    return MmCopyVirtualMemory(PsGetCurrentProcess(), in, target.get(), address,
                                size, KernelMode, copied);
}

NTSTATUS QueryProcess(HANDLE pid, MEMVIEW_PROCESS_INFO& out)
{
    out.isWow64 = FALSE;

    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return target.status();

    out.isWow64 = PsGetProcessWow64Process(target.get()) != nullptr;
    return STATUS_SUCCESS;
}

ULONG ListModules(HANDLE pid, MEMVIEW_MODULE_INFO* out, ULONG maxCount)
{
    if (maxCount == 0)
        return 0;

    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return 0;

    if (PVOID wow64Peb = PsGetProcessWow64Process(target.get()))
        return ListModulesWow64(target.get(), wow64Peb, out, maxCount);

    PPEB peb = PsGetProcessPeb(target.get());
    if (!peb)
        return 0;
    return ListModulesNative(target.get(), peb, out, maxCount);
}

NTSTATUS QueryRegion(HANDLE pid, PVOID address, MEMVIEW_REGION_INFO& out)
{
    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return target.status();

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T returned = 0;
    NTSTATUS status;
    {
        ProcessAttach attach(target.get());
        status = ZwQueryVirtualMemory(ZwCurrentProcess(), address,
            MemoryBasicInformation, &mbi, sizeof(mbi), &returned);
    }
    if (!NT_SUCCESS(status))
        return status;

    out.base    = reinterpret_cast<ULONGLONG>(mbi.BaseAddress);
    out.size    = mbi.RegionSize;
    out.protect = mbi.Protect;
    out.type    = mbi.Type;
    out.state   = mbi.State;
    return STATUS_SUCCESS;
}

NTSTATUS ProtectMemory(HANDLE pid, PVOID address, SIZE_T size, ULONG newProtect, ULONG& oldProtect)
{
    oldProtect = 0;

    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return target.status();

    PVOID  base       = address;
    SIZE_T regionSize = size;
    ProcessAttach attach(target.get());
    return ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &regionSize, newProtect, &oldProtect);
}

} // namespace memview
