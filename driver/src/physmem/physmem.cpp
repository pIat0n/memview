#include "physmem.hpp"
#include "../nt/process.hpp"

namespace memview {
namespace {

// MmMapIoSpaceEx doesn't check this itself - without it, a write could land
// on MMIO/reserved space and bugcheck.
bool IsInsideInstalledRam(ULONGLONG addr, SIZE_T size)
{
    const PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges)
        return false;

    bool inRange = false;
    for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0; ++i)
    {
        const ULONGLONG base = static_cast<ULONGLONG>(ranges[i].BaseAddress.QuadPart);
        const ULONGLONG len  = static_cast<ULONGLONG>(ranges[i].NumberOfBytes.QuadPart);
        if (addr >= base && size <= len && addr - base <= len - size)
        {
            inRange = true;
            break;
        }
    }

    ExFreePool(ranges);
    return inRange;
}

} // namespace

NTSTATUS ReadPhysicalMemory(PVOID physAddr, PVOID out, SIZE_T size, PSIZE_T copied)
{
    MM_COPY_ADDRESS src{};
    src.PhysicalAddress.QuadPart = reinterpret_cast<LONGLONG>(physAddr);
    return MmCopyMemory(out, src, size, MM_COPY_MEMORY_PHYSICAL, copied);
}

NTSTATUS WritePhysicalMemory(PVOID physAddr, PVOID in, SIZE_T size, PSIZE_T copied)
{
    *copied = 0;

    const ULONGLONG addr = reinterpret_cast<ULONGLONG>(physAddr);
    if (!IsInsideInstalledRam(addr, size))
        return STATUS_ACCESS_DENIED;

    PHYSICAL_ADDRESS pa{};
    pa.QuadPart = static_cast<LONGLONG>(addr);

    const PVOID mapped = MmMapIoSpaceEx(pa, size, PAGE_READWRITE);
    if (!mapped)
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(mapped, in, size);
    MmUnmapIoSpace(mapped, size);

    *copied = size;
    return STATUS_SUCCESS;
}

ULONG GetPhysicalRanges(MEMVIEW_PHYSICAL_RANGE* out, ULONG maxCount)
{
    if (maxCount == 0)
        return 0;

    const PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges)
        return 0;

    ULONG count = 0;
    for (ULONG i = 0; ranges[i].NumberOfBytes.QuadPart != 0 && count < maxCount; ++i)
    {
        out[count].base = static_cast<ULONGLONG>(ranges[i].BaseAddress.QuadPart);
        out[count].size = static_cast<ULONGLONG>(ranges[i].NumberOfBytes.QuadPart);
        ++count;
    }

    ExFreePool(ranges);
    return count;
}

NTSTATUS VirtualToPhysical(HANDLE pid, PVOID va, PULONGLONG outPa)
{
    *outPa = 0;

    ProcessRef target(pid);
    if (!NT_SUCCESS(target.status()))
        return target.status();

    PHYSICAL_ADDRESS pa{};
    {
        ProcessAttach attach(target.get());
        pa = MmGetPhysicalAddress(va);
    }

    *outPa = static_cast<ULONGLONG>(pa.QuadPart);
    return STATUS_SUCCESS;
}

} // namespace memview
