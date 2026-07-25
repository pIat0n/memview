#include "dispatch.hpp"

#include "ioctl.hpp"
#include "../memory/memory.hpp"

namespace memview {

NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP irp)
{
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP irp)
{
    const PIO_STACK_LOCATION stack  = IoGetCurrentIrpStackLocation(irp);
    const ULONG code   = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    PVOID    sysBuf = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    SIZE_T   copied = 0;

    const auto complete = [&]() -> NTSTATUS
    {
        irp->IoStatus.Status      = status;
        irp->IoStatus.Information = copied;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    };

    if (sysBuf == nullptr)
    {
        status = STATUS_INVALID_PARAMETER;
        return complete();
    }

    switch (code)
    {
    case MEMVIEW_IOCTL_READ:
    case MEMVIEW_IOCTL_WRITE:
    {
        if (inLen < sizeof(MEMVIEW_REQUEST))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const MEMVIEW_REQUEST req = *static_cast<MEMVIEW_REQUEST*>(sysBuf);
        if (req.size == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (code == MEMVIEW_IOCTL_READ)
        {
            // Output buffer must hold the whole requested read.
            if (outLen < req.size)
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            status = ReadProcessMemory(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req.pid)),
                                  reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(req.address)),
                                  sysBuf, static_cast<SIZE_T>(req.size), &copied);
        }
        else
        {
            // Input holds the header followed by `size` payload bytes.
            if (inLen < sizeof(MEMVIEW_REQUEST) + req.size)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = WriteProcessMemory(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req.pid)),
                                   reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(req.address)),
                                   static_cast<PUCHAR>(sysBuf) + sizeof(MEMVIEW_REQUEST),
                                   static_cast<SIZE_T>(req.size), &copied);
        }

        // A short copy is a failure to the caller, but report what did move.
        if (NT_SUCCESS(status) && copied != req.size)
            status = STATUS_PARTIAL_COPY;
        break;
    }

    case MEMVIEW_IOCTL_QUERY_PROCESS:
    {
        if (inLen < sizeof(MEMVIEW_PID_REQUEST) || outLen < sizeof(MEMVIEW_PROCESS_INFO))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const MEMVIEW_PID_REQUEST req = *static_cast<MEMVIEW_PID_REQUEST*>(sysBuf);

        MEMVIEW_PROCESS_INFO info{};
        status = QueryProcess(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req.pid)), info);
        if (NT_SUCCESS(status))
        {
            *static_cast<MEMVIEW_PROCESS_INFO*>(sysBuf) = info;
            copied = sizeof(info);
        }
        break;
    }

    case MEMVIEW_IOCTL_LIST_MODULES:
    {
        if (inLen < sizeof(MEMVIEW_PID_REQUEST))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const MEMVIEW_PID_REQUEST req = *static_cast<MEMVIEW_PID_REQUEST*>(sysBuf);

        const ULONG maxOut = outLen / sizeof(MEMVIEW_MODULE_INFO);
        const ULONG cap    = maxOut < MEMVIEW_MAX_MODULES ? maxOut : MEMVIEW_MAX_MODULES;
        const ULONG count  = ListModules(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req.pid)),
                                          static_cast<MEMVIEW_MODULE_INFO*>(sysBuf), cap);
        copied = static_cast<SIZE_T>(count) * sizeof(MEMVIEW_MODULE_INFO);
        status = STATUS_SUCCESS;
        break;
    }

    case MEMVIEW_IOCTL_QUERY_REGION:
    {
        if (inLen < sizeof(MEMVIEW_QUERY_REGION_REQUEST) || outLen < sizeof(MEMVIEW_REGION_INFO))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const MEMVIEW_QUERY_REGION_REQUEST req = *static_cast<MEMVIEW_QUERY_REGION_REQUEST*>(sysBuf);

        MEMVIEW_REGION_INFO info{};
        status = QueryRegion(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req.pid)),
                              reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(req.address)), info);
        if (NT_SUCCESS(status))
        {
            *static_cast<MEMVIEW_REGION_INFO*>(sysBuf) = info;
            copied = sizeof(info);
        }
        break;
    }

    case MEMVIEW_IOCTL_PROTECT:
    {
        if (inLen < sizeof(MEMVIEW_PROTECT_REQUEST) || outLen < sizeof(MEMVIEW_PROTECT_RESPONSE))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        const MEMVIEW_PROTECT_REQUEST req = *static_cast<MEMVIEW_PROTECT_REQUEST*>(sysBuf);
        if (req.size == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONG oldProtect = 0;
        status = ProtectMemory(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(req.pid)),
                                reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(req.address)),
                                static_cast<SIZE_T>(req.size), req.newProtect, oldProtect);
        if (NT_SUCCESS(status))
        {
            const MEMVIEW_PROTECT_RESPONSE resp{ oldProtect };
            *static_cast<MEMVIEW_PROTECT_RESPONSE*>(sysBuf) = resp;
            copied = sizeof(resp);
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return complete();
}

} // namespace memview
