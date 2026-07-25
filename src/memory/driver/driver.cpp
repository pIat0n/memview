#include "memory/driver/driver.hpp"

#include <windows.h>
#include <winioctl.h>
#include <vector>

#include "ioctl/ioctl.hpp"
#include "memory/memory.hpp"

namespace mem::driver {
namespace {

// The open handle to \\.\MemView, or INVALID_HANDLE_VALUE when the driver isn't up.
HANDLE g_device = INVALID_HANDLE_VALUE;

// memview.sys ships next to memview.exe, so derive the SCM binary path from our own.
std::wstring driverSysPath()
{
    wchar_t exe[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};

    std::wstring p(exe, n);
    const size_t slash = p.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return {};
    return p.substr(0, slash + 1) + L"memview.sys";
}

// Returns bytes transferred (0 on any failure, so a denied read looks like a short one).
size_t drvRead(DWORD pid, uintptr_t addr, void* buf, size_t n)
{
    if (g_device == INVALID_HANDLE_VALUE || n == 0)
        return 0;

    MEMVIEW_REQUEST req{ pid, (unsigned long long)addr, (unsigned long long)n };
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_READ, &req, sizeof(req),
                         buf, (DWORD)n, &returned, nullptr))
        return 0;
    return returned;
}

// Header + payload go in one input buffer; the driver only reports success on a full copy.
size_t drvWrite(DWORD pid, uintptr_t addr, const void* buf, size_t n)
{
    if (g_device == INVALID_HANDLE_VALUE || n == 0)
        return 0;

    std::vector<uint8_t> in(sizeof(MEMVIEW_REQUEST) + n);
    MEMVIEW_REQUEST req{ pid, (unsigned long long)addr, (unsigned long long)n };
    memcpy(in.data(), &req, sizeof(req));
    memcpy(in.data() + sizeof(req), buf, n);

    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_WRITE, in.data(), (DWORD)in.size(),
                         nullptr, 0, &returned, nullptr))
        return 0;
    return n;
}

bool drvIsWow64(DWORD pid)
{
    if (g_device == INVALID_HANDLE_VALUE)
        return false;

    MEMVIEW_PID_REQUEST req{ pid };
    MEMVIEW_PROCESS_INFO info{};
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_QUERY_PROCESS, &req, sizeof(req),
                         &info, sizeof(info), &returned, nullptr))
        return false;
    return info.isWow64 != 0;
}

// Short name is just the full path's last component (Toolhelp's szModule equivalent).
std::vector<mem::ModuleEntry> drvListModules(DWORD pid)
{
    std::vector<mem::ModuleEntry> out;
    if (g_device == INVALID_HANDLE_VALUE)
        return out;

    MEMVIEW_PID_REQUEST req{ pid };
    std::vector<MEMVIEW_MODULE_INFO> buf(MEMVIEW_MAX_MODULES);
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_LIST_MODULES, &req, sizeof(req),
                         buf.data(), (DWORD)(buf.size() * sizeof(MEMVIEW_MODULE_INFO)),
                         &returned, nullptr))
        return out;

    const size_t count = returned / sizeof(MEMVIEW_MODULE_INFO);
    out.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        char pathBuf[1024];
        WideCharToMultiByte(CP_UTF8, 0, buf[i].path, -1, pathBuf, sizeof(pathBuf), nullptr, nullptr);

        std::string path = pathBuf;
        std::string name = path;
        if (const size_t slash = path.find_last_of("\\/"); slash != std::string::npos)
            name = path.substr(slash + 1);

        out.push_back({ (uintptr_t)buf[i].base, (size_t)buf[i].size, name, path });
    }
    return out;
}

bool drvQueryRegion(DWORD pid, uintptr_t addr, mem::Region& out)
{
    if (g_device == INVALID_HANDLE_VALUE)
        return false;

    MEMVIEW_QUERY_REGION_REQUEST req{ pid, (unsigned long long)addr };
    MEMVIEW_REGION_INFO info{};
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_QUERY_REGION, &req, sizeof(req),
                         &info, sizeof(info), &returned, nullptr))
        return false;

    out.base    = (uintptr_t)info.base;
    out.size    = (size_t)info.size;
    out.protect = info.protect;
    out.type    = info.type;
    out.state   = info.state;
    return true;
}

bool drvProtect(DWORD pid, uintptr_t addr, size_t n, DWORD newProtect, DWORD& oldProtect)
{
    oldProtect = 0;
    if (g_device == INVALID_HANDLE_VALUE)
        return false;

    MEMVIEW_PROTECT_REQUEST req{ pid, (unsigned long long)addr, (unsigned long long)n, newProtect };
    MEMVIEW_PROTECT_RESPONSE resp{};
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_PROTECT, &req, sizeof(req),
                         &resp, sizeof(resp), &returned, nullptr))
        return false;

    oldProtect = resp.oldProtect;
    return true;
}

// Register/clear the hooks mem::read_bytes/write_bytes/etc. dispatch through.
void registerBackend()
{
    mem::g_kernel.read        = &drvRead;
    mem::g_kernel.write       = &drvWrite;
    mem::g_kernel.isWow64     = &drvIsWow64;
    mem::g_kernel.listModules = &drvListModules;
    mem::g_kernel.queryRegion = &drvQueryRegion;
    mem::g_kernel.protect     = &drvProtect;
}
void unregisterBackend() { mem::g_kernel = mem::KernelBackend{}; }

// Returns true once the service is running; `status` gets a reason on failure.
bool ensureServiceRunning(const std::wstring& sysPath, std::string& status)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
    {
        status = (GetLastError() == ERROR_ACCESS_DENIED)
            ? "Administrator rights required to load the driver."
            : "Could not open the Service Control Manager.";
        return false;
    }

    // Create the service if it isn't registered yet; otherwise open the existing one.
    SC_HANDLE svc = CreateServiceW(scm, MEMVIEW_SERVICE_NAME, MEMVIEW_SERVICE_NAME,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, sysPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc && GetLastError() == ERROR_SERVICE_EXISTS)
        svc = OpenServiceW(scm, MEMVIEW_SERVICE_NAME, SERVICE_ALL_ACCESS);

    if (!svc)
    {
        status = "Could not register the driver service.";
        CloseServiceHandle(scm);
        return false;
    }

    bool ok = true;
    if (!StartServiceW(svc, 0, nullptr))
    {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            ok = true;
        }
        else if (err == ERROR_INVALID_IMAGE_HASH) // 577
        {
            status = "Driver is not signed. Enable test signing "
                     "(bcdedit /set testsigning on).";
            ok = false;
        }
        else
        {
            status = "Failed to start the driver service (error "
                   + std::to_string(err) + ").";
            ok = false;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

// Best-effort: failures are ignored (usually just means it was never installed).
void removeServiceIfPresent()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        return;

    if (SC_HANDLE svc = OpenServiceW(scm, MEMVIEW_SERVICE_NAME, SERVICE_ALL_ACCESS))
    {
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

} // namespace

bool start(std::string& status)
{
    if (active())
    {
        status = "Kernel driver active.";
        return true;
    }

    const std::wstring sysPath = driverSysPath();
    if (sysPath.empty() || GetFileAttributesW(sysPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        status = "Driver not found.";
        return false;
    }

    if (!ensureServiceRunning(sysPath, status))
        return false;

    g_device = CreateFileW(MEMVIEW_WIN32_NAME, GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_device == INVALID_HANDLE_VALUE)
    {
        status = "Driver service started but the device could not be opened (error "
               + std::to_string(GetLastError()) + ").";
        return false;
    }

    registerBackend();
    status = "Kernel driver active.";
    return true;
}

void stop(bool removeService)
{
    unregisterBackend();

    if (g_device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_device);
        g_device = INVALID_HANDLE_VALUE;
    }

    if (removeService)
        removeServiceIfPresent();
}

bool active()
{
    return g_device != INVALID_HANDLE_VALUE;
}

} // namespace mem::driver
