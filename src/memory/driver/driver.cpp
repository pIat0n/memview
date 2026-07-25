#include "memory/driver/driver.hpp"

#include <windows.h>
#include <winioctl.h>
#include <vector>

#include "ioctl/ioctl.hpp"
#include "memory/memory.hpp"

namespace mem::driver {
namespace {

HANDLE g_device = INVALID_HANDLE_VALUE;

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

    status = "Kernel driver active.";
    return true;
}

void stop(bool removeService)
{
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

size_t read(uint32_t pid, uintptr_t addr, void* buf, size_t n)
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

size_t write(uint32_t pid, uintptr_t addr, const void* buf, size_t n)
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

bool isWow64(uint32_t pid)
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

std::vector<mem::ModuleEntry> listModules(uint32_t pid)
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

bool queryRegion(uint32_t pid, uintptr_t addr, mem::Region& out)
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

bool protect(uint32_t pid, uintptr_t addr, size_t n, unsigned long newProtect, unsigned long& oldProtect)
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

namespace phys {

size_t read(uint64_t addr, void* buf, size_t n)
{
    if (g_device == INVALID_HANDLE_VALUE || n == 0)
        return 0;

    MEMVIEW_PHYSICAL_REQUEST req{ addr, (unsigned long long)n };
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_READ_PHYSICAL, &req, sizeof(req),
                         buf, (DWORD)n, &returned, nullptr))
        return 0;
    return returned;
}

bool write(uint64_t addr, const void* buf, size_t n)
{
    if (g_device == INVALID_HANDLE_VALUE || n == 0)
        return false;

    std::vector<uint8_t> in(sizeof(MEMVIEW_PHYSICAL_REQUEST) + n);
    MEMVIEW_PHYSICAL_REQUEST req{ addr, (unsigned long long)n };
    memcpy(in.data(), &req, sizeof(req));
    memcpy(in.data() + sizeof(req), buf, n);

    DWORD returned = 0;
    return DeviceIoControl(g_device, MEMVIEW_IOCTL_WRITE_PHYSICAL, in.data(), (DWORD)in.size(),
                           nullptr, 0, &returned, nullptr) != 0;
}

std::vector<Range> ranges()
{
    std::vector<Range> out;
    if (g_device == INVALID_HANDLE_VALUE)
        return out;

    std::vector<MEMVIEW_PHYSICAL_RANGE> buf(MEMVIEW_MAX_PHYSICAL_RANGES);
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_QUERY_PHYSICAL_RANGES, nullptr, 0,
                         buf.data(), (DWORD)(buf.size() * sizeof(MEMVIEW_PHYSICAL_RANGE)),
                         &returned, nullptr))
        return out;

    const size_t count = returned / sizeof(MEMVIEW_PHYSICAL_RANGE);
    out.reserve(count);
    for (size_t i = 0; i < count; ++i)
        out.push_back({ buf[i].base, buf[i].size });
    return out;
}

uint64_t translate(uint32_t pid, uint64_t va)
{
    if (g_device == INVALID_HANDLE_VALUE)
        return 0;

    MEMVIEW_VIRT_TO_PHYS_REQUEST req{ pid, va };
    MEMVIEW_VIRT_TO_PHYS_RESPONSE resp{};
    DWORD returned = 0;
    if (!DeviceIoControl(g_device, MEMVIEW_IOCTL_VIRTUAL_TO_PHYSICAL, &req, sizeof(req),
                         &resp, sizeof(resp), &returned, nullptr))
        return 0;
    return resp.physicalAddress;
}

} // namespace phys

} // namespace mem::driver
