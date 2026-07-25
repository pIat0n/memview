#define NOMINMAX // d3d11.h drags in windows.h, so this has to come first
#include "ui/process_picker.hpp"
#include "app/app.hpp"
#include "memory/driver/driver.hpp"
#include <imgui.h>
#include <windows.h>
#include <shellapi.h> // ExtractIconExW for the icon cache below
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <cstdio>
#include <cstring>

namespace ui {

namespace {
    constexpr float kIconSize = 16.0f;

    // s.procSelected indexes s.procList (>= 0); this marks the pinned row instead.
    constexpr int kPhysicalMemorySelected = -2;
}

void drawProcessPicker(app::AppState& s)
{
    if (!s.showProcPicker) { s.procNextRefresh = 0.0; s.wasProcPickerOpen = false; return; }

    const ImGuiViewport* vp = ImGui::GetMainViewport();

    const bool justOpened = !s.wasProcPickerOpen;
    s.wasProcPickerOpen = true;
    if (justOpened) s.attachError[0] = '\0';

    if (!app::beginBlockingModal("Select Process", &s.showProcPicker, vp, 500, 400))
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showProcPicker = false;

    // Refresh the process list every second, keeping the selection by PID.
    const double now = ImGui::GetTime();
    if (now >= s.procNextRefresh)
    {
        const bool wasPhysSelected = (s.procSelected == kPhysicalMemorySelected);
        DWORD selPid = (s.procSelected >= 0 && s.procSelected < (int)s.procList.size())
                     ? s.procList[s.procSelected].pid : 0;

        s.procList     = mem::list_processes();
        s.procSelected = wasPhysSelected ? kPhysicalMemorySelected : -1;
        if (selPid)
            for (int i = 0; i < (int)s.procList.size(); ++i)
                if (s.procList[i].pid == selPid) { s.procSelected = i; break; }

        s.procNextRefresh = now + 1.0;
    }

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##filter", "Filter by name or PID...",
        s.procFilter, sizeof(s.procFilter));

    ImGui::Separator();

    // Filtered row indices - the clipper needs them contiguous.
    std::vector<int> rows;
    rows.reserve(s.procList.size());
    for (int i = 0; i < (int)s.procList.size(); ++i)
    {
        if (s.procFilter[0])
        {
            auto icontains = [](const char* hay, const char* nd) {
                for (; *hay; ++hay)
                    if (_strnicmp(hay, nd, strlen(nd)) == 0) return true;
                return false;
            };
            char pid[16]; snprintf(pid, sizeof(pid), "%lu", s.procList[i].pid);
            if (!icontains(s.procList[i].name.c_str(), s.procFilter) &&
                !icontains(pid, s.procFilter)) continue;
        }
        rows.push_back(i);
    }

    const float errH = s.attachError[0] ? ImGui::GetTextLineHeightWithSpacing() : 0.f;
    const float listH = ImGui::GetContentRegionAvail().y
                      - ImGui::GetFrameHeightWithSpacing() - errH - 8;

    ImGuiTableFlags tfl =
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

    if (ImGui::BeginTable("##proclist", 3, tfl, ImVec2(-1, listH)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("##icon",  ImGuiTableColumnFlags_WidthFixed, kIconSize + 8);
        ImGui::TableSetupColumn("PID",     ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // Pinned row: attach to raw physical RAM instead of a process.
        {
            const bool driverUp = mem::driver::active();
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(1);

            ImGui::BeginDisabled(!driverUp);
            const bool physSel = (s.procSelected == kPhysicalMemorySelected);
            if (ImGui::Selectable("-", physSel,
                ImGuiSelectableFlags_SpanAllColumns |
                ImGuiSelectableFlags_AllowOverlap))
                s.procSelected = kPhysicalMemorySelected;

            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
            {
                if (app::attachToPhysicalMemory(s))
                {
                    s.showProcPicker = false;
                    ImGui::EndDisabled();
                    ImGui::EndTable(); ImGui::End(); return;
                }
            }
            ImGui::EndDisabled();

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted("Physical Memory");
            if (!driverUp && ImGui::IsItemHovered())
                ImGui::SetTooltip("Requires the kernel driver - enable it in Settings.");
        }

        // Also keeps icons cheap: off-screen rows never reach icons::get().
        ImGuiListClipper clipper;
        clipper.Begin((int)rows.size());
        while (clipper.Step())
        {
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r)
            {
                const int   i = rows[r];
                const auto& e = s.procList[i];

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(1);

                char lbl[32]; snprintf(lbl, sizeof(lbl), "%lu", e.pid);
                bool sel = (s.procSelected == i);
                if (ImGui::Selectable(lbl, sel,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowOverlap))
                    s.procSelected = i;

                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))
                {
                    if (app::attachToProcess(s, e))
                    {
                        s.showProcPicker = false;
                        clipper.End(); // has to come before EndTable
                        ImGui::EndTable(); ImGui::End(); return;
                    }
                }

                ImGui::TableSetColumnIndex(0);
                if (auto* icon = icons::get(e.path))
                    ImGui::Image((ImTextureID)(intptr_t)icon, ImVec2(kIconSize, kIconSize));
                else
                    ImGui::Dummy(ImVec2(kIconSize, kIconSize)); // keeps the row height steady

                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(e.name.c_str());
            }
        }
        ImGui::EndTable();
    }

    if (s.attachError[0])
    {
        ImGui::TextColored(ImVec4(0.85f, 0.1f, 0.1f, 1.f), "%s", s.attachError);
    }

    ImGui::Separator();
    const bool physSelected = (s.procSelected == kPhysicalMemorySelected);
    ImGui::BeginDisabled(
        (physSelected && !mem::driver::active()) ||
        (!physSelected && (s.procSelected < 0 || s.procSelected >= (int)s.procList.size())));
    if (ImGui::Button("Open", ImVec2(80, 0)))
    {
        const bool ok = physSelected ? app::attachToPhysicalMemory(s)
                                      : app::attachToProcess(s, s.procList[s.procSelected]);
        if (ok) s.showProcPicker = false;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(80, 0)))
        s.showProcPicker = false;

    ImGui::End();
}

} // namespace ui

// --- Process-icon cache (ui::icons) ------------------------------------------

namespace ui::icons {

namespace {
    // I/O bound: four threads gave 2.5x, eight gave nothing more (GDI lock).
    constexpr int kMaxWorkers = 4;

    // Just a cap, so a burst of decodes can't spike a frame.
    constexpr int kUploadsPerFrame = 16;

    // Generic app icon in imageres.dll - what Explorer shows for the many exes
    // that carry none of their own.
    constexpr int kStockIconIndex = 11;

    struct Entry {
        State                     state = State::Pending;
        ID3D11ShaderResourceView* srv   = nullptr;
    };

    struct Job { std::string path; int index = 0; };

    // Worker -> render thread; w == 0 means nothing was extracted.
    struct Decoded {
        std::string          path;
        std::vector<uint8_t> pixels;
        int                  w = 0, h = 0;
    };

    // Worker-visible state. On the heap so shutdown() can abandon a stuck worker.
    struct Shared {
        std::mutex              mu;
        std::condition_variable cv;
        std::vector<Job>        queue; // taken from the back: newest request wins
        std::vector<Decoded>    done;
        bool                    stop = false;
    };

    ID3D11Device*            g_device = nullptr;
    Shared*                  g_shared = nullptr;
    std::vector<std::thread> g_workers;

    // Render thread only.
    std::unordered_map<std::string, Entry> g_cache;
    std::vector<Decoded>                   g_ready; // waiting for an upload slot
    ID3D11ShaderResourceView*              g_stock = nullptr;

    // Convert an HICON into a top-down 32bpp RGBA buffer. Returns false on failure.
    bool iconToRGBA(HICON hIcon, std::vector<uint8_t>& pixels, int& w, int& h)
    {
        ICONINFO info = {};
        if (!GetIconInfo(hIcon, &info)) return false;

        BITMAP bmColor = {};
        GetObject(info.hbmColor, sizeof(bmColor), &bmColor);
        w = bmColor.bmWidth;
        h = bmColor.bmHeight;

        bool ok = false;
        HDC dc = CreateCompatibleDC(nullptr);
        if (dc && w > 0 && h > 0)
        {
            BITMAPINFO bi = {};
            bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
            bi.bmiHeader.biWidth       = w;
            bi.bmiHeader.biHeight      = -h; // top-down
            bi.bmiHeader.biPlanes      = 1;
            bi.bmiHeader.biBitCount    = 32;
            bi.bmiHeader.biCompression = BI_RGB;

            pixels.resize((size_t)w * h * 4);
            ok = GetDIBits(dc, info.hbmColor, 0, h, pixels.data(), &bi, DIB_RGB_COLORS) != 0;

            if (ok)
            {
                // BGRA -> RGBA, and recover per-pixel alpha from the mask if the
                // color bitmap didn't carry a real alpha channel (common for
                // older/ICO-style icons where alpha is all zero).
                bool anyAlpha = false;
                for (size_t i = 0; i < pixels.size(); i += 4)
                    if (pixels[i + 3] != 0) { anyAlpha = true; break; }

                if (!anyAlpha)
                {
                    std::vector<uint8_t> mask((size_t)w * h * 4);
                    BITMAPINFO mbi = bi;
                    if (GetDIBits(dc, info.hbmMask, 0, h, mask.data(), &mbi, DIB_RGB_COLORS))
                        for (size_t i = 0; i < pixels.size(); i += 4)
                            pixels[i + 3] = mask[i] ? 0 : 255; // AND-mask: 1 = transparent
                    else
                        for (size_t i = 0; i < pixels.size(); i += 4)
                            pixels[i + 3] = 255;
                }

                for (size_t i = 0; i < pixels.size(); i += 4)
                    std::swap(pixels[i], pixels[i + 2]);
            }
        }
        if (dc) DeleteDC(dc);
        if (info.hbmColor) DeleteObject(info.hbmColor);
        if (info.hbmMask)  DeleteObject(info.hbmMask);
        return ok;
    }

    ID3D11ShaderResourceView* uploadTexture(const std::vector<uint8_t>& pixels, int w, int h)
    {
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width            = w;
        desc.Height           = h;
        desc.MipLevels        = 1;
        desc.ArraySize        = 1;
        desc.Format           = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage            = D3D11_USAGE_IMMUTABLE;
        desc.BindFlags        = D3D11_BIND_SHADER_RESOURCE;

        D3D11_SUBRESOURCE_DATA sub = {};
        sub.pSysMem     = pixels.data();
        sub.SysMemPitch = w * 4;

        ID3D11Texture2D* tex = nullptr;
        if (FAILED(g_device->CreateTexture2D(&desc, &sub, &tex)) || !tex)
            return nullptr;

        ID3D11ShaderResourceView* srv = nullptr;
        g_device->CreateShaderResourceView(tex, nullptr, &srv);
        tex->Release();
        return srv;
    }

    // Disk and GDI only - no device, no cache. That's why shutdown() can abandon it.
    void workerMain(Shared* sh)
    {
        for (;;)
        {
            Job job;
            {
                std::unique_lock<std::mutex> lk(sh->mu);
                sh->cv.wait(lk, [sh] { return sh->stop || !sh->queue.empty(); });
                if (sh->stop) return;
                job = std::move(sh->queue.back());
                sh->queue.pop_back();
            }

            Decoded out;
            out.path = job.path;

            wchar_t pathW[MAX_PATH * 2]; // GLOBALROOT paths can outrun MAX_PATH
            HICON   hIcon = nullptr;
            if (MultiByteToWideChar(CP_UTF8, 0, job.path.c_str(), -1,
                    pathW, MAX_PATH * 2) > 0 &&
                ExtractIconExW(pathW, job.index, nullptr, &hIcon, 1) > 0 && hIcon)
            {
                if (!iconToRGBA(hIcon, out.pixels, out.w, out.h))
                    out.w = out.h = 0;
                DestroyIcon(hIcon);
            }

            std::lock_guard<std::mutex> lk(sh->mu);
            sh->done.push_back(std::move(out));
        }
    }

    const std::string& stockIconPath()
    {
        static const std::string path = [] {
            wchar_t dir[MAX_PATH];
            const UINT n = GetSystemDirectoryW(dir, MAX_PATH);
            if (n == 0 || n >= MAX_PATH) return std::string();

            const std::wstring w = std::wstring(dir, n) + L"\\imageres.dll";
            char buf[MAX_PATH * 2];
            if (WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                    buf, sizeof(buf), nullptr, nullptr) <= 0)
                return std::string();
            return std::string(buf);
        }();
        return path;
    }

    void ensureWorkers()
    {
        if (!g_shared) g_shared = new Shared();
        if (!g_workers.empty()) return;

        const unsigned hc = std::thread::hardware_concurrency();
        const int      n  = (int)std::min<unsigned>(kMaxWorkers, hc ? hc : 1);
        for (int i = 0; i < n; ++i)
        {
            g_workers.emplace_back(workerMain, g_shared);
            // Same as the symbol worker: never starve the render thread.
            SetThreadPriority(g_workers.back().native_handle(), THREAD_PRIORITY_BELOW_NORMAL);
        }
    }

    // Queued with the first real request, not at startup.
    void requestStockIcon()
    {
        const std::string& path = stockIconPath();
        if (path.empty() || g_cache.count(path)) return;

        g_cache.emplace(path, Entry{});
        {
            std::lock_guard<std::mutex> lk(g_shared->mu);
            g_shared->queue.push_back({ path, kStockIconIndex });
        }
        g_shared->cv.notify_one();
    }
}

void init(ID3D11Device* device)
{
    g_device = device;
}

ID3D11ShaderResourceView* get(const std::string& exePath)
{
    if (exePath.empty() || !g_device) return nullptr;

    auto it = g_cache.find(exePath);
    if (it != g_cache.end())
        return it->second.state == State::Fallback ? g_stock : it->second.srv;

    // The entry doubles as the in-flight marker: eighty svchost.exe rows, one job.
    g_cache.emplace(exePath, Entry{});

    ensureWorkers();
    requestStockIcon();
    {
        std::lock_guard<std::mutex> lk(g_shared->mu);
        g_shared->queue.push_back({ exePath, 0 });
    }
    g_shared->cv.notify_one();
    return nullptr;
}

State state(const std::string& exePath)
{
    if (exePath.empty()) return State::Missing;
    auto it = g_cache.find(exePath);
    return it == g_cache.end() ? State::Missing : it->second.state;
}

void pump()
{
    if (!g_shared) return;

    {
        std::lock_guard<std::mutex> lk(g_shared->mu);
        if (g_ready.empty())
            g_ready.swap(g_shared->done);
        else if (!g_shared->done.empty())
        {
            for (auto& d : g_shared->done) g_ready.push_back(std::move(d));
            g_shared->done.clear();
        }
    }

    const size_t n = std::min(g_ready.size(), (size_t)kUploadsPerFrame);
    for (size_t i = 0; i < n; ++i)
    {
        Decoded& d = g_ready[i];
        Entry&   e = g_cache[d.path];
        e.srv   = (d.w > 0 && d.h > 0) ? uploadTexture(d.pixels, d.w, d.h) : nullptr;
        e.state = e.srv ? State::Ready : State::Fallback;
        if (d.path == stockIconPath()) g_stock = e.srv;
    }
    g_ready.erase(g_ready.begin(), g_ready.begin() + n);
}

void shutdown()
{
    if (g_shared)
    {
        {
            std::lock_guard<std::mutex> lk(g_shared->mu);
            g_shared->stop = true;
            g_shared->queue.clear();
        }
        g_shared->cv.notify_all();

        // ExtractIconExW can't be cancelled and blocks on a dead share, so give the
        // workers one budget to notice and don't hang the exit on the rest.
        const ULONGLONG deadline  = GetTickCount64() + 200;
        bool            abandoned = false;
        for (auto& t : g_workers)
        {
            const ULONGLONG now  = GetTickCount64();
            const DWORD     wait = now < deadline ? (DWORD)(deadline - now) : 0;
            if (WaitForSingleObject(t.native_handle(), wait) == WAIT_OBJECT_0)
                t.join();
            else
            {
                t.detach();
                abandoned = true;
            }
        }
        g_workers.clear();

        // An abandoned worker still writes here when it returns, so leak it.
        if (!abandoned) delete g_shared;
        g_shared = nullptr;
    }

    for (auto& [path, e] : g_cache)
        if (e.srv) e.srv->Release();
    g_cache.clear();
    g_ready.clear();
    g_stock  = nullptr;
    g_device = nullptr;
}

} // namespace ui::icons
