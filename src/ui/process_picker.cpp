#include "ui/process_picker.hpp"
#include "app/app.hpp"
#include "memory/driver/driver.hpp"
#include <imgui.h>
#include <windows.h>
#include <shellapi.h> // ExtractIconExW for the icon cache below
#include <unordered_map>
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

        for (int i = 0; i < (int)s.procList.size(); ++i)
        {
            auto& e = s.procList[i];

            if (s.procFilter[0])
            {
                auto icontains = [](const char* hay, const char* nd) {
                    for (; *hay; ++hay)
                        if (_strnicmp(hay, nd, strlen(nd)) == 0) return true;
                    return false;
                };
                char pid[16]; snprintf(pid, sizeof(pid), "%lu", e.pid);
                if (!icontains(e.name.c_str(), s.procFilter) &&
                    !icontains(pid, s.procFilter)) continue;
            }

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
                    ImGui::EndTable(); ImGui::End(); return;
                }
            }

            ImGui::TableSetColumnIndex(0);
            if (auto* icon = icons::get(e.path))
                ImGui::Image((ImTextureID)(intptr_t)icon, ImVec2(kIconSize, kIconSize));

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(e.name.c_str());
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
    ID3D11Device* g_device = nullptr;
    std::unordered_map<std::string, ID3D11ShaderResourceView*> g_cache;

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
}

void init(ID3D11Device* device)
{
    g_device = device;
}

ID3D11ShaderResourceView* get(const std::string& exePath)
{
    if (exePath.empty() || !g_device) return nullptr;

    auto it = g_cache.find(exePath);
    if (it != g_cache.end()) return it->second;

    ID3D11ShaderResourceView* srv = nullptr;

    wchar_t pathW[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), -1, pathW, MAX_PATH);

    HICON hIcon = nullptr;
    UINT  n     = ExtractIconExW(pathW, 0, nullptr, &hIcon, 1);
    if (n > 0 && hIcon)
    {
        std::vector<uint8_t> pixels;
        int w = 0, h = 0;
        if (iconToRGBA(hIcon, pixels, w, h))
            srv = uploadTexture(pixels, w, h);
        DestroyIcon(hIcon);
    }

    g_cache.emplace(exePath, srv); // cache the miss too, so we don't retry every refresh
    return srv;
}

void shutdown()
{
    for (auto& [path, srv] : g_cache)
        if (srv) srv->Release();
    g_cache.clear();
    g_device = nullptr;
}

} // namespace ui::icons
