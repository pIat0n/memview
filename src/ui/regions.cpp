#include "ui/memory_view.hpp"
#include "app/app.hpp"
#include "memory/memory.hpp"
#include <imgui.h>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ui {

namespace {

// Case-insensitive substring test for the Modules name filter. Empty filter
// matches everything.
bool nameContains(const std::string& name, const char* needle)
{
    if (!needle || !needle[0]) return true;
    const size_t nlen = name.size();
    const size_t flen = strlen(needle);
    if (flen > nlen) return false;
    for (size_t i = 0; i + flen <= nlen; ++i)
        if (_strnicmp(name.c_str() + i, needle, flen) == 0)
            return true;
    return false;
}

// "RWX"-style protection flags for a region.
void protString(DWORD prot, char out[4])
{
    const bool readable = prot & (PAGE_READONLY | PAGE_READWRITE |
        PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY);
    out[0] = readable            ? 'R' : '-';
    out[1] = mem::is_writable(prot)   ? 'W' : '-';
    out[2] = mem::is_executable(prot) ? 'X' : '-';
    out[3] = '\0';
}

const char* typeString(DWORD type)
{
    switch (type)
    {
    case MEM_IMAGE:   return "Image";
    case MEM_MAPPED:  return "Mapped";
    case MEM_PRIVATE: return "Private";
    default:          return "";
    }
}

} // namespace

void drawRegions(app::AppState& s)
{
    // Refresh the region snapshot every second (every frame would be thousands
    // of syscalls).
    const double now = ImGui::GetTime();
    if (now >= s.regionsNextRefresh)
    {
        s.memRegions = mem::query_regions(s.proc);
        s.regionsNextRefresh = now + 1.0;
    }

    // Mouse "back" button undoes the last jump in both panes, since a region
    // jump moves disasm and hex together.
    if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(kMouseButtonBack))
    {
        const bool went = goBack(s.disasmHistory, s.disasmAddr);
        if (goBack(s.hexHistory, s.hexAddr) || went)
            snprintf(s.memGotoInput, sizeof(s.memGotoInput), "%llX",
                (unsigned long long)s.disasmAddr);
    }

    // Highlight the region Disassembly is in, so the map shows where you are
    // without being asked. A follow from its menu just forces the scroll too.
    int  curRow      = -1;
    bool scrollToCur = s.regionsFollow;
    s.regionsFollow  = false;
    for (int i = 0; i < (int)s.memRegions.size(); ++i)
        if (s.disasmAddr >= s.memRegions[i].base &&
            s.disasmAddr <  s.memRegions[i].base + s.memRegions[i].size)
        {
            curRow = i;
            // Scroll only when the region changes, or the list could never be
            // scrolled by hand.
            if (s.memRegions[i].base != s.regionsShownBase)
            {
                s.regionsShownBase = s.memRegions[i].base;
                scrollToCur        = true;
            }
            break;
        }
    if (curRow < 0)
        s.regionsShownBase = 0; // forget it, so coming back scrolls again

    ImGui::Text("%d committed regions", (int)s.memRegions.size());
    ImGui::SameLine();
    ImGui::TextDisabled("(double-click a row to view it)");

    const ImGuiTableFlags flags =
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

    if (!ImGui::BeginTable("##regions", 6, flags))
        return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Size");
    ImGui::TableSetupColumn("Protect");
    ImGui::TableSetupColumn("Type");
    ImGui::TableSetupColumn("State");
    ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin((int)s.memRegions.size());
    // The clipper skips off-screen rows, so exempt the one we're scrolling to.
    if (curRow >= 0 && scrollToCur)
        clipper.IncludeItemByIndex(curRow);
    while (clipper.Step())
    {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
        {
            const mem::Region& rg = s.memRegions[i];
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            char label[24];
            snprintf(label, sizeof(label), "%llX",
                (unsigned long long)rg.base);
            if (ImGui::Selectable(label, i == curRow,
                ImGuiSelectableFlags_SpanAllColumns |
                ImGuiSelectableFlags_AllowDoubleClick) &&
                ImGui::IsMouseDoubleClicked(0))
            {
                pushHistory(s.disasmHistory, s.disasmAddr);
                pushHistory(s.hexHistory, s.hexAddr);
                s.disasmAddr = rg.base;
                s.hexAddr    = rg.base;
                // Claim the row now, or the next frame scrolls it out from
                // under the cursor.
                s.regionsShownBase = rg.base;
                snprintf(s.memGotoInput, sizeof(s.memGotoInput), "%llX",
                    (unsigned long long)rg.base);
            }
            if (i == curRow && scrollToCur)
                ImGui::SetScrollHereY(0.5f);

            // Right-click to copy the base address. The popup binds to the
            // Selectable above, whose per-row label is unique.
            if (ImGui::BeginPopupContextItem())
            {
                if (ImGui::MenuItem("Copy Address"))
                {
                    // Unpadded, no leading zeros.
                    char copyBuf[24];
                    snprintf(copyBuf, sizeof(copyBuf), "%llX",
                        (unsigned long long)rg.base);
                    ImGui::SetClipboardText(copyBuf);
                }

                // Offset from the module base; disabled outside any module.
                const mem::ModuleEntry* rvaMod = app::findModule(s, rg.base);
                if (ImGui::MenuItem("Copy RVA", nullptr, false, rvaMod != nullptr))
                {
                    char rva[24];
                    snprintf(rva, sizeof(rva), "%llX",
                        (unsigned long long)(rg.base - rvaMod->base));
                    ImGui::SetClipboardText(rva);
                }
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%llX", (unsigned long long)rg.size);

            ImGui::TableSetColumnIndex(2);
            if (s.proc.backend == mem::Backend::Physical)
                // rg.protect is a stand-in value (see query_regions) - no real
                // per-page protection to show for physical RAM.
                ImGui::TextDisabled("N/A");
            else
            {
                char prot[4];
                protString(rg.protect, prot);
                ImGui::TextUnformatted(prot);
            }

            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(typeString(rg.type));

            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(rg.state == MEM_COMMIT ? "Commit"
                : rg.state == MEM_RESERVE ? "Reserve" : "Free");

            // Info: module name on the base (header) row, section name on each
            // section row below it.
            ImGui::TableSetColumnIndex(5);
            if (const mem::ModuleEntry* mod = app::findModule(s, rg.base))
            {
                if (const char* sec = app::findSectionName(s, *mod, rg.base))
                    ImGui::TextUnformatted(sec);
                else
                    ImGui::TextUnformatted(mod->name.c_str());
            }
            else
                ImGui::TextDisabled("-");
        }
    }

    ImGui::EndTable();
}

void drawModules(app::AppState& s)
{
    // s.modules is refreshed once per frame in drawMemoryView before the panes
    // are drawn, so here we only render it.

    // Mouse "back" button undoes the last jump in both panes, matching Regions:
    // a module jump moves disasm and hex together.
    if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(kMouseButtonBack))
    {
        const bool went = goBack(s.disasmHistory, s.disasmAddr);
        if (goBack(s.hexHistory, s.hexAddr) || went)
            snprintf(s.memGotoInput, sizeof(s.memGotoInput), "%llX",
                (unsigned long long)s.disasmAddr);
    }

    // Rows passing the name filter, by index into s.modules. Built each frame -
    // a few hundred short comparisons is nothing next to the table draw.
    std::vector<int> rows;
    rows.reserve(s.modules.size());
    for (int i = 0; i < (int)s.modules.size(); ++i)
        if (nameContains(s.modules[i].name, s.moduleFilter))
            rows.push_back(i);

    if (s.moduleFilter[0])
        ImGui::Text("%d / %d modules", (int)rows.size(), (int)s.modules.size());
    else
        ImGui::Text("%d modules", (int)s.modules.size());

    // Bulk symbol load: the only entry point for "fetch everything up front".
    // Cheap to re-press - requestModuleSymbols skips modules already loaded,
    // queued, or known to have none. Progress shows in the status strip below.
    ImGui::SameLine();
    ImGui::BeginDisabled(!s.symbols.settings().enabled);
    if (ImGui::SmallButton("Load all symbols"))
        app::requestAllModuleSymbols(s);
    ImGui::EndDisabled();
    // AllowWhenDisabled: without it the "turned off" explanation below would
    // never show, since the button is disabled in exactly that case.
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip(s.symbols.settings().enabled
            ? (s.symbols.settings().useServer
                ? "Look for every module's PDB, downloading what's missing."
                : "Look for every module's PDB on disk.\n"
                  "Turn on the symbol server in Settings to download the rest.")
            : "Symbols are turned off in Settings.");

    ImGui::SameLine();
    ImGui::TextDisabled("(double-click a row to view it)");

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##modfilter", "Filter by name...",
        s.moduleFilter, sizeof(s.moduleFilter));

    const ImGuiTableFlags flags =
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;

    if (!ImGui::BeginTable("##modules", 4, flags))
        return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Size");
    ImGui::TableSetupColumn("Syms");
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin((int)rows.size());
    while (clipper.Step())
    {
        for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r)
        {
            const mem::ModuleEntry& m = s.modules[rows[r]];
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            char label[24];
            snprintf(label, sizeof(label), "%llX",
                (unsigned long long)m.base);
            if (ImGui::Selectable(label, false,
                ImGuiSelectableFlags_SpanAllColumns |
                ImGuiSelectableFlags_AllowDoubleClick) &&
                ImGui::IsMouseDoubleClicked(0))
            {
                pushHistory(s.disasmHistory, s.disasmAddr);
                pushHistory(s.hexHistory, s.hexAddr);
                s.disasmAddr = m.base;
                s.hexAddr    = m.base;
                snprintf(s.memGotoInput, sizeof(s.memGotoInput), "%llX",
                    (unsigned long long)m.base);
            }

            // Right-click to copy the base address, unpadded.
            if (ImGui::BeginPopupContextItem())
            {
                if (ImGui::MenuItem("Copy Address"))
                {
                    char copyBuf[24];
                    snprintf(copyBuf, sizeof(copyBuf), "%llX",
                        (unsigned long long)m.base);
                    ImGui::SetClipboardText(copyBuf);
                }
                if (ImGui::MenuItem("Copy Name"))
                    ImGui::SetClipboardText(m.name.c_str());
                ImGui::Separator();
                symbolsContextMenu(s, m);
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%llX", (unsigned long long)m.size);

            // Symbol count, or why there are none. Right-click loads them.
            ImGui::TableSetColumnIndex(2);
            symbolStatusCell(s.symbols.find(m.base));

            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(m.name.c_str());
        }
    }

    ImGui::EndTable();
}

} // namespace ui
