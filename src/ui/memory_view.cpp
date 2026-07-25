#include "ui/memory_view.hpp"
#include "app/app.hpp"
#include "memory/memory.hpp"
#include "memory/value_format.hpp"
#include <imgui.h>
#include <imgui_internal.h> // DockBuilder* for the layout, FindWindowByName for modals
#include <cmath>  // sinf for the indeterminate progress sweep
#include <cstdio>
#include <cstdlib> // strtoull for hex value entry
#include <string>

// The Memory View container: a separate OS window whose dockspace hosts the
// four panes (Disassembly, Hex View, Memory Regions, Modules), which can be
// dragged apart or torn out. Also owns the shared Go/Back bar driving both panes.
namespace ui {

namespace {

// NoResize drops ImGui's corner grip; a torn-out pane is still resizable by its
// native OS border. Docked panes use node-level splitters regardless.
const ImGuiWindowFlags kPaneFlags = ImGuiWindowFlags_NoResize |
    ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoScrollbar;

// "Go to Address" popup shared by the Disassembly and Hex View menus. Each
// caller passes its own show flag/input/target so the panes stay independent,
// plus an anchor window so the popup centers on that pane's OS window.
void drawGotoAddressModal(app::AppState& s, bool& show, char* input,
    size_t inputSize, uintptr_t& target, std::vector<uintptr_t>& history,
    const char* popupId, const char* anchorWindow)
{
    if (!show) return;

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* win = ImGui::FindWindowByName(anchorWindow))
        vp = win->Viewport;

    if (!app::beginBlockingModal(popupId, &show, vp, 340, 0))
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        show = false;

    ImGui::TextUnformatted("Address");
    ImGui::SetNextItemWidth(-1);
    // Focus the input only on the frame it appears; every frame would fight
    // clicks on Go/Cancel.
    if (ImGui::IsWindowAppearing())
        ImGui::SetKeyboardFocusHere();
    const bool submit = app::addrInput(s, "##gotoaddrinput", input, inputSize,
        ImGuiInputTextFlags_EnterReturnsTrue);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    uintptr_t parsed = 0;
    const bool valid = input[0] != '\0' && app::parseAddrExpr(s, input, parsed);

    ImGui::BeginDisabled(!valid);
    if (ImGui::Button("Go", ImVec2(120, 0)) || (submit && valid))
    {
        pushHistory(history, target);
        target = parsed;
        show   = false;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0)))
        show = false;

    ImGui::End();
}

// Type-aware write at one byte, opened from the hex grid (double-click / menu).
void drawHexEditValueModal(app::AppState& s)
{
    if (!s.showHexEditValue) return;

    // Center on the Hex View's own OS window; it may be torn out to another monitor.
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGuiWindow* win = ImGui::FindWindowByName("Hex View"))
        vp = win->Viewport;

    if (!app::beginBlockingModal("Edit Value##hex", &s.showHexEditValue, vp, 360, 0))
        return;

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        s.showHexEditValue = false;

    const mem::ValueType vt = app::uiValueType(s.hexEditValueType);
    const bool utf16 = (vt == mem::ValueType::String && s.hexEditValueEncoding == 1);

    // Hex display/entry is offered for integer types only.
    const bool isInt = (vt == mem::ValueType::UInt8 || vt == mem::ValueType::Int16 ||
                        vt == mem::ValueType::Int32 || vt == mem::ValueType::Int64);
    const bool hexMode = isInt && s.hexEditValueHex;

    // Scalars have a fixed width; String/Pattern use the length field.
    auto widthFor = [&]() -> size_t {
        size_t w = mem::value_size(vt);
        if (w == 0)
        {
            int len = s.hexEditValueLength;
            if (len < 1)   len = 1;
            if (len > 256) len = 256;
            w = (size_t)len;
        }
        return w;
    };

    auto readCurrent = [&](std::string& out) -> bool {
        if (!s.proc.is_open()) return false;
        uint8_t buf[256] = {};
        const size_t w = widthFor();
        if (!mem::read_raw(s.proc, s.hexEditValueAddr, buf, w)) return false;
        if (hexMode)
        {
            uint64_t v = 0; memcpy(&v, buf, w); // w <= 8 for integers
            char tmp[24];
            snprintf(tmp, sizeof(tmp), "%llX", (unsigned long long)v);
            out = tmp;
        }
        else
            out = app::formatValueStr(buf, w, vt, utf16);
        return true;
    };

    // Prefill from memory on open and whenever the type/length/encoding/hex
    // flag changes, since the old text no longer matches the new representation.
    static int prevType = -1, prevLen = -1, prevEnc = -1, prevHex = -1;
    if (ImGui::IsWindowAppearing()) { prevType = prevLen = prevEnc = prevHex = -1; }
    if (prevType != s.hexEditValueType || prevLen != s.hexEditValueLength ||
        prevEnc != s.hexEditValueEncoding || prevHex != (int)hexMode)
    {
        std::string cur;
        if (readCurrent(cur))
            snprintf(s.hexEditValueInput, sizeof(s.hexEditValueInput), "%s", cur.c_str());
        s.hexEditValueError[0] = '\0';
        prevType = s.hexEditValueType;
        prevLen  = s.hexEditValueLength;
        prevEnc  = s.hexEditValueEncoding;
        prevHex  = (int)hexMode;
    }

    char lbl[40];
    app::formatAddrLabel(s, s.hexEditValueAddr, lbl, sizeof(lbl));
    ImGui::Text("Address: %s", lbl);

    ImGui::Spacing();
    ImGui::TextUnformatted("Type");
    ImGui::SetNextItemWidth(-1);
    ImGui::Combo("##hexedittype", &s.hexEditValueType,
        app::kValueTypeNames, app::kValueTypeCount);

    if (isInt)
    {
        ImGui::Spacing();
        ImGui::Checkbox("Hexadecimal", &s.hexEditValueHex);
    }

    // String/Pattern have no fixed width, so let the user pick how many bytes.
    if (vt == mem::ValueType::String || vt == mem::ValueType::ArrayOfBytes)
    {
        ImGui::Spacing();
        ImGui::TextUnformatted("Length (bytes)");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputInt("##hexeditlen", &s.hexEditValueLength);
        if (s.hexEditValueLength < 1)   s.hexEditValueLength = 1;
        if (s.hexEditValueLength > 256) s.hexEditValueLength = 256;
    }

    if (vt == mem::ValueType::String)
    {
        ImGui::Spacing();
        ImGui::TextUnformatted("Encoding");
        ImGui::SetNextItemWidth(-1);
        const char* encNames[] = { "UTF-8", "UTF-16" };
        ImGui::Combo("##hexeditenc", &s.hexEditValueEncoding, encNames, 2);
    }

    // Live readout of what's in memory now, re-read every frame.
    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Current:");
    ImGui::SameLine();
    {
        std::string cur;
        if (readCurrent(cur)) ImGui::TextUnformatted(cur.c_str());
        else                  ImGui::TextDisabled("Unreadable");
    }

    ImGui::Spacing();
    ImGui::TextUnformatted("New value");
    ImGui::SetNextItemWidth(-1);
    if (ImGui::IsWindowAppearing())
        ImGui::SetKeyboardFocusHere();
    const bool submit = ImGui::InputText("##hexeditval", s.hexEditValueInput,
        sizeof(s.hexEditValueInput), ImGuiInputTextFlags_EnterReturnsTrue);

    if (s.hexEditValueError[0])
        ImGui::TextColored(ImVec4(0.85f, 0.1f, 0.1f, 1.f), "%s", s.hexEditValueError);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    auto doWrite = [&]() {
        if (!s.proc.is_open())
        {
            snprintf(s.hexEditValueError, sizeof(s.hexEditValueError),
                "No process attached.");
            return;
        }
        uint8_t buf[256] = {};
        size_t  n = 0;
        if (hexMode)
        {
            // Write the low width bytes of the hex input (raw bit pattern),
            // so e.g. -1 as 4 Bytes = FFFFFFFF.
            const size_t w = mem::value_size(vt);
            char* end = nullptr;
            const unsigned long long v = strtoull(s.hexEditValueInput, &end, 16);
            if (end == s.hexEditValueInput)
            {
                snprintf(s.hexEditValueError, sizeof(s.hexEditValueError),
                    "Not a valid hexadecimal number.");
                return;
            }
            memcpy(buf, &v, w);
            n = w;
        }
        else
        {
            n = app::parseValue(s.hexEditValueInput, vt, buf, sizeof(buf), utf16);
            if (n == 0)
            {
                snprintf(s.hexEditValueError, sizeof(s.hexEditValueError),
                    "Couldn't parse the value for this type.");
                return;
            }
        }
        if (!mem::write_raw(s.proc, s.hexEditValueAddr, buf, n))
        {
            snprintf(s.hexEditValueError, sizeof(s.hexEditValueError),
                "Write failed (err %lu). Address may be unwritable.",
                (unsigned long)GetLastError());
            return;
        }
        s.showHexEditValue = false;
    };

    const bool canWrite = s.proc.is_open() && s.hexEditValueInput[0] != '\0';
    ImGui::BeginDisabled(!canWrite);
    if (ImGui::Button("Write", ImVec2(120, 0)) || (submit && canWrite))
        doWrite();
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120, 0)))
        s.showHexEditValue = false;

    ImGui::End();
}

// Bottom status strip: what the symbol worker is doing right now - download
// progress, a local parse, and the queue behind it. Only drawn while a load is
// running, so there's no idle state here. Reads only thread-safe accessors.
void drawSymbolStatusBar(app::AppState& s)
{
    auto mb = [](uint64_t bytes) { return (double)bytes / (1024.0 * 1024.0); };

    const std::string active = s.symbols.activeName();
    const uint64_t    got    = s.symbols.progress().received.load();
    const uint64_t    total  = s.symbols.progress().total.load();

    // received/total only move during a download, so non-zero means a fetch;
    // otherwise the worker is searching disk or parsing a local PDB.
    const bool downloading = (got != 0 || total != 0);

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(downloading ? "Downloading" : "Loading");
    // active_ is briefly empty between jobs while the queue drains; skip the
    // name then rather than flashing a blank.
    if (!active.empty())
    {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", active.c_str());
    }

    if (const size_t queued = s.symbols.pending(); queued > 1)
    {
        ImGui::SameLine();
        ImGui::TextDisabled("(+%zu queued)", queued - 1);
    }

    ImGui::SameLine();
    // Leave room for the Cancel button at the right edge; the bar fills the
    // rest. Both are frame-height, so they sit level with the label.
    const ImGuiStyle& st = ImGui::GetStyle();
    const float cancelW = ImGui::CalcTextSize("Cancel").x + st.FramePadding.x * 2.0f;
    float barW = ImGui::GetContentRegionAvail().x - cancelW - st.ItemSpacing.x;
    if (barW < 60.0f) barW = 60.0f;
    const ImVec2 barSz(barW, ImGui::GetFrameHeight());

    if (downloading && total > 0)
    {
        char overlay[48];
        snprintf(overlay, sizeof(overlay), "%.1f / %.1f MB", mb(got), mb(total));
        ImGui::ProgressBar((float)got / (float)total, barSz, overlay);
    }
    else
    {
        // No known length (server sent none) or a local parse: sweep an
        // indeterminate bar so the UI clearly reads as "working".
        const float t = (float)ImGui::GetTime();
        const float frac = 0.5f + 0.5f * sinf(t * 3.0f);
        char overlay[32] = "";
        if (downloading) snprintf(overlay, sizeof(overlay), "%.1f MB", mb(got));
        ImGui::ProgressBar(frac, barSz, overlay);
    }

    ImGui::SameLine();
    if (ImGui::Button("Cancel"))
        s.symbols.cancelPending();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Stop loading symbols and clear the queue.");
}

} // namespace

void drawMemoryView(app::AppState& s)
{
    // Track visibility so a close+reopen can rebuild the dock layout below.
    static bool memViewWasOpen = false;
    if (!s.showMemView) { memViewWasOpen = false; return; }

    // Center the window on its first open; FirstUseEver then lets a dragged
    // position win on later opens. (The brief 0,0 flash on open is a separate,
    // DWM-composition issue handled by cloaking in main.cpp, not by this seed.)
    const ImGuiViewport* mainVp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(mainVp->GetCenter(), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(820, 620), ImGuiCond_FirstUseEver);
    // Always its own OS window: never dockable, never auto-merged into the main
    // window. The three panes inside still dock freely among themselves.
    ImGuiWindowClass alwaysOwnWindow;
    alwaysOwnWindow.ViewportFlagsOverrideSet = ImGuiViewportFlags_NoAutoMerge;
    ImGui::SetNextWindowClass(&alwaysOwnWindow);
    // NoResize: resizing is done by the native OS border (see kPaneFlags).
    // NoScrollbar/NoScrollWithMouse: this window is just a fixed host for the
    // dockspace and the status strip, so it must never scroll - the panes inside
    // handle their own scrolling.
    const ImGuiWindowFlags memViewFlags = ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse;
    if (!ImGui::Begin("Memory View", &s.showMemView, memViewFlags))
    {
        ImGui::End();
        return;
    }

    if (!s.proc.is_open())
    {
        ImGui::TextUnformatted("No process attached.");
        ImGui::End();
        return;
    }

    // Auto-detect the disassembly mode from the target's bitness every frame, so
    // it stays correct even if the user re-attaches to a different process while
    // this window is open. A WOW64 process (32-bit on 64-bit Windows) is x86.
    s.memViewArch = mem::is_wow64(s.proc) ? 1 : 0;

    // Refresh the module list every couple seconds; modules change rarely, so
    // this still catches a freshly loaded DLL cheaply.
    const double modNow = ImGui::GetTime();
    if (modNow >= s.modulesNextRefresh)
    {
        // Module bases may have shifted; this drops the base-keyed caches and
        // re-resolves anchored addy entries too.
        app::refreshModules(s);
        s.modulesNextRefresh = modNow + 2.0;
    }

    // --- Shared address bar (seeds both the disasm and hex panes) -----------
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Go to");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    const bool go = app::addrInput(s, "##goto", s.memGotoInput,
        sizeof(s.memGotoInput), ImGuiInputTextFlags_EnterReturnsTrue);

    ImGui::SameLine();
    uintptr_t gotoAddr = 0;
    const bool gotoValid = s.memGotoInput[0] && app::parseAddrExpr(s, s.memGotoInput, gotoAddr);
    ImGui::BeginDisabled(!gotoValid);
    if ((ImGui::Button("Go") || (go && gotoValid)))
    {
        pushHistory(s.disasmHistory, s.disasmAddr);
        pushHistory(s.hexHistory, s.hexAddr);
        s.disasmAddr = gotoAddr;
        s.hexAddr    = gotoAddr;
    }
    ImGui::EndDisabled();

    // Back undoes the shared Go above in both panes at once.
    ImGui::SameLine();
    ImGui::BeginDisabled(s.disasmHistory.empty() && s.hexHistory.empty());
    if (ImGui::Button("Back"))
    {
        goBack(s.disasmHistory, s.disasmAddr);
        goBack(s.hexHistory, s.hexAddr);
        // Reflect the restored address in the Go field so Back doesn't look like
        // a no-op when the Memory Regions tab is in front.
        snprintf(s.memGotoInput, sizeof(s.memGotoInput), "%llX",
            (unsigned long long)s.disasmAddr);
    }
    ImGui::EndDisabled();

    ImGui::SameLine(0, 20);
    ImGui::Text("Mode: %s", s.memViewArch == 1 ? "x86" : "x64");

    if (s.writeError[0] && ImGui::GetTime() < s.writeErrorUntil)
    {
        ImGui::SameLine(0, 20);
        ImGui::TextColored(ImVec4(0.85f, 0.1f, 0.1f, 1.f), "%s", s.writeError);
    }

    ImGui::Separator();

    // --- IDA-style pane sync -------------------------------------------------
    // Whichever pane moved since last frame drags the opted-in other along.
    // Done once up front so every navigation source propagates the same way,
    // without pushing history (the follow isn't a jump the user asked for).
    if (s.syncHexToDisasm && s.disasmAddr != s.prevDisasmAddr)
        s.hexAddr = s.disasmAddr;
    if (s.syncDisasmToHex && s.hexAddr != s.prevHexAddr)
        s.disasmAddr = s.hexAddr;
    s.prevDisasmAddr = s.disasmAddr;
    s.prevHexAddr    = s.hexAddr;

    // --- Dockspace hosting the three panels ---------------------------------
    // Default layout: Disassembly on top with Memory Regions tabbed behind it,
    // Hex View below, both visible at once. The user can re-split freely.
    const ImGuiID dockId = ImGui::GetID("MemViewDockSpace");
    static bool layoutBuilt = false;
    static bool focusDisasm = false;
    // Remember the split nodes so a re-opened pane re-docks to its home.
    static ImGuiID topId = 0, bottomId = 0;
    // While hidden, ImGui eventually garbage-collects the dock node, so a reopen
    // must rebuild the layout rather than assume the old node still exists.
    const bool justReopened = !memViewWasOpen;
    memViewWasOpen = true;
    if (justReopened) layoutBuilt = false;

    // Tearing Hex View out leaves its split node behind as an empty gray gap.
    // Reclaim that space by collapsing to a single node with
    // Disassembly/Memory Regions; the floating Hex View is left as-is.
    if (layoutBuilt && bottomId != 0)
    {
        ImGuiDockNode* botNode = ImGui::DockBuilderGetNode(bottomId);
        if (botNode && botNode->IsEmpty())
        {
            ImGui::DockBuilderRemoveNode(dockId);
            ImGui::DockBuilderAddNode(dockId,
                ImGuiDockNodeFlags_DockSpace | ImGuiDockNodeFlags_NoWindowMenuButton);
            ImGui::DockBuilderSetNodeSize(dockId, ImGui::GetContentRegionAvail());
            ImGui::DockBuilderDockWindow("Disassembly", dockId);
            ImGui::DockBuilderDockWindow("Memory Regions", dockId);
            ImGui::DockBuilderDockWindow("Modules", dockId);
            ImGui::DockBuilderFinish(dockId);
            topId = dockId;
            bottomId = 0;
        }
    }

    if (!layoutBuilt)
    {
        layoutBuilt = true;
        focusDisasm = true;
        ImGui::DockBuilderRemoveNode(dockId);
        ImGui::DockBuilderAddNode(dockId,
            ImGuiDockNodeFlags_DockSpace | ImGuiDockNodeFlags_NoWindowMenuButton);
        ImGui::DockBuilderSetNodeSize(dockId, ImGui::GetContentRegionAvail());

        topId = ImGui::DockBuilderSplitNode(
            dockId, ImGuiDir_Up, 0.58f, nullptr, &bottomId);

        // Disassembly + Memory Regions + Modules on top, Hex View below.
        ImGui::DockBuilderDockWindow("Disassembly", topId);
        ImGui::DockBuilderDockWindow("Memory Regions", topId);
        ImGui::DockBuilderDockWindow("Modules", topId);
        ImGui::DockBuilderDockWindow("Hex View", bottomId);
        ImGui::DockBuilderFinish(dockId);
    }
    // The status strip only shows while a load runs; when idle the dockspace
    // fills the window. It's a Separator plus one frame-height row, so reserve
    // that height and the two spacing gaps below the dockspace.
    const bool showStatus = s.symbols.busy();
    const float footerH = showStatus
        ? ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y * 2.0f
        : 0.0f;
    // NoWindowMenuButton removes the little arrow/menu button on the tab bars.
    ImGui::DockSpace(dockId, ImVec2(0, -footerH), ImGuiDockNodeFlags_NoWindowMenuButton);

    if (showStatus)
    {
        ImGui::Separator();
        drawSymbolStatusBar(s);
    }

    ImGui::End();

    // Each pane is a separate docked window with a null p_open, so it gets no
    // close button; the panes can be torn out but never closed. Submission order
    // sets the tab order, so Disassembly comes before Memory Regions.
    //
    // Re-docking on re-open: right after the whole Memory View window was
    // hidden and shown again, steer every pane back to its original node for
    // that one frame instead of letting it reappear as a loose float.
    if (justReopened) ImGui::SetNextWindowDockID(topId, ImGuiCond_Always);
    if (ImGui::Begin("Disassembly", nullptr, kPaneFlags))
        drawDisasm(s);
    ImGui::End();

    if (justReopened) ImGui::SetNextWindowDockID(topId, ImGuiCond_Always);
    if (ImGui::Begin("Memory Regions", nullptr, ImGuiWindowFlags_NoResize))
        drawRegions(s);
    ImGui::End();

    if (justReopened) ImGui::SetNextWindowDockID(topId, ImGuiCond_Always);
    if (ImGui::Begin("Modules", nullptr, ImGuiWindowFlags_NoResize))
        drawModules(s);
    ImGui::End();

    if (justReopened) ImGui::SetNextWindowDockID(bottomId, ImGuiCond_Always);
    if (ImGui::Begin("Hex View", nullptr, kPaneFlags))
        drawHex(s);
    ImGui::End();

    // A later-submitted sibling would be auto-selected, so force Disassembly
    // active once.
    if (focusDisasm)
    {
        focusDisasm = false;
        ImGui::SetWindowFocus("Disassembly");
    }

    // Bring the Regions pane forward; it clears the flag on the first frame it
    // gets to draw.
    if (s.regionsFollow)
        ImGui::SetWindowFocus("Memory Regions");

    drawAssembleModal(s);
    drawAsmNopConfirm(s);
    drawChangeOpcodeModal(s);
    drawSignatureModal(s);
    drawFindSignatureModal(s);
    drawGotoAddressModal(s, s.showGotoDisasm, s.gotoDisasmInput,
        sizeof(s.gotoDisasmInput), s.disasmAddr, s.disasmHistory,
        "Go to Address##disasm", "Disassembly");
    drawGotoAddressModal(s, s.showGotoHex, s.gotoHexInput,
        sizeof(s.gotoHexInput), s.hexAddr, s.hexHistory,
        "Go to Address##hex", "Hex View");
    drawHexEditValueModal(s);
}

} // namespace ui
