#pragma once
#include "app/state.hpp"
#include <d3d11.h>
#include <string>

// Modal process list for attaching to a target (opened from the toolbar).
namespace ui {

void drawProcessPicker(app::AppState& s);

} // namespace ui

// Cache of process-icon textures, keyed by exe path. Extraction runs on worker
// threads; the render thread only looks up in get() and uploads in pump().
namespace ui::icons {

enum class State {
    Missing,  // never asked for, or the path is empty
    Pending,
    Ready,
    Fallback, // no icon in the file; get() returns the generic one
};

// Call once after the D3D11 device is created.
void init(ID3D11Device* device);

// Icon texture for `exePath`. The first call queues it and returns nullptr; a
// later frame returns it, or the generic icon for exes carrying none.
ID3D11ShaderResourceView* get(const std::string& exePath);

// For callers reserving layout space before the texture lands. Queues nothing.
State state(const std::string& exePath);

// Call once a frame: uploads whatever the workers finished.
void pump();

// Stops the workers and releases the textures. Call before destroying the device.
void shutdown();

} // namespace ui::icons
