cmake_minimum_required(VERSION 3.20)

# Standalone project: the kernel driver is built with the MSVC-compatible toolchain
# (cl.exe or clang-cl) plus the Windows Driver Kit, NOT the app's clang/vcpkg preset.
# Configure it on its own, e.g. from a "x64 Native Tools" prompt:
#     cmake --preset release && cmake --build --preset release  (or "debug")
# Output: driver/build/memview.sys  (copy it next to memview.exe). See README.md.
project(memview_driver CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The memview driver only builds on Windows.")
endif()

# clang-cl reports as Clang but drives MSVC-style flags; plain gcc/clang can't build
# a kernel driver here.
if(NOT (MSVC OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
    message(FATAL_ERROR
        "Configure the driver with an MSVC-compatible compiler (cl or clang-cl). "
        "Run from a Visual Studio 'x64 Native Tools' command prompt.")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

# CMake's Debug preset adds /RTC1, which calls into _RTC_CheckStackVars/_RTC_InitBase/
# _RTC_Shutdown - CRT runtime-check support that doesn't exist in kernel mode (NODEFAULTLIB
# below). Strip it so Debug links; the WDK doesn't offer a runtime-checks equivalent.
string(REGEX REPLACE "/RTC[1su]+" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
string(REGEX REPLACE "/RTC[1su]+" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

wdk_add_driver(memview src/main.cpp src/memory/memory.cpp src/physmem/physmem.cpp src/ioctl/dispatch.cpp)

# Test-sign right after linking, so any build trigger (VS Code's Build button,
# `cmake --build`, build.cmd) produces a loadable .sys, not just the standalone
# script. sign.ps1 runs via Start-Process as a genuinely separate child process,
# so its own `exit 1` on failure only ends that child - the outer -Command then
# unconditionally `exit 0`s, leaving the build itself green (a failed/unelevated
# sign still prints its own error text above, .sys is just left unsigned).
add_custom_command(TARGET memview POST_BUILD
    COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command
        "Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${CMAKE_CURRENT_SOURCE_DIR}/sign.ps1','-SysPath','$<TARGET_FILE:memview>' -Wait -NoNewWindow; exit 0"
    COMMENT "Test-signing memview.sys"
    VERBATIM
)
