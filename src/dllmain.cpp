/*
 * MIT License
 *
 * Copyright (c) 2024 Dominik Protasewicz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file dllmain.cpp
 * @brief Valkyria Chronicles Fix
 *
 * @details
 * Reference build: Steam `Valkyria.exe`, 32-bit, image base `0x00400000`. `FUN_`/`DAT_` names are Ghidra's
 * default labels for that build. Every patch locates its code by signature.
 *
 * How the game sizes its screen:
 * - **Screen struct.** `FUN_00404340` reads the resolution from `system_config.xml` and, on a screen wider
 *   than 16:9, fits a centered 16:9 box inside it. Render targets, `DisplayWidth`/`DisplayHeight`
 *   (`0x01a7fc20`/`0x01a7fc24`) and the UI screen table all derive from that box, and the final composite
 *   draws the frame at the box's offset. [`fixResolution`] widens the box to the full screen.
 * - **3D is Hor+.** The perspective builder (`FUN_0081bb90`) treats the FOV as vertical against
 *   `DisplayHeight`, so a wider frame shows more to the sides with the same vertical view.
 */

// System includes
#include <windows.h>
#include <string>
#include <filesystem>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <array>
#include <vector>
#include <cstring>

// Local includes
#include "utils.hpp"

// Version string
constexpr std::string VERSION = "1.0.1";

// .yml to struct
typedef struct yml_t {
    std::string name;
    bool masterEnable;
} yml_t;

// Globals
namespace {
    Utils::ModuleInfo module(GetModuleHandle(nullptr));

    YAML::Node config;  ///< Loaded by `readYml`, which catches a missing or invalid file.
    yml_t yml{};

    /**
     * @brief The screen the game renders at, recorded by the resolution hook.
     *
     * @details
     * The resolution hook only runs on screens wider than 16:9, so `ultrawide` stays false at 16:9 and
     * narrower, and every other hook then leaves the game alone.
     */
    struct Screen {
        bool ultrawide = false;
        f32 width = 0.0f;       ///< Back-buffer width W.
        f32 height = 0.0f;      ///< Back-buffer height H.
        f32 width169 = 0.0f;    ///< Width of the centered 16:9 box, H * 16 / 9.
        f32 offset169 = 0.0f;   ///< Left edge of the centered 16:9 box, (W - W169) / 2.
    } screen;

    /// The largest texture current GPUs create under D3D9 (`D3DCAPS9::MaxTextureWidth`). The render targets are
    /// `W x W`, so wider screens keep the game's 16:9 box.
    constexpr i32 maxTextureSize = 16384;

    /**
     * @brief The screen struct `FUN_00404340` fills, located through the operands of its own stores.
     *
     * @details
     * `boxH` (`0x01b94830`) is the operand of the hooked `mov [boxH], esi`; the other fields sit at fixed
     * offsets from it: real width and height at -0xC/-0x8, box width at -0x4, the static-init guard at +0x14.
     */
    struct ScreenStruct {
        i32* width = nullptr;
        i32* height = nullptr;
        i32* boxWidth = nullptr;
        i32* boxHeight = nullptr;
        i32* squareWidth = nullptr;   ///< Render-target width `sqW` (+0x04).
        i32* squareHeight = nullptr;  ///< Render-target height `sqH` (+0x08).
        u32* guard = nullptr;
    } screenStruct;
}

/**
 * @brief Opens and initializes logging system.
 *
 * @return void
 */
void logOpen() {
    // spdlog initialisation
    auto logger = spdlog::basic_logger_mt("ValkyriaChroniclesFix", "ValkyriaChroniclesFix.log", true);
    spdlog::set_default_logger(logger);
    spdlog::flush_on(spdlog::level::debug);

    // Get game name and exe path
    WCHAR exePath[_MAX_PATH] = { 0 };
    GetModuleFileNameW(module.address, exePath, MAX_PATH);
    std::filesystem::path exeFilePath = exePath;
    module.name = exeFilePath.filename().string();

    // Log module details
    LOG("-------------------------------------");
    LOG("Compiler: {:s}", Utils::getCompilerInfo());
    LOG("Compiled: {:s} at {:s}", __DATE__, __TIME__);
    LOG("Version: {:s}", VERSION);
    LOG("Module Name: {:s}", module.name);
    LOG("Module Path: {:s}", exeFilePath.string());
    LOG("Module Addr: 0x{:x}", reinterpret_cast<uintptr_t>(module.address));
    LOG("-------------------------------------");
}

/**
 * @brief Closes and cleans up the logging system.
 *
 * @details
 * Flushes all pending log messages, drops all loggers, and shuts down the spdlog system.
 *
 * @return void
 */
void logClose() {
    spdlog::drop_all();
    spdlog::shutdown();
}

/**
 * @brief Reads and parses configuration settings from a YAML file.
 *
 * @return void
 */
void readYml() {
    try {
        config = YAML::LoadFile("ValkyriaChroniclesFix.yml");

        yml.name = config["name"].as<std::string>("Valkyria Chronicles Fix");

        yml.masterEnable = config["masterEnable"].as<bool>(true);
    }
    catch (const std::exception& e) {
        // A missing or malformed file must not take the game down at startup.
        spdlog::error("readYml : Could not read ValkyriaChroniclesFix.yml ({}); the fix is disabled", e.what());
        yml = yml_t{};
        yml.masterEnable = false;
    }

    LOG("Name: {}", yml.name);
    LOG("MasterEnable: {}", yml.masterEnable);
    LOG("-------------------------------------");
}

/**
 * @brief Removes the pillarbox so the game renders across the whole ultrawide back buffer.
 *
 * @details
 * The game sizes everything it draws from one screen struct, built once by the function-local static
 * constructor `FUN_00404340`. Its first caller is the C++ static initializer `FUN_00844dc0`, which `__cinit`
 * runs before `WinMain`. The constructor reads the resolution the launcher stored in `system_config.xml`,
 * width `W` in ECX and height `H` in ESI, and compares `W * 9` against `H * 16` (EBX). When the screen is
 * wider than 16:9 it fits a 16:9 region inside it:
 *
 * ```
 * mov  eax, 0x38E38E39   ; EBX = H * 16 here
 * mul  ebx
 * mov  edi, edx          ; EDI = EBX / 9 * 2
 * mov  eax, 0x38E38E39
 * imul ebx
 * sar  edx, 1
 * mov  eax, edx
 * shr  eax, 0x1F
 * add  eax, edx          ; EAX = EBX / 9            -> render width
 * sub  ecx, eax
 * shr  edi, 1            ; EDI = EBX / 9            -> width for UI scaling
 * sar  ecx, 1            ; ECX = (W - EAX) / 2      -> viewport X offset
 * mov  [boxH], esi       ; <- hook
 * mov  [Y], 0
 * mov  [renderH], esi
 * mov  [renderW], eax
 * mov  [X], ecx
 * mov  ebx, esi          ; then [boxW] = edi at the join
 * ```
 *
 * The results are stored as the viewport X offset, the render width, and the width every size in the engine
 * derives from (render targets, `DisplayWidth`, the UI screen table). Only the final composite
 * (`FUN_00584610`, and its copy `FUN_0056c2c0`) reads the offset: it clears the full back buffer to black and
 * draws the 16:9 frame at that offset, so a 32:9 screen gets black bars at its sides.
 *
 * How was this found?
 * `0x38E38E39` is `ceil(2^33 / 9)`, the constant MSVC emits for a division by 9, and the block above is the
 * only place where it divides `H * 16`. It runs only on the `W * 9 > H * 16` branch: exactly 16:9 and narrower
 * screens never reach it. The real `W` and `H` were stored at `boxH - 0xC` and `boxH - 0x8` before the branch,
 * and every store above is checked against those offsets before hooking.
 *
 * Why it works:
 * At the first store the hook sets `EAX = EDI = W`, `ECX = 0` and `ESI = H`, which is what the game computes
 * for a 16:9 screen: no offset, and every size follows `W`. The 3D view is Hor+ (`FUN_0081bb90` treats the
 * FOV as vertical against `DisplayHeight`), so the wider frame shows more to the sides with the same
 * vertical FOV. Ultimate ASI Loader loads this DLL from the game's first kernel32 call
 * (`GetSystemTimeAsFileTime` in `__security_init_cookie`), before `__cinit`, so the hook is in place before the
 * struct is built. The stores are identical in an exe that was statically patched at the math above, so the
 * hook also replaces such hard-coded values with the launcher's resolution.
 *
 * The hook records the screen size for the other fixes and applies the operand patches, since this is the
 * first moment the resolution is known. Every render target becomes `W x W`, so a screen wider than the largest
 * texture GPUs create (16384) keeps the game's own 16:9 box, written out explicitly, and every other fix stays
 * off. The HUD fixes only act when the screen is at least 16 units of
 * `W * 9 - H * 16` wider than 16:9, which leaves rounding cases like 1366x768 alone; for those the hook only
 * widens the box by the one pixel column the game would leave black.
 *
 * @return void
 */
void fixResolution() {
    Utils::SignatureHook hook {
        .tag = __func__,
        .signature = "89 35 ?? ?? ?? ??    C7 05 ?? ?? ?? ?? 00 00 00 00    89 35 ?? ?? ?? ??    A3 ?? ?? ?? ??    "
                     "89 0D ?? ?? ?? ??    8B DE",
        .offset = 0
    };
    bool enable = yml.masterEnable;
    if (!enable) {
        return;
    }
    uintptr_t addr = Utils::patternScan(module.address, hook.signature);
    if (addr == 0) {
        LOG("{} : Did not find '{}'", hook.tag, hook.signature);
        return;
    }
    auto operand = [addr](uintptr_t offset) { return *reinterpret_cast<uintptr_t*>(addr + offset); };
    uintptr_t boxH = operand(0x02);
    if (operand(0x08) != boxH - 0x18 || operand(0x12) != boxH - 0x10 || operand(0x17) != boxH - 0x14 ||
        operand(0x1D) != boxH - 0x1C) {
        LOG("{} : Unexpected screen struct layout around {:x}; not hooked", hook.tag, boxH);
        return;
    }
    screenStruct.width = reinterpret_cast<i32*>(boxH - 0x0C);
    screenStruct.height = reinterpret_cast<i32*>(boxH - 0x08);
    screenStruct.boxWidth = reinterpret_cast<i32*>(boxH - 0x04);
    screenStruct.boxHeight = reinterpret_cast<i32*>(boxH);
    screenStruct.squareWidth = reinterpret_cast<i32*>(boxH + 0x04);
    screenStruct.squareHeight = reinterpret_cast<i32*>(boxH + 0x08);
    screenStruct.guard = reinterpret_cast<u32*>(boxH + 0x14);
    if ((*screenStruct.guard & 1) != 0 || *screenStruct.width != 0) {
        LOG("{} : The screen struct is already built, this DLL was loaded too late to fix it. Load it with "
            "Ultimate ASI Loader as d3d9.dll in the game folder.", hook.tag);
        return;
    }
    Utils::injectHook(enable, module, hook,
        [](SafetyHookContext& ctx) {
            i32 w = *screenStruct.width;
            i32 h = *screenStruct.height;
            bool ultrawide = w * 9 - h * 16 >= 16;
            if (ultrawide && w > maxTextureSize) {
                // The W x W render targets would exceed the GPU's texture size. Keep the game's own 16:9 box
                // (0x00404438..0x00404455), written out so that an exe statically patched at that math gets it too.
                // screen.ultrawide stays false, so every other fix stays off.
                spdlog::error("fixResolution : {} pixels is wider than the {} pixel textures GPUs create; keeping the "
                    "game's 16:9 pillarbox", w, maxTextureSize);
                i32 box = h * 16 / 9;
                ctx.eax = box;
                ctx.edi = box;
                ctx.ecx = (w - box) >> 1;
                ctx.esi = h;
                return;
            }
            ctx.eax = w;
            ctx.edi = w;
            ctx.ecx = 0;
            ctx.esi = h;

            screen.ultrawide = ultrawide;
            screen.width = static_cast<f32>(w);
            screen.height = static_cast<f32>(h);
            screen.width169 = screen.height * 16.0f / 9.0f;
            screen.offset169 = (screen.width - screen.width169) / 2.0f;
        }
    );
}

/**
 * @brief Entry point for a DLL, called by the system when the DLL is loaded or unloaded.
 *
 * @details
 * - **DLL_PROCESS_ATTACH**: Initializes logging, reads the configuration and applies every fix. Ultimate
 *   ASI Loader loads this DLL on the game's main thread from the game's first kernel32 call, before the
 *   C++ static initializers that build the screen struct and the UI screen table. Applying the fixes here,
 *   synchronously, guarantees they are in place before that. The log stays open: the resolution hook can
 *   still report a screen too wide to fix when the static initializers run.
 *
 * - **DLL_PROCESS_DETACH**: Closes the log when the DLL is unloaded with FreeLibrary.
 *
 * - **DLL_THREAD_ATTACH**, **DLL_THREAD_DETACH**: No action is taken.
 *
 * @param hModule Handle to the DLL module. This parameter is used to identify the DLL.
 * @param ul_reason_for_call Indicates the reason for the call (e.g., process attach, thread attach).
 * @param lpReserved Reserved for future use. This parameter is typically NULL.
 * @return BOOL Always returns TRUE to indicate successful execution.
 */
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        try {
            logOpen();
        }
        catch (const std::exception&) {
            // The log file could not be created. Run the game unmodified rather than crash it at startup.
            return TRUE;
        }
        try {
            readYml();
            fixResolution();
        }
        catch (const std::exception& e) {
            spdlog::error("DllMain : {}; the fixes installed before this point stay active", e.what());
        }
        break;
    case DLL_PROCESS_DETACH:
        // lpReserved is null for FreeLibrary; at process exit other threads are already gone and nothing
        // needs releasing.
        if (lpReserved == nullptr) {
            logClose();
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
