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
 * - **UI screen table.** The static initializer `FUN_00844dc0` builds a HyScreen preset at `0x017542cc`
 *   from the box: viewport, center, 2D offset `(boxW - 1280) / 2` at `+0x44` and 2D scale `boxW / 1280`
 *   at `+0x4c`, `boxH / 720` at `+0x50`. Every HUD and menu is laid out in a virtual 1280x720 space and
 *   mapped to pixels by the 2D ortho of `FUN_0082a100`: `px = W/2 + sx * (x + offx - W/2)`.
 *   [`fixHud`] makes that mapping a centered, undistorted 16:9 box.
 * - **Pixel/virtual conversions.** A few draws compute a position in pixels and convert it to virtual
 *   units by dividing by the 2D scale, assuming `px = x * sx`. With the centered mapping those need the
 *   16:9 offset removed. The other fixes handle them one by one.
 */

// System includes
#include <windows.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <array>
#include <vector>
#include <bit>
#include <cstring>

// Local includes
#include "utils.hpp"

// Version string
constexpr std::string VERSION = "1.0.1";

// .yml to struct
typedef struct resolution_t {
    i32 width;
    i32 height;
} resolution_t;

typedef struct yml_t {
    std::string name;
    bool masterEnable;
    resolution_t resolution;
    bool borderless;
    bool hud;
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
        bool hudCentred = false;    ///< `fixHud` has centered the UI screen table.
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

    /// A byte patch whose original bytes were matched by its signature, applied once the mode is known.
    struct BytePatch {
        uintptr_t address = 0;
        std::vector<u8> bytes;
    };

    /// Return address of the `FUN_00610430` call in the unit avoidance check `FUN_004da1f0`.
    uintptr_t avoidanceReturn = 0;

    /// UI screen table y scale `boxH / 720`; the x scale `boxW / 1280` is the float right before it.
    f32* uiTableScaleY = nullptr;
    /// The launcher's "windowed" setting from `system_config.xml` (`0x01b940ac`), 1 for a windowed device.
    i32* windowedSetting = nullptr;

    /**
     * @brief Reads a 4-byte absolute operand from the instruction bytes of a signature match.
     *
     * @param sig IDA-style signature to scan for.
     * @param operandOffset Offset of the operand from the start of the match.
     * @return T The operand as a pointer, or nullptr if the signature was not found.
     */
    template <typename T>
    T* resolveOperand(std::string sig, uintptr_t operandOffset) {
        uintptr_t addr = Utils::patternScan(module.address, sig);
        return addr != 0 ? *reinterpret_cast<T**>(addr + operandOffset) : nullptr;
    }

    /**
     * @brief The horizontal offset the centered HUD adds to every virtual position.
     *
     * @details
     * Inlined, so that callbacks at sites with live x87 values never call a function returning in ST(0).
     *
     * @return f32 (W - W169) / 2 once `fixHud` has centered the UI table on an ultrawide screen, else 0.
     */
    __forceinline f32 hudOffset() {
        return screen.hudCentred ? screen.offset169 : 0.0f;
    }

    /**
     * @brief Writes a byte patch.
     */
    void applyBytePatch(const BytePatch& patch) {
        DWORD oldProtect;
        LPVOID addr = reinterpret_cast<LPVOID>(patch.address);
        VirtualProtect(addr, patch.bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(addr, patch.bytes.data(), patch.bytes.size());
        VirtualProtect(addr, patch.bytes.size(), oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), addr, patch.bytes.size());
    }
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
 * @details
 * `resolution` replaces the resolution the game runs at and `borderless` runs it in a borderless window (see
 * `fixDisplayMode`).
 * Every fix takes the width and height from the game's own state.
 *
 * @return void
 */
void readYml() {
    try {
        config = YAML::LoadFile("ValkyriaChroniclesFix.yml");

        yml.name = config["name"].as<std::string>("Valkyria Chronicles Fix");

        yml.masterEnable = config["masterEnable"].as<bool>(true);

        yml.resolution.width = config["resolution"]["width"].as<i32>(0);
        yml.resolution.height = config["resolution"]["height"].as<i32>(0);
        yml.borderless = config["borderless"].as<bool>(true);

        yml.hud = config["hud"].as<bool>(true);
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
    LOG("Resolution.Width: {}", yml.resolution.width);
    LOG("Resolution.Height: {}", yml.resolution.height);
    LOG("Borderless: {}", yml.borderless);
    LOG("HUD: {}", yml.hud);
    LOG("-------------------------------------");
}

/**
 * @brief Sets the large-address-aware flag in an exe on disk; the original is kept as `<exe>.bak`.
 *
 * @return true if the exe now has the flag.
 */
bool patchLargeAddressAware(const std::filesystem::path& exe) {
    std::filesystem::path patched = exe;
    patched += ".laa";
    std::filesystem::path backup = exe;
    backup += ".bak";
    std::error_code ec;
    if (!std::filesystem::copy_file(exe, patched, std::filesystem::copy_options::overwrite_existing, ec)) {
        return false;
    }
    bool written = false;
    {
        std::fstream file(patched, std::ios::in | std::ios::out | std::ios::binary);
        LONG ntOffset = 0;
        DWORD signature = 0;
        WORD characteristics = 0;
        std::streamoff field = offsetof(IMAGE_NT_HEADERS, FileHeader.Characteristics);
        file.seekg(offsetof(IMAGE_DOS_HEADER, e_lfanew));
        file.read(reinterpret_cast<char*>(&ntOffset), sizeof(ntOffset));
        file.seekg(ntOffset);
        file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
        file.seekg(ntOffset + field);
        file.read(reinterpret_cast<char*>(&characteristics), sizeof(characteristics));
        if (file && signature == IMAGE_NT_SIGNATURE) {
            characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
            file.seekp(ntOffset + field);
            file.write(reinterpret_cast<const char*>(&characteristics), sizeof(characteristics));
            written = static_cast<bool>(file.flush());
        }
    }
    // Windows lets a running exe be renamed but not replaced, so it moves aside for the patched copy.
    if (written) {
        std::filesystem::rename(exe, backup, ec);
        written = !ec;
    }
    if (written) {
        std::filesystem::rename(patched, exe, ec);
        if (ec) {
            std::filesystem::rename(backup, exe, ec);
            written = false;
        }
    }
    if (!written) {
        std::filesystem::remove(patched, ec);
    }
    return written;
}

/**
 * @brief Gives the game 4 GB of address space instead of 2 GB by making Valkyria.exe large-address-aware.
 *
 * @details
 * Every render target is `W x W`, and the PC port keeps CPU heap copies of four of them to restore them after a
 * device Reset (`FUN_004046f0`), each refreshed through a full-size `4 * W * W` byte SYSTEMMEM readback: about
 * 900 MB of copies plus 225 MB blocks at 7680 wide, more than a 32-bit exe without the flag can fit next to the
 * rest of the game. The game's D3D error report then crashes on the failed readback (it indexes its 11-entry
 * name table with kind 11).
 *
 * Windows reads IMAGE_FILE_LARGE_ADDRESS_AWARE from the exe header when the process starts. When this process
 * started without it, the exe is patched on disk (`patchLargeAddressAware`) at the entry of WinMain
 * (`FUN_005cd480`), before the game takes its single-instance mutex, starts Steam or creates its window, and the
 * game is started again with the same command line while this process ends. A Steam file verification or update
 * restores the original exe, and the next start patches it again.
 *
 * @return void
 */
void fixLargeAddressAware() {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module.address);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<u8*>(module.address) + dos->e_lfanew);
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0) {
        return;
    }
    Utils::SignatureHook hook {
        .tag = __func__,
        .signature = "55    8B EC    83 E4 F8    81 EC C0 08 00 00    56    57    68 ?? ?? ?? ??    6A 01    6A 00    FF 15",
        .offset = 0
    };
    Utils::injectHook(yml.masterEnable, module, hook,
        [](SafetyHookContext& ctx) {
            WCHAR path[MAX_PATH] = { 0 };
            GetModuleFileNameW(module.address, path, MAX_PATH);
            std::filesystem::path exe = path;
            if (!patchLargeAddressAware(exe)) {
                spdlog::error("fixLargeAddressAware : Could not patch {:s}; the game keeps 2 GB of memory and can run "
                    "out of it at ultrawide resolutions", exe.string());
                return;
            }
            STARTUPINFOW startup { sizeof(startup) };
            PROCESS_INFORMATION process {};
            std::wstring commandLine = GetCommandLineW();
            if (!CreateProcessW(exe.c_str(), commandLine.data(), nullptr, nullptr, FALSE, 0, nullptr,
                exe.parent_path().c_str(), &startup, &process)) {
                spdlog::error("fixLargeAddressAware : Patched {:s}, but could not restart it; it gets 4 GB from the next "
                    "start", exe.string());
                return;
            }
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            LOG("fixLargeAddressAware : Patched {:s} and restarted it", exe.string());
            TerminateProcess(GetCurrentProcess(), 0);
        }
    );
}

/**
 * @brief Runs the game in a borderless window (`borderless`) and at the yml's `resolution`.
 *
 * @details
 * The launcher writes a resolution and a "windowed" setting to `system_config.xml`, which `FUN_006de690` parses
 * at the start of `FUN_00404340`. That function then loads the selected resolution at `0x004043e9` (ECX = width,
 * ESI = height, 1280x720 when the config has none) and stores it in the screen struct, from which the game
 * sizes everything else: the window (`FUN_00821360`, `FUN_00821110`), the D3D back buffer (`FUN_00825f10`) and
 * the 16:9 box. WinMain parses the file again (`FUN_006dfe50`) before it creates the device, so the "windowed"
 * setting is only final when the device creation reads it (`0x008050dd`: without it the creation flags get the
 * fullscreen bit 0x40000000, an exclusive fullscreen device). The window style is applied by
 * `FUN_00821110(andMask, orMask)`, which sets `(style & andMask) | orMask` and then sizes the window to exactly
 * W x H, centered on the adapter's monitor. The game passes WS_POPUP | WS_VISIBLE | WS_SYSMENU for fullscreen and
 * an overlapped window with a caption in windowed mode. It centers in the monitor's work area (`FUN_006e7bc0`
 * copies `rcWork`), which puts a full-height window above the top edge by half the taskbar.
 *
 * How was this found?
 * `CreateWindowExA` (`FUN_00821360`) and the only `SetWindowLongA` (`FUN_00821110`) both size the window from the
 * screen struct's width and height, and `0x01b940ac` is referenced by exactly two instructions, `0x008050dd` and
 * `0x00821a33`. Valkyria.exe's manifest declares it DPI aware, so the window size is in physical pixels.
 *
 * Why it works:
 * Replacing the loaded resolution behaves exactly like choosing it in the launcher. Setting "windowed" right
 * before the device reads it gives a windowed D3D device, forcing the game's own fullscreen style on every
 * `FUN_00821110` call makes its window borderless, and centering in `rcMonitor` instead of `rcWork` puts it at
 * the monitor's origin: W x H covering the whole screen at the desktop resolution. A smaller `resolution`, such as
 * 21:9 on a 32:9 monitor, gives a centered borderless window.
 *
 * A `resolution` of 0 keeps the desktop's in borderless mode and the launcher's otherwise, so with `borderless`
 * off and no `resolution` the game starts exactly as the launcher set it up.
 *
 * @return void
 */
void fixDisplayMode() {
    Utils::SignatureHook sizeHook {
        .tag = "fixDisplayMode (size)",
        .signature = "8B 48 04    8B 30    EB 0A    B9 00 05 00 00    BE D0 02 00 00    8B DE    C1 E3 04",
        .offset = 0x11
    };
    Utils::SignatureHook styleHook {
        .tag = "fixDisplayMode (style)",
        .signature = "6A FF    68 ?? ?? ?? ??    64 A1 00 00 00 00    50    83 EC 28    A1 ?? ?? ?? ??    33 C4    "
                     "89 44 24 24    53    55    56",
        .offset = 0
    };
    // `mov edi, [windowed]; sub edi, ebp; neg edi; sbb edi, edi; and edi, 0x40000000` before device creation.
    Utils::SignatureHook windowedHook {
        .tag = "fixDisplayMode (windowed)",
        .signature = "8B 3D ?? ?? ?? ??    2B FD    F7 DF    1B FF    81 E7 00 00 00 40",
        .offset = 0
    };
    bool resize = yml.borderless || yml.resolution.width > 0 || yml.resolution.height > 0;
    bool enable = yml.masterEnable && resize;
    if (enable && yml.borderless) {
        windowedSetting = resolveOperand<i32>(windowedHook.signature, 0x02);
        if (windowedSetting == nullptr) {
            LOG("fixDisplayMode : Did not find the windowed setting; the game keeps its fullscreen mode");
        }
    }
    bool borderless = enable && windowedSetting != nullptr;
    // FUN_006e7bc0 copying the monitor's rcWork: `movq xmm0, [esp+0x1c]; movq [esi+0x2c], xmm0; movq xmm0, [esp+0x24]`.
    // MONITORINFO is at esp+8, so rcMonitor is at esp+0x0c and esp+0x14.
    std::string workAreaSig = "85 C0    75 2B    F3 0F 7E 44 24 1C    66 0F D6 46 2C    F3 0F 7E 44 24 24    66 0F D6 46 34    C6 06 01";
    uintptr_t workArea = borderless ? Utils::patternScan(module.address, workAreaSig) : 0;
    if (workArea != 0) {
        applyBytePatch({ workArea + 0x09, { 0x0C } });
        applyBytePatch({ workArea + 0x14, { 0x14 } });
    }
    else if (borderless) {
        LOG("fixDisplayMode : Did not find the monitor rect lookup; the window stays centered in the work area");
    }
    Utils::injectHook(borderless, module, windowedHook,
        [](SafetyHookContext& ctx) {
            *windowedSetting = 1;
        }
    );
    Utils::injectHook(enable, module, sizeHook,
        [](SafetyHookContext& ctx) {
            // 0 keeps the desktop resolution in a borderless window and the launcher's otherwise.
            auto [desktopWidth, desktopHeight] = Utils::getDesktopDimensions();
            i32 defaultWidth = yml.borderless ? static_cast<i32>(desktopWidth) : static_cast<i32>(ctx.ecx);
            i32 defaultHeight = yml.borderless ? static_cast<i32>(desktopHeight) : static_cast<i32>(ctx.esi);
            i32 w = yml.resolution.width > 0 ? yml.resolution.width : defaultWidth;
            i32 h = yml.resolution.height > 0 ? yml.resolution.height : defaultHeight;
            if (w > 0 && h > 0) {
                ctx.ecx = static_cast<uintptr_t>(w);
                ctx.esi = static_cast<uintptr_t>(h);
            }
        }
    );
    Utils::injectHook(borderless, module, styleHook,
        [](SafetyHookContext& ctx) {
            // At the entry: [esp] return address, [esp+4] andMask, [esp+8] orMask.
            u32* args = reinterpret_cast<u32*>(ctx.esp);
            args[1] = 0;
            args[2] = WS_POPUP | WS_VISIBLE | WS_SYSMENU;
        }
    );
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
 * @brief Centers the HUD and menus in an undistorted 16:9 box.
 *
 * @details
 * Every HUD and menu tree is laid out in a virtual 1280x720 space and drawn through a HyScreen whose 2D
 * offset and scale come from the UI screen table that the static initializer `FUN_00844dc0` builds at
 * `0x017542cc` from the screen struct: offset `(boxW - 1280) / 2` at `+0x44`, x scale `boxW / 1280` at
 * `+0x4c` (`0x01754318`) and y scale `boxH / 720` at `+0x50` (`0x0175431c`). The ShEnvServer constructor
 * (`FUN_0056aea0`) copies them into the screens used by every scene context, and VlLoading
 * (`FUN_005e6d30`), the UI model screens and the radar read them too. `FUN_0082a100` maps a virtual `x` to
 * `px = W/2 + sx * (x + offx - W/2)`.
 *
 * With the full-width box the x scale is `W / 1280`, so the virtual 1280 units stretch across the whole
 * ultrawide screen.
 *
 * How was this found?
 * The table's last store is `fstp [0x0175431c]`, the y scale, right before `FUN_00844dc0` restores the SEH
 * frame (`mov fs:[0], ecx`). `W169 / 1280 == H / 720` exactly, so copying the y scale into the x scale and
 * keeping the offset `(W - 1280) / 2` gives `px = (W - W169) / 2 + x * H / 720`: the virtual space lands in a
 * centered, undistorted 16:9 box. At 16:9 `W / 1280 == H / 720`, so the copy changes nothing. Patching the
 * table before WinMain means every screen built from it gets the centered mapping, including the ones the
 * game creates before its first loading screen.
 *
 * @return void
 */
void fixHud() {
    Utils::SignatureHook hook {
        .tag = __func__,
        .signature = "DC 35 ?? ?? ?? ??    5E    5B    D9 1D ?? ?? ?? ??    64 89 0D 00 00 00 00    8B E5    5D    C3",
        .offset = 0x0E
    };
    bool enable = yml.masterEnable && yml.hud;
    if (enable) {
        // The operand of `fstp [scaleY]` at +8, and of the table's `fild [boxW]; fdiv [1280.0]; fstp [scaleX]`.
        uiTableScaleY = resolveOperand<f32>(hook.signature, 0x0A);
        std::string xScaleSig = "DB 05 ?? ?? ?? ??    DC 35 ?? ?? ?? ??    D9 1D ?? ?? ?? ??    75";
        uintptr_t xScale = Utils::patternScan(module.address, xScaleSig);
        bool xScaleOk = xScale != 0 && screenStruct.boxWidth != nullptr &&
            *reinterpret_cast<uintptr_t*>(xScale + 0x02) == reinterpret_cast<uintptr_t>(screenStruct.boxWidth) &&
            *reinterpret_cast<f64*>(*reinterpret_cast<uintptr_t*>(xScale + 0x08)) == 1280.0;
        f32* uiTableScaleX = xScaleOk ? *reinterpret_cast<f32**>(xScale + 0x0E) : nullptr;
        enable = uiTableScaleY != nullptr && uiTableScaleX == uiTableScaleY - 1;
        if (!enable) {
            LOG("{} : The UI table's x scale is not right before its y scale; not hooked, the HUD stays stretched",
                hook.tag);
        }
    }
    // Every HUD position fix checks screen.hudCentred, which stays false unless this callback ran.
    Utils::injectHook(enable, module, hook,
        [](SafetyHookContext& ctx) {
            if (!screen.ultrawide) {
                return;
            }
            uiTableScaleY[-1] = uiTableScaleY[0];
            screen.hudCentred = true;
        }
    );
}

/**
 * @brief Moves the full-screen backgrounds of talk scenes and the book menu back onto the screen.
 *
 * @details
 * Talk scenes with character portraits (VlTalkEventSystem and GameEndSystem, both through `FUN_00647650`)
 * draw a capture of the 3D frame behind the portraits, and the book menu (EsdInterfaceMainDraw, through
 * `FUN_0059a0f0`) draws its background render target. Both build a quad of `boxW x boxH` pixels, scale it by
 * `1 / sx` and `1 / sy` (`fld [0x01754318]`, `fdiv [0x0175431c]` into a scale matrix) and draw it through the
 * current scene context's HyScreen. That cancels the 2D scale but not the 2D offset, so on screen the quad
 * starts at `D = sx * (offx - W/2) + W/2`: 0 with the stock mapping, `(W - W169) / 2` with the centered HUD.
 *
 * How was this found?
 * At the draw call the four vertices are `{x, y, z, color, u, v}` with a stride of `0x18`, at `[esp+0x40]` in
 * `FUN_00647650` and `[esp+0x34]` in `FUN_0059a0f0` (`lea edx, [esp+...]; push 9; push edx` before
 * `FUN_0082ebd0`). The shift matches the reported 1280 px at 5120x1440, where `D = (5120 - 2560) / 2`.
 *
 * Why it works:
 * Subtracting `D` from each vertex x makes the quad cover exactly `[0, W]`, which is what the capture holds.
 *
 * @return void
 */
void fixFullscreenBackgrounds() {
    Utils::SignatureHook talkHook {
        .tag = "fixFullscreenBackgrounds (talk)",
        .signature = "83 C4 04    8D 54 24 40    6A 09    52    BF 02 00 00 00    E8",
        .offset = 3
    };
    Utils::SignatureHook bookHook {
        .tag = "fixFullscreenBackgrounds (book)",
        .signature = "E8 ?? ?? ?? ??    8D 54 24 34    6A 09    52    33 FF    E8",
        .offset = 5
    };
    bool enable = yml.masterEnable && yml.hud;
    Utils::injectHook(enable, module, talkHook,
        [](SafetyHookContext& ctx) {
            f32 shift = hudOffset();
            for (u32 i = 0; i < 4; i++) {
                *reinterpret_cast<f32*>(ctx.esp + 0x40 + i * 0x18) -= shift;
            }
        }
    );
    Utils::injectHook(enable, module, bookHook,
        [](SafetyHookContext& ctx) {
            f32 shift = hudOffset();
            for (u32 i = 0; i < 4; i++) {
                *reinterpret_cast<f32*>(ctx.esp + 0x34 + i * 0x18) -= shift;
            }
        }
    );
}

/**
 * @brief Keeps scene fades and the black curtain covering the whole screen.
 *
 * @details
 * VlSimpleFade (`FUN_00606f30`) draws a colored rect of `[0x017542d4] x [0x017542d8]` = 1280x720 virtual
 * units centered on the fade position, (640, 360), and the ShProcessManager curtain (`FUN_0057ab00`) draws
 * an opaque black quad from (0, 0) to (1280, 720). With the centered HUD the virtual 1280 units only cover the
 * 16:9 box.
 *
 * How was this found?
 * The fade's width is stored at `[esp+0x1c]` right before `FUN_00616df0` builds the rect (after the
 * `push eax` at the hook). The curtain writes `0.0` to the vertex x at `[esp+0x30]`/`[esp+0x40]` and `1280.0`
 * to `[esp+0x50]`/`[esp+0x60]` before `FUN_0082ecd0`.
 *
 * Why it works:
 * The whole screen spans `1280 * W / W169` virtual units around the center at 640. Widening the fade to that
 * and moving the curtain's edges to `640 -/+ 640 * W / W169` covers `[0, W]`.
 *
 * @return void
 */
void fixFades() {
    Utils::SignatureHook fadeHook {
        .tag = "fixFades (fade)",
        .signature = "50    C7 44 24 28 02 00 00 00    89 54 24 24    E8",
        .offset = 1
    };
    Utils::SignatureHook curtainHook {
        .tag = "fixFades (curtain)",
        .signature = "8D 44 24 30    6A 07    50    BF 02 00 00 00    E8",
        .offset = 0
    };
    bool enable = yml.masterEnable && yml.hud;
    Utils::injectHook(enable, module, fadeHook,
        [](SafetyHookContext& ctx) {
            if (!screen.hudCentred) {
                return;
            }
            *reinterpret_cast<f32*>(ctx.esp + 0x1C) *= screen.width / screen.width169;
        }
    );
    Utils::injectHook(enable, module, curtainHook,
        [](SafetyHookContext& ctx) {
            if (!screen.hudCentred) {
                return;
            }
            f32 half = 640.0f * screen.width / screen.width169;
            *reinterpret_cast<f32*>(ctx.esp + 0x30) = 640.0f - half;
            *reinterpret_cast<f32*>(ctx.esp + 0x40) = 640.0f - half;
            *reinterpret_cast<f32*>(ctx.esp + 0x50) = 640.0f + half;
            *reinterpret_cast<f32*>(ctx.esp + 0x60) = 640.0f + half;
        }
    );
}

/**
 * @brief Keeps the HUD markers drawn over units on their units.
 *
 * @details
 * Two functions project a world position to the main 3D screen and convert the pixel position to virtual
 * UI units as `sX / sx`:
 * - `FUN_0058d1b0`, slot 8 of SlgInterfaceHpMini, SlgInterfaceIWSpriteParts and VlInterfaceSprite3D (unit
 *   HP gauges, impact warnings, 3D sprites). The projected x sits at `[esp+0x18]`.
 * - `FUN_00610430`, the projection used by VlSprite, the scout direction band and unit selection. The
 *   projected x has been stored to `[esi]`; EDI holds the HyScreen whose 2D params divide it.
 *
 * `x / sx` is only the inverse of the 2D mapping while the 2D offset cancels against the screen center,
 * which holds for the stock table. With the centered HUD the marker lands `(W - W169) / 2` too far right.
 *
 * One caller of `FUN_00610430` is not a marker: the unit avoidance check `FUN_004da1f0` subtracts
 * `(DisplayWidth / 2, DisplayHeight / 2)` pixels from the virtual result and compares the distance against a
 * pixel radius, mixing units. For that caller (recognized by its return address) the hook instead keeps the
 * value the check sees on a 16:9 screen of the same height: `sX' = sX - D + sx * D`, so that
 * `sX' / sx - W / 2 = sX169 / sx - W169 / 2`.
 *
 * How was this found?
 * Both divisions read the HyScreen's 2D x scale at `+0x88` (`fdiv [eax+0x88]` / `fdiv [edi+0x88]`) right
 * after the projection.
 *
 * Why it works:
 * The inverse of `px = W/2 + sx * (x + offx - W/2)` is `x = (px - D) / sx` with
 * `D = sx * (offx - W/2) + W/2`. Subtracting `D` from the projected x before the game divides gives the
 * exact virtual position. `D` is `(W - W169) / 2` for screens built from the centered table and 0 for
 * pixel-space screens (scale 1, offset 0), so each call gets the right value for its own screen.
 *
 * @return void
 */
void fixHudMarkers() {
    Utils::SignatureHook spriteHook {
        .tag = "fixHudMarkers (sprite3d)",
        .signature = "E8 ?? ?? ?? ??    D9 44 24 18    8B 15 ?? ?? ?? ??    8B 82 94 00 00 00    D8 B0 88 00 00 00",
        .offset = 5
    };
    Utils::SignatureHook projectHook {
        .tag = "fixHudMarkers (project)",
        .signature = "D9 87 8C 00 00 00    D9 5C 24 1C    D9 06    D8 B7 88 00 00 00    D9 1E",
        .offset = 0
    };
    bool enable = yml.masterEnable && yml.hud;
    Utils::injectHook(enable, module, spriteHook,
        [](SafetyHookContext& ctx) {
            *reinterpret_cast<f32*>(ctx.esp + 0x18) -= hudOffset();
        }
    );
    if (enable) {
        std::string avoidanceSig = "8D B5 60 FF FF FF    E8 ?? ?? ?? ??    D9 85 64 FF FF FF    D8 65 B4";
        uintptr_t addr = Utils::patternScan(module.address, avoidanceSig);
        avoidanceReturn = addr != 0 ? addr + 0x0B : 0;
        if (addr == 0) {
            LOG("fixHudMarkers (avoidance) : Did not find '{}'", avoidanceSig);
        }
    }
    Utils::injectHook(enable, module, projectHook,
        [](SafetyHookContext& ctx) {
            if (!screen.hudCentred) {
                return;
            }
            // The x87 stack holds one value here, so this only uses SSE arithmetic.
            f32 offx = *reinterpret_cast<f32*>(ctx.edi + 0x80);
            f32 sx = *reinterpret_cast<f32*>(ctx.edi + 0x88);
            f32 halfWidth = screen.width / 2.0f;
            f32 shift = sx * (offx - halfWidth) + halfWidth;
            f32& x = *reinterpret_cast<f32*>(ctx.esi);
            if (*reinterpret_cast<uintptr_t*>(ctx.ebp + 4) == avoidanceReturn) {
                x += (sx - 1.0f) * shift;
            }
            else {
                x -= shift;
            }
        }
    );
}

/**
 * @brief Keeps the command mode eye marks where a 16:9 screen puts them.
 *
 * @details
 * The eye marks of the command cursor (SlgInterfaceEyeMarkSpriteParts) are placed by three projections of
 * the main 3D screen whose pixel x is stored as the mark's translation (`+0xc0`, applied by `FUN_00516360` in
 * the HUD's virtual space): one in `FUN_00517120` and two in `FUN_00517280`. A fourth state
 * (`FUN_00517460`) projects through a temporary virtual 1280x720 screen and needs nothing.
 *
 * The 3D view is Hor+, so a point that is at pixel `x` on a 16:9 screen of the same height is at
 * `x + (W - W169) / 2` on the full-width screen, while the HUD it is drawn in starts at the same 16:9 offset.
 *
 * How was this found?
 * Each site pushes `&outX` (`[ebp-8]`, `[ebp-0xc]`, `[ebp-0x10]`) for the projection `FUN_0080fba0` and
 * copies it into `+0xc0` after the call. The hooks sit right after each call.
 *
 * Why it works:
 * Subtracting `(W - W169) / 2` from the projected x gives the value a 16:9 screen of the same height
 * produces, which the centered HUD then places at the same spot over the 3D view.
 *
 * @return void
 */
void fixEyeMarks() {
    // outX is at [ebp-8], [ebp-0xc] and [ebp-0x10] respectively.
    Utils::SignatureHook state1 {
        .tag = "fixEyeMarks (state 1)",
        .signature = "8D 55 E0    8D 7D F4    E8 ?? ?? ?? ??    8B 55 FC    8B 42 08    85 C0    74 ??    6A 00    68",
        .offset = 0x0B
    };
    Utils::SignatureHook state5a {
        .tag = "fixEyeMarks (state 5a)",
        .signature = "8D 55 E0    8D 7D F0    E8 ?? ?? ?? ??    8B 55 FC    8B 42 08    85 C0    0F 84",
        .offset = 0x0B
    };
    Utils::SignatureHook state5b {
        .tag = "fixEyeMarks (state 5b)",
        .signature = "8D 55 D0    8D 7D F4    E8 ?? ?? ?? ??    8B 45 FC    8B 40 08    85 C0",
        .offset = 0x0B
    };
    bool enable = yml.masterEnable && yml.hud;
    Utils::injectHook(enable, module, state1,
        [](SafetyHookContext& ctx) { *reinterpret_cast<f32*>(ctx.ebp - 0x08) -= hudOffset(); });
    Utils::injectHook(enable, module, state5a,
        [](SafetyHookContext& ctx) { *reinterpret_cast<f32*>(ctx.ebp - 0x0C) -= hudOffset(); });
    Utils::injectHook(enable, module, state5b,
        [](SafetyHookContext& ctx) { *reinterpret_cast<f32*>(ctx.ebp - 0x10) -= hudOffset(); });
}

/**
 * @brief Keeps the 3D pieces of the HUD (CP and AP gauges and the like) where a 16:9 screen puts them.
 *
 * @details
 * `FUN_0058a810` places the 3D model parts of every VlInterfaceDraw (CP and AP gauges, the gravepost, the
 * radar window frame) by unprojecting a fixed screen x at the part's depth through the main 3D screen. The
 * unprojection is relative to the screen center, which moves from `W169 / 2` to `W / 2` with the full-width
 * box, so the parts drift left of the centered HUD by `(W - W169) / 2`.
 *
 * How was this found?
 * On the fixed-position branch (`+0xa8 == 0`) the part's `+0x80`/`+0x84` are loaded into ECX/EDX and stored
 * as the point to unproject (`mov [ebp-0x20], ecx; mov [ebp-0x1c], edx`) before `FUN_0080f530`.
 *
 * Why it works:
 * Adding `(W - W169) / 2` to x keeps its distance from the screen center, so the unprojected point is exactly
 * where a 16:9 screen of the same height puts it.
 *
 * @return void
 */
void fixHudModels() {
    Utils::SignatureHook hook {
        .tag = __func__,
        .signature = "8B 88 80 00 00 00    8B 90 84 00 00 00    89 4D E0    89 55 E4    D9 80 88 00 00 00",
        .offset = 0x0C
    };
    bool enable = yml.masterEnable && yml.hud;
    Utils::injectHook(enable, module, hook,
        [](SafetyHookContext& ctx) {
            f32 shift = hudOffset();
            if (shift == 0.0f) {
                return;
            }
            f32 x = std::bit_cast<f32>(static_cast<u32>(ctx.ecx));
            ctx.ecx = std::bit_cast<u32>(x + shift);
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
            fixLargeAddressAware();
            fixDisplayMode();
            fixResolution();
            fixHud();
            fixFullscreenBackgrounds();
            fixFades();
            fixHudMarkers();
            fixEyeMarks();
            fixHudModels();
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
