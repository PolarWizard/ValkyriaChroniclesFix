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
 * @note There are still some issues present, but not big enough to really
 * devout time for to try to track down and fix. None the less if anyone
 * wants to help out please do so!
 * 1. When loading a save game, the screen following will be stretched to the
 * size of the window, which is not what we want, the static background is
 * designed for 16:9 and stretches the image to fit the window entirely. This
 * is very small detail that isn't worth fixing, but if anyone wants to it is
 * open.
 * 2. During cutscenes when characters and their portraits are drawn, the
 * background becomes part of the UI and it shifts to the right by 1280 pixels
 * if the resolution is 32:9. This is a small detail that isn't worth fixing
 * in the grand scheme of things but none the less it's a small blemish. If
 * anyone pursues this issue search for 1920.0f, assuming 32:9, and keeping
 * changing those memory loations to 1280.0f until the UI shifts to the left
 * back to (0,0) window coordinates. I think this peice is worth investigating
 * further and probably something here will lead to an answer and hopefully a
 * fix where the background can be shifted to the left only and the characters
 * portraits stay in place.
 *
 * @note This game is a port from the PS3 version of the game. The code has
 * heavy reliance on using the value 1280 in all forms, int, float, double,
 * etc. especially when performing initialization of the game.
 *
 * @note During game startup there are two important structs that get
 * initialized, this is assuming 5120x2560 resolution:
 * 1. Valkyria.exe+1794810, relevent game code: Valkyria.exe+3438
 *  a. 01 00 00 00 - Serves as a flag that the game has been initialized (???)
 *  b. 00 00 00 00 - Viewport X offset, if this value is positive then the
 *                      viewport will be shifted right by X amount of pixels.
 *                      If this value is negative then the viewport will be
 *                      shifted to the left by X amount of pixels. Without
 *                      the fix the game, the game calculates this to be 1280,
 *                      So that the viewport can be centered on the screen for
 *                      16:9 ratio regardless of game resolution.
 *  b. 00 00 00 00 - Viewport X offset, if this value is positive then the
 *                      viewport will be shifted up by X amount of pixels.
 *                      If this value is negative then the viewport will be
 *                      shifted down by X amount of pixels.
 *  d. 00 14 00 00 - Width of the screen that the game should render for.
 *                      By default game will scale your width down to 16:9 if
 *                      your resolution > 16:9. If < 16:9 there is another
 *                      routine in the code to handle this, but its 2024 no one
 *                      uses monitors that are less than 16:9... so who cares.
 *  e. A0 05 00 00 - Height of the screen that the game should render for.
 *  f. 00 14 00 00 - Actual desktop resolution width captured by the game.
 *  g. A0 05 00 00 - Actual desktop resolution height captured by the game.
 *  h. 00 14 00 00 - Width of the screen that the game should render for.
 *                      By default game will scale your width down to 16:9 if
 *                      your resolution > 16:9. If < 16:9 there is another
 *                      routine in the code to handle this, but its 2024 no one
 *                      uses monitors that are less than 16:9... so who cares.
 *  i. A0 05 00 00 - Height of the screen that the game should render for.
 *                      uses monitors that are less than 16:9... so who cares.
 *  j. 00 14 00 00 - Width of the screen this is used for X-axis scaling and
 *                      calculating the correct proportions for certain things.
 *                      This value should be consistent with d. as inconsistencies
 *                      will break things.
 *  k. 00 14 00 00 - Width of the screen this is used for Y-axis scaling and
 *                      calculating the correct proportions for certain things.
 *                      This value should be consistent with d. as inconsistencies
 *                      will break things.
 *  l. CD CC CC 38 - Calculated by doing 0.5 / 5120.0. No idea what this does,
 *                      no visible change observed when changing this value.
 *  m. 61 0B B6 39 - Calculated by doing 0.5 / 1440.0. No idea what this does,
 *                      no visible change observed when changing this value.
 * 2. Valkyria.exe+13542E4 = h. : scales various UI elements - relevent code : Valkyria.exe+444EAD
 * 3. Valkyria.exe+13542F0 = h. / 2.0f : scales the viewport - relevent code : Valkyria.exe+444F29
 * 4. Valkyria.exe+1354310 = (h. - 1280.f) / 2.0f : offset for certain UI elements - relevent code : Valkyria.exe+444FDB
 * 5. Valkyria.exe+1354318 = h. / 1280.0f : scales various UI elements - relevent code : Valkyria.exe+44505B
 */

// System includes
#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <filesystem>
#include <numeric>
#include <numbers>
#include <cmath>
#include <cstdint>
#include <algorithm>

// 3rd party includes
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "yaml-cpp/yaml.h"
#include "safetyhook.hpp"

// Local includes
#include "utils.hpp"

// Macros
#define VERSION "1.0.1"
#define LOG(STRING, ...) spdlog::info("{} : " STRING, __func__, ##__VA_ARGS__)

// .yml to struct
typedef struct resolution_t {
    int width;
    int height;
    float aspectRatio;
} resolution_t;

typedef struct centerHud_t {
    bool enable;
} textures_t;

typedef struct fix_t {
    centerHud_t centerHud;
} fix_t;

typedef struct yml_t {
    std::string name;
    bool masterEnable;
    resolution_t resolution;
    fix_t fix;
} yml_t;

// Globals
HMODULE baseModule = GetModuleHandle(NULL);
YAML::Node config = YAML::LoadFile("ValkyriaChroniclesFix.yml");
yml_t yml;

/**
 * @brief Initializes logging for the application.
 *
 * This function performs the following tasks:
 * 1. Initializes the spdlog logging library and sets up a file logger.
 * 2. Retrieves and logs the path and name of the executable module.
 * 3. Logs detailed information about the module to aid in debugging.
 *
 * @return void
 */
void logInit() {
    // spdlog initialisation
    auto logger = spdlog::basic_logger_mt("ValkyriaChroniclesFix", "ValkyriaChroniclesFix.log", true);
    spdlog::set_default_logger(logger);
    spdlog::flush_on(spdlog::level::debug);

    // Get game name and exe path
    WCHAR exePath[_MAX_PATH] = { 0 };
    GetModuleFileNameW(baseModule, exePath, MAX_PATH);
    std::filesystem::path exeFilePath = exePath;
    std::string exeName = exeFilePath.filename().string();

    // Log module details
    LOG("-------------------------------------");
    LOG("Compiler: {:s}", Utils::getCompilerInfo().c_str());
    LOG("Compiled: {:s} at {:s}", __DATE__, __TIME__);
    LOG("Version: {:s}", VERSION);
    LOG("Module Name: {:s}", exeName.c_str());
    LOG("Module Path: {:s}", exeFilePath.string().c_str());
    LOG("Module Addr: 0x{:x}", (uintptr_t)baseModule);
}

/**
 * @brief Reads and parses configuration settings from a YAML file.
 *
 * This function performs the following tasks:
 * 1. Reads general settings from the configuration file and assigns them to the `yml` structure.
 * 2. Initializes global settings if certain values are missing or default.
 * 3. Logs the parsed configuration values for debugging purposes.
 *
 * @return void
 */
void readYml() {
    yml.name = config["name"].as<std::string>();

    yml.masterEnable = config["masterEnable"].as<bool>();

    yml.resolution.width = config["resolution"]["width"].as<int>();
    yml.resolution.height = config["resolution"]["height"].as<int>();

    yml.fix.centerHud.enable = config["fixes"]["centerHud"]["enable"].as<bool>();

    if (yml.resolution.width == 0 || yml.resolution.height == 0) {
        std::pair<int, int> dimensions = Utils::GetDesktopDimensions();
        yml.resolution.width  = dimensions.first;
        yml.resolution.height = dimensions.second;
    }
    yml.resolution.aspectRatio = (float)yml.resolution.width / (float)yml.resolution.height;

    LOG("Name: {}", yml.name);
    LOG("MasterEnable: {}", yml.masterEnable);
    LOG("Resolution.Width: {}", yml.resolution.width);
    LOG("Resolution.Height: {}", yml.resolution.height);
    LOG("Resolution.AspectRatio: {}", yml.resolution.aspectRatio);
    LOG("Fix.CenterHud.Enable: {}", yml.fix.centerHud.enable);
}

/**
 * @brief Centers player and enemy UI icons correctly.
 *
 * This function performs the following tasks:
 * 1. Checks if the master enable is enabled based on the configuration.
 * 2. Searches for a specific memory pattern in the base module.
 * 3. Hooks at the identified pattern to inject a new value into the esp + 0xC.
 *
 * @details
 * The function uses a pattern scan to find a specific byte sequence in the memory of the base module.
 * If the pattern is found, a hook is created at an offset from the found pattern address. The hook
 * injects a new value into the esp + 0xC.
 *
 * How was this found?
 * This is another case of things being offset incorrectly. Given our values during initialization,
 * the value that the game would use is 2560.0f. This is wrong. We need to go back to the default
 * value the game itself would calculate and use which is 1280.0f.
 * This works because, assuming X resolution is 5120, the game makes the initial calculation as said
 * before of 2560.0f (5120.0f / 2.0f) and then adds 1280.0f, this is very common in the game code,
 * to get the final value, which would be 3840.0f, this offset on the viewport can be seen on a 32:9
 * monitor, but this is not desirable. We need to scale back! So we inject back in 1280.0f. Now the
 * game in its infinite wisdom is able to scale things properly.
 *
 * @return void
 */
void centerUiIconsFix() {
    const char* patternFind = "D9 46 64    D9 5C 24 1C    D9 46 68    D9 5C 24 14    D9 46 6C";
    uintptr_t  hookOffset = 0;

    bool enable = yml.masterEnable & yml.fix.centerHud.enable;
    LOG("Fix {}", enable ? "Enabled" : "Disabled");
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset;
            uintptr_t hookRelAddr = relAddr + hookOffset;
            static SafetyHookMid centerUiIconsHook{};
            centerUiIconsHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    *((float*)(ctx.esp + 0xC)) = 1280.0f;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind);
        }
    }
}

/**
 * @brief Fixes the minimap overlay so icons are on the map and scale properly.
 *
 * This function performs the following tasks:
 * 1. Checks if the master enable is enabled based on the configuration.
 * 2. Searches for a specific memory pattern in the base module.
 * 3. Hooks at the identified pattern to inject a new value into the eax + 0x90 and + 0x98.
 *
 * @details
 * The function uses a pattern scan to find a specific byte sequence in the memory of the base module.
 * If the pattern is found, a hook is created at an offset from the found pattern address. The hook
 * injects a new value into the eax + 0x90 and + 0x98.
 *
 * How was this found?
 * This was found by complete accident by playing around with a random scaler value 2.0f if 5120.0f
 * and it was observed that changed this scaler value would scale the minimap overlay, not correctly
 * at all, but it would scale it in a lot of ways: offset and stretching. Digging a bit deeper into
 * the code we land upon some code that uses that 2.0f in order to scale the minimap overlay icons.
 * Wierdly enough the origins of this scaler value come from the 2.0f modification that we made earlier
 * in the `uiScalingFix()` function.
 *
 * Diving into the code the calculation to offset and scale this UI element is quite complex as observed
 * below. Let's break down the original equation that we would find in the code, note this is only the
 * X-coordinate part of the calculation:
 * (164.0f +/- 77.0f) * 2.0f + 1280.0f
 *  1. 164.0f - This is hardcoded pixel offset, so draw this icon starting at 164 pixels from the left
 *              edge of the viewport.
 *  2. +/- 77.0f - The game always assumes 16:9, so this is hardcoded value, this determines how much we add
 *                 or subtract from the offset above.
 *  3. 2.0f - This is precalculated during initialization of the game scaler value, this determines how
 *            much we scale the minimap overlay by, and will effect how stretched/squished and how offset the
 *            minimap overlay is.
 *  4. 1280.0f - Screen offset calculation to figure out how many we need to offset before we get to the
 *               center of the screen where 16:9 rendering starts. So for 5120, we need to 16:9'erize that
 *               width, which would be 2560 and then plug into the formula: (5120 - 2560) / 2 which will
 *               get me the offset to the center of the screen where 16:9 viewport starts on a 32:9 monitor.
 *               For 21:9 assume 3440x1440, this would be (3440 - 2560) / 2 = 440.
 *
 * In this calculation all that really needs to be done is scaling that +/- number to our resolution. If we
 * leave it as is the overlay will be a bit squished and not fit perfectly onto the map. So regardless of
 * X resolution, we do: (77.0f * (xResolution / 2560.0f))
 * If xResolution is 5120 then we get 154.0f, if xResolution is 3440 then we get 103.46875f, and so on.
 *
 * @return void
 */
void minimapOverlayFix() {
    const char* patternFind = "DE C1    DE C9    D9 98 9C 00 00 00";
    uintptr_t  hookOffset = 0;

    bool enable = yml.masterEnable & yml.fix.centerHud.enable;
    LOG("Fix {}", enable ? "Enabled" : "Disabled");
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset;
            uintptr_t hookRelAddr = relAddr + hookOffset;
            static SafetyHookMid minimapOverlayHook{};
            minimapOverlayHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    float width = static_cast<float>(yml.resolution.width);
                    float height = static_cast<float>(yml.resolution.height);
                    float defaultWidth = (height * 16.0f) / 9.0f; // 16:9'erizes yml provided width
                    float pixelScaler = (77.0f * (width / defaultWidth));
                    *((float*)(ctx.eax + 0x90)) = ((164.0f - pixelScaler) * 2.0f) + ((width - defaultWidth) / 2.0f);
                    *((float*)(ctx.eax + 0x98)) = ((164.0f + pixelScaler) * 2.0f) + ((width - defaultWidth) / 2.0f);
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind);
        }
    }
}

/**
 * @brief Fixes the textbox backgrounds that are missing when resolution becomes > 16:9.
 *
 * This function performs the following tasks:
 * 1. Checks if the master enable is enabled based on the configuration.
 * 2. Searches for a specific memory pattern in the base module.
 * 3. Hooks at the identified pattern to inject a new value into the ebp - 0x8.
 *
 * @details
 * The function uses a pattern scan to find a specific byte sequence in the memory of the base module.
 * If the pattern is found, a hook is created at an offset from the found pattern address. The hook
 * injects a new value into the ebp - 0x8.
 *
 * How was this found?
 * This goes back to the game once again using the magi c number 1280.0f to determine where to fit certain
 * things. When going beyond 32:9 the calculation below would have been 5120.0f / 2.0f. Which would be
 * 2560.0f. When the game later uses this number it would actually offset the textbox background all the
 * way to the next screen, assuming 32:9. So the textbox would still be here but would not be offset
 * correctly. We need to scale the resolution back to 16:9 so that the game does not offset the
 * textbox background off the screen and keeps in place where it should be.
 *
 * It is important to note that on 21:9 this anomaly does not seem to be observed.
 *
 * @return void
 */
void textboxFix() {
    const char* patternFind = "D9 5D F8    A8 04    74 0E";
    uintptr_t  hookOffset = 3;

    // This needs to be always on regardless of enabling of other fixes
    bool enable = yml.masterEnable;
    LOG("Fix {}", enable ? "Enabled" : "Disabled");
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset;
            uintptr_t hookRelAddr = relAddr + hookOffset;
            static SafetyHookMid textboxHook{};
            textboxHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    *((float*)(ctx.ebp - 0x8)) = 1280.0f;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind);
        }
    }
}

/**
 * @brief Fixes the UI scaling.
 *
 * This function performs the following tasks:
 * 1. Checks if the master enable is enabled based on the configuration.
 * 2. Searches for a specific memory pattern in the base module.
 * 3. Hooks at the identified pattern to inject a new value into the memory location pointed to by
 * `uiScalerAddr` variable.

 * @details
 * The function uses a pattern scan to find a specific byte sequence in the memory of the base module.
 * If the pattern is found, a hook is created at an offset from the found pattern address. The hook
 * injects a new value into memory location pointed to by `uiScalerAddr` variable.
 *
 * How was this found?
 * First navigate to the top and read over the documentation going over the structs that handle in game
 * initialization at the very start, way before a window is even created. 5. is the relevant data necessary
 * to understand what is going on here. Through thorough experimentation it was found that if 5. is edited
 * to back to what the game expects so 2.0f it will fix the UI scaling so that it fits and is centered 16:9.
 *
 * But why does that work, put it simply it is a scaling factor that plays with the magic number 1280.0f.
 * The game calculates it to be 2.0f when we are 2560 pixels in width, but if we go wider to 5120, then this
 * number becomes 4.0f and this means the game needs to scale the UI by a factor of 4.0f in order to fit
 * the screen, so if we change it back to 2.0f we are forcing the game to scale the UI to fit in 16:9
 * and of course this does not center the UI, there is another value that allows it to be centered, but
 * I am not going to be exploring that as it is irrelevent to this fix and should be left alone.
 *
 * @return void
 */
uintptr_t* uiScalerAddr;
void uiScalingFix() {
    const char* patternFind = "D9 05 ?? ?? ?? ??    D9 98 88 00 00 00    D9 45 08";
    uintptr_t  hookOffset = 0;

    bool enable = yml.masterEnable & yml.fix.centerHud.enable;
    LOG("Fix {}", enable ? "Enabled" : "Disabled");
    if (enable) {
        std::vector<uint64_t> addr;
        Utils::patternScan(baseModule, patternFind, &addr);
        uint8_t* hit = (uint8_t*)addr[0];
        uintptr_t absAddr = (uintptr_t)hit;
        uintptr_t relAddr = (uintptr_t)hit - (uintptr_t)baseModule;
        if (hit) {
            LOG("Found '{}' @ 0x{:x}", patternFind, relAddr);
            uintptr_t hookAbsAddr = absAddr + hookOffset;
            uintptr_t hookRelAddr = relAddr + hookOffset;
            uiScalerAddr = *(uintptr_t**)(hookAbsAddr + 2);
            LOG("masterStructAddr: 0x{:x}", (uintptr_t)uiScalerAddr);
            LOG("masterStructAddr: 0x{:x}", (uintptr_t)*uiScalerAddr);
            static SafetyHookMid uiScalingHook{};
            uiScalingHook = safetyhook::create_mid(reinterpret_cast<void*>(hookAbsAddr),
                [](SafetyHookContext& ctx) {
                    *(float*)uiScalerAddr = 2.0f;
                }
            );
            LOG("Hooked @ 0x{:x} + 0x{:x} = 0x{:x}", relAddr, hookOffset, hookRelAddr);
        }
        else {
            LOG("Did not find '{}'", patternFind);
        }
    }
}

/**
 * @brief This function serves as the entry point for the DLL. It performs the following tasks:
 * 1. Initializes the logging system.
 * 2. Reads the configuration from a YAML file.
 * 3. Applies a center UI icons fix.
 * 4. Applies a UI scaling fix.
 * 5. Applies a minimap overlay fix.
 * 6. Applies a textbox fix.
 *
 * @param lpParameter Unused parameter.
 * @return Always returns TRUE to indicate successful execution.
 */
DWORD __stdcall Main(void* lpParameter) {
    logInit();
    readYml();
    centerUiIconsFix();
    uiScalingFix();
    minimapOverlayFix();
    textboxFix();
    return true;
}

/**
 * @brief Entry point for a DLL, called by the system when the DLL is loaded or unloaded.
 *
 * This function handles various events related to the DLL's lifetime and performs actions
 * based on the reason for the call. Specifically, it creates a new thread when the DLL is
 * attached to a process.
 *
 * @details
 * The `DllMain` function is called by the system when the DLL is loaded or unloaded. It handles
 * different reasons for the call specified by `ul_reason_for_call`. In this implementation:
 *
 * - **DLL_PROCESS_ATTACH**: When the DLL is loaded into the address space of a process, it
 *   creates a new thread to run the `Main` function. The thread priority is set to the highest,
 *   and the thread handle is closed after creation.
 *
 * - **DLL_THREAD_ATTACH**: Called when a new thread is created in the process. No action is taken
 *   in this implementation.
 *
 * - **DLL_THREAD_DETACH**: Called when a thread exits cleanly. No action is taken in this implementation.
 *
 * - **DLL_PROCESS_DETACH**: Called when the DLL is unloaded from the address space of a process.
 *   No action is taken in this implementation.
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
    HANDLE mainHandle;
    HANDLE currentThread;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        mainHandle = CreateThread(NULL, 0, Main, 0, NULL, 0);
        if (mainHandle)
        {
            SetThreadPriority(mainHandle, THREAD_PRIORITY_HIGHEST);
            CloseHandle(mainHandle);
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
