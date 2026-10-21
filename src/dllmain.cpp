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
