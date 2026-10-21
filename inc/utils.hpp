/*
 * MIT License
 *
 * Copyright (c) 2025 Dominik Protasewicz
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

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <span>

// 3rd party includes
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "yaml-cpp/yaml.h"
#include "safetyhook.hpp"

#define LOG(STRING, ...) spdlog::info("{} : " STRING, __func__, ##__VA_ARGS__)

namespace
{
    typedef uint8_t  u8;
    typedef uint16_t u16;
    typedef uint32_t u32;
    typedef uint64_t u64;
    typedef int8_t   i8;
    typedef int16_t  i16;
    typedef int32_t  i32;
    typedef int64_t  i64;
    typedef float    f32;
    typedef double   f64;
}

namespace Utils
{
    struct ModuleInfo {
        HMODULE address{};
        std::string name{};
        explicit ModuleInfo(HMODULE address) : address(address) {}
    };

    struct SignatureHook {
        std::string tag{};
        std::string signature{};
        uintptr_t offset{};
    };

    struct SignaturePatch {
        std::string tag{};
        std::string signature{};
        uintptr_t signatureOffset{};
        std::string patch{};
        uintptr_t patchOffset{};
    };

    /**
     * @brief Retrieves information about the compiler being used.
     * @details This function returns a string containing the name and version of the
     *      compiler. It checks for several well-known compilers and formats the version
     *      information accordingly:
     *
     * - **GCC:** The version is formatted as "GCC - major.minor.patch".
     * - **Clang:** The version is formatted as "Clang - major.minor.patch".
     * - **MSVC:** The version is formatted as "MSVC - version number".
     * - **Unknown Compiler:** If the compiler is not recognized, it returns "UNKNOWN".
     *
     * @return `std::string` containing the compiler name and version.
     */
    std::string getCompilerInfo();

    /**
     * @brief Converts memory bytes into string representation.
     * @details Converts the bytes referenced by the `bytes` parameter into a IDA-style byte string.
     *      The output is formatted as space-separated byte values, appearing in the same order
     *      as they exist in memory. For example, if an integer `0x12345678` is passed the
     *      function returns `"78 56 34 12"` on a little-endian system.
     *
     * @param bytes A span of bytes representing the memory region.
     * @return std::string containing the IDA-style byte string.
     *
     * @code
     * float a = 3.5555556; // In hex: 0x40638E39
     * std::string myString = bytesToString(std::as_bytes(std::span{&value, 1}));
     * std::cout << myString << std::endl; // Prints "39 8E 63 40"
     *
     * std::vector<u8> data = {0x40, 0x63, 0x8E, 0x39};
     * std::string myString = bytesToString(data);
     * std::cout << myString << std::endl; // Prints "40 63 8E 39"
     * @endcode
     */
    std::string bytesToString(std::span<const u8> bytes);

    /**
     * @brief Get the width and height of the desktop in pixels.
     *
     * @return std::pair<u32, u32> containing the width and height.
     */
    std::pair<u32, u32> getDesktopDimensions();

    /**
     * @brief Patch an area of memory with a pattern.
     * @details Overwrites memory at `address` using the provided pattern. The `pattern`
     *      must be formatted as a space-separated hex string (e.g., `"DE AD BE EF"`).
     *      The function modifies memory at the specified address, spanning the number
     *      of bytes determined by the pattern length. Proper care should be taken to
     *      avoid segmentation faults or corruption of unintended memory regions.
     *
     * @param address Memory address to patch.
     * @param pattern IDA-style byte array pattern.
     */
    void patch(uintptr_t address, std::string& pattern);

    /**
     * @brief Scan for a given byte pattern in a module.
     * @details Searches the specified module's memory for occurrences of the given
     *      IDA-style byte pattern. Each match is appended to the `address` vector.
     *      Wildcard bytes ("??") can be used to match any byte in the pattern.
     *
     * @param module Base address of the module to scan.
     * @param signature IDA-style byte array pattern.
     * @param address Vector to store found addresses.
     *
     * @return uintptr_t containing the address of the first hit if the signature is
     *      found else 0.
     */
    uintptr_t patternScan(void* module, std::string& signature);

    /**
     * @brief Injects a mid-function hook based on a signature pattern match.
     *
     * @tparam Func The type of the callback function.
     * @param enable If true, the hook will be injected; otherwise, it is skipped.
     * @param module The module to scan for the signature.
     * @param sh The signature pattern and offset information for the hook.
     * @param callback The function to execute when the hook is triggered.
     * @return true if the hook was installed.
     *
     * @details
     * This function scans the specified module for the given signature pattern.
     * If a match is found, it calculates the absolute and relative addresses,
     * logs the location, and applies a mid-function hook at the computed address.
     *
     * @note This function only hooks the first match found in the module.
     *
     * @see Utils::patternScan
     */
    template <typename Func>
    bool injectHook(bool enable, Utils::ModuleInfo& module, Utils::SignatureHook& sh, Func&& callback) {
        if (enable) {
            uintptr_t addr = Utils::patternScan(module.address, sh.signature);
            if (addr != 0) {
                uintptr_t hit = addr;
                uintptr_t absAddr = hit;
                uintptr_t relAddr = hit - reinterpret_cast<uintptr_t>(module.address);
                spdlog::info("{} : Found '{}' @ {:s}+{:x}", sh.tag, sh.signature, module.name, relAddr);
                uintptr_t hookAbsAddr = absAddr + sh.offset;
                uintptr_t hookRelAddr = relAddr + sh.offset;
                static std::vector<SafetyHookMid> hooks;
                SafetyHookMid hook = safetyhook::create_mid(
                    reinterpret_cast<void*>(hookAbsAddr),
                    callback
                );
                bool hooked = static_cast<bool>(hook);
                hooks.push_back(std::move(hook));
                if (hooked) {
                    spdlog::info("{} : Hooked @ {:s}+{:x}", sh.tag, module.name, hookRelAddr);
                }
                else {
                    spdlog::info("{} : Failed to hook @ {:s}+{:x}", sh.tag, module.name, hookRelAddr);
                }
                return hooked;
            }
            else {
                spdlog::info("{} : Did not find '{}'", sh.tag, sh.signature);
            }
        }
        return false;
    }

    /**
     * @brief Injects an inline hook, replacing a whole function, based on a signature pattern match.
     *
     * @tparam Func The type of the detour function pointer.
     * @param enable If true, the hook will be injected; otherwise, it is skipped.
     * @param module The module to scan for the signature.
     * @param sh The signature pattern and offset information for the hook.
     * @param hook Receives the hook, the detour calls the original function through it.
     * @param detour The function that runs in place of the hooked function.
     *
     * @details
     * This function scans the specified module for the given signature pattern.
     * If a match is found, it calculates the absolute and relative addresses,
     * logs the location, and applies an inline hook at the computed address.
     *
     * The hook is created disabled, moved into `hook` and only then enabled. The game keeps running while
     * hooks are injected, so this guarantees that the detour never runs before `hook` holds the trampoline
     * that the detour uses to call the original function.
     *
     * @note This function only hooks the first match found in the module.
     *
     * @see Utils::patternScan
     */
    template <typename Func>
    void injectInlineHook(bool enable, Utils::ModuleInfo& module, Utils::SignatureHook& sh, SafetyHookInline& hook, Func detour) {
        if (enable) {
            uintptr_t addr = Utils::patternScan(module.address, sh.signature);
            if (addr != 0) {
                uintptr_t hit = addr;
                uintptr_t absAddr = hit;
                uintptr_t relAddr = hit - reinterpret_cast<uintptr_t>(module.address);
                spdlog::info("{} : Found '{}' @ {:s}+{:x}", sh.tag, sh.signature, module.name, relAddr);
                uintptr_t hookAbsAddr = absAddr + sh.offset;
                uintptr_t hookRelAddr = relAddr + sh.offset;
                hook = safetyhook::create_inline(
                    reinterpret_cast<void*>(hookAbsAddr),
                    reinterpret_cast<void*>(detour),
                    SafetyHookInline::StartDisabled
                );
                if (hook && hook.enable()) {
                    spdlog::info("{} : Hooked @ {:s}+{:x}", sh.tag, module.name, hookRelAddr);
                }
                else {
                    spdlog::info("{} : Failed to hook @ {:s}+{:x}", sh.tag, module.name, hookRelAddr);
                }
            }
            else {
                spdlog::info("{} : Did not find '{}'", sh.tag, sh.signature);
            }
        }
    }

    /**
     * @brief Resolves the target of a relative operand.
     * @details Instructions such as `call rel32` or `jmp rel32` encode their target relative to the end of
     *      the instruction. This reads the 32-bit displacement and returns the absolute
     *      address it points to.
     *
     * @param address Address of the instruction.
     * @param dispOffset Offset of the 32-bit displacement within the instruction.
     * @param length Length of the instruction in bytes.
     *
     * @return uintptr_t containing the absolute target address.
     *
     * @code
     * // E8 xx xx xx xx            call target
     * uintptr_t target = resolveRelative(callAddr, 1, 5);
     * @endcode
     */
    uintptr_t resolveRelative(uintptr_t address, uintptr_t dispOffset, uintptr_t length);

    /**
     * @brief Patches bytes based on the provided signature to scan for.
     *
     * @param enable If true, the patch will be applied; otherwise, it is skipped.
     * @param module The module to scan for the signature.
     * @param sp Struct containing the signature and patch information.
     *
     * @details
     * This function scans the specified module for the given signature pattern.
     * If a match is found, it calculates the absolute and relative addresses,
     * logs the location, and applies a patch at the computed address based on the
     * information provided in the `patch` struct.
     *
     * @note This function only patches the first match found in the module.
     *
     * @see Utils::patternScan
     * @see Utils::patch
     */
    void injectPatch(bool enable, Utils::ModuleInfo& module, Utils::SignaturePatch& sp);
}
