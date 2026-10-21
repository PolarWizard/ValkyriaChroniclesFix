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

#include <windows.h>
#include <vector>
#include <format>
#include <iostream>
#include <sstream>
#include <span>
#include <cstdint>
#include <algorithm>

#include "utils.hpp"

namespace Utils
{
    std::string getCompilerInfo()
    {
#if defined(__GNUC__)
        std::string compiler = "GCC - "
            + std::to_string(__GNUC__) + "."
            + std::to_string(__GNUC_MINOR__) + "."
            + std::to_string(__GNUC_PATCHLEVEL__);
#elif defined(__clang__)
        std::string compiler = "Clang - "
            + std::to_string(__clang_major__) + "."
            + std::to_string(__clang_minor__) + "."
            + std::to_string(__clang_patchlevel__);
#elif defined(_MSC_VER)
        std::string compiler = "MSVC - "
            + std::to_string(_MSC_VER);
#else
        std::string compiler = "UNKNOWN";
#endif
        return compiler;
    }

    std::string bytesToString(std::span<const u8> bytes)
    {
        std::string pattern;
        for (u8 byte : bytes) {
            pattern += std::format("{:02X} ", byte);
        }
        if (!pattern.empty()) {
            pattern.pop_back();
        }
        return pattern;
    }

    std::pair<u32, u32> getDesktopDimensions()
    {
        DEVMODE devMode{};
        devMode.dmSize = sizeof(DEVMODE);
        if (EnumDisplaySettings(nullptr, ENUM_CURRENT_SETTINGS, &devMode)) {
            return { devMode.dmPelsWidth, devMode.dmPelsHeight };
        }
        return {};
    }

    void patch(uintptr_t address, std::string& pattern)
    {
        static auto patternToByte = [](std::string& pattern) {
            std::vector<u8> bytes;
            std::istringstream stream(pattern.data());
            std::string byteStr;

            while (stream >> byteStr) {  // Extract space-separated hex values
                bytes.push_back(static_cast<u8>(std::stoul(byteStr, nullptr, 16)));
            }
            return bytes;
        };

        DWORD oldProtect;
        auto patternBytes = patternToByte(pattern);
        VirtualProtect((LPVOID)address, patternBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((LPVOID)address, patternBytes.data(), patternBytes.size());
        VirtualProtect((LPVOID)address, patternBytes.size(), oldProtect, &oldProtect);
    }

    uintptr_t patternScan(void* module, std::string& signature)
    {
        static auto pattern_to_byte = [](const char* pattern) {
            struct Pattern {
                std::vector<u8> bytes;
                std::vector<u8> check;
            };
            auto start = const_cast<char*>(pattern);
            auto end = const_cast<char*>(pattern) + strlen(pattern);

            Pattern pat = {};
            for (auto current = start; current < end; ++current) {
                if (*current == ' ') {
                    continue;
                }
                else if (*current == '?') {
                    current += 2;
                    pat.bytes.push_back(0xFF);
                    pat.check.push_back(0);
                }
                else {
                    pat.bytes.push_back(strtoul(current, &current, 16));
                    pat.check.push_back(1);
                }
            }
            return pat;
        };

        auto dosHeader = (PIMAGE_DOS_HEADER)module;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((u8*)module + dosHeader->e_lfanew);

        auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto pattern = pattern_to_byte(signature.c_str());
        auto scanBytes = reinterpret_cast<u8*>(module);

        auto size = pattern.bytes.size();
        auto data = pattern.bytes.data();
        auto check = pattern.check.data();

        for (auto i = 0ul; i < sizeOfImage - size; ++i) {
            bool found = true;
            for (auto j = 0ul; j < pattern.bytes.size(); ++j) {
                u8 byte = pattern.bytes.data()[j];
                if (check[j] == 1 && scanBytes[i + j] != pattern.bytes.data()[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return reinterpret_cast<uintptr_t>(&scanBytes[i]);
            }
        }
        return 0;
    }

    uintptr_t resolveRelative(uintptr_t address, uintptr_t dispOffset, uintptr_t length)
    {
        i32 disp = *reinterpret_cast<i32*>(address + dispOffset);
        return address + length + disp;
    }

    void injectPatch(bool enable, Utils::ModuleInfo& module, Utils::SignaturePatch& sp)
    {
        if (enable) {
            uintptr_t addr = Utils::patternScan(module.address, sp.signature);
            if (addr != 0) {
                uintptr_t hit = addr;
                uintptr_t absAddr = hit;
                uintptr_t relAddr = hit - reinterpret_cast<uintptr_t>(module.address);
                spdlog::info("{} : Found '{}' @ {:s}+{:x}", sp.tag, sp.signature, module.name, relAddr);
                uintptr_t patchAbsAddr = absAddr + sp.patchOffset;
                uintptr_t patchRelAddr = relAddr + sp.patchOffset;
                Utils::patch(patchAbsAddr, sp.patch);
                spdlog::info("{} : Patched '{}' @ {:s}+{:x}", sp.tag, sp.patch, module.name, patchRelAddr);
            }
            else {
                spdlog::info("{} : Did not find '{}'", sp.tag, sp.signature);
            }
        }
    }
}
