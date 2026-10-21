# Valkyria Chronicles Fix
![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/PolarWizard/ValkyriaChroniclesFix/total)

Adds support for ultrawide resolutions and additional features.

***This project is designed exclusively for Windows due to its reliance on Windows-specific APIs. The build process requires the use of PowerShell.***

## Fixes

## Build and Install
### Using CMake
1. Build and install:
```ps1
git clone https://github.com/PolarWizard/ValkyriaChroniclesFix.git
cd ValkyriaChroniclesFix; mkdir build; cd build
# If install is not needed you may omit -DCMAKE_INSTALL_PREFIX and cmake install step.
cmake -A Win32 -DCMAKE_INSTALL_PREFIX=<FULL-PATH-TO-GAME-FOLDER> ..
cmake --build . --config Release
cmake --install .
```
2. Download [d3d9.dll](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) Win32 version
3. Extract to game folder: `Valkyria Chronicles`

### Using Release
Download and follow instructions in [latest release](https://github.com/PolarWizard/ValkyriaChroniclesFix/releases)

## Configuration
- Adjust settings in `Valkyria Chronicles/scripts/ValkyriaChroniclesFix.yml`

## Screenshots
| ![Demo1](images/ValkyriaChroniclesFix_1.gif) |
| --- |
| <p align='center'> Fix disabled → Fix enabled with centered HUD → Fix enabled with spanned HUD </p> |

## License
Distributed under the MIT License. See [LICENSES](LICENSES) for more information.

## External Tools
- [safetyhook](https://github.com/cursey/safetyhook)
- [spdlog](https://github.com/gabime/spdlog)
- [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
- [yaml-cpp](https://github.com/jbeder/yaml-cpp)
- [zydis](https://github.com/zyantific/zydis)

## Special Thanks
- Thank you czarman from wsgf for the [original fix](https://ko-fi.com/album/Valkyria-Chronicles-X8X15XA7F)!
