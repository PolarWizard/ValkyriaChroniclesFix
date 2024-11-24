# Valkyria Chronicles Fix
Adds support for ultrawide resolutions and additional features.

***This project is designed exclusively for Windows due to its reliance on Windows-specific APIs. The build process requires the use of PowerShell.***

## Features
- Support for resolutions > 16:9
- Span or center HUD to 16:9

## Build and Install
### Using CMake
1. Build and install:
```ps1
git clone --recurse-submodules https://github.com/PolarWizard/ValkyriaChroniclesFix.git
cd ValkyriaChroniclesFix; mkdir build; cd build
cmake -DCMAKE_GENERATOR_PLATFORM=Win32 ..
cmake --build .
cmake --install .
```
`cmake -DCMAKE_GENERATOR_PLATFORM=Win32 ..` will attempt to find the game folder in `C:/Program Files (x86)/Steam/steamapps/common/`. If the game folder cannot be found rerun the command providing the path to the game folder:<br>`cmake -DCMAKE_GENERATOR_PLATFORM=Win32 .. -DGAME_FOLDER="<FULL-PATH-TO-GAME-FOLDER>"`

2. Download [d3d9.dll](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) Win32 version
3. Extract to `Valkyria Chronicles`

### Using Release
1. Download and follow instructions in [latest release](https://github.com/PolarWizard/ValkyriaChroniclesFix/releases)

## Configuration
- Adjust settings in `Valkyria Chronicles/scripts/ValkyriaChroniclesFix.yml`

## Screenshots
![Demo](images/ValkyriaChroniclesFix_1.gif)

## License
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## External Tools

### Python
- [PyYAML](https://github.com/yaml/pyyaml)
- [screeninfo](https://github.com/rr-/screeninfo)
- [PyInstaller](https://github.com/pyinstaller/pyinstaller)

### C/C++
- [safetyhook](https://github.com/cursey/safetyhook)
- [spdlog](https://github.com/gabime/spdlog)
- [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
- [yaml-cpp](https://github.com/jbeder/yaml-cpp)
- [zydis](https://github.com/zyantific/zydis)

## Special Thanks
- Thank you czarman from wsgf for the original fix!
