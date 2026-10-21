# MIT License
#
# Copyright (c) 2025 Dominik Protasewicz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

include(FetchContent)

# SAFETYHOOK
FetchContent_Declare(
    safetyhook
    GIT_REPOSITORY https://github.com/cursey/safetyhook.git
    GIT_TAG        v0.6.9
    CMAKE_ARGS
        -DSAFETYHOOK_FETCH_ZYDIS=ON
    EXCLUDE_FROM_ALL
)
# SPDLOG
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.17.0
    EXCLUDE_FROM_ALL
)
# YAML-CPP
FetchContent_Declare(
    yamlcpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        c268020 # Can't use 0.8.0 release as that doesn't build with CMake 4.0
    EXCLUDE_FROM_ALL
)

# This will now respect EXCLUDE_FROM_ALL thanks to the FETCHCONTENT_TRY_EXCLUDE_FROM_ALL_* vars
FetchContent_MakeAvailable(
    safetyhook
    spdlog
    yamlcpp
)
