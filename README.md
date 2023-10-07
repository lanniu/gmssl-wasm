# GmSSL

[![CMake](https://github.com/guanzhi/GmSSL/workflows/CMake/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/cmake.yml)
[![CMake-Android](https://github.com/guanzhi/GmSSL/actions/workflows/android-ci.yml/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/android-ci.yml)
[![CMake-iOS](https://github.com/guanzhi/GmSSL/actions/workflows/ios.yml/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/ios.yml)

GmSSL是由北京大学自主开发的国产商用密码开源库，实现了对国密算法、标准和安全通信协议的全面功能覆盖，支持包括移动端在内的主流操作系统和处理器，支持密码钥匙、密码卡等典型国产密码硬件，提供功能丰富的命令行工具及多种编译语言编程接口。

该库主要是针对其常用的加解密接口做了 WebAssembly 的封装

1. 首先需要安装 [Emscripten](https://emscripten.org/docs/getting_started/downloads.html)
2. 确保已经加载了 emscripten 环境
3. mkdir build_wasm
4. cd build_wasm
5. emcmake cmake ..

然后参考 wasm 目录中的 example
