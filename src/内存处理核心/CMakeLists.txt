cmake_minimum_required(VERSION 3.16)
project(memory_handler LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -flto")

add_executable(memory_handler memory_handler.cpp)

if(MSVC)
    target_compile_options(memory_handler PRIVATE /O2 /GL /arch:AVX2)
else()
    target_compile_options(memory_handler PRIVATE -O3 -march=native -flto -funroll-loops)
endif()