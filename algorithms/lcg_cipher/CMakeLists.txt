cmake_minimum_required(VERSION 3.10)

project(lcg_cipher)

add_library(lcg_cipher SHARED
    lcg_cipher.cpp
    lcg_cipher.h
)

target_include_directories(lcg_cipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(lcg_cipher PRIVATE
    CRYPTO_BUILD_DLL
)

set_target_properties(lcg_cipher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/lcg_cipher"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/lcg_cipher"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/lcg_cipher"
)
