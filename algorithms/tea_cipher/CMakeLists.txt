cmake_minimum_required(VERSION 3.10)

project(tea_cipher)

add_library(tea_cipher SHARED
    tea_cipher.cpp
    tea_cipher.h
)

target_include_directories(tea_cipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(tea_cipher PRIVATE
    CRYPTO_BUILD_DLL
)

set_target_properties(tea_cipher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/tea_cipher"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/tea_cipher"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/tea_cipher"
)
