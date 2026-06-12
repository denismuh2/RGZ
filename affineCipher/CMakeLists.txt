cmake_minimum_required(VERSION 3.10)

project(affineCipher)

add_library(affineCipher SHARED
    affineCipher.cpp
    affineCipher.h
)

target_include_directories(affineCipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(affineCipher PRIVATE
    CRYPTO_BUILD_DLL
)

set_target_properties(affineCipher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/affineCipher"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/affineCipher"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/affineCipher"
)