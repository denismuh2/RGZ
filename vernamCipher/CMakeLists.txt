cmake_minimum_required(VERSION 3.10)

project(vernamCipher)

add_library(vernamCipher SHARED
    vernamCipher.cpp
    vernamCipher.h
)

target_include_directories(vernamCipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(vernamCipher PRIVATE
    CRYPTO_BUILD_DLL
)

set_target_properties(vernamCipher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/vernamCipher"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/vernamCipher"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/algorithms/vernamCipher"
)