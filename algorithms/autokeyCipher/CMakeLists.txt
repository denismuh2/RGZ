cmake_minimum_required(VERSION 3.10)
project(autokey_cipher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(autokey_cipher SHARED autokeyCipher.cpp)

target_include_directories(autokey_cipher PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)
