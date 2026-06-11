cmake_minimum_required(VERSION 3.10)
project(caesarCipher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME} SHARED caesarCipher.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE CRYPTO_BUILD_DLL)
endif()

if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".dll")
else()
    set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "lib" SUFFIX ".so")
endif()

if(UNIX AND NOT WIN32)
    target_compile_options(${PROJECT_NAME} PRIVATE -fvisibility=default)
endif()

message(STATUS "Configuring caesarCipher library")