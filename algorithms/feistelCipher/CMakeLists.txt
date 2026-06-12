cmake_minimum_required(VERSION 3.10)
project(feistelCipher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Создаём SHARED библиотеку
add_library(${PROJECT_NAME} SHARED feistelCipher.cpp)

# Путь к общим заголовкам
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# Макрос для экспорта функций (только для Windows)
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE CRYPTO_BUILD_DLL)
endif()

# Кроссплатформенные настройки имени выходного файла
if(WIN32)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
    )
else()
    set_target_properties(${PROJECT_NAME} PROPERTIES
        PREFIX "lib"
        SUFFIX ".so"
    )
endif()

# Для Linux: добавить флаг видимости символов
if(UNIX AND NOT WIN32)
    target_compile_options(${PROJECT_NAME} PRIVATE -fvisibility=default)
endif()

message(STATUS "Configuring feistelCipher library")
message(STATUS "  Source: ${CMAKE_CURRENT_SOURCE_DIR}/feistelCipher.cpp")
if(WIN32)
    message(STATUS "  Output: ${PROJECT_NAME}.dll")
else()
    message(STATUS "  Output: lib${PROJECT_NAME}.so")
endif()
