cmake_minimum_required(VERSION 3.10)
project(EncryptionRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Путь к общим заголовкам
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Подключаем подпроекты (каждая DLL собирается отдельно)
add_subdirectory(algorithms/autokeyCipher)
add_subdirectory(algorithms/feistelCipher)
# add_subdirectory(algorithms/другие...)

# Главное приложение (EXE)
add_executable(cryptum main.cpp)
target_include_directories(cryptum PRIVATE ${INCLUDE_DIR})

# Для Windows: копируем DLL в папку с EXE после сборки
if(WIN32)
    add_custom_command(TARGET cryptum POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/algorithms/autokeyCipher/autokey_cipher.dll
            ${CMAKE_BINARY_DIR}/autokey_cipher.dll
        COMMENT "Copying autokey_cipher.dll to binary directory"
    )
endif()