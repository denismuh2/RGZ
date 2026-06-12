cmake_minimum_required(VERSION 3.10)
project(EncryptionRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Путь к общим заголовкам
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Подключаем подпроекты (каждая библиотека собирается отдельно)
add_subdirectory(algorithms/autokeyCipher)
add_subdirectory(algorithms/feistelCipher)
add_subdirectory(algorithms/caesarCipher)
add_subdirectory(algorithms/lcgCipher)
add_subdirectory(algorithms/teaCipher) 
# add_subdirectory(algorithms/другие...)

# Главное приложение (EXE)
add_executable(EncryptionRGR main.cpp)

target_include_directories(EncryptionRGR PRIVATE ${INCLUDE_DIR})

if(MSVC)
    target_compile_options(EncryptionRGR PRIVATE /source-charset:utf-8 /execution-charset:windows-1251)
else()
    target_compile_options(EncryptionRGR PRIVATE -finput-charset=UTF-8 -fexec-charset=CP1251)
endif()

# Для Linux: добавляем библиотеку dl (для dlopen/dlsym)
if(UNIX AND NOT WIN32)
    target_link_libraries(EncryptionRGR dl)
endif()

# ВАЖНО: Указываем, что EXE зависит от DLL (чтобы DLL собрались первыми)
if(WIN32)
    add_dependencies(EncryptionRGR autokeyCipher feistelCipher caesarCipher lcgCipher teaCipher) 
endif()

# Кроссплатформенное копирование библиотек после сборки
if(WIN32)
    # Windows: копируем .dll
    add_custom_command(TARGET EncryptionRGR POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/algorithms/autokeyCipher/autokeyCipher.dll
            ${CMAKE_BINARY_DIR}/autokeyCipher.dll
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/algorithms/feistelCipher/feistelCipher.dll
            ${CMAKE_BINARY_DIR}/feistelCipher.dll
        COMMAND ${CMAKE_COMMAND} -E copy_if_different                      
            ${CMAKE_BINARY_DIR}/algorithms/caesarCipher/caesarCipher.dll  
            ${CMAKE_BINARY_DIR}/caesarCipher.dll
        COMMAND ${CMAKE_COMMAND} -E copy_if_different                      
            ${CMAKE_BINARY_DIR}/algorithms/lcgCipher/lcgCipher.dll          
            ${CMAKE_BINARY_DIR}/lcgCipher.dll
        COMMAND ${CMAKE_COMMAND} -E copy_if_different                      
            ${CMAKE_BINARY_DIR}/algorithms/teaCipher/teaCipher.dll          
            ${CMAKE_BINARY_DIR}/teaCipher.dll                              
        COMMENT "Copying DLLs to binary directory"
    )
else()
    # Linux: копируем .so
    add_custom_command(TARGET EncryptionRGR POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/algorithms/autokeyCipher/libautokeyCipher.so
            ${CMAKE_BINARY_DIR}/libautokeyCipher.so
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/algorithms/feistelCipher/libfeistelCipher.so
            ${CMAKE_BINARY_DIR}/libfeistelCipher.so
        COMMAND ${CMAKE_COMMAND} -E copy_if_different                      
            ${CMAKE_BINARY_DIR}/algorithms/caesarCipher/libcaesarCipher.so
            ${CMAKE_BINARY_DIR}/libcaesarCipher.so
        COMMAND ${CMAKE_COMMAND} -E copy_if_different                      
            ${CMAKE_BINARY_DIR}/algorithms/lcgCipher/liblcgCipher.so
            ${CMAKE_BINARY_DIR}/liblcgCipher.so
        COMMAND ${CMAKE_COMMAND} -E copy_if_different                      
            ${CMAKE_BINARY_DIR}/algorithms/teaCipher/libteaCipher.so
            ${CMAKE_BINARY_DIR}/libteaCipher.so                            
        COMMENT "Copying shared libraries to binary directory"
    )
endif()

message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "  Executable: ${PROJECT_NAME}")
message(STATUS "  Libraries: autokeyCipher, feistelCipher, caesarCipher, lcgCipher, teaCipher")