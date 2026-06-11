cmake_minimum_required(VERSION 3.10)
project(autokey_cipher)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Создаём DLL
add_library(${PROJECT_NAME} SHARED autokeyCipher.cpp)

# Путь к общим заголовкам (на 2 уровня вверх)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# макрос для экспорта функций
target_compile_definitions(${PROJECT_NAME} PRIVATE CRYPTO_BUILD_DLL)

# Настройка имени выходного файла
set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
)

# Выводим информацию
message(STATUS "Configuring autokey_cipher DLL")
message(STATUS "  Source: ${CMAKE_CURRENT_SOURCE_DIR}/autokeyCipher.cpp")
message(STATUS "  Output: ${PROJECT_NAME}.dll")