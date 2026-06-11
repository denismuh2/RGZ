#pragma once
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
// ========== МАКРОС ДЛЯ ЭКСПОРТА/ИМПОРТА DLL ==========
#ifdef _WIN32
    #ifdef CRYPTO_BUILD_DLL
        #define CRYPTO_EXPORT __declspec(dllexport)
    #else
        #define CRYPTO_EXPORT __declspec(dllimport)
    #endif
#else
    #define CRYPTO_EXPORT __attribute__((visibility("default")))
#endif

// ========== СТРУКТУРЫ ==========
struct ConstBuffer
{
    const uint8_t* data; // указатель на начало данных (входные)
    size_t size;
};

struct MutBuffer // указатель на начало буфера (выходные)
{
    uint8_t* data;
    size_t size;
};

struct AlgorithmInfo
{
    const char* algorithmName; //название шифра
    size_t keySize;
};

enum OperationType
{
    ENCRYPT_OPERATION = 0,
    DECRYPT_OPERATION = 1
};

// ========== ФУНКЦИИ (с CRYPTO_EXPORT) ==========
#ifdef __cplusplus
extern "C" {
#endif

CRYPTO_EXPORT const AlgorithmInfo* getAlgorithmInfo();
CRYPTO_EXPORT size_t getOutputSize(size_t inputSize, int operation_type);
CRYPTO_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
CRYPTO_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

#ifdef __cplusplus
}
#endif
