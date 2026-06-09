#pragma once

#include <cstddef>
#include <cstdint>

// ========== Ã¿ –Œ— ƒÀﬂ › —œŒ–“¿/»ÃœŒ–“¿ DLL ==========
#ifdef _WIN32
    #ifdef CRYPTO_BUILD_DLL
        #define CRYPTO_EXPORT __declspec(dllexport)
    #else
        #define CRYPTO_EXPORT __declspec(dllimport)
    #endif
#else
    #define CRYPTO_EXPORT __attribute__((visibility("default")))
#endif

// ========== —“–” “”–€ ==========
struct ConstBuffer
{
    const uint8_t* data;
    size_t size;
};

struct MutBuffer
{
    uint8_t* data;
    size_t size;
};

struct AlgorithmInfo
{
    const char* algorithm_name;
    size_t key_size;
};

enum OperationType
{
    ENCRYPT_OPERATION = 0,
    DECRYPT_OPERATION = 1
};

// ========== ‘”Õ ÷»» (Ò CRYPTO_EXPORT) ==========
#ifdef __cplusplus
extern "C" {
#endif

CRYPTO_EXPORT const AlgorithmInfo* get_algorithm_info();
CRYPTO_EXPORT size_t get_output_size(size_t input_size, int operation_type);
CRYPTO_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
CRYPTO_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);

#ifdef __cplusplus
}
#endif
