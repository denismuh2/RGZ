#pragma once
#include "../../include/cryptoApi.h"

extern "C"
{
    CRYPTO_EXPORT const AlgorithmInfo* getAlgorithmInfo();
    CRYPTO_EXPORT size_t getOutputSize(size_t inputSize, int operationType);
    CRYPTO_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
    CRYPTO_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
}