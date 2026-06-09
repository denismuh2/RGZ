#pragma once

#include "../../include/cryptoApi.h"

extern "C"
{

CRYPTO_EXPORT const AlgorithmInfo* get_algorithm_info();

CRYPTO_EXPORT size_t get_output_size(
    size_t input_size,
    int operation_type
);

CRYPTO_EXPORT int encrypt(
    ConstBuffer key,
    ConstBuffer input,
    MutBuffer* output
);

CRYPTO_EXPORT int decrypt(
    ConstBuffer key,
    ConstBuffer input,
    MutBuffer* output
);

}
