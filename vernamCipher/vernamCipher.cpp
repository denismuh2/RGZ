#include "vernamCipher.h"

namespace
{
    constexpr size_t KEY_SIZE = 32;

    int process(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        if (key.data == nullptr || key.size != KEY_SIZE)
        {
            return -1;
        }

        if (input.size > 0 && input.data == nullptr)
        {
            return -2;
        }

        if (output == nullptr ||
            (input.size > 0 && output->data == nullptr))
        {
            return -3;
        }

        if (output->size < input.size)
        {
            return -4;
        }

        for (size_t i = 0; i < input.size; ++i)
        {
            output->data[i] =
                input.data[i] ^
                key.data[i % KEY_SIZE];
        }

        output->size = input.size;

        return 0;
    }
}

extern "C"
{
    CRYPTO_EXPORT const AlgorithmInfo* getAlgorithmInfo()
    {
        static AlgorithmInfo info =
        {
            "Vernam Cipher",
            KEY_SIZE
        };

        return &info;
    }

    CRYPTO_EXPORT size_t getOutputSize(
        size_t inputSize,
        int operation_type
    )
    {
        (void)operation_type;
        return inputSize;
    }

    CRYPTO_EXPORT int encrypt(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        return process(key, input, output);
    }

    CRYPTO_EXPORT int decrypt(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        return process(key, input, output);
    }
}