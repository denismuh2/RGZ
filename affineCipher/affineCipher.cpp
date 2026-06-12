#include "affineCipher.h"

namespace
{
    constexpr size_t KEY_SIZE = 32;

    int gcd(int a, int b)
    {
        while (b != 0)
        {
            int t = a % b;
            a = b;
            b = t;
        }

        return a;
    }

    int modInverse(int a)
    {
        for (int x = 1; x < 256; ++x)
        {
            if ((a * x) % 256 == 1)
            {
                return x;
            }
        }

        return -1;
    }
}

extern "C"
{
    CRYPTO_EXPORT const AlgorithmInfo* getAlgorithmInfo()
    {
        static AlgorithmInfo info =
        {
            "Affine Cipher",
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

        uint8_t a = key.data[0];
        uint8_t b = key.data[1];

        if (gcd(a, 256) != 1)
        {
            return -5;
        }

        for (size_t i = 0; i < input.size; ++i)
        {
            output->data[i] =
                static_cast<uint8_t>(
                    (a * input.data[i] + b) % 256
                );
        }

        output->size = input.size;

        return 0;
    }

    CRYPTO_EXPORT int decrypt(
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

        uint8_t a = key.data[0];
        uint8_t b = key.data[1];

        int inverse = modInverse(a);

        if (inverse == -1)
        {
            return -5;
        }

        for (size_t i = 0; i < input.size; ++i)
        {
            int value =
                inverse *
                ((input.data[i] - b + 256) % 256);

            output->data[i] =
                static_cast<uint8_t>(value % 256);
        }

        output->size = input.size;

        return 0;
    }
}