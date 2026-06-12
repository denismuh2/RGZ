#include "lcg_cipher.h"


namespace
{
    constexpr size_t KEY_SIZE = 32;

    uint64_t read_u64_le(const uint8_t* p)
    {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
        {
            value |= static_cast<uint64_t>(p[i]) << (8 * i);
        }
        return value;
    }

    uint64_t make_odd(uint64_t value)
    {
        return value | 1ULL;
    }

    uint64_t next_lcg(uint64_t& state, uint64_t a, uint64_t c)
    {
        state = state * a + c;
        return state;
    }

    int process(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        if (key.data == nullptr || key.size != KEY_SIZE)
        {
            return -1;
        }

        if (input.size > 0 && input.data == nullptr)
        {
            return -2;
        }

        if (output == nullptr || (input.size > 0 && output->data == nullptr))
        {
            return -3;
        }

        if (output->size < input.size)
        {
            return -4;
        }

        uint64_t state = read_u64_le(key.data);
        uint64_t a = make_odd(read_u64_le(key.data + 8));
        uint64_t c = make_odd(read_u64_le(key.data + 16));
        uint64_t mix = read_u64_le(key.data + 24);

        state ^= mix;

        for (size_t i = 0; i < input.size; ++i)
        {
            if (i % 8 == 0)
            {
                next_lcg(state, a, c);
            }

            uint8_t gamma = static_cast<uint8_t>(state >> (8 * (i % 8)));
            output->data[i] = input.data[i] ^ gamma;
        }

        output->size = input.size;
        return 0;
    }
}

extern "C"
{
    CRYPTO_EXPORT const AlgorithmInfo* getAlgorithmInfo()
    {
        static AlgorithmInfo info = {"LCG Cipher", KEY_SIZE};
        return &info;
    }

    CRYPTO_EXPORT size_t getOutputSize(size_t input_size, int operation_type)
    {
        (void)operation_type;
        return input_size;
    }

    CRYPTO_EXPORT int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        return process(key, input, output);
    }

    CRYPTO_EXPORT int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        return process(key, input, output);
    }
}
