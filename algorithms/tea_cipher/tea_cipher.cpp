#include "tea_cipher.h"

#include <cstdint>
#include <cstddef>

namespace
{
    constexpr size_t KEY_SIZE = 32;
    constexpr uint32_t DELTA = 0x9E3779B9;
    constexpr int ROUNDS = 32;

    uint32_t read_u32_le(const uint8_t* p)
    {
        return static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    }

    uint64_t read_u64_le(const uint8_t* p)
    {
        uint64_t value = 0;
        for (int i = 0; i < 8; ++i)
        {
            value |= static_cast<uint64_t>(p[i]) << (8 * i);
        }
        return value;
    }

    void write_u64_le(uint64_t value, uint8_t* out)
    {
        for (int i = 0; i < 8; ++i)
        {
            out[i] = static_cast<uint8_t>(value >> (8 * i));
        }
    }

    void tea_encrypt_block(uint32_t& v0, uint32_t& v1, const uint32_t k[4])
    {
        uint32_t sum = 0;

        for (int i = 0; i < ROUNDS; ++i)
        {
            sum += DELTA;
            v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
            v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        }
    }

    void make_gamma_block(uint64_t counter, const uint32_t tea_key[4], uint8_t gamma[8])
    {
        uint32_t v0 = static_cast<uint32_t>(counter);
        uint32_t v1 = static_cast<uint32_t>(counter >> 32);

        tea_encrypt_block(v0, v1, tea_key);

        uint64_t block = static_cast<uint64_t>(v0) |
                         (static_cast<uint64_t>(v1) << 32);

        write_u64_le(block, gamma);
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

        uint32_t tea_key[4];
        tea_key[0] = read_u32_le(key.data);
        tea_key[1] = read_u32_le(key.data + 4);
        tea_key[2] = read_u32_le(key.data + 8);
        tea_key[3] = read_u32_le(key.data + 12);

        uint64_t nonce = read_u64_le(key.data + 16) ^ read_u64_le(key.data + 24);

        uint8_t gamma[8];

        for (size_t i = 0; i < input.size; ++i)
        {
            if (i % 8 == 0)
            {
                uint64_t counter = nonce + static_cast<uint64_t>(i / 8);
                make_gamma_block(counter, tea_key, gamma);
            }

            output->data[i] = input.data[i] ^ gamma[i % 8];
        }

        output->size = input.size;
        return 0;
    }
}

extern "C"
{
    CRYPTO_EXPORT const AlgorithmInfo* get_algorithm_info()
    {
        static AlgorithmInfo info = {"TEA Cipher", KEY_SIZE};
        return &info;
    }

    CRYPTO_EXPORT size_t get_output_size(size_t input_size, int operation_type)
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
