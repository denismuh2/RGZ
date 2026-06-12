#include "chacha20.h"
#include <cstring>
#include <algorithm>

namespace
{
    constexpr size_t KEY_SIZE = 32;      // Только ключ
    constexpr size_t NONCE_SIZE = 12;    // Nonce отдельно
    constexpr size_t TOTAL_SIZE = 44;    // 32 key + 12 nonce (для API)
    constexpr size_t BLOCK_SIZE = 64;
    constexpr size_t QUARTER_ROUNDS = 20;

    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    const AlgorithmInfo algorithm_info{ "ChaCha20", TOTAL_SIZE };

    class ChaCha20
    {
    public:
        ChaCha20(const uint8_t* key, const uint8_t* nonce)
        {
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            // Чтение 32-байтного ключа
            for (int i = 0; i < 8; ++i)
            {
                state[4 + i] = static_cast<uint32_t>(key[i*4]) |
                              (static_cast<uint32_t>(key[i*4+1]) << 8) |
                              (static_cast<uint32_t>(key[i*4+2]) << 16) |
                              (static_cast<uint32_t>(key[i*4+3]) << 24);
            }

            state[12] = 0;
            state[13] = 0;

            // Чтение 12-байтного nonce
            state[14] = static_cast<uint32_t>(nonce[0]) |
                       (static_cast<uint32_t>(nonce[1]) << 8) |
                       (static_cast<uint32_t>(nonce[2]) << 16) |
                       (static_cast<uint32_t>(nonce[3]) << 24);

            state[15] = static_cast<uint32_t>(nonce[4]) |
                       (static_cast<uint32_t>(nonce[5]) << 8) |
                       (static_cast<uint32_t>(nonce[6]) << 16) |
                       (static_cast<uint32_t>(nonce[7]) << 24);

            // Оставшиеся 4 байта nonce не используются в стандартном ChaCha20
        }

        void nextBlock(uint8_t* output)
        {
            uint32_t working[16];
            std::memcpy(working, state, sizeof(working));

            for (int round = 0; round < 10; ++round)
            {
                quarterRound(working, 0, 4, 8, 12);
                quarterRound(working, 1, 5, 9, 13);
                quarterRound(working, 2, 6, 10, 14);
                quarterRound(working, 3, 7, 11, 15);
                quarterRound(working, 0, 5, 10, 15);
                quarterRound(working, 1, 6, 11, 12);
                quarterRound(working, 2, 7, 8, 13);
                quarterRound(working, 3, 4, 9, 14);
            }

            for (int i = 0; i < 16; ++i)
                working[i] += state[i];

            for (int i = 0; i < 16; ++i)
            {
                output[4 * i] = (working[i] >> 0) & 0xFF;
                output[4 * i + 1] = (working[i] >> 8) & 0xFF;
                output[4 * i + 2] = (working[i] >> 16) & 0xFF;
                output[4 * i + 3] = (working[i] >> 24) & 0xFF;
            }

            if (++state[12] == 0)
                ++state[13];
        }

    private:
        uint32_t state[16];

        static void quarterRound(uint32_t* x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >> 16);
            x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >> 20);
            x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >> 24);
            x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >> 25);
        }
    };
}

extern "C"
{
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    size_t getOutputSize(size_t inputSize, int /*operationType*/)
    {
        return inputSize;
    }

    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            if (key.data == nullptr || key.size != TOTAL_SIZE)
                return INVALID_KEY;
            if (input.data == nullptr)
                return INVALID_INPUT;
            if (output == nullptr || output->data == nullptr)
                return INVALID_OUTPUT;
            if (output->size < input.size)
                return INVALID_OUTPUT;

            // Разделяем ключ и nonce
            const uint8_t* secretKey = key.data;           // Первые 32 байта
            const uint8_t* nonce = key.data + KEY_SIZE;    // Следующие 12 байт

            ChaCha20 cipher(secretKey, nonce);
            uint8_t keystream[BLOCK_SIZE];
            size_t processed = 0;

            while (processed < input.size)
            {
                cipher.nextBlock(keystream);
                size_t chunk = std::min<size_t>(BLOCK_SIZE, input.size - processed);
                for (size_t i = 0; i < chunk; ++i)
                    output->data[processed + i] = input.data[processed + i] ^ keystream[i];
                processed += chunk;
            }
            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        // Для ChaCha20 шифрование и дешифрование одинаковы (XOR с потоком)
        return encrypt(key, input, output);
    }
}
