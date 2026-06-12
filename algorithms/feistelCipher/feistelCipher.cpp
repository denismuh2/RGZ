#include "feistelCipher.h"
#include <vector>
#include <cstring>


// анонимное пространство имен
namespace
{
    constexpr size_t KEY_SIZE = 16;
    constexpr size_t ROUNDS = 8;
    constexpr size_t BLOCK_SIZE = 8;
    constexpr size_t HALF_BLOCK = BLOCK_SIZE / 2;

    // коды возврата функций enc/dec
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    // Метаданные алгоритма
    AlgorithmInfo algorithm_info{"Feistel Network", KEY_SIZE};

    uint32_t roundFunction(uint32_t right, uint8_t keyByte){

        uint32_t result = 0;
        for (int i = 0; i < 4; ++i)
        {
            uint8_t byte = (right >> (i * 8)) & 0xFF;
            byte = ((byte << 1) | (byte >> 7)) ^ keyByte;
            result |= (static_cast<uint32_t>(byte) << (i * 8));
        }
        return result;
    }

    bool validateBuffers(ConstBuffer key,ConstBuffer input,MutBuffer* output){

        if (key.data == nullptr || key.size != KEY_SIZE)
            return false;
        if (input.data == nullptr)
            return false;
        if (output == nullptr || output->data == nullptr)
            return false;

        return true;
    }
}

extern "C"
{
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    size_t getOutputSize(size_t inputSize, int operationType)
    {
        if (operationType == DECRYPT_OPERATION)
        {
            return inputSize;
        }
        if (inputSize == 0){
            return BLOCK_SIZE;
        }
        size_t paddingSize = BLOCK_SIZE - (inputSize % BLOCK_SIZE);
        if (paddingSize == 0) paddingSize = BLOCK_SIZE;

        return inputSize + paddingSize;
    }

    int encrypt(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        try
        {
            if (input.size == 0){
                return 0;
            }

            if (!validateBuffers(key, input, output))
                return INVALID_INPUT;

            size_t workSize = getOutputSize(input.size, ENCRYPT_OPERATION);

            if (output->size < workSize)
                return INVALID_OUTPUT;

            std::vector<uint8_t> buffer(workSize, 0);
            std::memcpy(buffer.data(), input.data, input.size);

            size_t paddingSize = workSize - input.size;
            for (size_t i = 0; i < paddingSize; ++i)
            {
                buffer[input.size + i] = static_cast<uint8_t>(paddingSize);
            }

            for (size_t offset = 0; offset < workSize; offset += BLOCK_SIZE)
            {
                uint32_t left = 0;
                uint32_t right = 0;

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    left |= (static_cast<uint32_t>(buffer[offset + i]) << (i * 8));
                    right |= (static_cast<uint32_t>(buffer[offset + HALF_BLOCK + i]) << (i * 8));
                }

                for (size_t round = 0; round < ROUNDS; ++round)
                {
                    uint32_t f = roundFunction(right, key.data[round % KEY_SIZE]);

                    uint32_t newLeft = right;
                    uint32_t newRight = left ^ f;

                    left = newLeft;
                    right = newRight;
                }

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    buffer[offset + i] = static_cast<uint8_t>((left >> (i * 8)) & 0xFF);
                    buffer[offset + HALF_BLOCK + i] = static_cast<uint8_t>((right >> (i * 8)) & 0xFF);
                }
            }

            std::memcpy(output->data, buffer.data(), workSize);

            return static_cast<int>(workSize);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    int decrypt(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        try
        {
            if (input.size == 0){
                return 0;
            }

            if (!validateBuffers(key, input, output))
                return INVALID_INPUT;

            if (output->size < input.size)
                return INVALID_OUTPUT;

            if (input.size % BLOCK_SIZE != 0)
                return INVALID_INPUT;

            // 🔥 ВАЖНО: работаем через промежуточный буфер
            std::vector<uint8_t> buffer(input.size);
            std::memcpy(buffer.data(), input.data, input.size);

            for (size_t offset = 0; offset < input.size; offset += BLOCK_SIZE)
            {
                uint32_t left = 0;
                uint32_t right = 0;

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    left |= (static_cast<uint32_t>(buffer[offset + i]) << (i * 8));
                    right |= (static_cast<uint32_t>(buffer[offset + HALF_BLOCK + i]) << (i * 8));
                }

                for (int round = static_cast<int>(ROUNDS) - 1; round >= 0; --round)
                {
                    uint32_t f = roundFunction(left, key.data[round % KEY_SIZE]);

                    uint32_t newRight = left;
                    uint32_t newLeft = right ^ f;

                    left = newLeft;
                    right = newRight;
                }

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    buffer[offset + i] = static_cast<uint8_t>((left >> (i * 8)) & 0xFF);
                    buffer[offset + HALF_BLOCK + i] = static_cast<uint8_t>((right >> (i * 8)) & 0xFF);
                }
            }

            // копируем обратно
            std::memcpy(output->data, buffer.data(), input.size);

            // удаление PKCS#7 padding (упрощённо и корректно)
            uint8_t paddingSize = buffer[input.size - 1];

            if (paddingSize > 0 &&
                paddingSize <= BLOCK_SIZE &&
                paddingSize <= input.size)
            {
                bool valid = true;
                for (size_t i = input.size - paddingSize; i < input.size; ++i)
                {
                    if (buffer[i] != paddingSize)
                    {
                        valid = false;
                        break;
                    }
                }

                if (valid)
                {
                    return static_cast<int>(input.size - paddingSize);
                }
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
