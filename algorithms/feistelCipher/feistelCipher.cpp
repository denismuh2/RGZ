#include "feistelCipher.h"
#include <vector>
#include <cstring>

namespace
{
    constexpr size_t KEY_SIZE = 16;           // 16 байт
    constexpr size_t ROUNDS = 8;              // количество раундов
    constexpr size_t BLOCK_SIZE = 8;          // размер блока 8 байт
    constexpr size_t HALF_BLOCK = BLOCK_SIZE / 2;  // половина блока = 4 байта

    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = 1;
    constexpr int INVALID_INPUT = 2;
    constexpr int INVALID_OUTPUT = 3;

    AlgorithmInfo algorithm_info
    {
        "Feistel Network",
        KEY_SIZE
    };

    uint32_t roundFunction(uint32_t right, uint8_t keyByte)
    {
        // Применяем циклический сдвиг и XOR к каждому байту
        uint32_t result = 0;
        for (int i = 0; i < 4; ++i)
        {
            uint8_t byte = (right >> (i * 8)) & 0xFF;
            byte = ((byte << 1) | (byte >> 7)) ^ keyByte;
            result |= (static_cast<uint32_t>(byte) << (i * 8));
        }
        return result;
    }

    bool validateBuffers(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
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

    // Вычисление размера выходного буфера с PKCS#7 padding
    size_t getOutputSize(size_t inputSize, int operationType)
    {
        if (operationType == DECRYPT_OPERATION)
        {
            // При расшифровании размер не меняется
            return inputSize;
        }

        // При шифровании: добавляем PKCS#7 padding до BLOCK_SIZE
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
            if (!validateBuffers(key, input, output))
                return INVALID_INPUT;

            // Вычисляем размер с PKCS#7 padding
            size_t workSize = getOutputSize(input.size, ENCRYPT_OPERATION);

            if (output->size < workSize)
                return INVALID_OUTPUT;

            // Создаём буфер с PKCS#7 padding
            std::vector<uint8_t> buffer(workSize, 0);
            std::memcpy(buffer.data(), input.data, input.size);

            // PKCS#7 padding
            size_t paddingSize = workSize - input.size;
            for (size_t i = 0; i < paddingSize; ++i)
            {
                buffer[input.size + i] = static_cast<uint8_t>(paddingSize);
            }

            // Обрабатываем каждый блок по BLOCK_SIZE байт
            for (size_t offset = 0; offset < workSize; offset += BLOCK_SIZE)
            {
                // Извлекаем левую и правую половины блока
                uint32_t left = 0;
                uint32_t right = 0;

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    left |= (static_cast<uint32_t>(buffer[offset + i]) << (i * 8));
                    right |= (static_cast<uint32_t>(buffer[offset + HALF_BLOCK + i]) << (i * 8));
                }

                // 8 раундов Фейстеля
                for (size_t round = 0; round < ROUNDS; ++round)
                {
                    uint32_t f = roundFunction(right, key.data[round % KEY_SIZE]);
                    uint32_t newLeft = right;
                    uint32_t newRight = left ^ f;

                    left = newLeft;
                    right = newRight;
                }

                // Записываем результат обратно в буфер
                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    buffer[offset + i] = static_cast<uint8_t>((left >> (i * 8)) & 0xFF);
                    buffer[offset + HALF_BLOCK + i] = static_cast<uint8_t>((right >> (i * 8)) & 0xFF);
                }
            }

            // Копируем результат в выходной буфер
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
            if (!validateBuffers(key, input, output))
                return INVALID_INPUT;

            if (output->size < input.size)
                return INVALID_OUTPUT;

            // Копируем входные данные в выходной буфер
            std::memcpy(output->data, input.data, input.size);

            // Проверяем, что размер кратен блоку
            if (input.size % BLOCK_SIZE != 0)
                return INVALID_INPUT;

            // Обрабатываем каждый блок по BLOCK_SIZE байт
            for (size_t offset = 0; offset < input.size; offset += BLOCK_SIZE)
            {
                // Извлекаем левую и правую половины блока
                uint32_t left = 0;
                uint32_t right = 0;

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    left |= (static_cast<uint32_t>(output->data[offset + i]) << (i * 8));
                    right |= (static_cast<uint32_t>(output->data[offset + HALF_BLOCK + i]) << (i * 8));
                }

                // Раунды Фейстеля в обратном порядке
                for (int round = static_cast<int>(ROUNDS) - 1; round >= 0; --round)
                {
                    uint32_t f = roundFunction(left, key.data[round % KEY_SIZE]);
                    uint32_t newRight = left;
                    uint32_t newLeft = right ^ f;

                    left = newLeft;
                    right = newRight;
                }

                // Записываем результат обратно в буфер
                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    output->data[offset + i] = static_cast<uint8_t>((left >> (i * 8)) & 0xFF);
                    output->data[offset + HALF_BLOCK + i] = static_cast<uint8_t>((right >> (i * 8)) & 0xFF);
                }
            }

            // Удаляем PKCS#7 padding
            if (input.size > 0)
            {
                uint8_t paddingSize = output->data[input.size - 1];

                // Проверка корректности padding
                if (paddingSize > 0 && paddingSize <= BLOCK_SIZE && paddingSize <= input.size)
                {
                    bool valid = true;
                    for (size_t i = input.size - paddingSize; i < input.size; ++i)
                    {
                        if (output->data[i] != paddingSize)
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
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
