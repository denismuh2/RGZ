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
    constexpr int INVALID_KEY = 1;
    constexpr int INVALID_INPUT = 2;
    constexpr int INVALID_OUTPUT = 3;

    // Метаданные алгоритма
    AlgorithmInfo algorithm_info{"Feistel Network", KEY_SIZE};

    // Раундовая функция F. Выполняет циклический сдвиг влево на 1 бит и XOR с ключом для каждого байта
    uint32_t roundFunction(uint32_t right, uint8_t keyByte){

        uint32_t result = 0;
        for (int i = 0; i < 4; ++i)
        {
            uint8_t byte = (right >> (i * 8)) & 0xFF;
            byte = ((byte << 1) | (byte >> 7)) ^ keyByte; // Циклический сдвиг влево на 1 бит и XOR с ключом
            result |= (static_cast<uint32_t>(byte) << (i * 8));
        }
        return result;
    }

    // проверка корректности входных буферов
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

// Экспортируемые функции из API
extern "C"
{
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    // Вычисляет размер выходного буфера, необходимый для результата операции
    size_t getOutputSize(size_t inputSize, int operationType)
    {
        if (operationType == DECRYPT_OPERATION)
        {
            return inputSize;
        }
        size_t paddingSize = BLOCK_SIZE - (inputSize % BLOCK_SIZE); // При шифровании добавляем PKCS#7 padding до BLOCK_SIZE
        if (paddingSize == 0) paddingSize = BLOCK_SIZE;

        return inputSize + paddingSize;
    }

    // Шифрование
    int encrypt(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        try
        {
            if (!validateBuffers(key, input, output)) // проверки
                return INVALID_INPUT;

            // размер с PKCS#7 padding
            size_t workSize = getOutputSize(input.size, ENCRYPT_OPERATION);

            if (output->size < workSize)
                return INVALID_OUTPUT;

            std::vector<uint8_t> buffer(workSize, 0); // буфер с паддингом
            std::memcpy(buffer.data(), input.data, input.size);

            // добавляем байты со значением = количеству добавленных байт
            size_t paddingSize = workSize - input.size;
            for (size_t i = 0; i < paddingSize; ++i)
            {
                buffer[input.size + i] = static_cast<uint8_t>(paddingSize);
            }

            // Шифрование блока
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
                    // Раундовая функция F применяется к правой половине
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
            // Копируем результат в выходной буфер
            std::memcpy(output->data, buffer.data(), workSize);

            return static_cast<int>(workSize);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    // Дешифрование
    int decrypt(
        ConstBuffer key,
        ConstBuffer input,
        MutBuffer* output
    )
    {
        try
        {
            if (!validateBuffers(key, input, output)) // Проверки
                return INVALID_INPUT;

            if (output->size < input.size)
                return INVALID_OUTPUT;

            std::memcpy(output->data, input.data, input.size);

            if (input.size % BLOCK_SIZE != 0) // Проверяем, что размер кратен блоку
                return INVALID_INPUT;

            // Дешифрование блока
            for (size_t offset = 0; offset < input.size; offset += BLOCK_SIZE)
            {
                uint32_t left = 0;
                uint32_t right = 0;

                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    left |= (static_cast<uint32_t>(output->data[offset + i]) << (i * 8));
                    right |= (static_cast<uint32_t>(output->data[offset + HALF_BLOCK + i]) << (i * 8));
                }

                // Раунды в обратном порядке
                for (int round = static_cast<int>(ROUNDS) - 1; round >= 0; --round)
                {
                    // При дешифровании функция F применяется к левой половине
                    uint32_t f = roundFunction(left, key.data[round % KEY_SIZE]);

                    uint32_t newRight = left;
                    uint32_t newLeft = right ^ f;

                    left = newLeft;
                    right = newRight;
                }
                for (size_t i = 0; i < HALF_BLOCK; ++i)
                {
                    output->data[offset + i] = static_cast<uint8_t>((left >> (i * 8)) & 0xFF);
                    output->data[offset + HALF_BLOCK + i] = static_cast<uint8_t>((right >> (i * 8)) & 0xFF);
                }
            }
            // Удаление паддинга. На что заканчиваются данные, столько байт мы удаляем с конца ><)
            if (input.size > 0)
            {
                uint8_t paddingSize = output->data[input.size - 1];

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
