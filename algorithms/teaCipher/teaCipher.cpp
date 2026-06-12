#include "teaCipher.h"

// Анонимное пространство имён
namespace
{
    constexpr size_t KEY_SIZE = 32;
    constexpr uint32_t DELTA = 0x9E3779B9;
    constexpr int ROUNDS = 32;

    // Размещаем в защищённой памяти (константная секция)
    static const char ALGO_NAME[] = "teaCipher";

    // Коды возврата для функций encrypt/decrypt
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    // Метаданные шифра
    const AlgorithmInfo algorithm_info
    {
        "TEACipher",
        KEY_SIZE
    };

    // Чтение 4 байт ключа как uint32_t
    uint32_t readU32LE(const uint8_t* data)
    {
        return static_cast<uint32_t>(data[0]) |
               (static_cast<uint32_t>(data[1]) << 8) |
               (static_cast<uint32_t>(data[2]) << 16) |
               (static_cast<uint32_t>(data[3]) << 24);
    }

    // Чтение 8 байт ключа как uint64_t
    uint64_t readU64LE(const uint8_t* data)
    {
        uint64_t value = 0;

        for (int i = 0; i < 8; ++i)
        {
            value |= static_cast<uint64_t>(data[i]) << (8 * i);
        }

        return value;
    }

    // Запись uint64_t в массив из 8 байт
    void writeU64LE(uint64_t value, uint8_t* output)
    {
        for (int i = 0; i < 8; ++i)
        {
            output[i] = static_cast<uint8_t>(value >> (8 * i));
        }
    }

    // Шифрование одного блока TEA размером 64 бита
    void encryptTEABlock(uint32_t& v0, uint32_t& v1, const uint32_t teaKey[4])
    {
        uint32_t sum = 0;

        for (int i = 0; i < ROUNDS; ++i)
        {
            sum += DELTA;
            v0 += ((v1 << 4) + teaKey[0]) ^ (v1 + sum) ^ ((v1 >> 5) + teaKey[1]);
            v1 += ((v0 << 4) + teaKey[2]) ^ (v0 + sum) ^ ((v0 >> 5) + teaKey[3]);
        }
    }

    // Создание 8 байт гаммы: TEA шифрует счётчик
    void makeGammaBlock(uint64_t counter, const uint32_t teaKey[4], uint8_t gamma[8])
    {
        uint32_t v0 = static_cast<uint32_t>(counter);
        uint32_t v1 = static_cast<uint32_t>(counter >> 32);

        encryptTEABlock(v0, v1, teaKey);

        uint64_t block = static_cast<uint64_t>(v0) |
                         (static_cast<uint64_t>(v1) << 32);

        writeU64LE(block, gamma);
    }

    // Общая функция для шифрования и расшифрования.
    // Используется режим гаммирования: TEA генерирует гамму, затем XOR с данными.
    void teaCrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        // TEA использует первые 16 байт ключа
        uint32_t teaKey[4];
        teaKey[0] = readU32LE(key.data);
        teaKey[1] = readU32LE(key.data + 4);
        teaKey[2] = readU32LE(key.data + 8);
        teaKey[3] = readU32LE(key.data + 12);

        // Оставшиеся 16 байт используем для начального счётчика
        uint64_t nonce = readU64LE(key.data + 16) ^ readU64LE(key.data + 24);

        uint8_t gamma[8];

        for (size_t i = 0; i < input.size; ++i)
        {
            if (i % 8 == 0)
            {
                uint64_t counter = nonce + static_cast<uint64_t>(i / 8);
                makeGammaBlock(counter, teaKey, gamma);
            }

            // Шифрование: открытый байт XOR байт гаммы
            // Расшифрование такое же: шифрбайт XOR тот же байт гаммы
            output->data[i] = input.data[i] ^ gamma[i % 8];
        }
    }
}

// Экспортируемые функции из DLL
extern "C"
{
    // характеристики алгоритма
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    // Вычисляет размер выходного буфера, необходимый для результата операции.
    // В TEA-гаммировании размер данных не меняется.
    size_t getOutputSize(size_t inputSize, int /*operationType*/)
    {
        return inputSize;
    }

    // шифрование
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            if (input.size == 0)
            {
                return SUCCESS;
            }

            if (key.data == nullptr)
            {
                return INVALID_KEY;
            }

            if (key.size != KEY_SIZE)
            {
                return INVALID_KEY;
            }

            if (input.size > 0 && input.data == nullptr)
            {
                return INVALID_INPUT;
            }

            if (output == nullptr)
            {
                return INVALID_OUTPUT;
            }

            if (output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }

            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            teaCrypt(key, input, output);

            output->size = input.size;
            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    // расшифрование
    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            if (key.data == nullptr)
            {
                return INVALID_KEY;
            }

            if (key.size != KEY_SIZE)
            {
                return INVALID_KEY;
            }

            if (input.size == 0)
            {
                return SUCCESS;
            }

            if (input.size > 0 && input.data == nullptr)
            {
                return INVALID_INPUT;
            }

            if (output == nullptr)
            {
                return INVALID_OUTPUT;
            }

            if (output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }

            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            teaCrypt(key, input, output);

            output->size = input.size;
            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
