#include "lcgCipher.h"

// Анонимное пространство имён
namespace
{
    constexpr size_t KEY_SIZE = 32;

    // Размещаем в защищённой памяти (константная секция)
    static const char ALGO_NAME[] = "lcgCipher";

    // Коды возврата для функций encrypt/decrypt
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    // Метаданные шифра
    const AlgorithmInfo algorithm_info
    {
        "LCGCipher",
        KEY_SIZE
    };

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

    // Делаем число нечётным, чтобы параметры LCG были лучше
    uint64_t makeOdd(uint64_t value)
    {
        return value | 1ULL;
    }

    // Один шаг генератора LCG: X(n+1) = a * X(n) + c
    uint64_t nextLCG(uint64_t& state, uint64_t a, uint64_t c)
    {
        state = state * a + c;
        return state;
    }

    // Общая функция для шифрования и расшифрования.
    // Для XOR-гаммирования encrypt и decrypt одинаковые.
    void lcgCrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        // 32-байтный ключ делим на 4 части по 8 байт
        uint64_t state = readU64LE(key.data);
        uint64_t a = makeOdd(readU64LE(key.data + 8));
        uint64_t c = makeOdd(readU64LE(key.data + 16));
        uint64_t mix = readU64LE(key.data + 24);

        state ^= mix;

        // Генерируем гамму LCG и XOR-им её с входными байтами
        for (size_t i = 0; i < input.size; ++i)
        {
            if (i % 8 == 0)
            {
                nextLCG(state, a, c);
            }

            uint8_t lcgByte = static_cast<uint8_t>(state >> (8 * (i % 8)));

            // Шифрование: открытый байт XOR байт гаммы
            // Расшифрование такое же: шифрбайт XOR тот же байт гаммы
            output->data[i] = input.data[i] ^ lcgByte;
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
    // В LCG размер данных не меняется.
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

            lcgCrypt(key, input, output);

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

            lcgCrypt(key, input, output);

            output->size = input.size;
            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
