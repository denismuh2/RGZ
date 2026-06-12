#include "affineCipher.h"

//Анонимное пространство имен
namespace
{
    constexpr size_t KEY_SIZE = 32;

    // Коды возврата для функций encrypt/decrypt
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = -1;
    constexpr int INVALID_INPUT = -2;
    constexpr int INVALID_OUTPUT = -3;

    // Метаданные шифра
    const AlgorithmInfo algorithm_info
    {
        "Affine Cipher",
        KEY_SIZE
    };

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

// Экспортируемые функции из DLL
extern "C"
{
    // характеристики алгоритма
    const AlgorithmInfo* getAlgorithmInfo()
    {
        return &algorithm_info;
    }

    // Вычисляет размер выходного буфера, необходимый для результата операции (размер данных не меняется)
    size_t getOutputSize(size_t inputSize, int /*operationType*/)
    {
        return inputSize;
    }

    // шифрование
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            if (key.data == nullptr || key.size != KEY_SIZE)
            {
                return INVALID_KEY;
            }
            if (input.size > 0 && input.data == nullptr)
            {
                return INVALID_INPUT;
            }
            if (input.size == 0)
            {
                return SUCCESS;
            }

            if (output == nullptr || output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }
            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            uint8_t a = key.data[0];
            uint8_t b = key.data[1];

            // Проверка: a должно быть нечётным и взаимно простым с 256
            if (a % 2 == 0 || gcd(a, 256) != 1)
            {
                return INVALID_KEY;
            }

            // Шифрование: E(x) = (a * x + b) mod 256
            for (size_t i = 0; i < input.size; ++i)
            {
                output->data[i] = static_cast<uint8_t>((a * input.data[i] + b) % 256);
            }

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
            if (key.data == nullptr || key.size != KEY_SIZE)
            {
                return INVALID_KEY;
            }
            if (input.size > 0 && input.data == nullptr)
            {
                return INVALID_INPUT;
            }
            if (input.size == 0)
            {
                return SUCCESS;
            }
            if (output == nullptr || output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }
            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            uint8_t a = key.data[0];
            uint8_t b = key.data[1];

            // Проверка: a должно быть нечётным и взаимно простым с 256
            if (a % 2 == 0 || gcd(a, 256) != 1)
            {
                return INVALID_KEY;
            }

            int inverse = modInverse(a);
            if (inverse == -1)
            {
                return INVALID_KEY;
            }

            // Расшифрование: D(y) = a^(-1) * (y - b) mod 256
            for (size_t i = 0; i < input.size; ++i)
            {
                int value = inverse * ((input.data[i] - b + 256) % 256);
                output->data[i] = static_cast<uint8_t>(value % 256);
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
