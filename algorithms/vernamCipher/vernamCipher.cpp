#include "vernamCipher.h"

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
        "Vernam Cipher",
        KEY_SIZE
    };
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

            // Шифрование Вернама: XOR с ключом (циклическое использование ключа)
            for (size_t i = 0; i < input.size; ++i)
            {
                output->data[i] = input.data[i] ^ key.data[i % KEY_SIZE];
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    // расшифрование (для шифра Вернама шифрование и дешифрование одинаковы)
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

            // Расшифрование Вернама: XOR с ключом (то же самое, что и шифрование)
            for (size_t i = 0; i < input.size; ++i)
            {
                output->data[i] = input.data[i] ^ key.data[i % KEY_SIZE];
            }

            return static_cast<int>(input.size);
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}
