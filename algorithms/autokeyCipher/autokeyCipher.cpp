#include "autokeyCipher.h"

//анонимное пространство имен
namespace
{
    constexpr size_t KEY_SIZE = 32;

    // Коды возврата для функций encrypt/decrypt
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = 1;
    constexpr int INVALID_INPUT = 2;
    constexpr int INVALID_OUTPUT = 3;

    // Метаданные шифра
    AlgorithmInfo algorithm_info
    {
        "autokeyСipher", KEY_SIZE
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

    // Вычисляет размер выходного буфера, необходимый для результата операции.(в автоключе размер данных не меняется)
    size_t getOutputSize(size_t inputSize, int /*operationType*/)
    {
        return inputSize;
    }

    // шифрование
    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
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

            if (input.data == nullptr)
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

            // Шифрование
            for (size_t i = 0; i < input.size; ++i)
            {
                uint8_t autokeyByte;

                if (i < KEY_SIZE)
                {
                    autokeyByte = key.data[i];
                }
                else
                {
                    autokeyByte = output->data[i - KEY_SIZE];
                }

                // открытый текст + байт ключа) % 256
                output->data[i] = (input.data[i] + autokeyByte) % 256;
            }
            return SUCCESS;
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

            if (input.data == nullptr)
            {
                return INVALID_INPUT;
            }

            if (output == nullptr || output->data == nullptr)
            {
                return INVALID_OUTPUT;
            }

            if (output->size < input.size)
            {
                return INVALID_OUTPUT;
            }

            for (size_t i = 0; i < input.size; ++i)
            {
                uint8_t autokeyByte;

                if (i < KEY_SIZE)
                {
                    autokeyByte = key.data[i];
                }
                else
                {
                    autokeyByte = input.data[i - KEY_SIZE];
                }

                // (шифротекст - ключевой_байт + 256) % 256
                output->data[i] = (input.data[i] - autokeyByte + 256) % 256;
            }
            return SUCCESS;
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

}
