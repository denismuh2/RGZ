#include "caesarCipher.h"

namespace
{
    constexpr size_t KEY_SIZE = 1;
    constexpr int SUCCESS = 0;
    constexpr int INVALID_KEY = 1;
    constexpr int INVALID_INPUT = 2;
    constexpr int INVALID_OUTPUT = 3;

    const AlgorithmInfo algorithm_info{ "Caesar Cipher", KEY_SIZE };
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
            if (key.data == nullptr || key.size != KEY_SIZE)
                return INVALID_KEY;
            if (input.data == nullptr)
                return INVALID_INPUT;
            if (output == nullptr || output->data == nullptr)
                return INVALID_OUTPUT;
            if (output->size < input.size)
                return INVALID_OUTPUT;

            uint8_t shift = key.data[0];
            for (size_t i = 0; i < input.size; ++i)
                output->data[i] = (input.data[i] + shift) % 256;

            return SUCCESS;
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output)
    {
        try
        {
            if (key.data == nullptr || key.size != KEY_SIZE)
                return INVALID_KEY;
            if (input.data == nullptr)
                return INVALID_INPUT;
            if (output == nullptr || output->data == nullptr)
                return INVALID_OUTPUT;
            if (output->size < input.size)
                return INVALID_OUTPUT;

            uint8_t shift = key.data[0];
            for (size_t i = 0; i < input.size; ++i)
                output->data[i] = (input.data[i] - shift + 256) % 256;

            return SUCCESS;
        }
        catch (...)
        {
            return INVALID_INPUT;
        }
    }
}