#include "autokeyCipher.h"

#include <array>
#include <algorithm>

namespace
{

constexpr size_t KEY_SIZE = 32;

constexpr int SUCCESS = 0;
constexpr int INVALID_KEY = 1;
constexpr int INVALID_INPUT = 2;
constexpr int INVALID_OUTPUT = 3;

AlgorithmInfo algorithm_info
{
    "autokey_cipher",
    KEY_SIZE
};

uint8_t add_mod_256(
    uint8_t lhs,
    uint8_t rhs
)
{
    return static_cast<uint8_t>(
        (static_cast<uint16_t>(lhs) +
         static_cast<uint16_t>(rhs)) & 0xFF
    );
}

uint8_t sub_mod_256(
    uint8_t lhs,
    uint8_t rhs
)
{
    return static_cast<uint8_t>(
        (256 +
         static_cast<int>(lhs) -
         static_cast<int>(rhs)) & 0xFF
    );
}

}

extern "C"
{

const AlgorithmInfo* get_algorithm_info()
{
    return &algorithm_info;
}

size_t get_output_size(
    size_t input_size,
    int
)
{
    return input_size;
}

int encrypt(
    ConstBuffer key,
    ConstBuffer input,
    MutBuffer* output
)
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

        for (size_t i = 0; i < input.size; ++i)
        {
            uint8_t autokey_byte;

            if (i < KEY_SIZE)
            {
                autokey_byte = key.data[i];
            }
            else
            {
                autokey_byte = output->data[i - KEY_SIZE];
            }

            output->data[i] =
                add_mod_256(
                    input.data[i],
                    autokey_byte
                );
        }

        return SUCCESS;
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

        for (size_t i = 0; i < input.size; ++i)
        {
            uint8_t autokey_byte;

            if (i < KEY_SIZE)
            {
                autokey_byte = key.data[i];
            }
            else
            {
                autokey_byte = input.data[i - KEY_SIZE];
            }

            output->data[i] =
                sub_mod_256(
                    input.data[i],
                    autokey_byte
                );
        }

        return SUCCESS;
    }
    catch (...)
    {
        return INVALID_INPUT;
    }
}

}
