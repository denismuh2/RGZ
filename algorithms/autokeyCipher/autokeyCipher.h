#pragma once

#include "../../include/cryptoApi.h"

// Экспортируемые функции из DLL
extern "C"
{
    // Получение информации об алгоритме
    CRYPTO_EXPORT const AlgorithmInfo* getAlgorithmInfo();

    // Вычисление размера выходного буфера
    CRYPTO_EXPORT size_t getOutputSize(
        size_t inputSize,
        int operationType
    );
    //Шифрование
    CRYPTO_EXPORT int encrypt(
        ConstBuffer key,      // ключ (32 байта)
        ConstBuffer input,    // данные для шифрования
        MutBuffer* output     // результат шифрования
    );

    //Дешифрование
    CRYPTO_EXPORT int decrypt(
        ConstBuffer key,      // ключ (32 байта)
        ConstBuffer input,    // данные для расшифрования (шифротекст)
        MutBuffer* output     // результат расшифрования (открытый текст)
    );
}
