#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>
#include <algorithm>
#include <windows.h>

#include "include/cryptoApi.h"

using namespace std;

struct CryptoModule
{
    HMODULE library = nullptr;
    string name;
    string path;

    const AlgorithmInfo* (*getAlgorithmInfo)() = nullptr;
    size_t (*getOutputSize)(size_t, int) = nullptr;
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
};

// Поиск всех DLL в папке algorithms/
vector<string> find_dlls_in_algorithms_folder()
{
    vector<string> dllPaths;

    // Папка algorithms находится в корне проекта
    filesystem::path algorithms_dir = filesystem::current_path() / "algorithms";

    if (!filesystem::exists(algorithms_dir))
    {
        cout << "Папка 'algorithms' не найдена в: " << filesystem::current_path() << "\n";
        return dllPaths;
    }

    for (const auto& entry : filesystem::directory_iterator(algorithms_dir))
    {
        if (entry.is_directory())
        {
            // Ищем .dll или .so в подпапке
            for (const auto& file : filesystem::directory_iterator(entry.path()))
            {
                string ext = file.path().extension().string();
                string filename = file.path().filename().string();

#ifdef _WIN32
                if (ext == ".dll")
#else
                if (ext == ".so" || filename.find(".so") != string::npos)
#endif
                {
                    dllPaths.push_back(file.path().string());
                    cout << "Найдена библиотека: " << file.path().filename().string() << "\n";
                }
            }
        }
        else
        {
            // Ищем .dll прямо в папке algorithms (если есть)
            string ext = entry.path().extension().string();
#ifdef _WIN32
            if (ext == ".dll")
#else
            if (ext == ".so")
#endif
            {
                dllPaths.push_back(entry.path().string());
                cout << "Найдена библиотека: " << entry.path().filename().string() << "\n";
            }
        }
    }

    return dllPaths;
}

// Загрузка модуля по пути
bool loadModule(const string& dll_path, CryptoModule& module)
{
    module.path = dll_path;
    module.name = filesystem::path(dll_path).filename().string();

    module.library = LoadLibraryA(dll_path.c_str());

    if (!module.library)
    {
        return false;
    }

    module.getAlgorithmInfo = reinterpret_cast<decltype(module.getAlgorithmInfo)>(
        GetProcAddress(module.library, "getAlgorithmInfo"));

    module.getOutputSize = reinterpret_cast<decltype(module.getOutputSize)>(
        GetProcAddress(module.library, "getOutputSize"));

    module.encrypt = reinterpret_cast<decltype(module.encrypt)>(
        GetProcAddress(module.library, "encrypt"));

    module.decrypt = reinterpret_cast<decltype(module.decrypt)>(
        GetProcAddress(module.library, "decrypt"));

    return module.getAlgorithmInfo &&
           module.getOutputSize &&
           module.encrypt &&
           module.decrypt;
}

// Выбор алгоритма из списка
bool selectAlgorithm(const vector<CryptoModule>& modules, CryptoModule& selected)
{
    if (modules.empty())
    {
        cout << "Алгоритмы не найдены!\n";
        return false;
    }

    cout << "\n=== Доступные алгоритмы ===\n";
    for (size_t i = 0; i < modules.size(); ++i)
    {
        const AlgorithmInfo* info = modules[i].getAlgorithmInfo();
        cout << i + 1 << ". " << info->algorithmName
                  << " (размер ключа: " << info->keySize  << " байт)\n";
        cout << "   Файл: " << modules[i].name << "\n";
    }

    int choice;
    cout << "\nВыберите алгоритм (1-" << modules.size() << "): ";
    cin >> choice;
    cin.ignore();

    if (choice < 1 || choice > static_cast<int>(modules.size()))
    {
        cout << "Неверный выбор\n";
        return false;
    }

    selected = modules[choice - 1];
    return true;
}

vector<uint8_t> generateKey(size_t size)
{
    random_device rd;
    vector<uint8_t> key(size);
    for (auto& b : key)
    {
        b = static_cast<uint8_t>(rd());
    }
    return key;
}

bool saveBinary(const string& path, const vector<uint8_t>& data)
{
    ofstream file(path, ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool loadBinary(const string& path, vector<uint8_t>& data)
{
    ifstream file(path, ios::binary);
    if (!file) return false;

    file.seekg(0, ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, ios::beg);

    data.resize(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    return true;
}

int main()
{
#ifdef _WIN32
    system("chcp 1251 > nul");  // Переключаем консоль на Windows-1251
#endif

    cout << "=== Multi-Algo Cryptotool ===\n\n";

    // 1. Поиск всех DLL в папке algorithms/
    cout << "Поиск библиотек в папке 'algorithms/'...\n";
    vector<string> dllPaths = find_dlls_in_algorithms_folder();

    if (dllPaths.empty())
    {
        cout << "Библиотеки не найдены. Поместите DLL ваших алгоритмов в папку 'algorithms/'.\n";
        cout << "Нажмите Enter для выхода...";
        cin.get();
        return 1;
    }

    // 2. Загрузка всех найденных модулей
    vector<CryptoModule> modules;
    for (const auto& path : dllPaths)
    {
        CryptoModule module;
        if (loadModule(path, module))
        {
            modules.push_back(module);
            cout << "Загружено: " << module.name << "\n";
        }
        else
        {
            cout << "Не удалось загрузить: " << path << "\n";
        }
    }

    if (modules.empty())
    {
        cout << "Нет загруженных алгоритмов.\n";
        return 1;
    }

    // 3. Выбор алгоритма пользователем
    CryptoModule module;
    if (!selectAlgorithm(modules, module))
    {
        return 1;
    }

    const AlgorithmInfo* info = module.getAlgorithmInfo();
    cout << "\n=== Выбран: " << info->algorithmName << " ===\n";
    cout << "Размер ключа: " << info->keySize << " байт\n";

    vector<uint8_t> key;

    // 4. Основное меню
    while (true)
    {
        int choice;

        cout << "\n=== Меню ===\n";
        cout << "1. Сгенерировать ключ\n";
        cout << "2. Загрузить ключ\n";
        cout << "3. Зашифровать текст\n";
        cout << "4. Расшифровать текст (из hex)\n";
        cout << "5. Зашифровать файл\n";
        cout << "6. Расшифровать файл\n";
        cout << "7. Сменить алгоритм\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";

        cin >> choice;
        cin.ignore();

        if (choice == 0)
        {
            break;
        }

        if (choice == 7)
        {
            // Переключение алгоритма
            if (!selectAlgorithm(modules, module))
            {
                continue;
            }
            info = module.getAlgorithmInfo();
            cout << "\n=== Выбран: " << info->algorithmName << " ===\n";
            cout << "Размер ключа: " << info->keySize  << " байт\n";
            key.clear(); // Очищаем старый ключ (он может быть неправильного размера)
            continue;
        }

        if (choice == 1)
        {
            key = generateKey(info->keySize);

            string path;
            cout << "Сохранить ключ в файл: ";
            getline(cin, path);

            if (saveBinary(path, key))
            {
                cout << "Ключ сохранён (" << key.size() << " байт)\n";
            }
            else
            {
                cout << "Не удалось сохранить ключ\n";
            }
        }

        else if (choice == 2)  // Load key
        {
            string path;
            cout << "Загрузить ключ из файла: ";
            getline(cin, path);

            vector<uint8_t> loadedKey;
            if (!loadBinary(path, loadedKey))
            {
                cout << "Не удалось загрузить ключ\n";
                continue;
            }

            if (loadedKey.size() != info->keySize)
            {
                cout << "Неверный размер ключа. Ожидалось " << info->keySize
                          << " байт, получено " << loadedKey.size() << " байт\n";
                continue;
            }

            key = loadedKey;
            cout << "Ключ загружен (" << key.size() << " байт)\n";
        }

        else if (choice == 3)  // Encrypt text
        {
            if (key.empty())
            {
                cout << "Пожалуйста, сначала сгенерируйте или загрузите ключ (пункт 1 или 2)\n";
                continue;
            }

            string text;
            cout << "Текст для шифрования: ";
            getline(cin, text);

            vector<uint8_t> input(text.begin(), text.end());
            vector<uint8_t> output(module.getOutputSize(input.size(), ENCRYPT_OPERATION));

            MutBuffer out{output.data(), output.size()};

            int result = module.encrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0)
            {
                cout << "\nЗашифрованные байты (" << output.size() << "):\n";
                for (uint8_t b : output)
                {
                    printf("%02X ", b);
                }
                cout << "\n";

                for (uint8_t b : output)
                {
                    printf("%02X", b);
                }
                cout << "\n";


            }
            else
            {
                cout << "Ошибка шифрования, код: " << result << "\n";
            }
        }

        else if (choice == 4)  // Decrypt text from hex
        {
            if (key.empty())
            {
                cout << "Пожалуйста, сначала сгенерируйте или загрузите ключ (пункт 1 или 2)\n";
                continue;
            }

            string hex_input;
            cout << "Зашифрованные hex-байты: ";
            getline(cin, hex_input);

            vector<uint8_t> input;
            for (size_t i = 0; i < hex_input.length(); i += 2)
            {
                if (i + 1 < hex_input.length())
                {
                    string  byteStr = hex_input.substr(i, 2);
                    uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
                    input.push_back(byte);
                }
            }
            vector<uint8_t> output(module.getOutputSize(input.size(), DECRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.decrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0)
            {
                string text(output.begin(), output.end());
                cout << "Расшифрованный текст: " << text << "\n";
            }
            else
            {
                cout << "Ошибка расшифрования, код: " << result << "\n";
            }
        }

        else if (choice == 5)  // Encrypt file
        {
            if (key.empty())
            {
                cout << "Пожалуйста, сначала сгенерируйте или загрузите ключ (пункт 1 или 2)\n";
                continue;
            }

            string inputPath, outputPath;
            cout << "Входной файл: ";
            getline(cin, inputPath);
            cout << "Выходной файл: ";
            getline(cin, outputPath);

            vector<uint8_t> input;
            if (!loadBinary(inputPath, input))
            {
                cout << "Не удалось прочитать входной файл\n";
                continue;
            }

            vector<uint8_t> output(module.getOutputSize(input.size(), ENCRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.encrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0 && saveBinary(outputPath, output))
            {
                cout << "Файл успешно зашифрован\n";
            }
            else
            {
                cout << "Ошибка шифрования\n";
            }
        }

        else if (choice == 6)  // Decrypt file
        {
            if (key.empty())
            {
                cout << "Пожалуйста, сначала сгенерируйте или загрузите ключ (пункт 1 или 2)\n";
                continue;
            }

            string inputPath, outputPath;
            cout << "Входной файл: ";
            getline(cin, inputPath);
            cout << "Выходной файл: ";
            getline(cin, outputPath);

            vector<uint8_t> input;
            if (!loadBinary(inputPath, input))
            {
                cout << "Не удалось прочитать входной файл\n";
                continue;
            }

            vector<uint8_t> output(module.getOutputSize(input.size(), DECRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.decrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0 && saveBinary(outputPath, output))
            {
                cout << "Файл успешно расшифрован\n";
            }
            else
            {
                cout << "Ошибка расшифрования\n";
            }
        }
    }

    // 5. Очистка
    for (auto& module : modules)
    {
        if (module.library)
        {
            FreeLibrary(module.library);
        }
    }

    return 0;
}
