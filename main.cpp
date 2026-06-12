#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>
#include <algorithm>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <dlfcn.h>
    #include <cstring>
#endif

#include "include/cryptoApi.h"

using namespace std;

// Кроссплатформенный тип для библиотеки
#ifdef _WIN32
    using LibHandle = HMODULE;
    const char* LIB_EXT = ".dll";
#else
    using LibHandle = void*;
    const char* LIB_EXT = ".so";
#endif

struct CryptoModule
{
    LibHandle library = nullptr;
    string name;
    string path;

    const AlgorithmInfo* (*getAlgorithmInfo)() = nullptr;
    size_t (*getOutputSize)(size_t, int) = nullptr;
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
};

// Кроссплатформенная загрузка библиотеки
LibHandle loadLibrary(const string& path)
{
#ifdef _WIN32
    return LoadLibraryA(path.c_str());
#else
    return dlopen(path.c_str(), RTLD_LAZY);
#endif
}

// Кроссплатформенное получение функции
void* getFunction(LibHandle lib, const char* name)
{
#ifdef _WIN32
    return (void*)GetProcAddress(lib, name);
#else
    return dlsym(lib, name);
#endif
}

// Кроссплатформенная выгрузка библиотеки
void unloadLibrary(LibHandle lib)
{
#ifdef _WIN32
    FreeLibrary(lib);
#else
    dlclose(lib);
#endif
}

// Поиск всех библиотек в папке algorithms/
vector<string> findLibsInAlgorithmsFolder()
{
    vector<string> libPaths;
    filesystem::path algorithms_dir = filesystem::current_path() / "algorithms";

    if (!filesystem::exists(algorithms_dir))
    {
        cout << "Папка 'algorithms' не найдена в: " << filesystem::current_path() << "\n";
        return libPaths;
    }

    for (const auto& entry : filesystem::directory_iterator(algorithms_dir))
    {
        if (entry.is_directory())
        {
            for (const auto& file : filesystem::directory_iterator(entry.path()))
            {
                string ext = file.path().extension().string();
                if (ext == LIB_EXT)
                {
                    libPaths.push_back(file.path().string());
                    cout << "Найдена библиотека: " << file.path().filename().string() << "\n";
                }
            }
        }
        else
        {
            string ext = entry.path().extension().string();
            if (ext == LIB_EXT)
            {
                libPaths.push_back(entry.path().string());
                cout << "Найдена библиотека: " << entry.path().filename().string() << "\n";
            }
        }
    }

    return libPaths;
}

// Загрузка модуля dll по пути
bool loadModule(const string& libPath, CryptoModule& module)
{
    module.path = libPath;
    module.name = filesystem::path(libPath).filename().string();

    module.library = loadLibrary(libPath);

    if (!module.library)
    {
#ifdef _WIN32
        cerr << "Ошибка загрузки: " << GetLastError() << endl;
#else
        cerr << "Ошибка загрузки: " << dlerror() << endl;
#endif
        return false;
    }

    module.getAlgorithmInfo = reinterpret_cast<decltype(module.getAlgorithmInfo)>(
        getFunction(module.library, "getAlgorithmInfo"));

    module.getOutputSize = reinterpret_cast<decltype(module.getOutputSize)>(
        getFunction(module.library, "getOutputSize"));

    module.encrypt = reinterpret_cast<decltype(module.encrypt)>(
        getFunction(module.library, "encrypt"));

    module.decrypt = reinterpret_cast<decltype(module.decrypt)>(
        getFunction(module.library, "decrypt"));

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
        cout << dec;
        const AlgorithmInfo* info = modules[i].getAlgorithmInfo();
        cout << i + 1 << ". " << info->algorithmName << " (размер ключа: " << info->keySize  << " байт)\n";
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

// Генерация ключа
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

// Сохранение бинарного файла
bool saveBinary(const string& path, const vector<uint8_t>& data)
{
    ofstream file(path, ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

// Загрузка бинарного файла
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
    system("chcp 1251 > nul");
#endif

    cout << "Поиск библиотек в папке 'algorithms/'...\n";
    vector<string> libPaths = findLibsInAlgorithmsFolder();

    if (libPaths.empty())
    {
        cout << "Библиотеки не найдены. Поместите библиотеки алгоритмов в папку 'algorithms/'.\n";
        cout << "Нажмите Enter для выхода...";
        cin.get();
        return 1;
    }

    vector<CryptoModule> modules;
    for (const auto& path : libPaths)
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

    // Выбор алгоритма пользователем
    CryptoModule module;
    if (!selectAlgorithm(modules, module))
    {
        return 1;
    }

    const AlgorithmInfo* info = module.getAlgorithmInfo();
    cout << "\n=== Выбран: " << info->algorithmName << " ===\n";
    cout << "Размер ключа: " << info->keySize << " байт\n";

    vector<uint8_t> key;

    // Основное меню
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
        if (cin.fail()){
        cin.clear();
        cin.ignore(10000, '\n');
        cout << "Ошибка! Введите число от 0 до 7\n";
        continue;
        }

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
            key.clear();
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

        else if (choice == 2)
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

        else if (choice == 3)
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
                cout << "\nЗашифрованные байты (" << result << "):\n";

                for (int i = 0; i < result; ++i){
                    cout << hex << setw(2) << setfill('0')
                    << static_cast<int>(output[i]) << " ";
                }
                cout << "\n";

                for (int i = 0; i < result; ++i){
                    cout << hex << setw(2) << setfill('0')
                    << static_cast<int>(output[i]);
                }
                cout << "\n";

                cout << dec; // вернуть десятичный вывод
            }
            else
            {
                cout << "Ошибка шифрования, код: " << result << "\n";
            }
        }

        else if (choice == 4)
        {
            if (key.empty())
            {
                cout << "Пожалуйста, сначала сгенерируйте или загрузите ключ (пункт 1 или 2)\n";
                continue;
            }

            string hexInput;
            cout << "Зашифрованные hex-байты: ";
            getline(cin, hexInput);
            if (hexInput.size() % 2 != 0){
                cout << "Ошибка: неверный hex\n";
                continue;
            }

            vector<uint8_t> input;
            bool badHex = false;
            for (size_t i = 0; i + 1 < hexInput.size(); i += 2){
                string byteStr = hexInput.substr(i, 2);

                if (!isxdigit(byteStr[0]) || !isxdigit(byteStr[1])){
                    badHex = true;
                    break;
                }
                input.push_back(
                static_cast<uint8_t>(stoi(byteStr, nullptr, 16))
                );
            }
            if (badHex || input.empty()){
                cout << "Ошибка: неверный hex\n";
                continue;
            }
            vector<uint8_t> output(module.getOutputSize(input.size(), DECRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.decrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0){
                string text(output.begin(), output.begin() + result);
                cout << "Расшифрованный текст: " << text << "\n";
            }
            else
            {
                cout << "Ошибка расшифрования, код: " << result << "\n";
            }
        }

        else if (choice == 5)
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

        else if (choice == 6)
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
    for (auto& mod : modules)
    {
        if (mod.library)
        {
            unloadLibrary(mod.library);
        }
    }

    return 0;
}
