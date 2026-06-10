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
        cout << "Folder 'algorithms' not found in: " << filesystem::current_path() << "\n";
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
                    cout << "Found DLL: " << file.path().filename().string() << "\n";
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
                cout << "Found DLL: " << entry.path().filename().string() << "\n";
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
        cout << "No algorithms found!\n";
        return false;
    }

    cout << "\n=== Available algorithms ===\n";
    for (size_t i = 0; i < modules.size(); ++i)
    {
        const AlgorithmInfo* info = modules[i].getAlgorithmInfo();
        cout << i + 1 << ". " << info->algorithmName
                  << " (key size: " << info->keySize  << " bytes)\n";
        cout << "   File: " << modules[i].name << "\n";
    }

    int choice;
    cout << "\nSelect algorithm (1-" << modules.size() << "): ";
    cin >> choice;
    cin.ignore();

    if (choice < 1 || choice > static_cast<int>(modules.size()))
    {
        cout << "Invalid choice\n";
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
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    cout << "=== Multi-Algo Cryptotool ===\n\n";

    // 1. Поиск всех DLL в папке algorithms/
    cout << "Searching for DLLs in 'algorithms/' folder...\n";
    vector<string> dllPaths = find_dlls_in_algorithms_folder();

    if (dllPaths.empty())
    {
        cout << "No DLLs found. Place your algorithm DLLs in 'algorithms/' folder.\n";
        cout << "Press Enter to exit...";
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
            cout << "Loaded: " << module.name << "\n";
        }
        else
        {
            cout << "Failed to load: " << path << "\n";
        }
    }

    if (modules.empty())
    {
        cout << "No valid algorithms loaded.\n";
        return 1;
    }

    // 3. Выбор алгоритма пользователем
    CryptoModule module;
    if (!selectAlgorithm(modules, module))
    {
        return 1;
    }

    const AlgorithmInfo* info = module.getAlgorithmInfo();
    cout << "\n=== Selected: " << info->algorithmName << " ===\n";
    cout << "Key size: " << info->keySize << " bytes\n";

    vector<uint8_t> key;

    // 4. Основное меню
    while (true)
    {
        int choice;

        cout << "\n=== Menu ===\n";
        cout << "1. Generate key\n";
        cout << "2. Load key\n";
        cout << "3. Encrypt text\n";
        cout << "4. Decrypt text (from hex)\n";
        cout << "5. Encrypt file\n";
        cout << "6. Decrypt file\n";
        cout << "7. Switch algorithm\n";
        cout << "0. Exit\n";
        cout << "Choice: ";

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
            cout << "\n=== Selected: " << info->algorithmName << " ===\n";
            cout << "Key size: " << info->keySize  << " bytes\n";
            key.clear(); // Очищаем старый ключ (он может быть неправильного размера)
            continue;
        }

        if (choice == 1)
        {
            key = generateKey(info->keySize );

            string path;
            cout << "Save key to file: ";
            getline(cin, path);

            if (saveBinary(path, key))
            {
                cout << "Key saved (" << key.size() << " bytes)\n";
            }
            else
            {
                cout << "Failed to save key\n";
            }
        }

        else if (choice == 2)  // Load key
        {
            string path;
            cout << "Load key from file: ";
            getline(cin, path);

            vector<uint8_t> loadedKey;
            if (!loadBinary(path, loadedKey))
            {
                cout << "Failed to load key\n";
                continue;
            }

            if (loadedKey.size() != info->keySize )
            {
                cout << "Invalid key size. Expected " << info->keySize
                          << " bytes, got " << loadedKey.size() << " bytes\n";
                continue;
            }

            key = loadedKey;
            cout << "Key loaded (" << key.size() << " bytes)\n";
        }

        else if (choice == 3)  // Encrypt text
        {
            if (key.empty())
            {
                cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            string text;
            cout << "Text to encrypt: ";
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
                cout << "\nEncrypted bytes (" << output.size() << "):\n";
                for (uint8_t b : output)
                {
                    printf("%02X ", b);
                }
                cout << "\n";
            }
            else
            {
                cout << "Encryption failed with code: " << result << "\n";
            }
        }

        else if (choice == 4)  // Decrypt text from hex
        {
            if (key.empty())
            {
                cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            string hex_input;
            cout << "Encrypted hex bytes: ";
            getline(cin, hex_input);

            vector<uint8_t> input;
            for (size_t i = 0; i < hex_input.length(); i += 2)
            {
                if (i + 1 < hex_input.length())
                {
                    string  byteStr = hex_input.substr(i, 2);
                    uint8_t byte = static_cast<uint8_t>(stoi( byteStr, nullptr, 16));
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
                cout << "Decrypted text: " << text << "\n";
            }
            else
            {
                cout << "Decryption failed with code: " << result << "\n";
            }
        }

        else if (choice == 5)  // Encrypt file
        {
            if (key.empty())
            {
                cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            string inputPath, outputPath;
            cout << "Input file: ";
            getline(cin, inputPath);
            cout << "Output file: ";
            getline(cin, outputPath);

            vector<uint8_t> input;
            if (!loadBinary(inputPath, input))
            {
                cout << "Failed to read input file\n";
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
                cout << "File encrypted successfully\n";
            }
            else
            {
                cout << "Encryption failed\n";
            }
        }

        else if (choice == 6)  // Decrypt file
        {
            if (key.empty())
            {
                cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            string inputPath, outputPath;
            cout << "Input file: ";
            getline(cin, inputPath);
            cout << "Output file: ";
            getline(cin, outputPath);

            vector<uint8_t> input;
            if (!loadBinary(inputPath, input))
            {
                cout << "Failed to read input file\n";
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
                cout << "File decrypted successfully\n";
            }
            else
            {
                cout << "Decryption failed\n";
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
