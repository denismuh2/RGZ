#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <random>
#include <algorithm>

#include <windows.h>

#include "include/cryptoApi.h"

namespace fs = std::filesystem;

struct CryptoModule
{
    HMODULE library = nullptr;
    std::string name;
    std::string path;

    const AlgorithmInfo* (*get_algorithm_info)() = nullptr;
    size_t (*get_output_size)(size_t, int) = nullptr;
    int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
    int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*) = nullptr;
};

// Поиск всех DLL в папке algorithms/
std::vector<std::string> find_dlls_in_algorithms_folder()
{
    std::vector<std::string> dll_paths;

    // Папка algorithms находится в корне проекта
    fs::path algorithms_dir = fs::current_path() / "algorithms";

    if (!fs::exists(algorithms_dir))
    {
        std::cout << "Folder 'algorithms' not found in: " << fs::current_path() << "\n";
        return dll_paths;
    }

    for (const auto& entry : fs::directory_iterator(algorithms_dir))
    {
        if (entry.is_directory())
        {
            // Ищем .dll или .so в подпапке
            for (const auto& file : fs::directory_iterator(entry.path()))
            {
                std::string ext = file.path().extension().string();
                std::string filename = file.path().filename().string();

#ifdef _WIN32
                if (ext == ".dll")
#else
                if (ext == ".so" || filename.find(".so") != std::string::npos)
#endif
                {
                    dll_paths.push_back(file.path().string());
                    std::cout << "Found DLL: " << file.path().filename().string() << "\n";
                }
            }
        }
        else
        {
            // Ищем .dll прямо в папке algorithms (если есть)
            std::string ext = entry.path().extension().string();
#ifdef _WIN32
            if (ext == ".dll")
#else
            if (ext == ".so")
#endif
            {
                dll_paths.push_back(entry.path().string());
                std::cout << "Found DLL: " << entry.path().filename().string() << "\n";
            }
        }
    }

    return dll_paths;
}

// Загрузка модуля по пути
bool load_module(const std::string& dll_path, CryptoModule& module)
{
    module.path = dll_path;
    module.name = fs::path(dll_path).filename().string();

    module.library = LoadLibraryA(dll_path.c_str());

    if (!module.library)
    {
        return false;
    }

    module.get_algorithm_info = reinterpret_cast<decltype(module.get_algorithm_info)>(
        GetProcAddress(module.library, "get_algorithm_info"));

    module.get_output_size = reinterpret_cast<decltype(module.get_output_size)>(
        GetProcAddress(module.library, "get_output_size"));

    module.encrypt = reinterpret_cast<decltype(module.encrypt)>(
        GetProcAddress(module.library, "encrypt"));

    module.decrypt = reinterpret_cast<decltype(module.decrypt)>(
        GetProcAddress(module.library, "decrypt"));

    return module.get_algorithm_info &&
           module.get_output_size &&
           module.encrypt &&
           module.decrypt;
}

// Выбор алгоритма из списка
bool select_algorithm(const std::vector<CryptoModule>& modules, CryptoModule& selected)
{
    if (modules.empty())
    {
        std::cout << "No algorithms found!\n";
        return false;
    }

    std::cout << "\n=== Available algorithms ===\n";
    for (size_t i = 0; i < modules.size(); ++i)
    {
        const AlgorithmInfo* info = modules[i].get_algorithm_info();
        std::cout << i + 1 << ". " << info->algorithm_name
                  << " (key size: " << info->key_size << " bytes)\n";
        std::cout << "   File: " << modules[i].name << "\n";
    }

    int choice;
    std::cout << "\nSelect algorithm (1-" << modules.size() << "): ";
    std::cin >> choice;
    std::cin.ignore();

    if (choice < 1 || choice > static_cast<int>(modules.size()))
    {
        std::cout << "Invalid choice\n";
        return false;
    }

    selected = modules[choice - 1];
    return true;
}

std::vector<uint8_t> generate_key(size_t size)
{
    std::random_device rd;
    std::vector<uint8_t> key(size);
    for (auto& b : key)
    {
        b = static_cast<uint8_t>(rd());
    }
    return key;
}

bool save_binary(const std::string& path, const std::vector<uint8_t>& data)
{
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

bool load_binary(const std::string& path, std::vector<uint8_t>& data)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;

    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

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

    std::cout << "=== Multi-Algo Cryptotool ===\n\n";

    // 1. Поиск всех DLL в папке algorithms/
    std::cout << "Searching for DLLs in 'algorithms/' folder...\n";
    std::vector<std::string> dll_paths = find_dlls_in_algorithms_folder();

    if (dll_paths.empty())
    {
        std::cout << "No DLLs found. Place your algorithm DLLs in 'algorithms/' folder.\n";
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    // 2. Загрузка всех найденных модулей
    std::vector<CryptoModule> modules;
    for (const auto& path : dll_paths)
    {
        CryptoModule module;
        if (load_module(path, module))
        {
            modules.push_back(module);
            std::cout << "Loaded: " << module.name << "\n";
        }
        else
        {
            std::cout << "Failed to load: " << path << "\n";
        }
    }

    if (modules.empty())
    {
        std::cout << "No valid algorithms loaded.\n";
        return 1;
    }

    // 3. Выбор алгоритма пользователем
    CryptoModule module;
    if (!select_algorithm(modules, module))
    {
        return 1;
    }

    const AlgorithmInfo* info = module.get_algorithm_info();
    std::cout << "\n=== Selected: " << info->algorithm_name << " ===\n";
    std::cout << "Key size: " << info->key_size << " bytes\n";

    std::vector<uint8_t> key;

    // 4. Основное меню
    while (true)
    {
        int choice;

        std::cout << "\n=== Menu ===\n";
        std::cout << "1. Generate key\n";
        std::cout << "2. Encrypt text\n";
        std::cout << "3. Decrypt text (from hex)\n";
        std::cout << "4. Encrypt file\n";
        std::cout << "5. Decrypt file\n";
        std::cout << "6. Switch algorithm\n";
        std::cout << "0. Exit\n";
        std::cout << "Choice: ";

        std::cin >> choice;
        std::cin.ignore();

        if (choice == 0)
        {
            break;
        }

        if (choice == 6)
        {
            // Переключение алгоритма
            if (!select_algorithm(modules, module))
            {
                continue;
            }
            info = module.get_algorithm_info();
            std::cout << "\n=== Selected: " << info->algorithm_name << " ===\n";
            std::cout << "Key size: " << info->key_size << " bytes\n";
            key.clear(); // Очищаем старый ключ (он может быть неправильного размера)
            continue;
        }

        if (choice == 1)
        {
            key = generate_key(info->key_size);

            std::string path;
            std::cout << "Save key to file: ";
            std::getline(std::cin, path);

            if (save_binary(path, key))
            {
                std::cout << "Key saved (" << key.size() << " bytes)\n";
            }
            else
            {
                std::cout << "Failed to save key\n";
            }
        }

        else if (choice == 2)  // Encrypt text
        {
            if (key.empty())
            {
                std::cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            std::string text;
            std::cout << "Text to encrypt: ";
            std::getline(std::cin, text);

            std::vector<uint8_t> input(text.begin(), text.end());
            std::vector<uint8_t> output(module.get_output_size(input.size(), ENCRYPT_OPERATION));

            MutBuffer out{output.data(), output.size()};

            int result = module.encrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0)
            {
                std::cout << "\nEncrypted bytes (" << output.size() << "):\n";
                for (uint8_t b : output)
                {
                    printf("%02X ", b);
                }
                std::cout << "\n";
            }
            else
            {
                std::cout << "Encryption failed with code: " << result << "\n";
            }
        }

        else if (choice == 3)  // Decrypt text from hex
        {
            if (key.empty())
            {
                std::cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            std::string hex_input;
            std::cout << "Encrypted hex bytes: ";
            std::getline(std::cin, hex_input);

            std::vector<uint8_t> input;
            for (size_t i = 0; i < hex_input.length(); i += 2)
            {
                if (i + 1 < hex_input.length())
                {
                    std::string byte_str = hex_input.substr(i, 2);
                    uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
                    input.push_back(byte);
                }
            }

            std::vector<uint8_t> output(module.get_output_size(input.size(), DECRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.decrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0)
            {
                std::string text(output.begin(), output.end());
                std::cout << "Decrypted text: " << text << "\n";
            }
            else
            {
                std::cout << "Decryption failed with code: " << result << "\n";
            }
        }

        else if (choice == 4)  // Encrypt file
        {
            if (key.empty())
            {
                std::cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            std::string input_path, output_path;
            std::cout << "Input file: ";
            std::getline(std::cin, input_path);
            std::cout << "Output file: ";
            std::getline(std::cin, output_path);

            std::vector<uint8_t> input;
            if (!load_binary(input_path, input))
            {
                std::cout << "Failed to read input file\n";
                continue;
            }

            std::vector<uint8_t> output(module.get_output_size(input.size(), ENCRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.encrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0 && save_binary(output_path, output))
            {
                std::cout << "File encrypted successfully\n";
            }
            else
            {
                std::cout << "Encryption failed\n";
            }
        }

        else if (choice == 5)  // Decrypt file
        {
            if (key.empty())
            {
                std::cout << "Please generate or load a key first (option 1)\n";
                continue;
            }

            std::string input_path, output_path;
            std::cout << "Input file: ";
            std::getline(std::cin, input_path);
            std::cout << "Output file: ";
            std::getline(std::cin, output_path);

            std::vector<uint8_t> input;
            if (!load_binary(input_path, input))
            {
                std::cout << "Failed to read input file\n";
                continue;
            }

            std::vector<uint8_t> output(module.get_output_size(input.size(), DECRYPT_OPERATION));
            MutBuffer out{output.data(), output.size()};

            int result = module.decrypt(
                {key.data(), key.size()},
                {input.data(), input.size()},
                &out
            );

            if (result >= 0 && save_binary(output_path, output))
            {
                std::cout << "File decrypted successfully\n";
            }
            else
            {
                std::cout << "Decryption failed\n";
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
