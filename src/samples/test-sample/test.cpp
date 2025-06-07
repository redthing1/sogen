#include <cstdint>
#include <cstring>
#include <string>
#include <fstream>
#include <thread>
#include <atomic>
#include <vector>
#include <optional>
#include <filesystem>
#include <string_view>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <intrin.h>

#ifdef __MINGW64__
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

using namespace std::literals;

// Externally visible and potentially modifiable state
// to trick compiler optimizations
__declspec(dllexport) bool do_the_task = true;

namespace
{
    struct tls_struct
    {
        DWORD num = 1337;

        tls_struct()
        {
            num = GetCurrentThreadId();
        }
    };

    thread_local tls_struct tls_var{};

    // getenv is broken right now :(
    std::string read_env(const char* env)
    {
        char buffer[0x1000] = {};
        if (!GetEnvironmentVariableA(env, buffer, sizeof(buffer)))
        {
            return {};
        }

        return buffer;
    }

    bool test_threads()
    {
        constexpr auto thread_count = 5ULL;

        std::atomic<uint64_t> counter{0};

        std::vector<std::thread> threads{};
        threads.reserve(thread_count);

        for (auto i = 0ULL; i < thread_count; ++i)
        {
            threads.emplace_back([&counter] {
                ++counter;
                std::this_thread::yield();
                ++counter;
                // Host scheduling/cpu performance can have impact on emulator scheduling
                // std::this_thread::sleep_for(std::chrono::milliseconds(100));
                ++counter;
            });
        }

        for (auto& t : threads)
        {
            t.join();
        }

        return counter == (thread_count * 3ULL);
    }

    bool test_tls()
    {
        std::atomic_bool kill{false};
        std::atomic_uint32_t successes{0};
        constexpr uint32_t thread_count = 2;

        std::vector<std::thread> ts{};
        kill = false;

        for (size_t i = 0; i < thread_count; ++i)
        {
            ts.emplace_back([&] {
                while (!kill)
                {
                    std::this_thread::yield();
                }

                if (tls_var.num == GetCurrentThreadId())
                {
                    ++successes;
                }
            });
        }

        LoadLibraryA("d3dcompiler_47.dll");
        LoadLibraryA("dsound.dll");
        LoadLibraryA("comctl32.dll");
        /*LoadLibraryA("d3d9.dll");
        LoadLibraryA("dxgi.dll");
        LoadLibraryA("wlanapi.dll");*/

        kill = true;

        for (auto& t : ts)
        {
            if (t.joinable())
            {
                t.join();
            }
        }

        return successes == thread_count;
    }

    bool test_env()
    {
        const auto computername = read_env("COMPUTERNAME");

        SetEnvironmentVariableA("BLUB", "LUL");

        const auto blub = read_env("BLUB");

        return !computername.empty() && blub == "LUL";
    }

    bool test_file_path_io(const std::filesystem::path& filename)
    {
        std::error_code ec{};
        const auto absolute_file = absolute(filename, ec);

        if (ec)
        {
            puts("Getting absolute path failed");
            return false;
        }

        const auto canonical_file = canonical(filename, ec);
        (void)canonical_file;

        if (ec)
        {
            puts("Getting canonical path failed");
            return false;
        }

        return true;
    }

    bool test_io()
    {
        const std::filesystem::path filename1 = "a.txt";
        const std::filesystem::path filename2 = "A.tXt";

        FILE* fp{};
        (void)fopen_s(&fp, filename1.string().c_str(), "wb");

        if (!fp)
        {
            puts("Bad file");
            return false;
        }

        const std::string text = "Blub";

        (void)fwrite(text.data(), 1, text.size(), fp);
        (void)fclose(fp);

        if (!test_file_path_io(filename1))
        {
            return false;
        }

        std::ifstream t(filename2);
        t.seekg(0, std::ios::end);
        const size_t size = t.tellg();
        std::string buffer(size, ' ');
        t.seekg(0);
        t.read(buffer.data(), static_cast<std::streamsize>(size));

        return text == buffer;
    }

    bool test_working_directory()
    {
        std::error_code ec{};

        const auto current_dir = std::filesystem::current_path(ec);
        if (ec)
        {
            puts("Failed to get current path");
            return false;
        }

        const std::filesystem::path sys32 = "C:/windows/system32";
        current_path(sys32, ec);

        if (ec)
        {
            puts("Failed to update working directory");
            return false;
        }

        const auto new_current_dir = std::filesystem::current_path();
        if (sys32 != new_current_dir)
        {
            puts("Updated directory is wrong!");
            return false;
        }

        if (!std::ifstream("ntdll.dll"))
        {
            puts("Working directory is not active!");
            return false;
        }

        current_path(current_dir);
        return std::filesystem::current_path() == current_dir;
    }

    bool test_dir_io()
    {
        size_t count = 0;

        for (auto i : std::filesystem::directory_iterator(R"(C:\Windows\System32\)"))
        {
            ++count;
            if (count > 30)
            {
                return true;
            }
        }

        return count > 30;
    }

    std::optional<std::string> read_registry_string(const HKEY root, const char* path, const char* value)
    {
        HKEY key{};
        if (RegOpenKeyExA(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        char data[MAX_PATH]{};
        DWORD length = sizeof(data);
        const auto res = RegQueryValueExA(key, value, nullptr, nullptr, reinterpret_cast<uint8_t*>(data), &length);

        if (RegCloseKey(key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        if (res != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        if (length == 0)
        {
            return "";
        }

        return {std::string(data, std::min(static_cast<size_t>(length - 1), sizeof(data)))};
    }

    std::optional<std::vector<std::string>> get_all_registry_keys(const HKEY root, const char* path)
    {
        HKEY key{};
        if (RegOpenKeyExA(root, path, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        std::vector<std::string> keys;
        std::vector<char> name_buffer(MAX_PATH + 1);

        for (DWORD i = 0;; ++i)
        {
            auto name_buffer_len = static_cast<DWORD>(name_buffer.size());
            const LSTATUS status =
                RegEnumKeyExA(key, i, name_buffer.data(), &name_buffer_len, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_SUCCESS)
            {
                keys.emplace_back(name_buffer.data(), name_buffer_len);
            }
            else if (status == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                keys.clear();
                break;
            }
        }

        if (keys.empty())
        {
            RegCloseKey(key);
            return std::nullopt;
        }

        if (RegCloseKey(key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        return keys;
    }

    std::optional<std::vector<std::string>> get_all_registry_values(const HKEY root, const char* path)
    {
        HKEY key{};
        if (RegOpenKeyExA(root, path, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        std::vector<std::string> values;
        std::vector<char> name_buffer(MAX_PATH + 1);

        for (DWORD i = 0;; ++i)
        {
            auto name_buffer_len = static_cast<DWORD>(name_buffer.size());
            const auto status =
                RegEnumValueA(key, i, name_buffer.data(), &name_buffer_len, nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_SUCCESS)
            {
                values.emplace_back(name_buffer.data(), name_buffer_len);
            }
            else if (status == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else
            {
                values.clear();
                break;
            }
        }

        if (values.empty())
        {
            RegCloseKey(key);
            return std::nullopt;
        }

        if (RegCloseKey(key) != ERROR_SUCCESS)
        {
            return std::nullopt;
        }

        return values;
    }

    bool test_registry()
    {
        // Basic Reading Test
        const auto prog_files_dir =
            read_registry_string(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows\CurrentVersion)", "ProgramFilesDir");
        if (!prog_files_dir || *prog_files_dir != "C:\\Program Files")
        {
            return false;
        }

        // WOW64 Redirection Test
        const auto pst_display = read_registry_string(
            HKEY_LOCAL_MACHINE,
            R"(SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Time Zones\Pacific Standard Time)", "Display");
        if (!pst_display || pst_display->empty())
        {
            return false;
        }

        // Key Sub-keys Enumeration Test
        const auto subkeys_opt =
            get_all_registry_keys(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)");
        if (!subkeys_opt)
        {
            return false;
        }

        bool found_fonts = false;
        for (const auto& key_name : *subkeys_opt)
        {
            if (key_name == "Fonts")
            {
                found_fonts = true;
                break;
            }
        }
        if (!found_fonts)
        {
            return false;
        }

        // Key Values Enumeration Test
        const auto values_opt =
            get_all_registry_values(HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)");
        if (!values_opt)
        {
            return false;
        }

        bool found_product_name = false;
        for (const auto& val_name : *values_opt)
        {
            if (val_name == "ProductName")
            {
                found_product_name = true;
                break;
            }
        }
        if (!found_product_name)
        {
            return false;
        }

        return true;
    }

    bool test_system_info()
    {
        char sys_dir[MAX_PATH];
        if (GetSystemDirectoryA(sys_dir, sizeof(sys_dir)) == 0)
        {
            return false;
        }
        if (strlen(sys_dir) != 19)
        {
            return false;
        }

        // TODO: This currently doesn't work.
        /*
        char username[256];
        DWORD username_len = sizeof(username);
        if (!GetUserNameA(username, &username_len))
        {
            return false;
        }
        if (username_len <= 1)
        {
            return false;
        }
        */

        return true;
    }

    bool test_time_zone()
    {
        DYNAMIC_TIME_ZONE_INFORMATION current_dtzi = {};
        DWORD result = GetDynamicTimeZoneInformation(&current_dtzi);

        if (result == TIME_ZONE_ID_INVALID)
        {
            return false;
        }

        if (current_dtzi.Bias != -60 || current_dtzi.StandardBias != 0 || current_dtzi.DaylightBias != -60 ||
            current_dtzi.DynamicDaylightTimeDisabled != FALSE)
        {
            return false;
        }

        if (wcscmp(current_dtzi.StandardName, L"W. Europe Standard Time") != 0 ||
            wcscmp(current_dtzi.DaylightName, L"W. Europe Daylight Time") != 0 ||
            wcscmp(current_dtzi.TimeZoneKeyName, L"W. Europe Standard Time") != 0)
        {
            return false;
        }

        if (current_dtzi.StandardDate.wYear != 0 || current_dtzi.StandardDate.wMonth != 10 ||
            current_dtzi.StandardDate.wDayOfWeek != 0 || current_dtzi.StandardDate.wDay != 5 ||
            current_dtzi.StandardDate.wHour != 3 || current_dtzi.StandardDate.wMinute != 0 ||
            current_dtzi.StandardDate.wSecond != 0 || current_dtzi.StandardDate.wMilliseconds != 0)
        {
            return false;
        }

        if (current_dtzi.DaylightDate.wYear != 0 || current_dtzi.DaylightDate.wMonth != 3 ||
            current_dtzi.DaylightDate.wDayOfWeek != 0 || current_dtzi.DaylightDate.wDay != 5 ||
            current_dtzi.DaylightDate.wHour != 2 || current_dtzi.DaylightDate.wMinute != 0 ||
            current_dtzi.DaylightDate.wSecond != 0 || current_dtzi.DaylightDate.wMilliseconds != 0)
        {
            return false;
        }

        return true;
    }

    void throw_exception()
    {
        if (do_the_task)
        {
            throw std::runtime_error("OK");
        }
    }

    bool test_exceptions()
    {
        try
        {
            throw_exception();
            return false;
        }
        catch (const std::exception& e)
        {
            return e.what() == std::string("OK");
        }
    }

    struct wsa_initializer
    {
        wsa_initializer()
        {
            WSADATA wsa_data;
            if (WSAStartup(MAKEWORD(2, 2), &wsa_data))
            {
                throw std::runtime_error("Unable to initialize WSA");
            }
        }

        ~wsa_initializer()
        {
            WSACleanup();
        }
    };

    bool test_socket()
    {
        wsa_initializer _{};
        constexpr std::string_view send_data = "Hello World";

        const auto sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        const auto receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sender == INVALID_SOCKET || receiver == INVALID_SOCKET)
        {
            puts("Socket creation failed");
            return false;
        }

        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        destination.sin_port = htons(28970);

        if (bind(receiver, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) == SOCKET_ERROR)
        {
            puts("Failed to bind socket!");
            return false;
        }

        const auto sent_bytes = sendto(sender, send_data.data(), static_cast<int>(send_data.size()), 0,
                                       reinterpret_cast<sockaddr*>(&destination), sizeof(destination));

        if (static_cast<size_t>(sent_bytes) != send_data.size())
        {
            puts("Failed to send data!");
            return false;
        }

        char buffer[100] = {};
        sockaddr_in sender_addr{};
        int sender_length = sizeof(sender_addr);

        const auto len =
            recvfrom(receiver, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&sender_addr), &sender_length);

        if (len != send_data.size())
        {
            puts("Failed to receive data!");
            return false;
        }

        return send_data == std::string_view(buffer, len);
    }

#ifndef __MINGW64__
    void throw_access_violation()
    {
        if (do_the_task)
        {
            *reinterpret_cast<int*>(1) = 1;
        }
    }

    bool test_access_violation_exception()
    {
        __try
        {
            throw_access_violation();
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode() == STATUS_ACCESS_VIOLATION;
        }
    }

    bool test_ud2_exception(void* address)
    {
        __try
        {
            reinterpret_cast<void (*)()>(address)();
            return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode() == STATUS_ILLEGAL_INSTRUCTION;
        }
    }

    bool test_illegal_instruction_exception()
    {
        const auto address = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!address)
        {
            return false;
        }

        memcpy(address, "\x0F\x0B", 2); // ud2

        const auto res = test_ud2_exception(address);

        VirtualFree(address, 0x1000, MEM_RELEASE);

        return res;
    }

    bool test_native_exceptions()
    {
        return test_access_violation_exception() && test_illegal_instruction_exception();
    }
#endif

    bool trap_flag_cleared = false;
    constexpr DWORD TRAP_FLAG_MASK = 0x100;

    LONG NTAPI single_step_handler(PEXCEPTION_POINTERS exception_info)
    {
        if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            PCONTEXT context = exception_info->ContextRecord;
            trap_flag_cleared = (context->EFlags & TRAP_FLAG_MASK) == 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool test_interrupts()
    {
        PVOID veh_handle = AddVectoredExceptionHandler(1, single_step_handler);
        if (!veh_handle)
            return false;

        __writeeflags(__readeflags() | TRAP_FLAG_MASK);

#ifdef __MINGW64__
        asm("nop");
#else
        __nop();
#endif

        RemoveVectoredExceptionHandler(veh_handle);

        return trap_flag_cleared;
    }

    void print_time()
    {
        const auto epoch_time = std::chrono::system_clock::now().time_since_epoch();
        printf("Time: %lld\n", std::chrono::duration_cast<std::chrono::nanoseconds>(epoch_time).count());
    }

    bool test_apis()
    {
        wchar_t buffer[0x100];
        DWORD size = sizeof(buffer) / 2;
        return GetComputerNameExW(ComputerNameNetBIOS, buffer, &size);
    }

    bool test_apc()
    {
        int executions = 0;

        auto* apc_func = +[](const ULONG_PTR param) {
            *reinterpret_cast<int*>(param) += 1; //
        };

        QueueUserAPC(apc_func, GetCurrentThread(), reinterpret_cast<ULONG_PTR>(&executions));
        QueueUserAPC(apc_func, GetCurrentThread(), reinterpret_cast<ULONG_PTR>(&executions));

        Sleep(1);

        if (executions != 0)
        {
            return false;
        }

        SleepEx(1, TRUE);
        return executions == 2;
    }
}

#define RUN_TEST(func, name)                 \
    {                                        \
        printf("Running test '" name "': "); \
        const auto res = func();             \
        valid &= res;                        \
        puts(res ? "Success" : "Fail");      \
    }

int main(const int argc, const char* argv[])
{
    if (argc == 2 && argv[1] == "-time"sv)
    {
        print_time();
        return 0;
    }

    bool valid = true;

    RUN_TEST(test_io, "I/O")
    RUN_TEST(test_dir_io, "Dir I/O")
    RUN_TEST(test_apis, "APIs")
    RUN_TEST(test_working_directory, "Working Directory")
    RUN_TEST(test_registry, "Registry")
    RUN_TEST(test_system_info, "System Info")
    RUN_TEST(test_time_zone, "Time Zone")
    RUN_TEST(test_threads, "Threads")
    RUN_TEST(test_env, "Environment")
    RUN_TEST(test_exceptions, "Exceptions")
#ifndef __MINGW64__
    RUN_TEST(test_native_exceptions, "Native Exceptions")
#endif
    if (!getenv("EMULATOR_ICICLE"))
    {
        RUN_TEST(test_interrupts, "Interrupts")
    }
    RUN_TEST(test_tls, "TLS")
    RUN_TEST(test_socket, "Socket")
    RUN_TEST(test_apc, "APC")

    return valid ? 0 : 1;
}
