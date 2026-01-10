#pragma once

#include "process_context.hpp"

struct syscall_context;
using syscall_handler = void (*)(const syscall_context& c);
using callback_completion_handler = void (*)(const syscall_context& c, uint64_t guest_result);

struct syscall_handler_entry
{
    syscall_handler handler{};
    std::string name{};
};

class windows_emulator;

class syscall_dispatcher
{
  public:
    syscall_dispatcher() = default;
    syscall_dispatcher(const exported_symbols& ntdll_exports, std::span<const std::byte> ntdll_data, const exported_symbols& win32u_exports,
                       std::span<const std::byte> win32u_data);

    void dispatch(windows_emulator& win_emu);
    static void dispatch_callback(windows_emulator& win_emu, std::string& syscall_name);
    void dispatch_completion(windows_emulator& win_emu, callback_id callback_id, uint64_t guest_result);

    void serialize(utils::buffer_serializer& buffer) const;
    void deserialize(utils::buffer_deserializer& buffer);

    void setup(const exported_symbols& ntdll_exports, std::span<const std::byte> ntdll_data, const exported_symbols& win32u_exports,
               std::span<const std::byte> win32u_data);

    std::string get_syscall_name(const uint64_t id)
    {
        return this->handlers_.at(id).name;
    }

  private:
    std::map<uint64_t, syscall_handler_entry> handlers_{};
    std::map<callback_id, callback_completion_handler> callbacks_{};

    static void add_handlers(std::map<std::string, syscall_handler>& handler_mapping);
    void add_handlers();
    void add_callbacks();
};
