#pragma once

#include "process_context.hpp"

struct syscall_context;
using syscall_handler = void (*)(const syscall_context& c);

struct syscall_handler_entry
{
    syscall_handler handler{};
    std::string name{};
};

enum class dispatch_result
{
    completed,
    new_callback,
    error
};

struct completion_state
{
    virtual ~completion_state() = default;

    void serialize(utils::buffer_serializer& buffer) const
    {
        this->serialize_object(buffer);
    }

    void deserialize(utils::buffer_deserializer& buffer)
    {
        this->deserialize_object(buffer);
    }

  private:
    virtual void serialize_object(utils::buffer_serializer&) const
    {
    }

    virtual void deserialize_object(utils::buffer_deserializer&)
    {
    }
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
    dispatch_result dispatch_completion(windows_emulator& win_emu, callback_id callback_id, completion_state* completion_state,
                                        uint64_t callback_result);

    void serialize(utils::buffer_serializer& buffer) const;
    void deserialize(utils::buffer_deserializer& buffer);

    void setup(const exported_symbols& ntdll_exports, std::span<const std::byte> ntdll_data, const exported_symbols& win32u_exports,
               std::span<const std::byte> win32u_data);

    std::string get_syscall_name(const uint64_t id)
    {
        return this->handlers_.at(id).name;
    }

    static std::unique_ptr<completion_state> create_completion_state(callback_id id)
    {
        if (auto it = completion_state_factories_.find(id); it != completion_state_factories_.end())
        {
            return it->second();
        }
        return {};
    }

  private:
    std::map<uint64_t, syscall_handler_entry> handlers_{};
    std::map<callback_id, syscall_handler> completion_handlers_;
    static std::map<callback_id, std::function<std::unique_ptr<completion_state>()>> completion_state_factories_;

    static void add_handlers(std::map<std::string, syscall_handler>& handler_mapping);
    void add_handlers();
    void add_callbacks();
};
