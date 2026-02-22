#include "std_include.hpp"
#include "win32k_userconnect.hpp"

#include "process_context.hpp"

namespace win32k_userconnect
{
    NTSTATUS narrow_wow64_address(const uint64_t address, uint32_t& narrowed)
    {
        narrowed = 0;

        if (address > std::numeric_limits<uint32_t>::max())
        {
            return STATUS_INVALID_PARAMETER;
        }

        narrowed = static_cast<uint32_t>(address);
        return STATUS_SUCCESS;
    }

    NTSTATUS resolve_wow64_destination(const uint64_t user_connect_ptr, const uint64_t user_connect_length, uint32_t& destination)
    {
        destination = 0;

        if (user_connect_ptr == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (user_connect_length < sizeof(WIN32K_USERCONNECT32))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }

        uint64_t offset = 0;
        if (user_connect_length == sizeof(WIN32K_USERCONNECT32))
        {
            offset = 0;
        }
        else if (user_connect_length == (sizeof(WIN32K_USERCONNECT32) + k_wow64_userconnect_header_size))
        {
            offset = k_wow64_userconnect_header_size;
        }
        else
        {
            return STATUS_INVALID_PARAMETER;
        }

        const auto destination64 = user_connect_ptr + offset;
        if (destination64 < user_connect_ptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        return narrow_wow64_address(destination64, destination);
    }

    NTSTATUS build_wow64_userconnect(const process_context& process, WIN32K_USERCONNECT32& connect)
    {
        connect = {};

        uint32_t psi{};
        uint32_t disp_info{};
        uint32_t ahe_list{};
        uint32_t monitor_info{};

        auto status = narrow_wow64_address(process.user_handles.get_server_info().value(), psi);
        if (status != STATUS_SUCCESS)
        {
            return status;
        }

        status = narrow_wow64_address(process.user_handles.get_display_info().value(), disp_info);
        if (status != STATUS_SUCCESS)
        {
            return status;
        }

        status = narrow_wow64_address(process.user_handles.get_handle_table().value(), ahe_list);
        if (status != STATUS_SUCCESS)
        {
            return status;
        }

        status = narrow_wow64_address(process.user_handles.get_display_info().value(), monitor_info);
        if (status != STATUS_SUCCESS)
        {
            return status;
        }

        connect.psi = psi;
        connect.disp_info_low = disp_info;
        connect.disp_info_high = 0;
        connect.ahe_list = ahe_list;
        connect.he_entry_size = sizeof(USER_HANDLEENTRY);
        connect.monitor_info = monitor_info;
        connect.wndmsg_count = k_wow64_wndmsg_count;
        connect.ime_msg_count = k_wow64_ime_msg_count;

        return STATUS_SUCCESS;
    }

    bool try_write_wow64_userconnect(memory_interface& memory, const uint64_t destination, const WIN32K_USERCONNECT32& connect)
    {
        try
        {
            const emulator_object<WIN32K_USERCONNECT32> connect_obj{memory, destination};
            connect_obj.write(connect);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    void populate_user_shared_info(USER_SHAREDINFO& shared, const process_context& process)
    {
        shared.psi = process.user_handles.get_server_info().value();
        shared.aheList = process.user_handles.get_handle_table().value();
        shared.HeEntrySize = sizeof(USER_HANDLEENTRY);
        shared.pDispInfo = process.user_handles.get_display_info().value();
    }

    bool try_write_user_shared_info(memory_interface& memory, const uint64_t destination, const process_context& process)
    {
        try
        {
            const emulator_object<USER_SHAREDINFO> shared_obj{memory, destination};
            auto shared = shared_obj.read();
            populate_user_shared_info(shared, process);
            shared_obj.write(shared);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool try_write_api_port_userconnect_reply(memory_interface& memory, const uint64_t reply_base, const process_context& process)
    {
        const auto destination = reply_base + k_wow64_userconnect_reply_shared_info_offset;
        if (destination < reply_base)
        {
            return false;
        }

        return try_write_user_shared_info(memory, destination, process);
    }
}
