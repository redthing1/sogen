#include "../std_include.hpp"
#include "../syscall_utils.hpp"
#include "common/segment_utils.hpp"

#include <utils/string.hpp>

namespace syscalls
{
    win32k_shared_state& ensure_win32k_shared_state(const syscall_context& c)
    {
        // Shared win32k state exposed to user32 via UserSharedInfoPtr
        constexpr uint32_t handle_entry_size = 0x20;
        constexpr uint32_t handle_entry_count = 0x1000;
        constexpr uint32_t msg_count = 0x2000;
        constexpr uint32_t ime_msg_count = 0x2000;
        constexpr size_t shared_align = 0x10;
        constexpr uint32_t gpsi_brush_offset = 0x1258;
        constexpr uint32_t gpsi_size = 0x1400;
        constexpr uint32_t handle_count_offset = 0x8;
        constexpr uint32_t handle_guard_offset = 0xC;

        auto& state = c.proc.win32k_shared;
        if (state.gpsi_address != 0)
        {
            return state;
        }

        state.handle_entry_size = handle_entry_size;
        state.handle_entry_count = handle_entry_count;

        const auto handle_table_size = static_cast<size_t>(state.handle_entry_size) * state.handle_entry_count;
        state.handle_table_address = c.proc.base_allocator.reserve(handle_table_size, shared_align);
        {
            std::vector<std::byte> zeros(handle_table_size);
            c.emu.write_memory(state.handle_table_address, zeros.data(), zeros.size());
        }

        state.msg_count = msg_count;
        const auto msg_bits_size = static_cast<size_t>((state.msg_count + 7) / 8);
        state.msg_bits_address = c.proc.base_allocator.reserve(msg_bits_size, shared_align);
        {
            std::vector<std::byte> zeros(msg_bits_size);
            c.emu.write_memory(state.msg_bits_address, zeros.data(), zeros.size());
        }

        state.ime_msg_count = ime_msg_count;
        const auto ime_bits_size = static_cast<size_t>((state.ime_msg_count + 7) / 8);
        state.ime_msg_bits_address = c.proc.base_allocator.reserve(ime_bits_size, shared_align);
        {
            std::vector<std::byte> zeros(ime_bits_size);
            c.emu.write_memory(state.ime_msg_bits_address, zeros.data(), zeros.size());
        }

        state.monitor_info_address = c.proc.base_allocator.reserve(0x10, shared_align);
        {
            std::vector<std::byte> zeros(0x10);
            c.emu.write_memory(state.monitor_info_address, zeros.data(), zeros.size());
        }

        state.shared_delta = 0;

        state.gpsi_size = gpsi_size;
        state.gpsi_address = c.proc.base_allocator.reserve(state.gpsi_size, shared_align);
        {
            std::vector<std::byte> zeros(state.gpsi_size);
            c.emu.write_memory(state.gpsi_address, zeros.data(), zeros.size());
        }

        state.shared_info_address = c.proc.base_allocator.reserve(sizeof(WIN32K_USERCONNECT32), shared_align);
        {
            std::vector<std::byte> zeros(sizeof(WIN32K_USERCONNECT32));
            c.emu.write_memory(state.shared_info_address, zeros.data(), zeros.size());
        }

        const auto gpsi = state.gpsi_address;
        const auto handle_count = state.handle_entry_count;
        c.emu.write_memory(gpsi + handle_count_offset, handle_count);
        c.emu.write_memory(gpsi + handle_guard_offset, 0u);

        // Brush handle
        const uint32_t handle = c.proc.gdi_next_handle_index++;
        c.emu.write_memory(gpsi + gpsi_brush_offset, handle);

        return state;
    }

    uint64_t resolve_wow64_callback_dispatcher(const syscall_context& c)
    {
        if (c.proc.wow64_ki_user_callback_dispatcher != 0)
        {
            return c.proc.wow64_ki_user_callback_dispatcher;
        }

        for (const auto& entry : c.win_emu.mod_manager.modules())
        {
            const auto& mod = entry.second;
            if (!utils::string::equals_ignore_case(std::string_view{mod.name}, std::string_view{"wow64.dll"}))
            {
                continue;
            }

            const auto dispatcher = mod.find_export("Wow64KiUserCallbackDispatcher");
            if (dispatcher != 0)
            {
                c.proc.wow64_ki_user_callback_dispatcher = dispatcher;
                return dispatcher;
            }
        }

        return 0;
    }

    uint64_t ensure_wow64_callback_buffer(const syscall_context& c, emulator_thread& thread)
    {
        constexpr uint32_t jmp_buf_size = 0x140;

        if (thread.win32k_callback_buffer == 0)
        {
            // Per-thread buffer for Wow64KiUserCallbackDispatcher
            thread.win32k_callback_buffer = c.proc.base_allocator.reserve(jmp_buf_size, 0x10);
            std::vector<std::byte> zeros(jmp_buf_size);
            c.emu.write_memory(thread.win32k_callback_buffer, zeros.data(), zeros.size());
        }

        return thread.win32k_callback_buffer;
    }

    bool schedule_wow64_client_callback(const syscall_context& c, emulator_thread& thread)
    {
        // Schedule win32k client thread setup callback
        constexpr uint32_t callback_id = 0x54;

        const auto dispatcher = resolve_wow64_callback_dispatcher(c);
        if (dispatcher == 0)
        {
            return false;
        }

        const auto cs_selector = c.emu.reg<uint16_t>(x86_register::cs);
        const auto bitness = segment_utils::get_segment_bitness(c.emu, cs_selector);
        if (!bitness || *bitness != segment_utils::segment_bitness::bit64)
        {
            return false;
        }

        const auto jmp_buf = ensure_wow64_callback_buffer(c, thread);

        c.emu.reg(x86_register::rcx, jmp_buf);
        c.emu.reg(x86_register::rdx, static_cast<uint64_t>(callback_id));
        c.emu.reg(x86_register::r8, 0);
        c.emu.reg(x86_register::r9, 0);
        c.emu.reg(x86_register::rip, dispatcher);

        return true;
    }

    NTSTATUS handle_NtUserGetThreadState(const syscall_context& c, const ULONG routine)
    {
        constexpr uint32_t thread_info_size = 0x1000;

        if (routine != 0xE)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (!c.proc.active_thread || !c.proc.active_thread->teb32)
        {
            return STATUS_UNSUCCESSFUL;
        }

        auto& thread = *c.proc.active_thread;

        if (thread.win32k_thread_info == 0)
        {
            thread.win32k_thread_info = c.proc.base_allocator.reserve(thread_info_size, 0x10);
            std::vector<std::byte> zeros(thread_info_size);
            c.emu.write_memory(thread.win32k_thread_info, zeros.data(), zeros.size());
        }

        const auto thread_info = thread.win32k_thread_info;
        const uint32_t low = static_cast<uint32_t>(thread_info & 0xFFFFFFFFu);
        const uint32_t high = static_cast<uint32_t>((thread_info >> 32) & 0xFFFFFFFFu);

        thread.teb32->access([&](TEB32& teb) {
            teb.User32Reserved[0xD] = low;
            teb.User32Reserved[0xE] = high;
            teb.Win32ThreadInfo = low;
        });

        if (thread.teb64)
        {
            thread.teb64->access([&](TEB64& teb64) { teb64.Win32ThreadInfo = thread_info; });
        }

        ensure_win32k_shared_state(c);

        if (!thread.win32k_thread_setup_done && !thread.win32k_thread_setup_pending)
        {
            if (!schedule_wow64_client_callback(c, thread))
            {
                return STATUS_UNSUCCESSFUL;
            }

            thread.win32k_thread_setup_pending = true;
        }

        return STATUS_SUCCESS;
    }

    uint64_t handle_NtUserRemoteConnectState()
    {
        return 1;
    }

    hdesk handle_NtUserGetThreadDesktop(const syscall_context& c, const ULONG thread_id)
    {
        emulator_thread* target = nullptr;
        if (thread_id == 0 || (c.proc.active_thread && c.proc.active_thread->id == thread_id))
        {
            target = c.proc.active_thread;
        }
        else
        {
            for (auto& entry : c.proc.threads)
            {
                auto& thread = entry.second;
                if (thread.id == thread_id)
                {
                    target = &thread;
                    break;
                }
            }
        }

        if (!target)
        {
            return 0;
        }

        if (target->win32k_desktop.bits == 0)
        {
            if (c.proc.default_desktop.bits == 0)
            {
                desktop desk{};
                desk.name = u"Default";
                c.proc.default_desktop = c.proc.desktops.store(std::move(desk));
            }

            target->win32k_desktop = c.proc.default_desktop;
        }

        return target->win32k_desktop.bits;
    }

    NTSTATUS handle_NtUserProcessConnect(const syscall_context& c, const handle /*process_handle*/, const ULONG length,
                                         const emulator_object<WIN32K_USERCONNECT32> user_connect)
    {
        if (length < sizeof(WIN32K_USERCONNECT32) || !user_connect)
        {
            return STATUS_BUFFER_TOO_SMALL;
        }

        auto& state = ensure_win32k_shared_state(c);

        WIN32K_USERCONNECT32 info{};
        info.psi = static_cast<uint32_t>(state.gpsi_address);
        info.ahe_list = static_cast<uint32_t>(state.handle_table_address);
        info.he_entry_size = state.handle_entry_size;
        info.monitor_info = static_cast<uint32_t>(state.monitor_info_address);
        info.shared_delta_low = static_cast<uint32_t>(state.shared_delta & 0xFFFFFFFFu);
        info.shared_delta_high = static_cast<uint32_t>((state.shared_delta >> 32) & 0xFFFFFFFFu);
        info.wndmsg_count = state.msg_count;
        info.wndmsg_bits = static_cast<uint32_t>(state.msg_bits_address);
        info.ime_msg_count = state.ime_msg_count;
        info.ime_msg_bits = static_cast<uint32_t>(state.ime_msg_bits_address);

        user_connect.write(info);
        c.emu.write_memory(state.shared_info_address, info);

        if (c.proc.peb32)
        {
            c.proc.peb32->access([&](PEB32& peb) { peb.UserSharedInfoPtr = static_cast<uint32_t>(state.shared_info_address); });
        }

        if (c.proc.active_thread)
        {
            c.proc.active_thread->win32k_thread_setup_pending = false;
            c.proc.active_thread->win32k_thread_setup_done = true;
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS handle_NtUserInitializeClientPfnArrays(const syscall_context& /*c*/, const emulator_pointer /*apfn_client_a*/,
                                                    const emulator_pointer /*apfn_client_w*/, const emulator_pointer /*apfn_client_worker*/,
                                                    const emulator_pointer /*hmod_user*/)
    {
        return STATUS_SUCCESS;
    }
}
