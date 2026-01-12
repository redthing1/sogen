#pragma once

#include "syscall_utils.hpp"

// TODO: Here we are calling guest functions directly, but this is not how it works in the real Windows kernel.
//       In the real implementation, the kernel invokes ntdll!KiUserCallbackDispatcher and passes a callback
//       index that refers to an entry in PEB->KernelCallbackTable. The dispatcher then looks up the function
//       pointer in that table and invokes the corresponding user-mode callback.
//       See Also: https://web.archive.org/web/20080717175308/http://www.nynaeve.net/?p=204

template <typename... Args>
void prepare_call_stack(x86_64_emulator& emu, uint64_t return_address, Args... args)
{
    constexpr size_t arg_count = sizeof...(Args);
    const size_t stack_args_size = aligned_stack_space(arg_count);

    const uint64_t current_rsp = emu.read_stack_pointer();
    const uint64_t aligned_rsp = align_down(current_rsp, 16);

    // We subtract the args size (including the shadow space) AND the size of the return address
    const uint64_t new_rsp = aligned_rsp - stack_args_size - sizeof(emulator_pointer);
    emu.reg(x86_register::rsp, new_rsp);

    emu.write_memory(new_rsp, &return_address, sizeof(return_address));

    size_t index = 0;
    (set_function_argument(emu, index++, static_cast<uint64_t>(args)), ...);
}

template <typename... Args>
void dispatch_user_callback(const syscall_context& c, callback_id completion_id, uint64_t func_address, Args... args)
{
    const callback_frame frame{
        .handler_id = completion_id,
        .rip = c.emu.read_instruction_pointer(),
        .rsp = c.emu.read_stack_pointer(),
        .r10 = c.emu.reg(x86_register::r10),
        .rcx = c.emu.reg(x86_register::rcx),
        .rdx = c.emu.reg(x86_register::rdx),
        .r8 = c.emu.reg(x86_register::r8),
        .r9 = c.emu.reg(x86_register::r9),
    };
    c.proc.active_thread->callback_stack.push_back(frame);

    prepare_call_stack(c.emu, c.proc.callback_sentinel_addr, args...);

    c.emu.reg(x86_register::rip, func_address);
    c.run_callback = true;
}
