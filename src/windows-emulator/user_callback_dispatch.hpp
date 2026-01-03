#pragma once

#include "syscall_utils.hpp"

// TODO: Here we are calling guest functions directly, but this is not how it works in the real Windows kernel.
//       In the real implementation, the kernel invokes ntdll!KiUserCallbackDispatcher and passes a callback
//       index that refers to an entry in PEB->KernelCallbackTable. The dispatcher then looks up the function
//       pointer in that table and invokes the corresponding user-mode callback.

template <typename... Args>
void dispatch_user_callback(const syscall_context& c, callback_id completion_id, uint64_t func_address, Args... args)
{
    const uint64_t original_rsp = c.emu.read_stack_pointer();

    // Save syscall argument registers BEFORE modifying anything
    const callback_frame frame{
        .handler_id = completion_id,
        .rip = c.emu.read_instruction_pointer(),
        .rsp = original_rsp,
        .r10 = c.emu.reg(x86_register::r10),
        .rcx = c.emu.reg(x86_register::rcx),
        .rdx = c.emu.reg(x86_register::rdx),
        .r8 = c.emu.reg(x86_register::r8),
        .r9 = c.emu.reg(x86_register::r9),
    };

    uint64_t stack_ptr = align_down(original_rsp, 16);

    constexpr size_t arg_count = sizeof...(Args);
    const size_t allocation_size = aligned_stack_space(arg_count);
    stack_ptr -= allocation_size;

    // Push the return address onto the stack (Simulating CALL)
    stack_ptr -= sizeof(emulator_pointer);
    c.emu.write_memory(stack_ptr, &c.proc.callback_sentinel_addr, sizeof(c.proc.callback_sentinel_addr));

    c.proc.active_thread->callback_stack.push_back(frame);

    c.emu.reg(x86_register::rsp, stack_ptr);

    size_t index = 0;
    (set_function_argument(c.emu, index++, static_cast<uint64_t>(args)), ...);

    c.emu.reg(x86_register::rip, func_address);
    c.run_callback = true;
}
