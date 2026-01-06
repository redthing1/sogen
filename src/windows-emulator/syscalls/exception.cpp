#include "../std_include.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

namespace syscalls
{
    NTSTATUS handle_NtRaiseHardError(const syscall_context& c, const NTSTATUS error_status, const ULONG number_of_parameters,
                                     const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> /*unicode_string_parameter_mask*/,
                                     const uint64_t parameters, const HARDERROR_RESPONSE_OPTION /*valid_response_option*/,
                                     const emulator_object<HARDERROR_RESPONSE> response)
    {
        if (response)
        {
            response.write(ResponseAbort);
        }

        if (error_status & STATUS_SERVICE_NOTIFICATION && number_of_parameters >= 3)
        {
            std::array<uint64_t, 3> params = {0, 0, 0};

            if (c.emu.try_read_memory(parameters, &params, sizeof(params)))
            {
                UNICODE_STRING<EmulatorTraits<Emu64>> unicode{};
                if (params[0] != 0 && c.emu.try_read_memory(params[0], &unicode, sizeof(unicode)))
                {
                    const auto length = static_cast<size_t>(unicode.Length);
                    std::u16string message{};
                    if (unicode.Buffer != 0 && length > 0 && length < 0x10000)
                    {
                        message.resize(length / sizeof(char16_t));
                        if (c.emu.try_read_memory(unicode.Buffer, message.data(), length))
                        {
                            c.win_emu.log.error("Error Message: %s\n", u16_to_u8(message).c_str());
                        }
                    }
                }
            }
        }

        c.proc.exit_status = error_status;
        c.win_emu.callbacks.on_exception();
        c.emu.stop();

        return STATUS_SUCCESS;
    }

    NTSTATUS handle_NtRaiseException(const syscall_context& c,
                                     const emulator_object<EMU_EXCEPTION_RECORD<EmulatorTraits<Emu64>>> /*exception_record*/,
                                     const emulator_object<CONTEXT64> /*thread_context*/, const BOOLEAN handle_exception)
    {
        if (handle_exception)
        {
            c.win_emu.log.error("Unhandled exceptions not supported yet!\n");
            c.emu.stop();
            return STATUS_NOT_SUPPORTED;
        }

        c.win_emu.callbacks.on_exception();
        c.emu.stop();

        return STATUS_SUCCESS;
    }
}
