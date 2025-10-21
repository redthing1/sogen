#include "../std_include.hpp"
#include "api_port.hpp"

#include "../windows_emulator.hpp"

namespace
{
    struct api_port : port
    {
        NTSTATUS handle_request(windows_emulator& win_emu, const lpc_request_context& c) override
        {
            // TODO: Fix this. This is broken and wrong.

            try
            {
                const emulator_object<PORT_DATA_ENTRY<EmulatorTraits<Emu64>>> data{win_emu.emu(), c.recv_buffer + 0x20};
                const auto dest = data.read();
                const auto base = dest.Base;

                const auto value = base + 0x10;
                win_emu.emu().write_memory(base + 8, &value, sizeof(value));
            }
            catch (...)
            {
                return STATUS_NOT_SUPPORTED;
            }

            return STATUS_SUCCESS;
        }
    };
}

std::unique_ptr<port> create_api_port()
{
    return std::make_unique<api_port>();
}
