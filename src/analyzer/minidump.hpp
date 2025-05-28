#pragma once

#include <windows_emulator.hpp>

namespace minidump
{
    void load_minidump(windows_emulator& win_emu, const std::filesystem::path& minidump_file);
}
