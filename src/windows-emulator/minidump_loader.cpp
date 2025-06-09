#include "std_include.hpp"
#include "minidump_loader.hpp"
#include "windows_emulator.hpp"

minidump_loader::minidump_loader(windows_emulator& win_emu, const std::filesystem::path& minidump_path)
    : win_emu_(win_emu),
      minidump_path_(minidump_path)
{
}

void minidump_loader::load_into_emulator()
{
    // TODO: Implement minidump loading
    win_emu_.log.info("Loading minidump from file: %s\n", minidump_path_.string().c_str());
}