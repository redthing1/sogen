#include "snapshot.hpp"

#include <utils/io.hpp>

namespace minidump
{
    void load_minidump(windows_emulator& win_emu, const std::filesystem::path& minidump_file)
    {
        std::vector<std::byte> data{};
        if (!utils::io::read_file(minidump_file, &data))
        {
            throw std::runtime_error("Failed to read minidump file: " + minidump_file.string());
        }

        throw std::runtime_error("Minidump loading is not implemented yet!");
    }
}
