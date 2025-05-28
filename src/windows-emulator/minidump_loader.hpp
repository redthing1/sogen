#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>

#include "windows_emulator.hpp"

#include "minidump/minidump.hpp"

class minidump_loader
{
  public:
    minidump_loader(windows_emulator& win_emu, const std::filesystem::path& minidump_file)
        : win_emu_(win_emu)
    {
        dump_ = minidump::minidump_file::parse(minidump_file);
        if (!dump_)
        {
            throw std::runtime_error("Failed to parse minidump file: " + minidump_file.string());
        }
        win_emu_.log.info("Parsed minidump file: %s\n", minidump_file.string().c_str());
    }

    void load_into_emulator()
    {
        // TODO
    }

  private:
    std::unique_ptr<minidump::minidump_file> dump_;
    windows_emulator& win_emu_;
};
