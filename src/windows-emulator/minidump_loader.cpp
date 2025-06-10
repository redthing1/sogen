#include "std_include.hpp"
#include "minidump_loader.hpp"
#include "windows_emulator.hpp"

#include <minidump/minidump.hpp>
#include <iomanip>
#include <sstream>

namespace
{
    struct dump_statistics
    {
        size_t thread_count = 0;
        size_t module_count = 0;
        size_t memory_region_count = 0;
        size_t memory_segment_count = 0;
        size_t handle_count = 0;
        uint64_t total_memory_size = 0;
        bool has_exception = false;
        bool has_system_info = false;
    };

    std::string format_address(uint64_t address)
    {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << address;
        return oss.str();
    }

    std::string format_size(uint64_t size)
    {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        double sz = static_cast<double>(size);
        int unit = 0;

        while (sz >= 1024.0 && unit < 4)
        {
            sz /= 1024.0;
            unit++;
        }

        std::ostringstream oss;
        if (unit == 0)
        {
            oss << static_cast<uint64_t>(sz) << " " << units[unit];
        }
        else
        {
            oss << std::fixed << std::setprecision(2) << sz << " " << units[unit];
        }
        return oss.str();
    }

    std::string get_architecture_string(const minidump::minidump_file* dump_file)
    {
        if (!dump_file)
        {
            return "Unknown";
        }

        const auto* sys_info = dump_file->get_system_info();
        if (!sys_info)
        {
            return "Unknown";
        }

        const auto arch = static_cast<minidump::processor_architecture>(sys_info->processor_architecture);
        switch (arch)
        {
        case minidump::processor_architecture::amd64:
            return "x64 (AMD64)";
        case minidump::processor_architecture::intel:
            return "x86 (Intel)";
        case minidump::processor_architecture::arm64:
            return "ARM64";
        default:
            return "Unknown (" + std::to_string(static_cast<int>(arch)) + ")";
        }
    }

    bool parse_minidump_file(windows_emulator& win_emu, const std::filesystem::path& minidump_path,
                             std::unique_ptr<minidump::minidump_file>& dump_file,
                             std::unique_ptr<minidump::minidump_reader>& dump_reader)
    {
        win_emu.log.info("Parsing minidump file\n");

        if (!std::filesystem::exists(minidump_path))
        {
            win_emu.log.error("Minidump file does not exist: %s\n", minidump_path.string().c_str());
            return false;
        }

        const auto file_size = std::filesystem::file_size(minidump_path);
        win_emu.log.info("File size: %s\n", format_size(file_size).c_str());

        auto parsed_file = minidump::minidump_file::parse(minidump_path.string());
        if (!parsed_file)
        {
            win_emu.log.error("Failed to parse minidump file\n");
            return false;
        }

        win_emu.log.info("Minidump header parsed successfully\n");

        auto reader = parsed_file->get_reader();
        if (!reader)
        {
            win_emu.log.error("Failed to create minidump reader\n");
            return false;
        }

        dump_file = std::move(parsed_file);
        dump_reader = std::move(reader);

        win_emu.log.info("Minidump reader created successfully\n");
        return true;
    }

    bool validate_dump_compatibility(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        win_emu.log.info("Validating dump compatibility\n");

        if (!dump_file)
        {
            win_emu.log.error("Dump file not loaded\n");
            return false;
        }

        const auto& header = dump_file->header();

        if (!header.is_valid())
        {
            win_emu.log.error("Invalid minidump signature or header\n");
            return false;
        }

        win_emu.log.info("Minidump signature: 0x%08X (valid)\n", header.signature);
        win_emu.log.info("Version: %u.%u\n", header.version, header.implementation_version);
        win_emu.log.info("Number of streams: %u\n", header.number_of_streams);
        win_emu.log.info("Flags: 0x%016llX\n", header.flags);

        const auto* sys_info = dump_file->get_system_info();
        if (sys_info)
        {
            const auto arch = static_cast<minidump::processor_architecture>(sys_info->processor_architecture);
            const bool is_x64 = (arch == minidump::processor_architecture::amd64);

            win_emu.log.info("Processor architecture: %s\n", get_architecture_string(dump_file).c_str());

            if (!is_x64)
            {
                win_emu.log.error("Only x64 minidumps are currently supported\n");
                return false;
            }

            win_emu.log.info("Architecture compatibility: OK (x64)\n");
        }
        else
        {
            win_emu.log.warn("No system info stream found - proceeding with caution\n");
        }

        return true;
    }

    void log_dump_summary(windows_emulator& win_emu, const minidump::minidump_file* dump_file, dump_statistics& stats)
    {
        win_emu.log.info("Generating dump summary\n");

        stats = {};

        if (!dump_file)
        {
            win_emu.log.error("Dump file not loaded\n");
            return;
        }

        stats.thread_count = dump_file->threads().size();
        stats.module_count = dump_file->modules().size();
        stats.memory_region_count = dump_file->memory_regions().size();
        stats.memory_segment_count = dump_file->memory_segments().size();
        stats.handle_count = dump_file->handles().size();
        stats.has_exception = (dump_file->get_exception_info() != nullptr);
        stats.has_system_info = (dump_file->get_system_info() != nullptr);

        for (const auto& segment : dump_file->memory_segments())
        {
            stats.total_memory_size += segment.size;
        }

        win_emu.log.info("Summary: %s, %zu threads, %zu modules, %zu regions, %zu segments, %zu handles, %s memory\n",
                         get_architecture_string(dump_file).c_str(), stats.thread_count, stats.module_count,
                         stats.memory_region_count, stats.memory_segment_count, stats.handle_count,
                         format_size(stats.total_memory_size).c_str());
    }

    void process_streams(windows_emulator& win_emu, const minidump::minidump_file* dump_file)
    {
        if (!dump_file)
        {
            return;
        }

        // Process system info
        const auto* sys_info = dump_file->get_system_info();
        if (sys_info)
        {
            win_emu.log.info("System: OS %u.%u.%u, %u processors, type %u, platform %u\n", sys_info->major_version,
                             sys_info->minor_version, sys_info->build_number, sys_info->number_of_processors,
                             sys_info->product_type, sys_info->platform_id);
        }

        // Process memory info
        const auto& memory_regions = dump_file->memory_regions();
        uint64_t total_reserved = 0, total_committed = 0;
        size_t guard_pages = 0;
        for (const auto& region : memory_regions)
        {
            total_reserved += region.region_size;
            if (region.state & 0x1000)
                total_committed += region.region_size;
            if (region.protect & 0x100)
                guard_pages++;
        }
        win_emu.log.info("Memory: %zu regions, %s reserved, %s committed, %zu guard pages\n", memory_regions.size(),
                         format_size(total_reserved).c_str(), format_size(total_committed).c_str(), guard_pages);

        // Process memory content
        const auto& memory_segments = dump_file->memory_segments();
        uint64_t min_addr = UINT64_MAX, max_addr = 0;
        for (const auto& segment : memory_segments)
        {
            min_addr = std::min(min_addr, segment.start_virtual_address);
            max_addr = std::max(max_addr, segment.end_virtual_address());
        }
        if (!memory_segments.empty())
        {
            win_emu.log.info("Content: %zu segments, range %s-%s (%s span)\n", memory_segments.size(),
                             format_address(min_addr).c_str(), format_address(max_addr).c_str(),
                             format_size(max_addr - min_addr).c_str());
        }

        // Process modules
        const auto& modules = dump_file->modules();
        for (const auto& module : modules)
        {
            win_emu.log.info("Module: %s at %s (%s)\n", module.module_name.c_str(),
                             format_address(module.base_of_image).c_str(), format_size(module.size_of_image).c_str());
        }

        // Process threads
        const auto& threads = dump_file->threads();
        for (const auto& thread : threads)
        {
            win_emu.log.info("Thread %u: TEB %s, stack %s (%s), context %u bytes\n", thread.thread_id,
                             format_address(thread.teb).c_str(),
                             format_address(thread.stack_start_of_memory_range).c_str(),
                             format_size(thread.stack_data_size).c_str(), thread.context_data_size);
        }

        // Process handles
        const auto& handles = dump_file->handles();
        if (!handles.empty())
        {
            std::map<std::string, size_t> handle_type_counts;
            for (const auto& handle : handles)
                handle_type_counts[handle.type_name]++;
            win_emu.log.info("Handles: %zu total\n", handles.size());
            for (const auto& [type, count] : handle_type_counts)
            {
                win_emu.log.info("  %s: %zu\n", type.c_str(), count);
            }
        }

        // Process exception info
        const auto* exception = dump_file->get_exception_info();
        if (exception)
        {
            win_emu.log.info("Exception: thread %u, code 0x%08X at %s\n", exception->thread_id,
                             exception->exception_record.exception_code,
                             format_address(exception->exception_record.exception_address).c_str());
        }
    }

    void reconstruct_memory_state(windows_emulator& win_emu, const minidump::minidump_file* dump_file,
                                  minidump::minidump_reader* dump_reader)
    {
        if (!dump_file || !dump_reader)
        {
            win_emu.log.error("Dump file or reader not loaded\n");
            return;
        }

        const auto& memory_regions = dump_file->memory_regions();
        const auto& memory_segments = dump_file->memory_segments();

        win_emu.log.info("Reconstructing memory: %zu regions, %zu data segments\n", memory_regions.size(),
                         memory_segments.size());
        size_t reserved_count = 0;
        size_t committed_count = 0;
        size_t failed_count = 0;

        for (const auto& region : memory_regions)
        {
            const bool is_reserved = (region.state & 0x2000) != 0;  // MEM_RESERVE
            const bool is_committed = (region.state & 0x1000) != 0; // MEM_COMMIT
            const bool is_free = (region.state & 0x10000) != 0;     // MEM_FREE

            if (is_free)
                continue;

            memory_permission perms = memory_permission::none;
            if (region.protect & 0x04)
                perms = memory_permission::read_write;
            if (region.protect & 0x02)
                perms = memory_permission::read;
            if (region.protect & 0x20)
                perms = memory_permission::read | memory_permission::exec;
            if (region.protect & 0x40)
                perms = memory_permission::all;

            try
            {
                if (is_committed)
                {
                    if (win_emu.memory.allocate_memory(region.base_address, region.region_size, perms, false))
                    {
                        committed_count++;
                        win_emu.log.info("  Allocated committed %s: size=%s, state=0x%08X, protect=0x%08X\n",
                                         format_address(region.base_address).c_str(),
                                         format_size(region.region_size).c_str(), region.state, region.protect);
                    }
                    else
                    {
                        failed_count++;
                        win_emu.log.warn("  Failed to allocate committed %s: size=%s\n",
                                         format_address(region.base_address).c_str(),
                                         format_size(region.region_size).c_str());
                    }
                }
                else if (is_reserved)
                {
                    if (win_emu.memory.allocate_memory(region.base_address, region.region_size, perms, true))
                    {
                        reserved_count++;
                        win_emu.log.info("  Reserved %s: size=%s, state=0x%08X, protect=0x%08X\n",
                                         format_address(region.base_address).c_str(),
                                         format_size(region.region_size).c_str(), region.state, region.protect);
                    }
                    else
                    {
                        failed_count++;
                        win_emu.log.warn("  Failed to reserve %s: size=%s\n",
                                         format_address(region.base_address).c_str(),
                                         format_size(region.region_size).c_str());
                    }
                }
            }
            catch (const std::exception& e)
            {
                failed_count++;
                win_emu.log.error("  Exception allocating %s: %s\n", format_address(region.base_address).c_str(),
                                  e.what());
            }
        }

        win_emu.log.info("Regions: %zu reserved, %zu committed, %zu failed\n", reserved_count, committed_count,
                         failed_count);
        size_t written_count = 0;
        size_t write_failed_count = 0;
        uint64_t total_bytes_written = 0;

        for (const auto& segment : memory_segments)
        {
            try
            {
                auto memory_data = dump_reader->read_memory(segment.start_virtual_address, segment.size);
                win_emu.memory.write_memory(segment.start_virtual_address, memory_data.data(), memory_data.size());
                written_count++;
                total_bytes_written += memory_data.size();
                win_emu.log.info("  Written segment %s: %s\n", format_address(segment.start_virtual_address).c_str(),
                                 format_size(memory_data.size()).c_str());
            }
            catch (const std::exception& e)
            {
                write_failed_count++;
                win_emu.log.error("  Failed to write segment %s: %s\n",
                                  format_address(segment.start_virtual_address).c_str(), e.what());
            }
        }

        win_emu.log.info("Content: %zu segments written (%s), %zu failed\n", written_count,
                         format_size(total_bytes_written).c_str(), write_failed_count);
    }
}

minidump_loader::minidump_loader(windows_emulator& win_emu, const std::filesystem::path& minidump_path)
    : win_emu_(win_emu),
      minidump_path_(minidump_path)
{
}

minidump_loader::~minidump_loader() = default;

void minidump_loader::load_into_emulator()
{
    win_emu_.log.info("Starting minidump loading process\n");
    win_emu_.log.info("Minidump file: %s\n", minidump_path_.string().c_str());

    try
    {
        std::unique_ptr<minidump::minidump_file> dump_file;
        std::unique_ptr<minidump::minidump_reader> dump_reader;

        if (!parse_minidump_file(win_emu_, minidump_path_, dump_file, dump_reader))
        {
            throw std::runtime_error("Failed to parse minidump file");
        }

        if (!validate_dump_compatibility(win_emu_, dump_file.get()))
        {
            throw std::runtime_error("Minidump compatibility validation failed");
        }

        dump_statistics stats;
        log_dump_summary(win_emu_, dump_file.get(), stats);
        process_streams(win_emu_, dump_file.get());
        reconstruct_memory_state(win_emu_, dump_file.get(), dump_reader.get());

        win_emu_.log.info("TODO: Module and process state reconstruction not yet implemented\n");
    }
    catch (const std::exception& e)
    {
        win_emu_.log.error("Minidump loading failed: %s\n", e.what());
        throw;
    }
}