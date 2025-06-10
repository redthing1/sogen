#include "../std_include.hpp"
#include "module_manager.hpp"
#include "module_mapping.hpp"
#include "windows-emulator/logger.hpp"

#include <serialization_helper.hpp>

namespace utils
{
    static void serialize(buffer_serializer& buffer, const exported_symbol& sym)
    {
        buffer.write(sym.name);
        buffer.write(sym.ordinal);
        buffer.write(sym.rva);
        buffer.write(sym.address);
    }

    static void deserialize(buffer_deserializer& buffer, exported_symbol& sym)
    {
        buffer.read(sym.name);
        buffer.read(sym.ordinal);
        buffer.read(sym.rva);
        buffer.read(sym.address);
    }

    static void serialize(buffer_serializer& buffer, const basic_memory_region& region)
    {
        buffer.write(region.start);
        buffer.write<uint64_t>(region.length);
        buffer.write(region.permissions);
    }

    static void deserialize(buffer_deserializer& buffer, basic_memory_region& region)
    {
        buffer.read(region.start);
        region.length = static_cast<size_t>(buffer.read<uint64_t>());
        buffer.read(region.permissions);
    }

    static void serialize(buffer_serializer& buffer, const mapped_section& mod)
    {
        buffer.write(mod.name);
        buffer.write(mod.region);
    }

    static void deserialize(buffer_deserializer& buffer, mapped_section& mod)
    {
        buffer.read(mod.name);
        buffer.read(mod.region);
    }

    static void serialize(buffer_serializer& buffer, const mapped_module& mod)
    {
        buffer.write(mod.name);
        buffer.write(mod.path);

        buffer.write(mod.image_base);
        buffer.write(mod.size_of_image);
        buffer.write(mod.entry_point);

        buffer.write_vector(mod.exports);
        buffer.write_map(mod.address_names);

        buffer.write_vector(mod.sections);

        buffer.write(mod.is_static);
    }

    static void deserialize(buffer_deserializer& buffer, mapped_module& mod)
    {
        buffer.read(mod.name);
        buffer.read(mod.path);

        buffer.read(mod.image_base);
        buffer.read(mod.size_of_image);
        buffer.read(mod.entry_point);

        buffer.read_vector(mod.exports);
        buffer.read_map(mod.address_names);

        buffer.read_vector(mod.sections);

        buffer.read(mod.is_static);
    }
}

module_manager::module_manager(memory_manager& memory, file_system& file_sys, callbacks& cb)
    : memory_(&memory),
      file_sys_(&file_sys),
      callbacks_(&cb)
{
}

void module_manager::map_main_modules(const windows_path& executable_path, const windows_path& ntdll_path,
                                      const windows_path& win32u_path, const logger& logger)
{
    this->executable = this->map_module(executable_path, logger, true);
    this->ntdll = this->map_module(ntdll_path, logger, true);
    this->win32u = this->map_module(win32u_path, logger, true);
}

mapped_module* module_manager::map_module(const windows_path& file, const logger& logger, const bool is_static)
{
    return this->map_local_module(this->file_sys_->translate(file), logger, is_static);
}

mapped_module* module_manager::map_local_module(const std::filesystem::path& file, const logger& logger,
                                                const bool is_static)
{
    auto local_file = weakly_canonical(absolute(file));

    for (auto& mod : this->modules_ | std::views::values)
    {
        if (mod.path == local_file)
        {
            return &mod;
        }
    }

    try
    {
        auto mod = map_module_from_file(*this->memory_, std::move(local_file));
        mod.is_static = is_static;

        const auto image_base = mod.image_base;
        const auto entry = this->modules_.try_emplace(image_base, std::move(mod));
        this->callbacks_->on_module_load(entry.first->second);
        return &entry.first->second;
    }
    catch (const std::exception& e)
    {
        logger.error("Failed to map %s: %s\n", file.generic_string().c_str(), e.what());
        return nullptr;
    }
    catch (...)
    {
        logger.error("Failed to map %s: Unknown error\n", file.generic_string().c_str());
        return nullptr;
    }
}

mapped_module* module_manager::map_memory_module(uint64_t base_address, uint64_t image_size,
                                                 const std::string& module_name, const logger& logger, bool is_static)
{
    for (auto& mod : this->modules_ | std::views::values)
    {
        if (mod.image_base == base_address)
        {
            return &mod;
        }
    }

    try
    {
        auto mod = ::map_module_from_memory(*this->memory_, base_address, image_size, module_name);
        mod.is_static = is_static;

        const auto image_base = mod.image_base;
        const auto entry = this->modules_.try_emplace(image_base, std::move(mod));
        this->callbacks_->on_module_load(entry.first->second);
        return &entry.first->second;
    }
    catch (const std::exception& e)
    {
        logger.error("Failed to map module from memory %s at 0x%016llX: %s\n", module_name.c_str(), base_address,
                     e.what());
        return nullptr;
    }
    catch (...)
    {
        logger.error("Failed to map module from memory %s at 0x%016llX: Unknown error\n", module_name.c_str(),
                     base_address);
        return nullptr;
    }
}

void module_manager::serialize(utils::buffer_serializer& buffer) const
{
    buffer.write_map(this->modules_);

    buffer.write(this->executable ? this->executable->image_base : 0);
    buffer.write(this->ntdll ? this->ntdll->image_base : 0);
    buffer.write(this->win32u ? this->win32u->image_base : 0);
}

void module_manager::deserialize(utils::buffer_deserializer& buffer)
{
    buffer.read_map(this->modules_);

    const auto executable_base = buffer.read<uint64_t>();
    const auto ntdll_base = buffer.read<uint64_t>();
    const auto win32u_base = buffer.read<uint64_t>();

    this->executable = executable_base ? this->find_by_address(executable_base) : nullptr;
    this->ntdll = ntdll_base ? this->find_by_address(ntdll_base) : nullptr;
    this->win32u = win32u_base ? this->find_by_address(win32u_base) : nullptr;
}

bool module_manager::unmap(const uint64_t address)
{
    const auto mod = this->modules_.find(address);
    if (mod == this->modules_.end())
    {
        return false;
    }

    if (mod->second.is_static)
    {
        return true;
    }

    this->callbacks_->on_module_unload(mod->second);
    unmap_module(*this->memory_, mod->second);
    this->modules_.erase(mod);

    return true;
}
