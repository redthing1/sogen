#pragma once
#include "x64_gdb_stub_handler.hpp"

#include <atomic>
#include <windows_emulator.hpp>
#include <utils/function.hpp>
#include <utils/string.hpp>

class win_x64_gdb_stub_handler : public x64_gdb_stub_handler
{
  public:
    win_x64_gdb_stub_handler(windows_emulator& win_emu, utils::optional_function<bool()> should_stop = {})
        : x64_gdb_stub_handler(win_emu.emu()),
          win_emu_(&win_emu),
          should_stop_(std::move(should_stop))
    {
        // Chain module load/unload callbacks to stop on library changes
        auto& callbacks = win_emu_->callbacks;

        old_on_module_load_ = std::move(callbacks.on_module_load);
        callbacks.on_module_load = [this](mapped_module& mod) {
            if (old_on_module_load_)
            {
                old_on_module_load_(mod);
            }
            library_stop_pending_ = true;
            win_emu_->stop();
        };

        old_on_module_unload_ = std::move(callbacks.on_module_unload);
        callbacks.on_module_unload = [this](mapped_module& mod) {
            if (old_on_module_unload_)
            {
                old_on_module_unload_(mod);
            }
            library_stop_pending_ = true;
            win_emu_->stop();
        };
    }

    ~win_x64_gdb_stub_handler() override
    {
        // Restore original callbacks
        win_emu_->callbacks.on_module_load = std::move(old_on_module_load_);
        win_emu_->callbacks.on_module_unload = std::move(old_on_module_unload_);
    }

    void on_interrupt() override
    {
        this->win_emu_->stop();
    }

    bool should_stop() override
    {
        return this->should_stop_();
    }

    gdb_stub::action run() override
    {
        try
        {
            this->win_emu_->start();
        }
        catch (const std::exception& e)
        {
            this->win_emu_->log.error("%s\n", e.what());
        }

        return gdb_stub::action::resume;
    }

    gdb_stub::action singlestep() override
    {
        try
        {
            this->win_emu_->start(1);
        }
        catch (const std::exception& e)
        {
            this->win_emu_->log.error("%s\n", e.what());
        }

        return gdb_stub::action::resume;
    }

    uint32_t get_current_thread_id() override
    {
        return this->win_emu_->current_thread().id;
    }

    std::vector<uint32_t> get_thread_ids() override
    {
        const auto& threads = this->win_emu_->process.threads;

        std::vector<uint32_t> ids{};
        ids.reserve(threads.size());

        for (const auto& t : threads | std::views::values)
        {
            if (!t.is_terminated())
            {
                ids.push_back(t.id);
            }
        }

        return ids;
    }

    bool switch_to_thread(const uint32_t thread_id) override
    {
        return this->win_emu_->activate_thread(thread_id);
    }

    std::optional<uint32_t> get_exit_code() override
    {
        const auto status = this->win_emu_->process.exit_status;
        if (!status)
        {
            return std::nullopt;
        }

        return static_cast<uint32_t>(*status);
    }

    std::string get_windows_path(const std::filesystem::path& path)
    {
        try
        {
            return win_emu_->file_sys.local_to_windows_path(path).string();
        }
        catch (...)
        {
            // Pseudo-modules like <wow64-heaven-gate> aren't in the filesystem
            return path.string();
        }
    }

    std::vector<gdb_stub::library_info> get_libraries() override
    {
        std::vector<gdb_stub::library_info> libs{};
        const auto& mod_manager = this->win_emu_->mod_manager;
        libs.reserve(this->win_emu_->mod_manager.modules().size());
        for (const auto& [base_addr, mod] : mod_manager.modules())
        {
            libs.push_back({get_windows_path(mod.path), base_addr + 0x1000});
        }

        return libs;
    }

    bool consume_library_stop() override
    {
        return library_stop_pending_.exchange(false);
    }

  private:
    windows_emulator* win_emu_{};
    utils::optional_function<bool()> should_stop_{};

    // Track library stop events
    std::atomic<bool> library_stop_pending_{false};
    utils::optional_function<void(mapped_module&)> old_on_module_load_{};
    utils::optional_function<void(mapped_module&)> old_on_module_unload_{};
};
