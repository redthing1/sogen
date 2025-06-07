#pragma once

#ifdef __MINGW64__
#include <unistd.h>
#endif

#include <cstdlib>
#include <gtest/gtest.h>
#include <windows_emulator.hpp>
#include <backend_selection.hpp>

#include <network/static_socket_factory.hpp>

#define ASSERT_NOT_TERMINATED(win_emu)                           \
    do                                                           \
    {                                                            \
        ASSERT_FALSE((win_emu).process.exit_status.has_value()); \
    } while (false)

#define ASSERT_TERMINATED_WITH_STATUS(win_emu, status)          \
    do                                                          \
    {                                                           \
        ASSERT_TRUE((win_emu).process.exit_status.has_value()); \
        ASSERT_EQ(*(win_emu).process.exit_status, status);      \
    } while (false)

#define ASSERT_TERMINATED_SUCCESSFULLY(win_emu) ASSERT_TERMINATED_WITH_STATUS(win_emu, STATUS_SUCCESS)

namespace test
{
    inline bool enable_verbose_logging()
    {
        const auto* env = getenv("EMULATOR_VERBOSE");
        return env && (env == "1"sv || env == "true"sv);
    }

    inline std::filesystem::path get_emulator_root()
    {
        const auto* env = getenv("EMULATOR_ROOT");
        if (!env)
        {
            throw std::runtime_error("No EMULATOR_ROOT set!");
        }

        return env;
    }

    struct sample_configuration
    {
        bool print_time{false};
    };

    inline application_settings get_sample_app_settings(const sample_configuration& config)
    {
        application_settings settings{.application = "C:\\test-sample.exe"};

        if (config.print_time)
        {
            settings.arguments.emplace_back(u"-time");
        }

        return settings;
    }

    inline windows_emulator create_emulator(emulator_settings settings, emulator_callbacks callbacks = {})
    {
        const auto is_verbose = enable_verbose_logging();

        if (is_verbose)
        {
            callbacks.on_stdout = [](const std::string_view data) {
                std::cout << data; //
            };
        }

        settings.emulation_root = get_emulator_root();

        settings.path_mappings["C:\\a.txt"] =
            std::filesystem::temp_directory_path() / ("emulator-test-file-" + std::to_string(getpid()) + ".txt");

        return windows_emulator{
            create_x86_64_emulator(),
            settings,
            std::move(callbacks),
            emulator_interfaces{
                .socket_factory = network::create_static_socket_factory(),
            },
        };
    }

    inline windows_emulator create_sample_emulator(emulator_settings settings, const sample_configuration& config = {},
                                                   emulator_callbacks callbacks = {})
    {
        const auto is_verbose = enable_verbose_logging();

        if (is_verbose)
        {
            callbacks.on_stdout = [](const std::string_view data) {
                std::cout << data; //
            };
        }

        settings.emulation_root = get_emulator_root();

        settings.path_mappings["C:\\a.txt"] =
            std::filesystem::temp_directory_path() / ("emulator-test-file-" + std::to_string(getpid()) + ".txt");

        return windows_emulator{
            create_x86_64_emulator(),
            get_sample_app_settings(config),
            settings,
            std::move(callbacks),
            emulator_interfaces{
                .socket_factory = network::create_static_socket_factory(),
            },
        };
    }

    inline windows_emulator create_sample_emulator(const sample_configuration& config = {})
    {
        emulator_settings settings{
            .use_relative_time = true,
        };

        return create_sample_emulator(std::move(settings), config);
    }

    inline windows_emulator create_empty_emulator()
    {
        emulator_settings settings{
            .use_relative_time = true,
        };

        return create_emulator(std::move(settings));
    }

    inline void bisect_emulation(windows_emulator& emu)
    {
        utils::buffer_serializer start_state{};
        emu.serialize(start_state);

        emu.start();
        const auto limit = emu.get_executed_instructions();

        const auto reset_emulator = [&] {
            utils::buffer_deserializer deserializer{start_state};
            emu.deserialize(deserializer);
        };

        const auto get_state_for_count = [&](const size_t count) {
            reset_emulator();
            emu.start(count);

            utils::buffer_serializer state{};
            emu.serialize(state);
            return state;
        };

        const auto has_diff_after_count = [&](const size_t count) {
            const auto s1 = get_state_for_count(count);
            const auto s2 = get_state_for_count(count);

            return s1.get_diff(s2).has_value();
        };

        if (!has_diff_after_count(static_cast<size_t>(limit)))
        {
            puts("Emulation has no diff");
        }

        auto upper_bound = limit;
        decltype(upper_bound) lower_bound = 0;

        printf("Bounds: %" PRIx64 " - %" PRIx64 "\n", lower_bound, upper_bound);

        while (lower_bound + 1 < upper_bound)
        {
            const auto diff = (upper_bound - lower_bound);
            const auto pivot = lower_bound + (diff / 2);

            const auto has_diff = has_diff_after_count(static_cast<size_t>(pivot));

            auto* bound = has_diff ? &upper_bound : &lower_bound;
            *bound = pivot;

            printf("Bounds: %" PRIx64 " - %" PRIx64 "\n", lower_bound, upper_bound);
        }

        (void)get_state_for_count(static_cast<size_t>(lower_bound));

        const auto rip = emu.emu().read_instruction_pointer();

        printf("Diff detected after 0x%" PRIx64 " instructions at 0x%" PRIx64 " (%s)\n", lower_bound, rip,
               emu.mod_manager.find_name(rip));
    }
}
