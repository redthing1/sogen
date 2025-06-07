#include "std_include.hpp"
#include "logger.hpp"

#include <utils/finally.hpp>

namespace
{
#ifdef _WIN32
#define COLOR(win, posix, web) win
    using color_type = WORD;
#elif defined(__EMSCRIPTEN__)
#define COLOR(win, posix, web) web
    using color_type = const char*;
#else
#define COLOR(win, posix, web) posix
    using color_type = const char*;
#endif

    color_type get_reset_color()
    {
        return COLOR(7, "\033[0m", "</span>");
    }

    color_type get_color_type(const color c)
    {
        using enum color;

        switch (c)
        {
        case black:
            return COLOR(0x8, "\033[0;90m", "<span class=\"terminal-black\">");
        case red:
            return COLOR(0xC, "\033[0;91m", "<span class=\"terminal-red\">");
        case green:
            return COLOR(0xA, "\033[0;92m", "<span class=\"terminal-green\">");
        case yellow:
            return COLOR(0xE, "\033[0;93m", "<span class=\"terminal-yellow\">");
        case blue:
            return COLOR(0x9, "\033[0;94m", "<span class=\"terminal-blue\">");
        case cyan:
            return COLOR(0xB, "\033[0;96m", "<span class=\"terminal-cyan\">");
        case pink:
            return COLOR(0xD, "\033[0;95m", "<span class=\"terminal-pink\">");
        case white:
            return COLOR(0xF, "\033[0;97m", "<span class=\"terminal-white\">");
        case dark_gray:
            return COLOR(0x8, "\033[0;97m", "<span class=\"terminal-dark-gray\">");
        case gray:
        default:
            return get_reset_color();
        }
    }

#ifdef _WIN32
    HANDLE get_console_handle()
    {
        return GetStdHandle(STD_OUTPUT_HANDLE);
    }
#endif

    void set_color(const color_type color)
    {
#ifdef _WIN32
        SetConsoleTextAttribute(get_console_handle(), color);
#else
        printf("%s", color);
#endif
    }

    void reset_color()
    {
        (void)fflush(stdout);
        set_color(get_reset_color());
        (void)fflush(stdout);
    }

    std::string_view format(va_list* ap, const char* message)
    {
        thread_local std::array<char, 0x1000> buffer{};

#ifdef _WIN32
        const int count = _vsnprintf_s(buffer.data(), buffer.size(), buffer.size(), message, *ap);
#else
        const int count = vsnprintf(buffer.data(), buffer.size(), message, *ap);
#endif

        if (count < 0)
        {
            return {};
        }

        return {buffer.data(), static_cast<size_t>(count)};
    }

#define format_to_string(msg, str)     \
    va_list ap;                        \
    va_start(ap, msg);                 \
    const auto str = format(&ap, msg); \
    va_end(ap)

    void print_colored(const std::string_view& line, const color_type base_color)
    {
        const auto _ = utils::finally(&reset_color);
        set_color(base_color);
        (void)fwrite(line.data(), 1, line.size(), stdout);
    }
}

void logger::print_message(const color c, const std::string_view message, const bool force) const
{
    if (!force && this->disable_output_)
    {
        return;
    }

    print_colored(message, get_color_type(c));
}

void logger::print(const color c, const std::string_view message)
{
    this->print_message(c, message);
}

// NOLINTNEXTLINE(cert-dcl50-cpp)
void logger::print(const color c, const char* message, ...)
{
    format_to_string(message, data);
    this->print_message(c, data);
}

// NOLINTNEXTLINE(cert-dcl50-cpp)
void logger::info(const char* message, ...) const
{
    format_to_string(message, data);
    this->print_message(color::cyan, data);
}

// NOLINTNEXTLINE(cert-dcl50-cpp)
void logger::warn(const char* message, ...) const
{
    format_to_string(message, data);
    this->print_message(color::yellow, data);
}

// NOLINTNEXTLINE(cert-dcl50-cpp)
void logger::error(const char* message, ...) const
{
    format_to_string(message, data);
    this->print_message(color::red, data, true);
}

// NOLINTNEXTLINE(cert-dcl50-cpp)
void logger::success(const char* message, ...) const
{
    format_to_string(message, data);
    this->print_message(color::green, data);
}

// NOLINTNEXTLINE(cert-dcl50-cpp)
void logger::log(const char* message, ...) const
{
    format_to_string(message, data);
    this->print_message(color::gray, data);
}
