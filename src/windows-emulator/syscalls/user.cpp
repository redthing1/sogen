#include "../std_include.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"
#include "windows-emulator/user_callback_dispatch.hpp"

namespace syscalls
{
    NTSTATUS handle_NtUserDisplayConfigGetDeviceInfo()
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_NtUserRegisterWindowMessage()
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_NtUserGetThreadState()
    {
        return 0;
    }

    hdc handle_NtUserGetDCEx(const syscall_context& /*c*/, const hwnd window, const uint64_t /*clip_region*/, const ULONG /*flags*/)
    {
        return window;
    }

    hdc handle_NtUserGetDC(const syscall_context& c, const hwnd window)
    {
        return handle_NtUserGetDCEx(c, window, 0, 0);
    }

    NTSTATUS handle_NtUserGetWindowDC()
    {
        return 1;
    }

    NTSTATUS handle_NtUserReleaseDC()
    {
        return STATUS_SUCCESS;
    }

    NTSTATUS handle_NtUserGetCursorPos()
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_NtUserSetCursor()
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_NtUserFindExistingCursorIcon()
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_NtUserFindWindowEx(const syscall_context& c, const hwnd, const hwnd,
                                       const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> class_name,
                                       const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> window_name)
    {
        if (c.win_emu.callbacks.on_generic_activity)
        {
            std::string class_name_str = "(null)";
            std::string window_name_str = "(null)";

            if (class_name)
            {
                class_name_str = u16_to_u8(read_unicode_string(c.emu, class_name));
            }

            if (window_name)
            {
                window_name_str = u16_to_u8(read_unicode_string(c.emu, window_name));
            }

            c.win_emu.callbacks.on_generic_activity("Window query for class '" + class_name_str + "' and name '" + window_name_str + "'");
        }

        return 0;
    }

    NTSTATUS handle_NtUserMoveWindow()
    {
        return 0;
    }

    NTSTATUS handle_NtUserGetProcessWindowStation()
    {
        return 0;
    }

    NTSTATUS handle_NtUserRegisterClassExWOW(const syscall_context& c, const emulator_pointer /*wnd_class_ex*/,
                                             const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> class_name,
                                             const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> /*class_version*/,
                                             const emulator_pointer /*class_menu_name*/, const DWORD /*function_id*/, const DWORD /*flags*/,
                                             const emulator_pointer /*wow*/)
    {
        uint16_t index = c.proc.add_or_find_atom(read_unicode_string(c.emu, class_name));
        return index;
    }

    NTSTATUS handle_NtUserUnregisterClass(const syscall_context& c, const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> class_name,
                                          const emulator_pointer /*instance*/, const emulator_pointer /*class_menu_name*/)
    {
        return c.proc.delete_atom(read_unicode_string(c.emu, class_name));
    }

    NTSTATUS handle_NtUserSetWindowsHookEx()
    {
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS handle_NtUserUnhookWindowsHookEx()
    {
        return STATUS_NOT_SUPPORTED;
    }

    std::u16string read_large_string(const emulator_object<LARGE_STRING> str_obj)
    {
        if (!str_obj)
        {
            return {};
        }

        const auto str = str_obj.read();
        if (!str.bAnsi)
        {
            return read_string<char16_t>(*str_obj.get_memory_interface(), str.Buffer, str.Length / 2);
        }

        const auto ansi_string = read_string<char>(*str_obj.get_memory_interface(), str.Buffer, str.Length);
        return u8_to_u16(ansi_string);
    }

    hwnd handle_NtUserCreateWindowEx(const syscall_context& c, const DWORD /*ex_style*/, const emulator_object<LARGE_STRING> class_name,
                                     const emulator_object<LARGE_STRING> /*cls_version*/, const emulator_object<LARGE_STRING> window_name,
                                     const DWORD /*style*/, const int x, const int y, const int width, const int height,
                                     const hwnd /*parent*/, const hmenu /*menu*/, const hinstance /*instance*/, const pointer /*l_param*/,
                                     const DWORD /*flags*/, const pointer /*acbi_buffer*/)
    {
        auto [handle, win] = c.proc.windows.create(c.win_emu.memory);
        win.x = x;
        win.y = y;
        win.width = width;
        win.height = height;
        win.thread_id = c.win_emu.current_thread().id;
        win.class_name = read_large_string(class_name);
        win.name = read_large_string(window_name);

        return handle.bits;
    }

    BOOL handle_NtUserDestroyWindow(const syscall_context& c, const hwnd window)
    {
        return c.proc.windows.erase(window);
    }

    BOOL handle_NtUserSetProp(const syscall_context& c, const hwnd window, const uint16_t atom, const uint64_t data)
    {
        auto* win = c.proc.windows.get(window);
        const auto* prop = c.proc.get_atom_name(atom);

        if (!win || !prop)
        {
            return FALSE;
        }

        win->props[*prop] = data;

        return TRUE;
    }

    BOOL handle_NtUserSetProp2(const syscall_context& c, const hwnd window,
                               const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> str, const uint64_t data)
    {
        auto* win = c.proc.windows.get(window);
        if (!win || !str)
        {
            return FALSE;
        }

        auto prop = read_unicode_string(c.emu, str);
        win->props[std::move(prop)] = data;

        return TRUE;
    }

    uint64_t handle_NtUserChangeWindowMessageFilterEx()
    {
        return 0;
    }

    BOOL handle_NtUserShowWindow(const syscall_context& c, const hwnd hwnd, const LONG cmd_show)
    {
        (void)c;
        (void)hwnd;
        (void)cmd_show;
        return TRUE;
    }

    BOOL handle_NtUserGetMessage(const syscall_context& c, const emulator_object<msg> message, const hwnd hwnd, const UINT msg_filter_min,
                                 const UINT msg_filter_max)
    {
        (void)c;
        (void)message;
        (void)hwnd;
        (void)msg_filter_min;
        (void)msg_filter_max;

        return TRUE;
    }

    BOOL handle_NtUserPeekMessage(const syscall_context& c, const emulator_object<msg> message, const hwnd hwnd, const UINT msg_filter_min,
                                  const UINT msg_filter_max, const UINT remove_message)
    {
        (void)c;
        (void)message;
        (void)hwnd;
        (void)msg_filter_min;
        (void)msg_filter_max;
        (void)remove_message;

        return FALSE;
    }

    NTSTATUS handle_NtUserEnumDisplayDevices(const syscall_context& c,
                                             const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> str_device, const DWORD dev_num,
                                             const emulator_object<EMU_DISPLAY_DEVICEW> display_device, const DWORD /*flags*/)
    {
        if (!str_device)
        {
            if (dev_num > 0)
            {
                return STATUS_UNSUCCESSFUL;
            }

            display_device.access([&](EMU_DISPLAY_DEVICEW& dev) {
                dev.StateFlags = 0x5; // DISPLAY_DEVICE_PRIMARY_DEVICE | DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
                utils::string::copy(dev.DeviceName, u"\\\\.\\DISPLAY1");
                utils::string::copy(dev.DeviceString, u"Emulated Virtual Adapter");
                utils::string::copy(dev.DeviceID, u"PCI\\VEN_10DE&DEV_0000&SUBSYS_00000000&REV_A1");
                utils::string::copy(dev.DeviceKey, u"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Video\\{00000001-"
                                                   u"0002-0003-0004-000000000005}\\0000");
            });
        }
        else
        {
            const auto dev_name = read_unicode_string(c.emu, str_device);

            if (dev_name != u"\\\\.\\DISPLAY1")
            {
                return STATUS_UNSUCCESSFUL;
            }

            if (dev_num > 0)
            {
                return STATUS_UNSUCCESSFUL;
            }

            display_device.access([&](EMU_DISPLAY_DEVICEW& dev) {
                dev.StateFlags = 0x1; // DISPLAY_DEVICE_ACTIVE
                utils::string::copy(dev.DeviceName, u"\\\\.\\DISPLAY1\\Monitor0");
                utils::string::copy(dev.DeviceString, u"Generic PnP Monitor");
                utils::string::copy(dev.DeviceID, u"MONITOR\\EMU1234\\{4d36e96e-e325-11ce-bfc1-08002be10318}\\0000");
                utils::string::copy(dev.DeviceKey, u"\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\DISPLAY\\EMU1234\\"
                                                   u"1&23a45b&0&UID67568640");
            });
        }

        return STATUS_SUCCESS;
    }

    NTSTATUS handle_NtUserEnumDisplaySettings(const syscall_context& c,
                                              const emulator_object<UNICODE_STRING<EmulatorTraits<Emu64>>> device_name,
                                              const DWORD mode_num, const emulator_object<EMU_DEVMODEW> dev_mode, const DWORD /*flags*/)
    {
        if (dev_mode && (mode_num == ENUM_CURRENT_SETTINGS || mode_num == 0))
        {
            const auto dev_name = read_unicode_string(c.emu, device_name);

            if (dev_name == u"\\\\.\\DISPLAY1")
            {
                dev_mode.access([](EMU_DEVMODEW& dm) {
                    dm.dmFields = 0x5C0000; // DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY
                    dm.dmPelsWidth = 1920;
                    dm.dmPelsHeight = 1080;
                    dm.dmBitsPerPel = 32;
                    dm.dmDisplayFrequency = 60;
                });

                return STATUS_SUCCESS;
            }
        }

        return STATUS_UNSUCCESSFUL;
    }

    BOOL handle_NtUserEnumDisplayMonitors(const syscall_context& c, const hdc hdc_in, const uint64_t clip_rect_ptr, const uint64_t callback,
                                          const uint64_t param)
    {
        if (!callback)
        {
            return FALSE;
        }

        const auto hmon = c.win_emu.process.default_monitor_handle.bits;
        const auto display_info = c.proc.user_handles.get_display_info().read();

        if (clip_rect_ptr)
        {
            RECT clip{};
            c.emu.read_memory(clip_rect_ptr, &clip, sizeof(clip));

            const emulator_object<USER_MONITOR> monitor_obj(c.emu, display_info.pPrimaryMonitor);
            const auto monitor = monitor_obj.read();

            auto effective_rc{monitor.rcMonitor};
            effective_rc.left = std::max(effective_rc.left, clip.left);
            effective_rc.top = std::max(effective_rc.top, clip.top);
            effective_rc.right = std::min(effective_rc.right, clip.right);
            effective_rc.bottom = std::min(effective_rc.bottom, clip.bottom);
            if (effective_rc.right <= effective_rc.left || effective_rc.bottom <= effective_rc.top)
            {
                return TRUE;
            }
        }

        const uint64_t rect_ptr = display_info.pPrimaryMonitor + offsetof(USER_MONITOR, rcMonitor);
        dispatch_user_callback(c, callback_id::NtUserEnumDisplayMonitors, callback, hmon, hdc_in, rect_ptr, param);
        return {};
    }

    BOOL completion_NtUserEnumDisplayMonitors(const syscall_context&, BOOL guest_result, const hdc /*hdc_in*/,
                                              const uint64_t /*clip_rect_ptr*/, const uint64_t /*callback*/, const uint64_t /*param*/)
    {
        return guest_result;
    }

    BOOL handle_NtUserGetHDevName(const syscall_context& c, handle hdev, emulator_pointer device_name)
    {
        if (hdev != c.proc.default_monitor_handle)
        {
            return FALSE;
        }

        const std::u16string name = u"\\\\.\\DISPLAY1";
        c.emu.write_memory(device_name, name.c_str(), (name.size() + 1) * sizeof(char16_t));

        return TRUE;
    }

    emulator_pointer handle_NtUserMapDesktopObject(const syscall_context& c, handle handle)
    {
        const auto index = handle.value.id;

        if (index == 0 || index >= user_handle_table::MAX_HANDLES)
        {
            return 0;
        }

        const auto handle_entry = c.proc.user_handles.get_handle_table().read(static_cast<size_t>(index));
        return handle_entry.pHead;
    }
}
