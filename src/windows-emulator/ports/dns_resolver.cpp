#include "../std_include.hpp"
#include "dns_resolver.hpp"

#include "binary_writer.hpp"
#include "../windows_emulator.hpp"

#define DNS_TYPE_A     0x01
#define DNS_TYPE_CNAME 0x05
#define DNS_TYPE_AAAA  0x1C

#ifndef OS_WINDOWS
#define ERROR_SUCCESS              0x0
#define DNS_ERROR_RCODE_NAME_ERROR 0x232B
#endif

namespace
{
    using IP4_ADDRESS = DWORD;

    struct DNS_A_DATA
    {
        IP4_ADDRESS IpAddress;
    };

    struct IP6_ADDRESS
    {
        std::array<uint64_t, 2> IP6Qword;
    };

    struct DNS_AAAA_DATA
    {
        IP6_ADDRESS Ip6Address;
    };

    template <typename Traits>
    struct DNS_RECORDW
    {
        EMULATOR_CAST(Traits::PVOID, DNS_RECORDW*) pNext;
        EMULATOR_CAST(Traits::PVOID, const char16_t*) pName;
        WORD wType;
        WORD wDataLength;
        DWORD Flags;
        DWORD dwTtl;
        DWORD dwReserved;
        union
        {
            DNS_A_DATA A;
            DNS_AAAA_DATA AAAA;
        } Data;

        void write(utils::aligned_binary_writer<Traits>& writer) const
        {
            writer.write_ndr_pointer(this->pNext);
            writer.write_ndr_pointer(this->pName);
            writer.write(this->wType);
            writer.write(this->wDataLength);
            writer.write(this->Flags);
            writer.write(this->dwTtl);
            writer.write(this->dwReserved);

            writer.write(this->wType); // union identifier
            writer.write(&this->Data, this->wDataLength, sizeof(typename Traits::PVOID));

            writer.write_ndr_u16string(reinterpret_cast<const char16_t*>(this->pName));
        }
    };
    static_assert(sizeof(DNS_RECORDW<EmulatorTraits<Emu64>>) == 48);

    template <typename Traits>
    struct DNS_QUERY_RESPONSE
    {
        std::optional<DNS_RECORDW<Traits>> dns_record;
        uint64_t error_code{};

        void write(utils::aligned_binary_writer<Traits>& writer) const
        {
            // NOTE: The response is pretty much just an array of DNS_RECORD, marshalled using NDR64.
            if (!this->dns_record)
            {
                writer.write_ndr_pointer(false);
            }
            else
            {
                writer.write_ndr_pointer(true);
                writer.write(*this->dns_record);
            }

            writer.align_to(sizeof(typename Traits::PVOID));
            writer.pad(24);
            writer.write(error_code);
            writer.pad(64);
        }
    };

    WORD convert_socket_famity_to_dns_type(const int family)
    {
        switch (family)
        {
        case AF_INET:
            return DNS_TYPE_A;
        case AF_INET6:
            return DNS_TYPE_AAAA;
        default:
            throw std::runtime_error("Unexpected DNS type!");
        }
    }

    template <typename Traits>
    std::optional<DNS_RECORDW<Traits>> resolve_host_address(const std::u16string& host, const WORD dns_type)
    {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;

        DNS_RECORDW<Traits> result{};
        result.pName = reinterpret_cast<Traits::PVOID>(host.c_str());
        result.Flags = 0x2009;
        result.dwTtl = 0x708;

        addrinfo* res = nullptr;
        int status = getaddrinfo(u16_to_u8(host).c_str(), nullptr, &hints, &res);
        if (status == 0)
        {
            for (addrinfo* p = res; p != nullptr && dns_type != result.wType; p = p->ai_next)
            {
                if (p->ai_family == AF_INET)
                {
                    auto* ipv4 = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                    memset(&result.Data, 0, 16);
                    memcpy(&result.Data, &ipv4->sin_addr, sizeof(ipv4->sin_addr));
                    result.wDataLength = sizeof(ipv4->sin_addr);
                }
                else if (p->ai_family == AF_INET6)
                {
                    auto* ipv6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
                    memset(&result.Data, 0, 16);
                    memcpy(&result.Data, &ipv6->sin6_addr, sizeof(ipv6->sin6_addr));
                    result.wDataLength = sizeof(ipv6->sin6_addr);
                }
                else
                {
                    continue;
                }
                result.wType = convert_socket_famity_to_dns_type(p->ai_family);
            }

            freeaddrinfo(res);
        }

        if (result.wType == DNS_TYPE_A && dns_type == DNS_TYPE_AAAA)
        {
            auto* addr = reinterpret_cast<uint8_t*>(&result.Data);
            addr[10] = 0xff;
            addr[11] = 0xff;
            memcpy(addr + 12, addr, 4);
            memset(addr, 0, 10);
            result.wType = DNS_TYPE_AAAA;
        }

        if (result.wType != dns_type || result.wType == 0)
        {
            return {};
        }

        return result;
    }

    struct dns_resolver : rpc_port
    {
        NTSTATUS handle_rpc(windows_emulator& win_emu, const uint32_t procedure_id, const lpc_request_context& c) override
        {
            std::array<uint8_t, 8> request_cookie;
            win_emu.emu().read_memory(c.send_buffer + c.send_buffer_length - 8, request_cookie.data(), request_cookie.size());

            utils::aligned_binary_writer<EmulatorTraits<Emu64>> writer(win_emu.emu(), c.recv_buffer);
            writer.write(request_cookie);

            switch (procedure_id)
            {
            case 2:
                handle_dns_query(win_emu, c, writer);
                break;
            case 3:
                return STATUS_NOT_SUPPORTED;
            default:
                throw std::runtime_error("Unimplemented procedure!");
            }

            return STATUS_SUCCESS;
        }

        template <typename Traits>
        static void handle_dns_query(windows_emulator& win_emu, const lpc_request_context& c, utils::aligned_binary_writer<Traits>& writer)
        {
            auto& emu = win_emu.emu();

            const auto hostname_length = static_cast<size_t>(emu.read_memory<uint64_t>(c.send_buffer + 0x08));
            const auto hostname_offset = c.send_buffer + 0x20;

            std::u16string hostname;
            hostname.resize(hostname_length - 1);
            emu.read_memory(hostname_offset, hostname.data(), (hostname_length - 1) * sizeof(char16_t));

            const auto query_type = emu.read_memory<uint16_t>(hostname_offset + hostname_length * sizeof(char16_t));

            if (query_type != DNS_TYPE_A && query_type != DNS_TYPE_AAAA)
            {
                throw std::runtime_error("Unexpected DNS query type!");
            }

            win_emu.callbacks.on_generic_activity("DNS query: " + u16_to_u8(hostname));

            DNS_QUERY_RESPONSE<Traits> response{};
            response.dns_record = resolve_host_address<Traits>(hostname, query_type);
            response.error_code = response.dns_record ? ERROR_SUCCESS : DNS_ERROR_RCODE_NAME_ERROR;
            writer.write(response);

            c.recv_buffer_length = static_cast<ULONG>(writer.offset());
        }
    };
}

std::unique_ptr<port> create_dns_resolver()
{
    return std::make_unique<dns_resolver>();
}
