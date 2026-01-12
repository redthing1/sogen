#pragma once

#include <cstdint>

#include "emulator/serialization.hpp"

struct win32k_shared_state
{
    uint64_t gpsi_address{0};
    uint32_t gpsi_size{0};
    uint64_t shared_info_address{0};
    uint64_t handle_table_address{0};
    uint32_t handle_entry_size{0};
    uint32_t handle_entry_count{0};
    uint64_t monitor_info_address{0};
    uint64_t msg_bits_address{0};
    uint32_t msg_count{0};
    uint64_t ime_msg_bits_address{0};
    uint32_t ime_msg_count{0};
    uint64_t shared_delta{0};

    void serialize(utils::buffer_serializer& buffer) const
    {
        buffer.write(this->gpsi_address);
        buffer.write(this->gpsi_size);
        buffer.write(this->shared_info_address);
        buffer.write(this->handle_table_address);
        buffer.write(this->handle_entry_size);
        buffer.write(this->handle_entry_count);
        buffer.write(this->monitor_info_address);
        buffer.write(this->msg_bits_address);
        buffer.write(this->msg_count);
        buffer.write(this->ime_msg_bits_address);
        buffer.write(this->ime_msg_count);
        buffer.write(this->shared_delta);
    }

    void deserialize(utils::buffer_deserializer& buffer)
    {
        buffer.read(this->gpsi_address);
        buffer.read(this->gpsi_size);
        buffer.read(this->shared_info_address);
        buffer.read(this->handle_table_address);
        buffer.read(this->handle_entry_size);
        buffer.read(this->handle_entry_count);
        buffer.read(this->monitor_info_address);
        buffer.read(this->msg_bits_address);
        buffer.read(this->msg_count);
        buffer.read(this->ime_msg_bits_address);
        buffer.read(this->ime_msg_count);
        buffer.read(this->shared_delta);
    }
};
