#include "compression.hpp"

#include <zstd.h>
#include <zlib.h>
#include <array>
#include <cstdint>
#include <cstring>

namespace utils::compression
{
    namespace zstd
    {
        std::vector<std::byte> decompress(const std::span<const std::byte> data)
        {
            const auto decompressed_size = ZSTD_getFrameContentSize(data.data(), data.size());

            if (decompressed_size == ZSTD_CONTENTSIZE_ERROR || decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN)
            {
                return {};
            }

            std::vector<std::byte> buffer(static_cast<size_t>(decompressed_size));

            const auto result = ZSTD_decompress(buffer.data(), buffer.size(), data.data(), data.size());

            if (ZSTD_isError(result))
            {
                return {};
            }

            return buffer;
        }

        std::vector<std::byte> compress(const std::span<const std::byte> data, const int compression_level)
        {
            const auto max_size = ZSTD_compressBound(data.size());
            std::vector<std::byte> result(max_size);

            const auto compressed_size = ZSTD_compress(result.data(), max_size, data.data(), data.size(), compression_level);

            if (ZSTD_isError(compressed_size))
            {
                return {};
            }

            result.resize(compressed_size);
            return result;
        }
    }

    namespace zlib
    {
        std::vector<std::byte> decompress(const std::span<const std::byte> data)
        {
            if (data.empty())
            {
                return {};
            }

            z_stream stream{};
            stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(data.data()));
            stream.avail_in = static_cast<uInt>(data.size());

            if (inflateInit(&stream) != Z_OK)
            {
                return {};
            }

            std::vector<std::byte> output{};
            output.reserve(data.size() * 4);

            constexpr size_t chunk_size = 64 * 1024;
            int status = Z_OK;

            while (status == Z_OK)
            {
                const auto previous_size = output.size();
                output.resize(previous_size + chunk_size);

                stream.next_out = reinterpret_cast<Bytef*>(output.data() + previous_size);
                stream.avail_out = static_cast<uInt>(chunk_size);

                status = inflate(&stream, Z_NO_FLUSH);
                if (status != Z_OK && status != Z_STREAM_END)
                {
                    inflateEnd(&stream);
                    return {};
                }

                output.resize(previous_size + (chunk_size - stream.avail_out));
            }

            inflateEnd(&stream);
            return output;
        }
    }
}
