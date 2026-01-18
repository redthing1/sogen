#pragma once

#include <cstdio>
#include <type_traits>

namespace utils
{
    class file_handle
    {
      public:
        struct rename_information
        {
            std::filesystem::path old_filepath;
            std::filesystem::path new_filepath;

            void serialize(utils::buffer_serializer& buffer) const
            {
                buffer.write(this->old_filepath.u16string());
                buffer.write(this->new_filepath.u16string());
            }

            void deserialize(utils::buffer_deserializer& buffer)
            {
                this->old_filepath = buffer.read<std::u16string>();
                this->new_filepath = buffer.read<std::u16string>();
            }
        };

        file_handle() = default;

        file_handle(FILE* file)
            : file_(file)
        {
        }

        ~file_handle()
        {
            this->release();
        }

        file_handle(const file_handle&) = delete;
        file_handle& operator=(const file_handle&) = delete;

        file_handle(file_handle&& obj) noexcept
            : file_handle()
        {
            this->operator=(std::move(obj));
        }

        file_handle& operator=(file_handle&& obj) noexcept
        {
            if (this != &obj)
            {
                this->release();
                this->file_ = obj.file_;
                obj.file_ = {};
            }

            return *this;
        }

        file_handle& operator=(FILE* file) noexcept
        {
            this->release();
            this->file_ = file;

            return *this;
        }

        [[nodiscard]] operator bool() const
        {
            return this->file_;
        }

        [[nodiscard]] operator FILE*() const
        {
            return this->file_;
        }

        [[nodiscard]] int64_t size() const
        {
            const auto current_position = this->tell();

            this->seek_to(0, SEEK_END);
            const auto size = this->tell();
            this->seek_to(current_position);

            return size;
        }

        bool seek_to(const int64_t position, const int origin = SEEK_SET) const
        {
            return _fseeki64(this->file_, position, origin) == 0;
        }

        [[nodiscard]] int64_t tell() const
        {
            return _ftelli64(this->file_);
        }

        void defer_rename(std::filesystem::path oldname, std::filesystem::path newname)
        {
            deferred_rename_ = {.old_filepath = std::move(oldname), .new_filepath = std::move(newname)};
        }

        void serialize(utils::buffer_serializer& buffer) const
        {
            buffer.write(this->tell());
            buffer.write_optional(this->deferred_rename_);
        }

        void deserialize(utils::buffer_deserializer& buffer)
        {
            int64_t position = 0;
            buffer.read(position);

            if (!this->seek_to(position))
            {
                throw std::runtime_error("Failed to seek to serialized file position");
            }

            buffer.read_optional(this->deferred_rename_);
        }

      private:
        FILE* file_{};
        std::optional<rename_information> deferred_rename_;

        void release()
        {
            if (this->file_)
            {
                (void)fclose(this->file_);
                this->file_ = {};
            }

            if (this->deferred_rename_)
            {
                std::error_code ec{};
                std::filesystem::rename(this->deferred_rename_->old_filepath, this->deferred_rename_->new_filepath, ec);
                this->deferred_rename_ = {};
            }
        }
    };
}
