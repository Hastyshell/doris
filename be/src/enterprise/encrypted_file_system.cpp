// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "enterprise/encrypted_file_system.h"

#include <gen_cpp/olap_file.pb.h>
#include <glog/logging.h>

#include <cstddef>
#include <cstdint>
#include <memory>

#include "common/status.h"
#include "enterprise/encrypted_file_reader.h"
#include "enterprise/encrypted_file_writer.h"
#include "enterprise/encryption_common.h"
#include "io/fs/file_reader.h"
#include "io/fs/file_reader_writer_fwd.h"
#include "util/coding.h"

namespace doris::io {

// info_pb_len(uint32_t) + version(uint8_t) + magic_code(uint64_t)
constexpr uint64_t footer_info_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint64_t);

Status EncryptedFileSystem::create_file_impl(const Path& file, FileWriterPtr* writer,
                                             const FileWriterOptions* opts) {
    auto maybe_encryption_info = io::EncryptionInfo::create(_algorithm);
    if (!maybe_encryption_info) {
        return Status::InternalError("create encryption info error: {}",
                                     maybe_encryption_info.error());
    }
    auto encryption_info = std::move(maybe_encryption_info.value());

    switch (encryption_info->data_key->algorithm()) {
    case EncryptionAlgorithmPB::AES_256_CTR:
    case EncryptionAlgorithmPB::SM4_128_CTR:
        break;
    default:
        return Status::InvalidArgument(
                "Invalid encryption mode {}, only support AES_256_CTR or SM4_128_CTR for now",
                encryption_info->data_key->algorithm());
    }

    RETURN_IF_ERROR(_fs_inner->create_file(file, writer, opts));
    *writer = std::make_unique<EncryptedFileWriter>(std::move(*writer), std::move(encryption_info));
    return Status::OK();
}

Result<FileEncryptionInfoPB> parse_footer(const Slice footer) {
    Slice magic_code_slice(footer.data + (footer.size - sizeof(uint64)), sizeof(uint64_t));
    auto magic_code = decode_fixed64_le(reinterpret_cast<uint8_t*>(magic_code_slice.data));
    if (magic_code != MAGIC_CODE) {
        return ResultError(
                Status::Corruption("Wrong magic code: {}, not a doris encrypted file", magic_code));
    }

    // ignore version field
    Slice info_len_slice(magic_code_slice.data - sizeof(uint8_t) - sizeof(uint32_t),
                         sizeof(uint32_t));
    auto info_pb_len = decode_fixed32_le(reinterpret_cast<uint8_t*>(info_len_slice.data));
    Slice info_pb_slice(footer.data, info_pb_len);
    FileEncryptionInfoPB info_pb;
    if (!info_pb.ParseFromArray(info_pb_slice.data, info_pb_slice.size)) {
        return ResultError(Status::Corruption("parse encryption info failed"));
    }
    return info_pb;
}

Status open_file_with_file_size(FileSystem* fs_inner, const Path& file, FileReaderSPtr* reader,
                                const FileReaderOptions* opts) {
    DCHECK_NE(opts, nullptr);
    DCHECK_NE(opts->file_size, -1);

    FileReaderOptions tmp_opts = *opts;
    tmp_opts.file_size = opts->file_size + sizeof(uint64_t);
    FileReaderSPtr tmp_reader;
    RETURN_IF_ERROR(fs_inner->open_file(file, &tmp_reader, &tmp_opts));
    Defer defer {[&tmp_reader]() {
        auto st = tmp_reader->close();
        LOG(WARNING) << "Close tmp reader failure=" << st;
    }};

    uint8_t footer_len_buf[sizeof(uint64_t)];
    Slice footer_len_slice(footer_len_buf, sizeof(uint64_t));
    size_t bytes_read;
    IOContext dummy_io_cyx;
    LOG(INFO) << "===> read footer length: origin file_size=" << opts->file_size;
    RETURN_IF_ERROR(
            tmp_reader->read_at(opts->file_size, footer_len_slice, &bytes_read, &dummy_io_cyx));
    if (bytes_read < sizeof(uint64_t)) {
        return Status::Corruption("Insufficient bytes to read footer length field, bytes_read={}",
                                  bytes_read);
    }

    auto footer_len = decode_fixed64_le(footer_len_buf);
    if (footer_len < footer_info_len) {
        return Status::Corruption("Insufficient bytes to reader footer, footer_len={}", footer_len);
    }

    tmp_opts.file_size += footer_len;
    int64_t fsize;
    RETURN_IF_ERROR(fs_inner->file_size(file, &fsize));
    LOG(INFO) << "===> assume file_size=" << tmp_opts.file_size << ", real file_size=" << fsize;
    RETURN_IF_ERROR(fs_inner->open_file(file, reader, &tmp_opts));

    auto reader_inner = *reader;
    std::vector<uint8_t> footer_buf(footer_len);
    Slice footer(footer_buf.data(), footer_len);
    LOG(INFO) << "===> footer offset=" << tmp_opts.file_size - footer_len
              << ", footer length=" << footer_len;
    RETURN_IF_ERROR(reader_inner->read_at(tmp_opts.file_size - footer_len, footer, &bytes_read,
                                          &dummy_io_cyx));
    if (bytes_read != footer_len) {
        return Status::Corruption("Insufficient bytes for footer, bytes_read={}, footer_len={}",
                                  bytes_read, footer_len);
    }

    auto info_pb = DORIS_TRY(parse_footer(footer));
    auto encryption_info = DORIS_TRY(EncryptionInfo::load(info_pb));
    *reader = std::make_shared<EncryptedFileReader>(std::move(reader_inner),
                                                    std::move(encryption_info), opts->file_size);

    return Status::OK();
}

Status open_file_normal(FileSystem* fs_inner, const Path& file, FileReaderSPtr* reader,
                        const FileReaderOptions* opts) {
    RETURN_IF_ERROR(fs_inner->open_file(file, reader, opts));
    IOContext dummy_io_cyx;
    auto reader_inner = *reader;
    auto file_size = reader_inner->size();
    std::vector<uint8_t> footer_info_buf(footer_info_len);
    Slice footer_info_slice(footer_info_buf.data(), footer_info_len);
    size_t bytes_read;
    RETURN_IF_ERROR(reader_inner->read_at(file_size - footer_info_len, footer_info_slice,
                                          &bytes_read, &dummy_io_cyx));
    if (bytes_read != footer_info_len) {
        return Status::Corruption(
                "Insufficient bytes to parse magic code, version and pb length, bytes_read={}, "
                "expect={}",
                bytes_read, footer_info_len);
    }
    Slice magic_code_slice(footer_info_slice.data + sizeof(uint32) + sizeof(uint8_t),
                           sizeof(uint64_t));
    auto magic_code = decode_fixed64_le(reinterpret_cast<uint8_t*>(magic_code_slice.data));
    if (magic_code != MAGIC_CODE) {
        return Status::Corruption("Wrong magic code: {}, not a doris encrypted file", magic_code);
    }
    Slice info_len_slice(footer_info_slice.data, sizeof(uint32_t));
    auto info_pb_len = decode_fixed32_le(reinterpret_cast<uint8_t*>(info_len_slice.data));

    std::vector<uint8_t> info_pb_buf(info_pb_len);
    Slice info_pb_slice(info_pb_buf.data(), info_pb_len);
    RETURN_IF_ERROR(reader_inner->read_at(file_size - footer_info_len - info_pb_len, info_pb_slice,
                                          &bytes_read, &dummy_io_cyx));
    if (bytes_read != info_pb_len) {
        return Status::Corruption("Insufficient bytes for info pb, bytes_read={}, expect={}",
                                  bytes_read, info_pb_len);
    }
    FileEncryptionInfoPB info_pb;
    if (!info_pb.ParseFromArray(info_pb_slice.data, info_pb_slice.size)) {
        return Status::Corruption("parse encryption info failed");
    }

    auto encryption_info = DORIS_TRY(EncryptionInfo::load(info_pb));
    *reader = std::make_shared<EncryptedFileReader>(
            std::move(reader_inner), std::move(encryption_info),
            file_size - (sizeof(uint64_t) + info_pb_len + sizeof(uint32_t) + sizeof(uint8_t) +
                         sizeof(uint64_t)));
    return Status::OK();
}

Status EncryptedFileSystem::open_file_impl(const Path& file, FileReaderSPtr* reader,
                                           const FileReaderOptions* opts) {
    if (opts != nullptr && opts->file_size != -1) {
        LOG(INFO) << "===> open file with size, path=" << file.string()
                  << ", origin fsize=" << opts->file_size;
        return open_file_with_file_size(_fs_inner.get(), file, reader, opts);
    }
    LOG(INFO) << "===> open file normal, path=" << file.string();
    return open_file_normal(_fs_inner.get(), file, reader, opts);
}

Status EncryptedFileSystem::create_directory_impl(const Path& dir, bool failed_if_exists) {
    return _fs_inner->create_directory(dir, failed_if_exists);
}

Status EncryptedFileSystem::delete_file_impl(const Path& file) {
    return _fs_inner->delete_file(file);
}

Status EncryptedFileSystem::delete_directory_impl(const Path& dir) {
    return _fs_inner->delete_directory(dir);
}

Status EncryptedFileSystem::batch_delete_impl(const std::vector<Path>& files) {
    return _fs_inner->batch_delete(files);
}

Status EncryptedFileSystem::exists_impl(const Path& path, bool* res) const {
    return _fs_inner->exists(path, res);
}

Status EncryptedFileSystem::file_size_impl(const Path& file, int64_t* file_size) const {
    return _fs_inner->file_size(file, file_size);
}

Status EncryptedFileSystem::list_impl(const Path& dir, bool only_file, std::vector<FileInfo>* files,
                                      bool* exists) {
    return _fs_inner->list(dir, only_file, files, exists);
}

Status EncryptedFileSystem::rename_impl(const Path& orig_name, const Path& new_name) {
    return _fs_inner->rename(orig_name, new_name);
}

Status EncryptedFileSystem::absolute_path(const Path& path, Path& abs_path) const {
    abs_path = path;
    return Status::OK();
}

} // namespace doris::io
