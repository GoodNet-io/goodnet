// SPDX-License-Identifier: Apache-2.0
#include "log_config.hpp"

#include <core/config/config.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace gn::core::util {

gn::log::LogConfig load_log_config(const gn::core::Config& cfg) {
    gn::log::LogConfig lc;
    {
        std::string s;
        if (cfg.get_string("log.level", s) == GN_OK) {
            lc.level = std::move(s);
        }
        if (cfg.get_string("log.console_level", s) == GN_OK) {
            lc.console_level = std::move(s);
        }
        if (cfg.get_string("log.file", s) == GN_OK) {
            lc.log_file = std::move(s);
        }
        if (cfg.get_string("log.project_root", s) == GN_OK) {
            lc.project_root = std::move(s);
        }
        if (cfg.get_string("log.console_pattern", s) == GN_OK) {
            lc.console_pattern = std::move(s);
        }
        if (cfg.get_string("log.file_pattern", s) == GN_OK) {
            lc.file_pattern = std::move(s);
        }
    }
    {
        std::int64_t i = 0;
        if (cfg.get_int64("log.max_size", i) == GN_OK && i > 0) {
            lc.max_size = static_cast<std::size_t>(i);
        }
        if (cfg.get_int64("log.max_files", i) == GN_OK && i > 0) {
            lc.max_files = static_cast<int>(i);
        }
        if (cfg.get_int64("log.source_detail_mode", i) == GN_OK
            && i >= 0 && i <= 3) {
            lc.source_detail = static_cast<gn::log::SourceDetail>(i);
        }
    }
    {
        bool b = false;
        if (cfg.get_bool("log.strip_extension", b) == GN_OK) {
            lc.strip_extension = b;
        }
    }
    return lc;
}

}  // namespace gn::core::util
