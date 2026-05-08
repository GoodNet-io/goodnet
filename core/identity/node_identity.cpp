/// @file   core/identity/node_identity.cpp
/// @brief  Aggregated node identity construction + on-disk format.
///
/// On-disk layout (variable length):
///   0  4   magic   = "GNID"
///   4  1   version = 0x01
///   5  1   flags   = reserved 0
///   6  8   expiry_unix_ts (BE64)
///  14 32   user_seed
///  46 32   device_seed
///  78 8    rotation_counter (BE64)
///  86 2    sub_key_count (BE16)
///  88 ..   sub_keys[]: each {purpose[1] || seed[32] ||
///                            label_len[1] || label[label_len] ||
///                            created_ts[8]}
///  ..  2   rotation_history_count (BE16)
///  ..  ..  rotation_history[]: each RotationEntry serialised
///                                (32+32+8+8+64 = 144 bytes)

#include "node_identity.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <core/util/log.hpp>

namespace gn::core::identity {

namespace {

constexpr std::array<char, 4>  kMagic{'G', 'N', 'I', 'D'};
constexpr std::uint8_t         kVersion   = 1;
constexpr std::size_t          kSeedBytes = kEd25519SeedBytes;

void encode_be16(std::uint16_t value, std::uint8_t* out) noexcept {
    out[0] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    out[1] = static_cast<std::uint8_t>( value       & 0xFFu);
}

[[nodiscard]] std::uint16_t decode_be16(const std::uint8_t* in) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[0]) << 8)
                                       | static_cast<std::uint16_t>(in[1]));
}

void encode_be64(std::int64_t value, std::uint8_t* out) noexcept {
    const auto u = static_cast<std::uint64_t>(value);
    out[0] = static_cast<std::uint8_t>((u >> 56) & 0xFFu);
    out[1] = static_cast<std::uint8_t>((u >> 48) & 0xFFu);
    out[2] = static_cast<std::uint8_t>((u >> 40) & 0xFFu);
    out[3] = static_cast<std::uint8_t>((u >> 32) & 0xFFu);
    out[4] = static_cast<std::uint8_t>((u >> 24) & 0xFFu);
    out[5] = static_cast<std::uint8_t>((u >> 16) & 0xFFu);
    out[6] = static_cast<std::uint8_t>((u >>  8) & 0xFFu);
    out[7] = static_cast<std::uint8_t>( u        & 0xFFu);
}

[[nodiscard]] std::int64_t decode_be64(const std::uint8_t* in) noexcept {
    std::uint64_t u = 0;
    u |= static_cast<std::uint64_t>(in[0]) << 56;
    u |= static_cast<std::uint64_t>(in[1]) << 48;
    u |= static_cast<std::uint64_t>(in[2]) << 40;
    u |= static_cast<std::uint64_t>(in[3]) << 32;
    u |= static_cast<std::uint64_t>(in[4]) << 24;
    u |= static_cast<std::uint64_t>(in[5]) << 16;
    u |= static_cast<std::uint64_t>(in[6]) <<  8;
    u |= static_cast<std::uint64_t>(in[7]);
    return static_cast<std::int64_t>(u);
}

void copy_seed_out(const KeyPair& kp,
                    std::span<std::uint8_t, kSeedBytes> dst) noexcept {
    const auto sk_view = kp.secret_key_view();
    std::memcpy(dst.data(), sk_view.data(), kSeedBytes);
}

[[nodiscard]] std::vector<std::uint8_t>
serialise(const NodeIdentity& self) {
    /// Pre-size: header 88 + sub_keys + rotation history.
    const auto& subs   = self.sub_keys().entries();
    const auto& rots   = self.rotation_history();
    std::size_t need = 88;
    for (const auto& e : subs) {
        need += 1 + kSeedBytes + 1 + e.label.size() + 8;
    }
    need += 2;  // rotation_history_count
    need += rots.size() * (32 + 32 + 8 + 8 + 64);

    std::vector<std::uint8_t> buf(need);
    std::size_t off = 0;
    std::memcpy(buf.data() + off, kMagic.data(), kMagic.size());
    off += kMagic.size();
    buf[off++] = kVersion;
    buf[off++] = 0;  // flags reserved
    encode_be64(self.attestation().expiry_unix_ts, buf.data() + off);
    off += 8;
    copy_seed_out(self.user(),   std::span<std::uint8_t, kSeedBytes>{buf.data() + off, kSeedBytes});
    off += kSeedBytes;
    copy_seed_out(self.device(), std::span<std::uint8_t, kSeedBytes>{buf.data() + off, kSeedBytes});
    off += kSeedBytes;
    encode_be64(static_cast<std::int64_t>(self.rotation_counter()),
                buf.data() + off);
    off += 8;
    encode_be16(static_cast<std::uint16_t>(subs.size()), buf.data() + off);
    off += 2;
    for (const auto& e : subs) {
        buf[off++] = static_cast<std::uint8_t>(e.purpose);
        const auto sk = e.kp.secret_key_view();
        std::memcpy(buf.data() + off, sk.data(), kSeedBytes);
        off += kSeedBytes;
        const auto label_len =
            std::min<std::size_t>(e.label.size(), 255);
        buf[off++] = static_cast<std::uint8_t>(label_len);
        std::memcpy(buf.data() + off, e.label.data(), label_len);
        off += label_len;
        encode_be64(e.created_unix_ts, buf.data() + off);
        off += 8;
    }
    encode_be16(static_cast<std::uint16_t>(rots.size()), buf.data() + off);
    off += 2;
    for (const auto& r : rots) {
        std::memcpy(buf.data() + off, r.prev_user_pk.data(), GN_PUBLIC_KEY_BYTES);
        off += GN_PUBLIC_KEY_BYTES;
        std::memcpy(buf.data() + off, r.next_user_pk.data(), GN_PUBLIC_KEY_BYTES);
        off += GN_PUBLIC_KEY_BYTES;
        encode_be64(static_cast<std::int64_t>(r.counter), buf.data() + off);
        off += 8;
        encode_be64(r.valid_from_unix_ts, buf.data() + off);
        off += 8;
        std::memcpy(buf.data() + off, r.sig_by_prev.data(), 64);
        off += 64;
    }
    buf.resize(off);
    return buf;
}

[[nodiscard]] ::gn::Result<NodeIdentity>
parse(std::span<const std::uint8_t> buf) {
    if (buf.size() < 88) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "identity: short header"});
    }
    /// magic + version + flags already gate-verified by caller.
    std::size_t off = 6;
    const auto expiry = decode_be64(buf.data() + off);
    off += 8;

    std::span<const std::uint8_t, kSeedBytes> user_seed{
        buf.data() + off, kSeedBytes};
    off += kSeedBytes;
    std::span<const std::uint8_t, kSeedBytes> device_seed{
        buf.data() + off, kSeedBytes};
    off += kSeedBytes;
    const auto rotation_counter =
        static_cast<std::uint64_t>(decode_be64(buf.data() + off));
    off += 8;
    const auto sub_count = decode_be16(buf.data() + off);
    off += 2;

    auto user_kp = KeyPair::from_seed(user_seed);
    if (!user_kp) return std::unexpected(user_kp.error());
    auto device_kp = KeyPair::from_seed(device_seed);
    if (!device_kp) return std::unexpected(device_kp.error());

    auto identity = NodeIdentity::compose(std::move(*user_kp),
                                           std::move(*device_kp),
                                           expiry);
    if (!identity) return std::unexpected(identity.error());

    /// Sub-keys.
    auto& reg = identity->sub_keys().entries_mut();
    reg.reserve(sub_count);
    for (std::uint16_t i = 0; i < sub_count; ++i) {
        if (off + 1 + kSeedBytes + 1 > buf.size()) {
            return std::unexpected(::gn::Error{
                GN_ERR_INTEGRITY_FAILED, "identity: sub-key truncated header"});
        }
        const auto purpose =
            static_cast<gn_key_purpose_t>(buf[off]);
        off += 1;
        std::span<const std::uint8_t, kSeedBytes> seed{
            buf.data() + off, kSeedBytes};
        off += kSeedBytes;
        const auto label_len = buf[off];
        off += 1;
        if (off + label_len + 8 > buf.size()) {
            return std::unexpected(::gn::Error{
                GN_ERR_INTEGRITY_FAILED, "identity: sub-key truncated payload"});
        }
        std::string label(reinterpret_cast<const char*>(buf.data() + off),
                           label_len);
        off += label_len;
        const auto created = decode_be64(buf.data() + off);
        off += 8;
        auto kp = KeyPair::from_seed(seed);
        if (!kp) return std::unexpected(kp.error());

        SubKeyEntry e;
        e.id              = encode_key_id(purpose, i + 1);
        e.purpose         = purpose;
        e.kp              = std::move(*kp);
        e.label           = std::move(label);
        e.created_unix_ts = created;
        reg.push_back(std::move(e));
    }

    if (off + 2 > buf.size()) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "identity: missing rotation_history_count"});
    }
    const auto rot_count = decode_be16(buf.data() + off);
    off += 2;
    for (std::uint16_t i = 0; i < rot_count; ++i) {
        if (off + 144 > buf.size()) {
            return std::unexpected(::gn::Error{
                GN_ERR_INTEGRITY_FAILED, "identity: rotation entry truncated"});
        }
        RotationEntry r;
        std::memcpy(r.prev_user_pk.data(), buf.data() + off, GN_PUBLIC_KEY_BYTES);
        off += GN_PUBLIC_KEY_BYTES;
        std::memcpy(r.next_user_pk.data(), buf.data() + off, GN_PUBLIC_KEY_BYTES);
        off += GN_PUBLIC_KEY_BYTES;
        r.counter            = static_cast<std::uint64_t>(decode_be64(buf.data() + off));
        off += 8;
        r.valid_from_unix_ts = decode_be64(buf.data() + off);
        off += 8;
        std::memcpy(r.sig_by_prev.data(), buf.data() + off, 64);
        off += 64;
        identity->push_rotation_history(r);
    }

    /// Rotation counter — written after compose so it sticks
    /// regardless of the per-call attestation reset.
    while (identity->rotation_counter() < rotation_counter) {
        identity->bump_rotation_counter();
    }
    return identity;
}

}  // namespace

::gn::Result<NodeIdentity> NodeIdentity::generate(std::int64_t expiry_unix_ts) {
    auto user_kp = KeyPair::generate();
    if (!user_kp) return std::unexpected(user_kp.error());

    auto device_kp = KeyPair::generate();
    if (!device_kp) return std::unexpected(device_kp.error());

    return compose(std::move(*user_kp), std::move(*device_kp),
                   expiry_unix_ts);
}

::gn::Result<NodeIdentity> NodeIdentity::compose(
    KeyPair&& user, KeyPair&& device, std::int64_t expiry_unix_ts) {

    NodeIdentity out;
    out.user_   = std::move(user);
    out.device_ = std::move(device);

    auto att = Attestation::create(out.user_, out.device_.public_key(),
                                    expiry_unix_ts);
    if (!att) return std::unexpected(att.error());
    out.att_ = *att;

    out.address_ = derive_address(out.device_.public_key());
    return out;
}

::gn::Result<void>
NodeIdentity::save_to_file(const NodeIdentity& self, const std::string& path) {
    if (path.empty()) {
        return std::unexpected(::gn::Error{
            GN_ERR_NULL_ARG, "save_to_file: empty path"});
    }
    if (!self.user_.has_secret() || !self.device_.has_secret()) {
        return std::unexpected(::gn::Error{
            GN_ERR_INVALID_STATE,
            "save_to_file: keypairs were wiped — nothing to persist"});
    }

    const auto buf = serialise(self);

    /// Open with O_EXCL; refuse to clobber. Mode 0600 keeps the
    /// secret seed unreadable by other host users.
    const int fd = ::open(path.c_str(),
                           O_CREAT | O_WRONLY | O_TRUNC | O_EXCL,
                           S_IRUSR | S_IWUSR);
    if (fd < 0) {
        const int err = errno;
        gn::log::warn("identity.save: open({}): {}",
                       path, std::strerror(err));
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY,
            "save_to_file: could not create file (exists?)"});
    }
    const auto written = ::write(fd, buf.data(), buf.size());
    const int  write_err = errno;
    if (::close(fd) != 0) {
        gn::log::warn("identity.save: close({}): {}",
                       path, std::strerror(errno));
    }
    if (written != static_cast<ssize_t>(buf.size())) {
        ::unlink(path.c_str());
        gn::log::warn("identity.save: short write ({} of {}): {}",
                       written, buf.size(), std::strerror(write_err));
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY,
            "save_to_file: short write to disk"});
    }
    return {};
}

::gn::Result<NodeIdentity> NodeIdentity::clone() const {
    auto user_kp = user_.clone();
    if (!user_kp) return std::unexpected(user_kp.error());
    auto device_kp = device_.clone();
    if (!device_kp) return std::unexpected(device_kp.error());

    auto out = compose(std::move(*user_kp), std::move(*device_kp),
                        att_.expiry_unix_ts);
    if (!out) return out;

    /// Carry over sub-keys and rotation history. Each sub-key
    /// keypair is re-seeded from its stored seed prefix.
    auto& dst = out->sub_keys().entries_mut();
    dst.reserve(sub_keys_.entries().size());
    for (const auto& src : sub_keys_.entries()) {
        auto kp = src.kp.clone();
        if (!kp) return std::unexpected(kp.error());
        SubKeyEntry e;
        e.id              = src.id;
        e.purpose         = src.purpose;
        e.kp              = std::move(*kp);
        e.label           = src.label;
        e.created_unix_ts = src.created_unix_ts;
        dst.push_back(std::move(e));
    }
    out->rotation_counter_ = rotation_counter_;
    out->rotation_history_ = rotation_history_;
    return out;
}

::gn::Result<NodeIdentity>
NodeIdentity::load_from_file(const std::string& path) {
    if (path.empty()) {
        return std::unexpected(::gn::Error{
            GN_ERR_NULL_ARG, "load_from_file: empty path"});
    }

    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_NOT_FOUND, "load_from_file: cannot open file"});
    }

    /// Read first 5 bytes to gate-check magic + version, then read
    /// the rest. The body is variable-length (sub-key registry +
    /// rotation history); cap at 64 KiB to keep the slot bounded.
    std::vector<std::uint8_t> buf(5);
    if (::read(fd, buf.data(), 5) != 5) {
        (void)::close(fd);
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED, "load_from_file: truncated header"});
    }

    if (std::memcmp(buf.data(), kMagic.data(), kMagic.size()) != 0
        || buf[kMagic.size()] != kVersion) {
        (void)::close(fd);
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED,
            "load_from_file: unknown magic / version"});
    }

    std::vector<std::uint8_t> rest(64u * 1024 - 5);
    const auto rd = ::read(fd, rest.data(), rest.size());
    (void)::close(fd);
    if (rd < 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY, "load_from_file: read failed"});
    }
    rest.resize(static_cast<std::size_t>(rd));
    buf.insert(buf.end(), rest.begin(), rest.end());

    auto identity = parse(std::span<const std::uint8_t>(buf));
    if (!identity) return identity;

    if (!identity->att_.verify(identity->user_.public_key(),
                                /*now_unix_ts*/ 0)) {
        if (!identity->att_.verify(identity->user_.public_key(),
                                    identity->att_.expiry_unix_ts)) {
            return std::unexpected(::gn::Error{
                GN_ERR_INTEGRITY_FAILED,
                "load_from_file: attestation signature mismatch"});
        }
    }
    return identity;
}

} // namespace gn::core::identity
