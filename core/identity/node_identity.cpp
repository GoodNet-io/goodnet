/// @file   core/identity/node_identity.cpp
/// @brief  Aggregated node identity construction + on-disk format.

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

#include <core/util/log.hpp>

namespace gn::core::identity {

namespace {

constexpr std::array<char, 4>  kMagic{'G', 'N', 'I', 'D'};
constexpr std::uint8_t         kVersion = 1;
constexpr std::size_t          kSeedBytes = kEd25519SeedBytes;

/// Pack a signed 64-bit big-endian integer into the 8-byte slot at
/// `out`. Mirrors the attestation's wire encoding so a hex dump of
/// the file lines up with the corresponding attestation bytes.
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

/// libsodium Ed25519 packs `(seed || pk)` into the 64-byte secret
/// key buffer. The first 32 bytes are exactly the seed
/// `crypto_sign_seed_keypair` consumes — copy them out for
/// serialization.
void copy_seed_out(const KeyPair& kp,
                    std::span<std::uint8_t, kSeedBytes> dst) noexcept {
    const auto sk_view = kp.secret_key_view();
    std::memcpy(dst.data(), sk_view.data(), kSeedBytes);
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

    out.address_ = derive_address(out.user_.public_key(),
                                   out.device_.public_key());
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

    /// Layout: 4 magic + 1 version + 8 expiry + 32 user_seed +
    /// 32 device_seed = 77 bytes. Fixed size, no length prefixes.
    std::array<std::uint8_t, kIdentityFileBytes> buf{};
    std::size_t off = 0;
    std::memcpy(buf.data() + off, kMagic.data(), kMagic.size());
    off += kMagic.size();
    buf[off++] = kVersion;
    encode_be64(self.att_.expiry_unix_ts, buf.data() + off);
    off += 8;
    copy_seed_out(self.user_,
                   std::span<std::uint8_t, kSeedBytes>{buf.data() + off, kSeedBytes});
    off += kSeedBytes;
    copy_seed_out(self.device_,
                   std::span<std::uint8_t, kSeedBytes>{buf.data() + off, kSeedBytes});

    /// `O_CREAT | O_WRONLY | O_TRUNC | O_EXCL`-with-fallback: refuse
    /// to clobber an existing file silently — operators replace
    /// identities only after an explicit `rm`. Mode 0600 so the
    /// secret seed never readable by other users on the host.
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
    /// Write the full buffer in one syscall; 77 bytes never short-
    /// writes on a sane filesystem, but check the count anyway so a
    /// truncated identity does not silently land on disk.
    const auto written = ::write(fd, buf.data(), buf.size());
    const int  write_err = errno;
    if (::close(fd) != 0) {
        gn::log::warn("identity.save: close({}): {}",
                       path, std::strerror(errno));
    }
    if (written != static_cast<ssize_t>(buf.size())) {
        ::unlink(path.c_str());  // do not leave a half-written file
        gn::log::warn("identity.save: short write ({} of {}): {}",
                       written, buf.size(), std::strerror(write_err));
        return std::unexpected(::gn::Error{
            GN_ERR_OUT_OF_MEMORY,
            "save_to_file: short write to disk"});
    }
    return {};
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

    std::array<std::uint8_t, kIdentityFileBytes> buf{};
    const auto rd = ::read(fd, buf.data(), buf.size());
    /// Probe one extra byte to detect oversized files — any tail
    /// past `kIdentityFileBytes` means the blob is not a v1 identity
    /// (longer format, garbage, or appended payload) and we reject
    /// before parsing.
    std::uint8_t tail = 0;
    const auto extra = ::read(fd, &tail, 1);
    (void)::close(fd);
    if (rd != static_cast<ssize_t>(buf.size()) || extra != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED,
            "load_from_file: file size != 77 bytes"});
    }

    if (std::memcmp(buf.data(), kMagic.data(), kMagic.size()) != 0) {
        return std::unexpected(::gn::Error{
            GN_ERR_INTEGRITY_FAILED,
            "load_from_file: magic prefix mismatch"});
    }
    if (buf[kMagic.size()] != kVersion) {
        return std::unexpected(::gn::Error{
            GN_ERR_VERSION_MISMATCH,
            "load_from_file: unsupported identity-file version"});
    }
    const std::int64_t expiry =
        decode_be64(buf.data() + kMagic.size() + 1);

    std::span<const std::uint8_t, kSeedBytes> user_seed_span{
        buf.data() + kMagic.size() + 1 + 8, kSeedBytes};
    std::span<const std::uint8_t, kSeedBytes> device_seed_span{
        buf.data() + kMagic.size() + 1 + 8 + kSeedBytes, kSeedBytes};

    auto user_kp = KeyPair::from_seed(user_seed_span);
    if (!user_kp) return std::unexpected(user_kp.error());
    auto device_kp = KeyPair::from_seed(device_seed_span);
    if (!device_kp) return std::unexpected(device_kp.error());

    /// Ed25519 signatures with libsodium are deterministic for given
    /// (seed, message), so re-running `compose` with the loaded seeds
    /// produces the same attestation bytes the saved instance had —
    /// no need to serialize the signature explicitly. The compose
    /// path also re-derives the address.
    auto identity = compose(std::move(*user_kp), std::move(*device_kp),
                             expiry);
    if (!identity) return std::unexpected(identity.error());

    /// Defence-in-depth: verify the reconstructed attestation against
    /// the user's own pk, ignoring expiry (callers may legitimately
    /// inspect a long-expired identity to read its address). A
    /// signature mismatch here means the seed bytes lied about which
    /// keypair they reconstruct — pointless to surface a half-valid
    /// identity to the caller.
    if (!identity->att_.verify(identity->user_.public_key(),
                                /*now_unix_ts*/ 0)) {
        /// `verify` includes the expiry check; treat «expired but
        /// otherwise valid» as success here — re-run the verify with
        /// `now_unix_ts == expiry` so the time gate passes
        /// regardless of wall clock, and rely on the signature check
        /// for tamper detection.
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
