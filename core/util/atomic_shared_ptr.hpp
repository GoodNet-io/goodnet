// SPDX-License-Identifier: MIT
// Portability shim: C++20 std::atomic<shared_ptr<T>> for platforms
// (Emscripten libc++) that lack the partial specialisation.
// On all other targets the real std::atomic<shared_ptr<T>> is used.

#pragma once

#include <atomic>
#include <memory>
#include <mutex>

namespace gn::core::util {

#ifdef __EMSCRIPTEN__

template <class T>
class AtomicSharedPtr {
public:
    AtomicSharedPtr() = default;
    explicit AtomicSharedPtr(std::shared_ptr<T> v) : val_(std::move(v)) {}

    std::shared_ptr<T> load(std::memory_order = std::memory_order_seq_cst) const {
        std::lock_guard<std::mutex> g(mtx_);
        return val_;
    }

    void store(std::shared_ptr<T> desired,
               std::memory_order = std::memory_order_seq_cst) {
        std::lock_guard<std::mutex> g(mtx_);
        val_ = std::move(desired);
    }

    bool compare_exchange_weak(std::shared_ptr<T>& expected,
                               std::shared_ptr<T>  desired,
                               std::memory_order, std::memory_order) {
        std::lock_guard<std::mutex> g(mtx_);
        if (val_ == expected) { val_ = std::move(desired); return true; }
        expected = val_;
        return false;
    }

private:
    mutable std::mutex mtx_;
    std::shared_ptr<T> val_;
};

#else

template <class T>
using AtomicSharedPtr = std::atomic<std::shared_ptr<T>>;

#endif

} // namespace gn::core::util
