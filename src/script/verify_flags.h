// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Type-safe wrapper for script verification flags.
// Adapted from Bitcoin Core PR #32998 (ajtowns, v31.0).

#ifndef NEURAI_SCRIPT_VERIFY_FLAGS_H
#define NEURAI_SCRIPT_VERIFY_FLAGS_H

#include <cstdint>

enum class script_verify_flag_name : uint8_t;

class script_verify_flags
{
public:
    using value_type = uint64_t;

    consteval script_verify_flags() = default;

    // Allow implicit construction from hard-coded 0 (but not other integers).
    // The throw is a compile-time check (consteval), not a runtime one.
    consteval explicit(false) script_verify_flags(value_type f)
        : m_value{f} { if (f != 0) throw 0; }

    // Implicit construction from a named flag constant.
    constexpr explicit(false) script_verify_flags(script_verify_flag_name f)
        : m_value{value_type{1} << static_cast<uint8_t>(f)} { }

    // Rule of 5 (all defaulted).
    constexpr script_verify_flags(const script_verify_flags&) = default;
    constexpr script_verify_flags(script_verify_flags&&) = default;
    constexpr script_verify_flags& operator=(const script_verify_flags&) = default;
    constexpr script_verify_flags& operator=(script_verify_flags&&) = default;
    constexpr ~script_verify_flags() = default;

    // Integer conversion must be explicit.
    static constexpr script_verify_flags from_int(value_type f) {
        script_verify_flags r; r.m_value = f; return r;
    }
    constexpr value_type as_int() const { return m_value; }

    // Bitwise operations (only between flags).
    constexpr script_verify_flags operator~() const {
        return from_int(~m_value);
    }
    friend constexpr script_verify_flags operator|(
        script_verify_flags a, script_verify_flags b) {
        return from_int(a.m_value | b.m_value);
    }
    friend constexpr script_verify_flags operator&(
        script_verify_flags a, script_verify_flags b) {
        return from_int(a.m_value & b.m_value);
    }
    friend constexpr script_verify_flags operator^(
        script_verify_flags a, script_verify_flags b) {
        return from_int(a.m_value ^ b.m_value);
    }
    constexpr script_verify_flags& operator|=(script_verify_flags vf) {
        m_value |= vf.m_value; return *this;
    }
    constexpr script_verify_flags& operator&=(script_verify_flags vf) {
        m_value &= vf.m_value; return *this;
    }
    constexpr script_verify_flags& operator^=(script_verify_flags vf) {
        m_value ^= vf.m_value; return *this;
    }

    // Tests.
    constexpr explicit operator bool() const { return m_value != 0; }
    constexpr bool operator==(script_verify_flags other) const {
        return m_value == other.m_value;
    }
    constexpr bool operator!=(script_verify_flags other) const {
        return m_value != other.m_value;
    }
    friend constexpr bool operator<(
        const script_verify_flags& a, const script_verify_flags& b) noexcept {
        return a.m_value < b.m_value;
    }

private:
    value_type m_value{0};
};

// Convenience operators for combining flag names directly.
inline constexpr script_verify_flags operator~(script_verify_flag_name f)
{
    return ~script_verify_flags{f};
}
inline constexpr script_verify_flags operator|(
    script_verify_flag_name f1, script_verify_flag_name f2)
{
    return script_verify_flags{f1} | f2;
}

#endif // NEURAI_SCRIPT_VERIFY_FLAGS_H
