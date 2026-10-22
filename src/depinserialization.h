// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_DEPINSERIALIZATION_H
#define NEURAI_DEPINSERIALIZATION_H

#include "serialize.h"
#include <ios>
#include <string>
#include <vector>

// Check declared sizes before allocating; stream.read then detects truncation.
// ReadCompactSize rejects non-minimal encodings. Works with disk and memory.
template <typename Stream>
std::vector<unsigned char> ReadDepinBytes(Stream& stream, size_t maximum, size_t minimum = 0)
{
    const uint64_t size = ReadCompactSize(stream);
    if (size < minimum || size > maximum) throw std::ios_base::failure("DePIN byte length out of range");
    std::vector<unsigned char> out(size);
    if (size) stream.read(reinterpret_cast<char*>(out.data()), size);
    return out;
}

template <typename Stream>
std::string ReadDepinString(Stream& stream, size_t maximum)
{
    const auto bytes = ReadDepinBytes(stream, maximum);
    return std::string(bytes.begin(), bytes.end());
}
#endif
