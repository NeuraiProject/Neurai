// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H
#define NEURAI_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H

#include "support/cleanse.h"

#include <memory>
#include <vector>

template <typename T>
struct zero_after_free_allocator : public std::allocator<T> {
    typedef std::allocator<T> base;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;
    typedef T value_type;
    zero_after_free_allocator() noexcept {}
    zero_after_free_allocator(const zero_after_free_allocator& a) noexcept : base(a) {}
    template <typename U>
    zero_after_free_allocator(const zero_after_free_allocator<U>& a) noexcept : base(a)
    {
    }
    ~zero_after_free_allocator() noexcept {}

    void deallocate(T* p, std::size_t n)
    {
        if (p != nullptr)
            memory_cleanse(p, sizeof(T) * n);
        std::allocator<T>::deallocate(p, n);
    }
};

// Byte-vector that clears its contents before deletion.
typedef std::vector<char, zero_after_free_allocator<char> > CSerializeData;

#endif // NEURAI_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H
