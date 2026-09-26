// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license; see COPYING.
#ifndef NEURAI_QT_WITNESSESTIMATE_H
#define NEURAI_QT_WITNESSESTIMATE_H

#include "consensus/consensus.h"
#include "pubkey.h"
#include "serialize.h"

#include <cstddef>
#include <vector>

namespace GUIUtil {
// Advisory wallet-template estimate, not a bound for arbitrary v1/P2WSH
// contracts. Generic v1 uses the wallet's default PQ + OP_TRUE template.
// Includes the witness item count. Transaction marker/flag are added once below.
inline size_t EstimateWitnessInputWeight(int version, const std::vector<unsigned char>& program)
{
    const size_t base = 41 * WITNESS_SCALE_FACTOR;
    if ((version == 1 || version == 2 || version == 3) && program.size() == 32) {
        const size_t sig = version == 3 ? 73 : ML_DSA_44_SIG_SIZE + 1;
        const size_t pub = version == 3 ? 33 : ML_DSA_44_PUBKEY_SIZE + 1;
        return base + 1 + 2 + GetSizeOfCompactSize(sig) + sig +
            GetSizeOfCompactSize(pub) + pub + 2;
    }
    // P2WPKH maximum signature template; also the historical generic fallback
    // for witness scripts whose spending data is not available to the dialog.
    return base + 1 + 1 + 73 + 1 + 33;
}

inline size_t EstimateControlVBytes(size_t inputWeight, size_t inputs,
                                  size_t witnessInputs, size_t outputs)
{
    // These dialogs receive amounts, not destination scripts: retain their
    // historical 34-byte output approximation. Asset suffixes and non-P2PKH
    // outputs can make the final transaction larger; wallet signing determines
    // the actual fee. Account for count prefixes without the 252-input shortcut.
    size_t weight = inputWeight + WITNESS_SCALE_FACTOR *
        (8 + GetSizeOfCompactSize(inputs) + GetSizeOfCompactSize(outputs) + outputs * 34);
    if (witnessInputs) {
        weight += 2 + inputs - witnessInputs; // marker/flag + empty legacy witnesses
    }
    return (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}
} // namespace GUIUtil
#endif
