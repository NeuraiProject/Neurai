// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/publication.h"

#include "privacy/notes.h"

#include <algorithm>

namespace privacy {
namespace {

struct Layout {
    bool deposit = false;
    size_t count = 0;
    size_t recordsAt = 0;
    size_t end = 0;
};

bool GetLayout(const std::string& form, Layout& layout, std::string& error)
{
    layout.deposit = form == "D0" || form == "D1";
    if (layout.deposit) {
        layout.count = 1;
    } else if (form.size() == 2 && form[0] == 'T' && form[1] >= '1' && form[1] <= '4') {
        layout.count = static_cast<size_t>(form[1] - '0');
    } else {
        error = "unsupported publication form";
        return false;
    }
    layout.recordsAt = 34 + layout.count * 32;
    layout.end = 34 + layout.count * 252;
    return true;
}

bool AllZero(Bytes::const_iterator begin, Bytes::const_iterator end)
{
    return std::all_of(begin, end, [](uint8_t b) { return b == 0; });
}

bool CanonicalRecord(const Bytes& record)
{
    return record.size() == RECORD_SIZE && record[0] == 1 && record[1] == 217 && record[2] == 0 &&
           AllZero(record.begin() + RECORD_USED, record.end());
}

} // namespace

bool PoolContext(const Bytes32& domain, const Bytes32& assetId, uint64_t unit, Bytes32& ctx, std::string& error,
                 const Bytes32& registryRoot)
{
    if (!IsCanonicalField(registryRoot)) {
        error = "registry root is not a field element";
        return false;
    }
    bool power = false;
    for (uint64_t p = 1, i = 0; i < 9; ++i, p *= 10) power |= unit == p;
    if (!power) {
        error = "invalid asset quantum";
        return false;
    }
    Bytes data;
    Append(data, std::string("NeuraiPoolCtx"));
    data.push_back(1);
    Append(data, domain);
    Append(data, assetId);
    Append(data, U64LE(unit));
    Append(data, registryRoot);
    ctx = PoseidonBytes(data);
    return true;
}

bool DecodePublication(const std::string& form, const Bytes& blob, Publication& publication, std::string& error)
{
    Layout layout;
    if (!GetLayout(form, layout, error)) return false;
    if (blob.size() != PUBLICATION_SIZE) {
        error = "publication must be 4096 bytes";
        return false;
    }
    if (blob[0] != 2 || blob[1] != layout.count) {
        error = "publication version/count mismatch";
        return false;
    }
    if (!AllZero(blob.begin() + layout.end, blob.end())) {
        error = "noncanonical publication padding";
        return false;
    }
    publication = Publication{};
    Bytes32 nf;
    std::copy(blob.begin() + 2, blob.begin() + 34, nf.begin());
    if (layout.deposit) {
        if (!IsZero(nf)) {
            error = "deposit cannot carry a nullifier";
            return false;
        }
    } else {
        if (!IsCanonicalField(nf) || IsZero(nf)) {
            error = "invalid nullifier";
            return false;
        }
        publication.nf = nf;
    }
    for (size_t i = 0; i < layout.count; ++i) {
        Bytes32 cm;
        std::copy(blob.begin() + 34 + i * 32, blob.begin() + 66 + i * 32, cm.begin());
        if (!IsCanonicalField(cm) || IsZero(cm) ||
            std::find(publication.cms.begin(), publication.cms.end(), cm) != publication.cms.end()) {
            error = "zero or duplicate commitment";
            return false;
        }
        publication.cms.push_back(cm);
        Bytes record(RECORD_SIZE, 0);
        const auto at = blob.begin() + layout.recordsAt + i * RECORD_USED;
        std::copy(at, at + RECORD_USED, record.begin());
        if (!CanonicalRecord(record)) {
            error = "noncanonical note record";
            return false;
        }
        publication.records.push_back(std::move(record));
    }
    return true;
}

bool EncodePublication(const std::string& form, const Publication& publication, Bytes& blob, std::string& error)
{
    Layout layout;
    if (!GetLayout(form, layout, error)) return false;
    if (publication.cms.size() != layout.count || publication.records.size() != layout.count) {
        error = "wrong note count";
        return false;
    }
    if (layout.deposit == publication.nf.has_value()) {
        error = "wrong nullifier presence";
        return false;
    }
    blob.assign(PUBLICATION_SIZE, 0);
    blob[0] = 2;
    blob[1] = static_cast<uint8_t>(layout.count);
    if (publication.nf) std::copy(publication.nf->begin(), publication.nf->end(), blob.begin() + 2);
    for (size_t i = 0; i < layout.count; ++i) {
        std::copy(publication.cms[i].begin(), publication.cms[i].end(), blob.begin() + 34 + i * 32);
        if (!CanonicalRecord(publication.records[i])) {
            error = "noncanonical note record";
            return false;
        }
        std::copy(publication.records[i].begin(), publication.records[i].begin() + RECORD_USED,
                  blob.begin() + layout.recordsAt + i * RECORD_USED);
    }
    Publication check;
    return DecodePublication(form, blob, check, error);
}

bool PublicationHash(const std::string& form, const Bytes& blob, Bytes32& hash, std::string& error)
{
    Publication check;
    if (!DecodePublication(form, blob, check, error)) return false;
    Bytes tag;
    Append(tag, std::string("NIP045/dat\x03"));
    Bytes first;
    Append(first, PoseidonBytes(tag));
    first.insert(first.end(), blob.begin(), blob.begin() + 2048);
    Bytes second;
    Append(second, PoseidonBytes(first));
    second.insert(second.end(), blob.begin() + 2048, blob.end());
    hash = PoseidonBytes(second);
    return true;
}

} // namespace privacy
