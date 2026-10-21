// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047: Silent Payments over the strict ECDSA family (witness v3).
//
// Protocol only: no consensus change. A reusable payment code carries a scan
// and a spend public key; every sender derives a fresh strict v3 output from
// its own inputs, and the receiver finds it by scanning. Shared by the wallet
// and by the node's light client index (silentpaymentindex.h), so it does not
// depend on the wallet.

#ifndef NEURAI_SILENTPAYMENTS_H
#define NEURAI_SILENTPAYMENTS_H

#include "amount.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "serialize.h"
#include "support/allocators/secure.h"
#include "uint256.h"

#include <string>
#include <vector>

namespace silentpayments {

static constexpr uint8_t PROFILE_VERSION = 0;
static constexpr uint8_t WITNESS_FAMILY = 3;
static constexpr unsigned int MAX_PAYMENTS_PER_GROUP = 16;
static constexpr size_t CODE_PAYLOAD_SIZE = 67;
static constexpr uint32_t PURPOSE = 352;

enum NetworkId : uint8_t { MAINNET = 0, TESTNET = 1, REGTEST = 2 };

/** Public payment code: network id plus the scan and spend public keys. */
struct PaymentCode {
    uint8_t networkId = 0;
    CPubKey scanKey;
    CPubKey spendKey;
};

/** Account keys of one identity. A view-only identity has no spend key. */
struct AccountKeys {
    CKey scan;
    CKey spend;
    CPubKey scanPub;
    CPubKey spendPub;
};

/** A payment found while scanning one transaction. */
struct Match {
    uint32_t vout;
    uint32_t k;
    uint256 tweak; //!< t_k: secret-derived, never logged
    CPubKey key;   //!< P_k
};

struct Recipient {
    PaymentCode code;
    CAmount amount;
};

/** Wallet record of a received payment. The tweak t_k is not stored: the
 *  wallet keeps d_k as an ordinary (encrypted) key instead. */
struct PaymentRecord {
    uint32_t k = 0;
    CPubKey key;
    uint256 blockHash; //!< null while unconfirmed
    int32_t height = -1;
    bool viewOnly = false;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(k);
        READWRITE(key);
        READWRITE(blockHash);
        READWRITE(height);
        READWRITE(viewOnly);
    }
};

/** Network id of the running chain (0 main, 1 test, 2 regtest). */
uint8_t LocalNetworkId();

/** Hash context N = network_id || genesis (display order) || profile || family. */
std::vector<unsigned char> Context(uint8_t networkId, const uint256& genesisHash);
std::vector<unsigned char> LocalContext();

std::string EncodeCode(const PaymentCode& code);
bool DecodeCode(const std::string& str, uint8_t localNetworkId, PaymentCode& code, std::string& error);

/** m/352'/coin'/network'/0'/{0',1'}/0' from the BIP39 seed of the wallet. */
bool DeriveAccountKeys(const SecureVector& seed, uint8_t networkId, AccountKeys& keys);

/** Strict v3 scriptPubKey (OP_3 <commitment>) of a compressed key. */
CScript PaymentScript(const CPubKey& key);
bool IsNativeV3Script(const CScript& script);

/** Cheap shape check before looking up prevouts: nVersion 2, not coinbase,
 *  and every input carries the strict v3 witness template. */
bool MayBeEligible(const CTransaction& tx);

/** Inputs of an eligible transaction: nVersion 2 and every prevout a native
 *  v3 output spent with the strict template. spent[i] is the output spent by
 *  vin[i]. Returns false if the transaction does not belong to the protocol. */
bool GetEligibleInputs(const CTransaction& tx, const std::vector<CTxOut>& spent,
                       std::vector<CPubKey>& pubkeys, std::vector<COutPoint>& outpoints);

/** Sender: the outputs paying `recipients`, in the same order, for a
 *  transaction spending exactly `outpoints` with private keys `inputKeys`. */
bool CreateOutputs(const std::vector<unsigned char>& context, const std::vector<CKey>& inputKeys,
                   const std::vector<COutPoint>& outpoints, const std::vector<Recipient>& recipients,
                   std::vector<CTxOut>& outputs, std::string& error);

/** Receiver: payments to (scanKey, spendPub) in an eligible transaction. */
std::vector<Match> ScanTransaction(const std::vector<unsigned char>& context, const CTransaction& tx,
                                   const std::vector<CPubKey>& pubkeys, const std::vector<COutPoint>& outpoints,
                                   const CKey& scanKey, const CPubKey& spendPub);

/** d_k = b_spend + t_k. */
bool PaymentPrivateKey(const CKey& spendKey, const uint256& tweak, CKey& out);

/** Sum of public keys, keeping repetitions; false if the sum is infinity. */
bool SumPublicKeys(const std::vector<CPubKey>& keys, CPubKey& sum);

/** Sum of private keys modulo n; a prefix may cancel to zero. */
bool SumPrivateKeys(const std::vector<CKey>& keys, CKey& sum);

/** Public tweak T = h*A of an eligible transaction, from the keys and
 *  outpoints returned by GetEligibleInputs. A receiver gets the shared secret
 *  as b_scan*T, the same point ScanTransaction computes as (b_scan*h)*A. No
 *  secret is involved. */
bool ComputeTweak(const std::vector<unsigned char>& context, const std::vector<CPubKey>& pubkeys,
                  const std::vector<COutPoint>& outpoints, CPubKey& tweak);

// Light client index format (format 1). One record per block: every eligible
// transaction with a native v3 output, its public tweak and all its native v3
// outputs, plus every outpoint of a native v3 output spent in the block.
// Canonical bytes: minimal CompactSize counters, hashes in internal byte
// order, 33 raw tweak bytes and little-endian fixed integers.

static constexpr uint8_t INDEX_FORMAT = 1;

struct IndexOutput {
    uint32_t vout = 0;
    uint256 commitment; //!< the 32 bytes after OP_3 0x20
    CAmount value = 0;
};

struct IndexEntry {
    uint256 txid;
    CPubKey tweak;
    std::vector<IndexOutput> outputs;
};

struct IndexBlock {
    uint256 hash;
    uint256 prev;
    uint32_t height = 0;
    std::vector<IndexEntry> entries;
    std::vector<COutPoint> spent;
};

bool operator==(const IndexBlock& a, const IndexBlock& b);

/** Index entry of one transaction; false if it is not a candidate (not
 *  eligible, or without native v3 outputs). spent[i] is the output spent by
 *  vin[i]. */
bool BuildIndexEntry(const std::vector<unsigned char>& context, const CTransaction& tx,
                     const std::vector<CTxOut>& spent, IndexEntry& entry);

/** Appends the canonical bytes of `block`. */
void SerializeIndexBlock(const IndexBlock& block, std::vector<unsigned char>& out);

/** Reads one block from data[pos...] and advances pos. Strict: rejects
 *  non-minimal counters, invalid tweaks, amounts outside MoneyRange and
 *  truncated data. Trailing bytes are left to the caller. */
bool DeserializeIndexBlock(const std::vector<unsigned char>& data, size_t& pos, IndexBlock& block, std::string& error);

/** TaggedHash("NeuraiSilentPayments/v0/IndexBlock", N || block bytes). */
uint256 IndexBlockDigest(const std::vector<unsigned char>& context, const std::vector<unsigned char>& blockBytes);

// Binary messages: "NSPT" || format || type || N (35 bytes), then the body.
enum IndexMessageType : uint8_t { INDEX_MESSAGE_BLOCK = 1, INDEX_MESSAGE_RANGE = 2 };

/** How a range client continues from next_height. */
enum IndexRangeStatus : uint8_t {
    INDEX_RANGE_MORE = 0,       //!< data available now from next_height
    INDEX_RANGE_TIP = 1,        //!< reached the tip of the snapshot: wait for a block
    INDEX_RANGE_WAIT = 2,       //!< the index is still being built: retry later
    INDEX_RANGE_INCOMPLETE = 3, //!< the index lacks data from next_height and cannot rebuild it
};

struct IndexRangeHeader {
    uint32_t snapshotHeight = 0;
    uint256 snapshotHash;
    uint32_t syncedHeight = 0;
    uint32_t nextHeight = 0;
    uint8_t status = INDEX_RANGE_MORE;
};

/** Message of one block: envelope || block bytes. */
void SerializeIndexBlockMessage(const std::vector<unsigned char>& context, const std::vector<unsigned char>& blockBytes,
                                std::vector<unsigned char>& out);

/** Message of a range: envelope || snapshot height || snapshot hash ||
 *  synced height || next height || status || count || blocks. */
void SerializeIndexRangeMessage(const std::vector<unsigned char>& context, const IndexRangeHeader& header,
                                const std::vector<std::vector<unsigned char>>& blocks, std::vector<unsigned char>& out);

/** Receiver: payments to (scanKey, spendPub) in an index entry. Same result as
 *  ScanTransaction on the transaction of the entry. */
std::vector<Match> ScanIndexEntry(const std::vector<unsigned char>& context, const IndexEntry& entry,
                                  const CKey& scanKey, const CPubKey& spendPub);

} // namespace silentpayments

#endif // NEURAI_SILENTPAYMENTS_H
