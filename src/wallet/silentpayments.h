// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047: Silent Payments over the strict ECDSA family (witness v3).
//
// Wallet-side protocol only: no consensus change. A reusable payment code
// carries a scan and a spend public key; every sender derives a fresh strict
// v3 output from its own inputs, and the receiver finds it by scanning.

#ifndef NEURAI_WALLET_SILENTPAYMENTS_H
#define NEURAI_WALLET_SILENTPAYMENTS_H

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

} // namespace silentpayments

#endif // NEURAI_WALLET_SILENTPAYMENTS_H
