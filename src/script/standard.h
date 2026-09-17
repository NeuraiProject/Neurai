// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_SCRIPT_STANDARD_H
#define NEURAI_SCRIPT_STANDARD_H

#include "pubkey.h"
#include "script/interpreter.h"
#include "uint256.h"

#include <boost/variant.hpp>

#include <stdint.h>

static const bool DEFAULT_ACCEPT_DATACARRIER = true;

class CScript;

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript& in);
    CScriptID(const uint160& in) : uint160(in) {}
};

/**
 * Default setting for nMaxDatacarrierBytes.
 * Mainnet: 80 bytes of data, +1 for OP_RETURN, +2 for the pushdata opcodes = 83 bytes
 * Testnet: 512 bytes for testing purposes
 */
static const unsigned int MAX_OP_RETURN_RELAY = 83;
static const unsigned int MAX_OP_RETURN_RELAY_TESTNET = 512;

// Forward declaration
class CChainParams;

/**
 * Get maximum OP_RETURN relay size based on network
 * Returns 512 bytes for testnet, 83 bytes for mainnet/regtest
 */
unsigned int GetMaxOPReturnRelay();

/**
 * A data carrying output is an unspendable output containing data. The script
 * type is designated as TX_NULL_DATA.
 */
extern bool fAcceptDatacarrier;

/** Maximum size of TX_NULL_DATA scripts that this node considers standard. */
extern unsigned nMaxDatacarrierBytes;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
static constexpr script_verify_flags MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

enum txnouttype
{
    TX_NONSTANDARD = 0,
    // 'standard' transaction types:
    TX_PUBKEY = 1,
    TX_PUBKEYHASH = 2,
    TX_SCRIPTHASH = 3,
    TX_MULTISIG = 4,
    TX_NULL_DATA = 5, //!< unspendable OP_RETURN script that carries data
    TX_WITNESS_V0_SCRIPTHASH = 6,
    TX_WITNESS_V0_KEYHASH = 7,
    /** XNA START */
    TX_NEW_ASSET = 8,
    TX_REISSUE_ASSET = 9,
    TX_TRANSFER_ASSET = 10,
    TX_RESTRICTED_ASSET_DATA = 11, //!< unspendable OP_NEURAI_ASSET script that carries data
    /** XNA END */
    TX_WITNESS_V1_AUTHSCRIPT = 12, //!< AuthScript pay-to-witness-v1-commitment (Bech32m)
    TX_WITNESS_V2_STRICT_PQ = 13,    //!< Strict AuthScript, witness v2: ML-DSA-44 key + OP_TRUE template
    TX_WITNESS_V3_STRICT_ECDSA = 14, //!< Strict AuthScript, witness v3: compressed secp256k1 key + OP_TRUE template
};

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/**
 * WitnessV1AuthScript: a 32-byte AuthScript commitment.
 * Encoded as a Bech32m address with HRP "nq" (mainnet), "tnq" (testnet/regtest).
 * scriptPubKey: OP_1 <32-byte-commitment>
 */
class WitnessV1AuthScript : public uint256
{
public:
    WitnessV1AuthScript() : uint256() {}
    explicit WitnessV1AuthScript(const uint256& in) : uint256(in) {}
};

/**
 * WitnessStrictAuthScript: a strict AuthScript destination, i.e. a versioned
 * 32-byte commitment under one of the strict families:
 *   version 2: post-quantum (ML-DSA-44) key, HRP "pq" / "tpq"
 *   version 3: classical compressed secp256k1 key, HRP "nq" / "tnq"
 * Both commit to the fixed template witnessScript = OP_TRUE and use the
 * commitment preimage lead byte equal to the witness version.
 * scriptPubKey: OP_<version> <32-byte-commitment>
 *
 * The version is part of the identity: the same 32 bytes under a different
 * version are a different destination (wallet, indexes and covenants must
 * always key on (version, commitment)).
 */
class WitnessStrictAuthScript
{
public:
    uint8_t version;
    uint256 commitment;

    WitnessStrictAuthScript() : version(0), commitment() {}
    WitnessStrictAuthScript(uint8_t versionIn, const uint256& commitmentIn) : version(versionIn), commitment(commitmentIn) {}

    bool IsPQ() const { return version == STRICT_AUTHSCRIPT_WITNESS_V2_PQ; }
    bool IsECDSA() const { return version == STRICT_AUTHSCRIPT_WITNESS_V3_ECDSA; }
    bool IsValid() const { return IsStrictAuthScriptWitnessVersion(version) && !commitment.IsNull(); }

    friend bool operator==(const WitnessStrictAuthScript& a, const WitnessStrictAuthScript& b) { return a.version == b.version && a.commitment == b.commitment; }
    friend bool operator!=(const WitnessStrictAuthScript& a, const WitnessStrictAuthScript& b) { return !(a == b); }
    friend bool operator<(const WitnessStrictAuthScript& a, const WitnessStrictAuthScript& b) {
        if (a.version != b.version) return a.version < b.version;
        return a.commitment < b.commitment;
    }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination (Base58, secp256k1)
 *  * CScriptID: TX_SCRIPTHASH destination (Base58, P2SH)
 *  * WitnessV1AuthScript: TX_WITNESS_V1_AUTHSCRIPT destination (Bech32m, generic AuthScript)
 *  * WitnessStrictAuthScript: TX_WITNESS_V2_STRICT_PQ / TX_WITNESS_V3_STRICT_ECDSA destination (Bech32m, strict AuthScript)
 *  A CTxDestination is the internal data type encoded in a neurai address
 */
typedef boost::variant<CNoDestination, CKeyID, CScriptID, WitnessV1AuthScript, WitnessStrictAuthScript> CTxDestination;

enum DestinationIndexType
{
    DEST_INDEX_NONE = 0,
    DEST_INDEX_KEY = 1,
    DEST_INDEX_SCRIPT = 2,
    DEST_INDEX_WITNESS_V1_AUTHSCRIPT = 3,
    DEST_INDEX_WITNESS_V2_STRICT_PQ = 4,    //!< never renumber: on-disk index type
    DEST_INDEX_WITNESS_V3_STRICT_ECDSA = 5, //!< never renumber: on-disk index type
};

/** Map a strict witness version to its txnouttype (TX_NONSTANDARD if not strict). */
txnouttype StrictAuthScriptTxnOutType(int witnessVersion);

/** Map a strict witness version to its destination index type (DEST_INDEX_NONE if not strict). */
int StrictAuthScriptDestIndexType(int witnessVersion);

/** The fixed witnessScript of the strict families: exactly OP_TRUE. */
CScript GetStrictAuthScriptTemplate();

/**
 * Build the strict destination for a public key: version 2 for a PQ key,
 * version 3 for a compressed secp256k1 key. Returns false for any other key.
 */
bool GetStrictAuthScriptDestinationForPubKey(const CPubKey& pubkey, WitnessStrictAuthScript& dest);

struct CDestinationIndexData
{
    int type;
    std::vector<unsigned char> payload;

    CDestinationIndexData() : type(DEST_INDEX_NONE) {}
    CDestinationIndexData(int typeIn, const std::vector<unsigned char>& payloadIn) : type(typeIn), payload(payloadIn) {}

    void SetNull()
    {
        type = DEST_INDEX_NONE;
        payload.clear();
    }

    bool IsNull() const
    {
        return type == DEST_INDEX_NONE || payload.empty();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(type);
        READWRITE(payload);
    }
};

inline bool operator==(const CDestinationIndexData& a, const CDestinationIndexData& b)
{
    return a.type == b.type && a.payload == b.payload;
}

inline bool operator!=(const CDestinationIndexData& a, const CDestinationIndexData& b)
{
    return !(a == b);
}

inline bool operator<(const CDestinationIndexData& a, const CDestinationIndexData& b)
{
    if (a.type == b.type) {
        return a.payload < b.payload;
    }
    return a.type < b.type;
}

/** Check whether a CTxDestination is a CNoDestination. */
bool IsValidDestination(const CTxDestination& dest);

/** Get the name of a txnouttype as a C string, or nullptr if unknown. */
const char* GetTxnOutputType(txnouttype t);

/**
 * Parse a scriptPubKey and identify script type for standard scripts. If
 * successful, returns script type and parsed pubkeys or hashes, depending on
 * the type. For example, for a P2SH script, vSolutionsRet will contain the
 * script hash, for P2PKH it will contain the key hash, etc.
 *
 * @param[in]   scriptPubKey   Script to parse
 * @param[out]  typeRet        The script type
 * @param[out]  vSolutionsRet  Vector of parsed pubkeys and hashes
 * @return                     True if script matches standard template
 */
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet);

/**
 * Parse a standard scriptPubKey for the destination address. Assigns result to
 * the addressRet parameter and returns true if successful. For multisig
 * scripts, instead use ExtractDestinations. Currently only works for P2PK,
 * P2PKH, and P2SH scripts.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/** Extract the spend destination encoded in an asset script. */
bool ExtractAssetDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/** Detect asset scripts that use a witness destination and extract the witness commitment and asset data suffix. */
bool GetAssetScriptWitnessProgram(const CScript& scriptPubKey, int& witnessversion, std::vector<unsigned char>& witnessprogram, std::vector<unsigned char>* assetData = nullptr);

/** Explicit-context variant for the script interpreter, which runs on worker
 *  threads without an activation scope and derives fStrictActive from its
 *  flags (SCRIPT_VERIFY_AUTHSCRIPT_STRICT). */
bool GetAssetScriptWitnessProgram(const CScript& scriptPubKey, int& witnessversion, std::vector<unsigned char>& witnessprogram, std::vector<unsigned char>* assetData, bool fStrictActive);

/** Derive the AuthScript descriptor bytes for a given auth type and pubkey payload. */
bool GetAuthScriptDescriptor(uint8_t authType, const CPubKey* pubkey, std::vector<unsigned char>& authDescriptor);

/**
 * Compute the tagged 32-byte AuthScript commitment.
 * commitmentVersion is the preimage lead byte: 0x01 for generic witness v1
 * (the historical value), 0x02 / 0x03 for the strict witness v2 / v3 families.
 * Returns a null hash for an invalid authType/pubkey combination or an
 * unknown commitmentVersion.
 */
uint256 GetAuthScriptCommitment(uint8_t authType, const CPubKey* pubkey, const CScript& witnessScript, uint8_t commitmentVersion = 0x01);

/** Convert a destination into the hash/type pair used by address and pubkey indexes. */
bool GetDestinationIndexKey(const CTxDestination& dest, uint160& hashBytes, int& type);

/** Extract the hash/type pair used by address and pubkey indexes from a spendable script. */
bool GetScriptDestinationIndexKey(const CScript& scriptPubKey, uint160& hashBytes, int& type);

/** Convert a destination into the payload/type pair used by address and pubkey indexes. */
bool GetDestinationIndexData(const CTxDestination& dest, CDestinationIndexData& data);

/** Extract the payload/type pair used by address and pubkey indexes from a spendable script. */
bool GetScriptDestinationIndexData(const CScript& scriptPubKey, CDestinationIndexData& data);

/**
 * Parse a standard scriptPubKey with one or more destination addresses. For
 * multisig scripts, this populates the addressRet vector with the pubkey IDs
 * and nRequiredRet with the n required to spend. For other destinations,
 * addressRet is populated with a single value and nRequiredRet is set to 1.
 * Returns true if successful. Currently does not extract address from
 * pay-to-witness scripts.
 */
bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet);

/**
 * Generate a Neurai scriptPubKey for the given CTxDestination. Returns a P2PKH
 * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
 * script for CNoDestination.
 */
CScript GetScriptForDestination(const CTxDestination& dest);

/** Generate a P2PK script for the given pubkey. */
CScript GetScriptForRawPubKey(const CPubKey& pubkey);

/** Generate a multisig script. */
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);

/** Generate a script that contains an address used for qualifier, and restricted assets data transactions */
CScript GetScriptForNullAssetDataDestination(const CTxDestination &dest);

/**
 * Generate a pay-to-witness script for the given redeem script. If the redeem
 * script is P2PK or P2PKH, this returns a P2WPKH script, otherwise it returns a
 * P2WSH script.
 */
CScript GetScriptForWitness(const CScript& redeemscript);

#endif // NEURAI_SCRIPT_STANDARD_H
