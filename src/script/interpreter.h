// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_SCRIPT_INTERPRETER_H
#define NEURAI_SCRIPT_INTERPRETER_H

#include "script_error.h"
#include "script/verify_flags.h"
#include "primitives/transaction.h"

#include <vector>
#include <stdint.h>
#include <string>

class CPubKey;

class CScript;

class CTransaction;

class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags — bit positions for the type-safe wrapper.
 *  Each enumerator holds a bit *position* (0, 1, 2, …); the wrapper class
 *  converts it to a bitmask via (1ULL << position).  See verify_flags.h. */
enum class script_verify_flag_name : uint8_t {
    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH,                                   // bit 0

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC,                               // bit 1

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG,                                  // bit 2

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S,                                   // bit 3

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY,                               // bit 4

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY,                              // bit 5

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA,                              // bit 6

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,               // bit 7

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    SCRIPT_VERIFY_CLEANSTACK,                               // bit 8

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,                      // bit 9

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,                      // bit 10

    // Support segregated witness
    //
    SCRIPT_VERIFY_WITNESS,                                  // bit 11

    // Making v1-v16 witness program non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,    // bit 12

    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF,                                // bit 13

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL,                                 // bit 14

    // Public keys in segregated witness scripts must be compressed
    //
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,                       // bit 15

    // Enable AuthScript witness v1 program verification.
    // When set, witness v1 programs with a 32-byte commitment are verified
    // using AuthScript semantics instead of being treated as upgradable/unknown.
    //
    SCRIPT_VERIFY_AUTHSCRIPT,                               // bit 16

    // Enable OP_CAT (BIP 347) - stack element concatenation.
    // When set, OP_CAT is executed instead of returning SCRIPT_ERR_DISABLED_OPCODE.
    //
    SCRIPT_VERIFY_CAT,                                      // bit 17

    // Enable OP_CHECKTEMPLATEVERIFY (BIP 119) - transaction template verification.
    // When set, OP_CHECKTEMPLATEVERIFY is executed instead of being treated as OP_NOP4.
    //
    SCRIPT_VERIFY_CHECKTEMPLATEVERIFY,                       // bit 18

    // Enable OP_CHECKSIGFROMSTACK - verify signature against arbitrary message.
    // When set, OP_CHECKSIGFROMSTACK is executed instead of being treated as OP_NOP5.
    //
    SCRIPT_VERIFY_CHECKSIGFROMSTACK,                         // bit 19

    // Enable OP_TXHASH - push hash of selected transaction fields to stack.
    // When set, OP_TXHASH is executed instead of being treated as OP_NOP6.
    //
    SCRIPT_VERIFY_TXHASH,                                   // bit 20

    // Enable OP_TXFIELD - push raw bytes of spent output fields to stack.
    // When set, OP_TXFIELD is executed instead of being treated as OP_NOP7.
    //
    SCRIPT_VERIFY_TXFIELD,                                  // bit 21

    // Enable OP_SPLIT - split a byte array into two parts at a given position.
    // When set, OP_SPLIT is executed instead of being treated as OP_NOP8.
    // Inverse of OP_CAT (BIP 347).
    //
    SCRIPT_VERIFY_SPLIT,                                    // bit 22

    // Enable OP_REVERSEBYTES - reverse the top stack element in place.
    // When set, OP_REVERSEBYTES is executed instead of being treated as an
    // upgradable opcode.
    //
    SCRIPT_VERIFY_REVERSEBYTES,                             // bit 23

    // Enable OP_OUTPUTVALUE - push the amount of a selected output as raw
    // 8-byte little-endian data.
    //
    SCRIPT_VERIFY_OUTPUTVALUE,                              // bit 24

    // Enable OP_TXLOCKTIME - push the transaction nLockTime as raw 4-byte
    // little-endian data.
    //
    SCRIPT_VERIFY_TXLOCKTIME,                               // bit 25

    // Enable OP_OUTPUTSCRIPT - push the scriptPubKey of a selected output
    // as raw bytes.
    //
    SCRIPT_VERIFY_OUTPUTSCRIPT,                             // bit 26

    // Enable OP_OUTPUTASSETFIELD - read asset payload fields from a selected
    // output by selector.
    //
    SCRIPT_VERIFY_OUTPUTASSETFIELD,                         // bit 27

    // Enable 64-bit arithmetic and reactivate OP_MUL/OP_DIV/OP_MOD while
    // widening the numeric covenant domain to 8-byte CScriptNum values.
    //
    SCRIPT_VERIFY_64BIT_INTEGERS,                           // bit 28

    // Enable OP_INPUTASSETFIELD - read asset payload fields from the prevout
    // referenced by a selected input.
    //
    SCRIPT_VERIFY_INPUTASSETFIELD,                          // bit 29

    // Enable OP_INPUTCOUNT / OP_OUTPUTCOUNT — push transaction
    // input/output count onto the stack as CScriptNum.
    //
    SCRIPT_VERIFY_INPUTOUTPUTCOUNT,                         // bit 30

    // End marker — must always be last.
    SCRIPT_VERIFY_END_MARKER
};

// Import all flag names into the enclosing scope for source compatibility.
using enum script_verify_flag_name;

// Canonical empty-flags value.
static constexpr script_verify_flags SCRIPT_VERIFY_NONE{};

// Compile-time capacity guards.
static constexpr int MAX_SCRIPT_VERIFY_FLAGS_BITS =
    static_cast<int>(script_verify_flag_name::SCRIPT_VERIFY_END_MARKER);
static_assert(0 < MAX_SCRIPT_VERIFY_FLAGS_BITS
    && MAX_SCRIPT_VERIFY_FLAGS_BITS <= 63,
    "Script verification flag space exhausted");

static constexpr script_verify_flags::value_type MAX_SCRIPT_VERIFY_FLAGS =
    ((script_verify_flags::value_type{1} << MAX_SCRIPT_VERIFY_FLAGS_BITS) - 1);

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, script_verify_flags flags, ScriptError *serror);

struct PrecomputedTransactionData
{
    // BIP143 double-SHA256 hashes (used by SignatureHash and OP_TXHASH)
    uint256 hashPrevouts, hashSequence, hashOutputs;
    bool ready = false;

    // BIP119 CTV single-SHA256 sub-hashes (anti-DoS precomputation)
    uint256 ctvHashSequences, ctvHashOutputs, ctvHashScriptSigs;
    bool ctvHasNonEmptyScriptSig = false;
    bool ctvReady = false;

    explicit PrecomputedTransactionData(const CTransaction &tx);
};

enum SigVersion
{
    SIGVERSION_BASE = 0,
    SIGVERSION_WITNESS_V0 = 1,
    SIGVERSION_AUTHSCRIPT = 2,
};

uint256 SignatureHash(const CScript &scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType, const CAmount &amount, SigVersion sigversion, const PrecomputedTransactionData *cache = nullptr, uint8_t authType = 0x00);

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(const std::vector<unsigned char> &scriptSig, const std::vector<unsigned char> &vchPubKey, const CScript &scriptCode, SigVersion sigversion, uint8_t authType = 0x00) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const
    {
        return false;
    }

    virtual bool CheckSequence(const CScriptNum &nSequence) const
    {
        return false;
    }

    // Compute the signature hash for a given scriptCode, hashtype and sigversion.
    // Used by PQ witness v1 verification to get the BIP143 sighash directly.
    virtual uint256 GetSigHash(const CScript& scriptCode, int nHashType, SigVersion sigversion, uint8_t authType = 0x00) const
    {
        return uint256();
    }

    virtual bool CheckTemplateVerify(const std::vector<unsigned char>& hash) const
    {
        return false;
    }

    virtual bool CheckSigFromStack(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& msg, const std::vector<unsigned char>& pubkey) const
    {
        return false;
    }

    virtual bool GetTxFieldHash(unsigned char fieldSelector, std::vector<unsigned char>& result) const
    {
        return false;
    }

    // Push raw bytes of a field from the spent UTXO (the output being spent).
    // Unlike GetTxFieldHash, this returns unprocessed data, not a hash.
    // Requires the checker to have been constructed with the spent scriptPubKey.
    virtual bool GetTxField(unsigned char selector, std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetOutputValue(unsigned int nOut, std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetOutputScript(unsigned int nOut, std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetOutputAssetField(unsigned int nOut, unsigned char selector, std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetInputAssetField(unsigned int nIn, unsigned char selector, std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetInputCount(std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetOutputCount(std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual bool GetTxLockTime(std::vector<unsigned char>& result) const
    {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const CTransaction *txTo;
    unsigned int nIn;
    const CAmount amount;
    const PrecomputedTransactionData *txdata;
    const CScript* m_spentScriptPubKey;  // scriptPubKey of the UTXO being spent (for OP_TXFIELD)
    const std::vector<CTxOut>* m_allPrevouts; // prevouts of all inputs, if available

protected:
    virtual bool VerifySignature(const std::vector<unsigned char> &vchSig, const CPubKey &vchPubKey, const uint256 &sighash) const;

public:
    TransactionSignatureChecker(const CTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr), m_spentScriptPubKey(nullptr), m_allPrevouts(nullptr) {}

    TransactionSignatureChecker(const CTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const PrecomputedTransactionData &txdataIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn), m_spentScriptPubKey(nullptr), m_allPrevouts(nullptr) {}

    // Constructor with spent scriptPubKey but without precomputed txdata.
    // Used by RPC signing paths (signrawtransaction, combinesignatures) where
    // PrecomputedTransactionData is not available but OP_TXFIELD must still work.
    TransactionSignatureChecker(const CTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const CScript& spentScriptPubKeyIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr), m_spentScriptPubKey(&spentScriptPubKeyIn), m_allPrevouts(nullptr) {}

    TransactionSignatureChecker(const CTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const CScript& spentScriptPubKeyIn, const std::vector<CTxOut>* allPrevoutsIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr), m_spentScriptPubKey(&spentScriptPubKeyIn), m_allPrevouts(allPrevoutsIn) {}

    // Constructor with both precomputed txdata and spent scriptPubKey — used by consensus validation.
    TransactionSignatureChecker(const CTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const PrecomputedTransactionData &txdataIn, const CScript& spentScriptPubKeyIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn), m_spentScriptPubKey(&spentScriptPubKeyIn), m_allPrevouts(nullptr) {}

    TransactionSignatureChecker(const CTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const PrecomputedTransactionData &txdataIn, const CScript& spentScriptPubKeyIn, const std::vector<CTxOut>* allPrevoutsIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn), m_spentScriptPubKey(&spentScriptPubKeyIn), m_allPrevouts(allPrevoutsIn) {}

    bool CheckSig(const std::vector<unsigned char> &scriptSig, const std::vector<unsigned char> &vchPubKey, const CScript &scriptCode, SigVersion sigversion, uint8_t authType = 0x00) const override;

    bool CheckLockTime(const CScriptNum &nLockTime) const override;

    bool CheckSequence(const CScriptNum &nSequence) const override;

    bool CheckTemplateVerify(const std::vector<unsigned char>& hash) const override;

    bool CheckSigFromStack(const std::vector<unsigned char>& sig, const std::vector<unsigned char>& msg, const std::vector<unsigned char>& pubkey) const override;

    bool GetTxFieldHash(unsigned char fieldSelector, std::vector<unsigned char>& result) const override;

    bool GetTxField(unsigned char selector, std::vector<unsigned char>& result) const override;

    bool GetOutputValue(unsigned int nOut, std::vector<unsigned char>& result) const override;

    bool GetOutputScript(unsigned int nOut, std::vector<unsigned char>& result) const override;

    bool GetOutputAssetField(unsigned int nOut, unsigned char selector, std::vector<unsigned char>& result) const override;

    bool GetInputAssetField(unsigned int nIn, unsigned char selector, std::vector<unsigned char>& result) const override;

    bool GetInputCount(std::vector<unsigned char>& result) const override;
    bool GetOutputCount(std::vector<unsigned char>& result) const override;

    bool GetTxLockTime(std::vector<unsigned char>& result) const override;

    uint256 GetSigHash(const CScript& scriptCode, int nHashType, SigVersion sigversion, uint8_t authType = 0x00) const override;
};

class MutableTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    const CTransaction txTo;

public:
    MutableTransactionSignatureChecker(const CMutableTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn) : TransactionSignatureChecker(&txTo, nInIn, amountIn), txTo(*txToIn) {}
    MutableTransactionSignatureChecker(const CMutableTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const CScript& spentScriptPubKeyIn)
        : TransactionSignatureChecker(&txTo, nInIn, amountIn, spentScriptPubKeyIn), txTo(*txToIn) {}
    MutableTransactionSignatureChecker(const CMutableTransaction *txToIn, unsigned int nInIn, const CAmount &amountIn, const CScript& spentScriptPubKeyIn, const std::vector<CTxOut>* allPrevoutsIn)
        : TransactionSignatureChecker(&txTo, nInIn, amountIn, spentScriptPubKeyIn, allPrevoutsIn), txTo(*txToIn) {}
};

bool EvalScript(std::vector<std::vector<unsigned char> > &stack, const CScript &script, script_verify_flags flags, const BaseSignatureChecker &checker, SigVersion sigversion, ScriptError *error = nullptr);

bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CScriptWitness *witness, script_verify_flags flags, const BaseSignatureChecker &checker, ScriptError *serror = nullptr);

size_t CountWitnessSigOps(const CScript &scriptSig, const CScript &scriptPubKey, const CScriptWitness *witness, script_verify_flags flags);

bool CastToBool(const std::vector<unsigned char>& vch);

#endif // NEURAI_SCRIPT_INTERPRETER_H
