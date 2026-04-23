// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "assets/assets.h"
#include "assets/assettypes.h"
#include "primitives/transaction.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "serialize.h"
#include "streams.h"

#include <algorithm>
#include <cstring>
#include <limits>

typedef std::vector<unsigned char> valtype;

static constexpr int64_t MIN_SCRIPT_INT64 = -std::numeric_limits<int64_t>::max();

static bool AddOverflow64(int64_t a, int64_t b, int64_t& result)
{
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_add_overflow(a, b, &result))
        return false;
    return result != std::numeric_limits<int64_t>::min();
#elif defined(__SIZEOF_INT128__)
    __int128 r = static_cast<__int128>(a) + static_cast<__int128>(b);
    if (r > std::numeric_limits<int64_t>::max() || r < MIN_SCRIPT_INT64)
        return false;
    result = static_cast<int64_t>(r);
    return true;
#else
    if ((b > 0 && a > std::numeric_limits<int64_t>::max() - b) ||
        (b < 0 && a < MIN_SCRIPT_INT64 - b))
        return false;
    result = a + b;
    return result != std::numeric_limits<int64_t>::min();
#endif
}

static bool SubOverflow64(int64_t a, int64_t b, int64_t& result)
{
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_sub_overflow(a, b, &result))
        return false;
    return result != std::numeric_limits<int64_t>::min();
#elif defined(__SIZEOF_INT128__)
    __int128 r = static_cast<__int128>(a) - static_cast<__int128>(b);
    if (r > std::numeric_limits<int64_t>::max() || r < MIN_SCRIPT_INT64)
        return false;
    result = static_cast<int64_t>(r);
    return true;
#else
    if ((b > 0 && a < MIN_SCRIPT_INT64 + b) ||
        (b < 0 && a > std::numeric_limits<int64_t>::max() + b))
        return false;
    result = a - b;
    return result != std::numeric_limits<int64_t>::min();
#endif
}

static bool MulOverflow64(int64_t a, int64_t b, int64_t& result)
{
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_mul_overflow(a, b, &result))
        return false;
    return result != std::numeric_limits<int64_t>::min();
#elif defined(__SIZEOF_INT128__)
    __int128 r = static_cast<__int128>(a) * static_cast<__int128>(b);
    if (r > std::numeric_limits<int64_t>::max() || r < MIN_SCRIPT_INT64)
        return false;
    result = static_cast<int64_t>(r);
    return true;
#else
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if (a == -1) {
        if (b == std::numeric_limits<int64_t>::min())
            return false;
        result = -b;
        return result != std::numeric_limits<int64_t>::min();
    }
    if (b == -1) {
        if (a == std::numeric_limits<int64_t>::min())
            return false;
        result = -a;
        return result != std::numeric_limits<int64_t>::min();
    }
    if ((a > 0 && b > 0 && a > std::numeric_limits<int64_t>::max() / b) ||
        (a > 0 && b < 0 && b < MIN_SCRIPT_INT64 / a) ||
        (a < 0 && b > 0 && a < MIN_SCRIPT_INT64 / b) ||
        (a < 0 && b < 0 && a < std::numeric_limits<int64_t>::max() / b))
        return false;
    result = a * b;
    return result != std::numeric_limits<int64_t>::min();
#endif
}

static bool ExtractAssetField_Transfer(
    const CAssetTransfer& t,
    unsigned char selector,
    std::vector<unsigned char>& result)
{
    switch (selector) {
        case 0x01:
            result.assign(t.strName.begin(), t.strName.end());
            return true;
        case 0x02: {
            result.resize(8);
            const int64_t v = static_cast<int64_t>(t.nAmount);
            memcpy(result.data(), &v, 8);
            return true;
        }
        case 0x07: {
            AssetType type;
            if (!IsAssetNameValid(t.strName, type))
                return false;
            result = {static_cast<unsigned char>(IntFromAssetType(type))};
            return true;
        }
        default:
            return false;
    }
}

static bool ExtractAssetField_New(
    const CNewAsset& a,
    unsigned char selector,
    std::vector<unsigned char>& result)
{
    switch (selector) {
        case 0x01:
            result.assign(a.strName.begin(), a.strName.end());
            return true;
        case 0x02: {
            result.resize(8);
            const int64_t v = static_cast<int64_t>(a.nAmount);
            memcpy(result.data(), &v, 8);
            return true;
        }
        case 0x03:
            result = {static_cast<unsigned char>(a.units)};
            return true;
        case 0x04:
            result = {static_cast<unsigned char>(a.nReissuable)};
            return true;
        case 0x05:
            result = {static_cast<unsigned char>(a.nHasIPFS)};
            return true;
        case 0x06:
            if (a.nHasIPFS == 0 || a.strIPFSHash.empty())
                return false;
            result.assign(a.strIPFSHash.begin(), a.strIPFSHash.end());
            return true;
        case 0x07: {
            AssetType type;
            if (!IsAssetNameValid(a.strName, type))
                return false;
            result = {static_cast<unsigned char>(IntFromAssetType(type))};
            return true;
        }
        default:
            return false;
    }
}

static bool ExtractAssetField_Reissue(
    const CReissueAsset& r,
    unsigned char selector,
    std::vector<unsigned char>& result)
{
    switch (selector) {
        case 0x01:
            result.assign(r.strName.begin(), r.strName.end());
            return true;
        case 0x02: {
            result.resize(8);
            const int64_t v = static_cast<int64_t>(r.nAmount);
            memcpy(result.data(), &v, 8);
            return true;
        }
        case 0x03:
            // nUnits: -1 (0xff) = unchanged, 0..8 = explicit value
            result = {static_cast<unsigned char>(r.nUnits)};
            return true;
        case 0x04:
            // nReissuable: always 0 or 1 in valid reissues (no sentinel)
            result = {static_cast<unsigned char>(r.nReissuable)};
            return true;
        case 0x06:
            if (r.strIPFSHash.empty())
                return false;
            result.assign(r.strIPFSHash.begin(), r.strIPFSHash.end());
            return true;
        case 0x07:
            result = {static_cast<unsigned char>(IntFromAssetType(AssetType::REISSUE))};
            return true;
        default:
            return false;
    }
}

static bool ExtractAssetField_Owner(
    const std::string& ownerName,
    unsigned char selector,
    std::vector<unsigned char>& result)
{
    switch (selector) {
        case 0x01:
            result.assign(ownerName.begin(), ownerName.end());
            return true;
        case 0x02: {
            result.resize(8);
            const int64_t v = static_cast<int64_t>(OWNER_ASSET_AMOUNT);
            memcpy(result.data(), &v, 8);
            return true;
        }
        case 0x07:
            result = {static_cast<unsigned char>(IntFromAssetType(AssetType::OWNER))};
            return true;
        default:
            return false;
    }
}

namespace
{

    inline bool set_success(ScriptError *ret)
    {
        if (ret)
            *ret = SCRIPT_ERR_OK;
        return true;
    }

    inline bool set_error(ScriptError *ret, const ScriptError serror)
    {
        if (ret)
            *ret = serror;
        return false;
    }

} // namespace

bool CastToBool(const valtype &vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size() - 1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))

static inline void popstack(std::vector<valtype> &stack)
{
    if (stack.empty())
        throw std::runtime_error("popstack(): stack empty");
    stack.pop_back();
}

bool static IsCompressedOrUncompressedPubKey(const valtype &vchPubKey)
{
    if (vchPubKey.size() < 33)
    {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04)
    {
        if (vchPubKey.size() != 65)
        {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    }
    else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03)
    {
        if (vchPubKey.size() != 33)
        {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    }
    else
    {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

bool static IsPostQuantumPubKey(const valtype &vchPubKey)
{
    return vchPubKey.size() == 1 + ML_DSA_44_PUBKEY_SIZE && !vchPubKey.empty() && vchPubKey[0] == 0x05;
}

bool static IsCompressedPubKey(const valtype &vchPubKey)
{
    if (vchPubKey.size() != 33)
    {
        //  Non-canonical public key: invalid length for compressed keys
        return false;
    }
    if (vchPubKey[0] != 0x02 && vchPubKey[0] != 0x03)
    {
        //  Non-canonical public key: invalid prefix for compressed key
        return false;
    }
    return true;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 *
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool static IsValidSignatureEncoding(const std::vector<unsigned char> &sig)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t) (lenR + lenS + 7) != sig.size()) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

bool static IsLowDERSignature(const valtype &vchSig, ScriptError *serror)
{
    if (!IsValidSignatureEncoding(vchSig))
    {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    if (!CPubKey::CheckLowS(vchSigCopy))
    {
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    }
    return true;
}

bool static IsDefinedHashtypeSignature(const valtype &vchSig)
{
    if (vchSig.size() == 0)
    {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, script_verify_flags flags, ScriptError *serror)
{
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0)
    {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig))
    {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror))
    {
        // serror is set
        return false;
    }
    else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig))
    {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool static CheckSignatureEncodingForPubKey(const std::vector<unsigned char> &vchSig, const valtype& vchPubKey, script_verify_flags flags, ScriptError *serror)
{
    if (!IsPostQuantumPubKey(vchPubKey)) {
        return CheckSignatureEncoding(vchSig, flags, serror);
    }

    // Empty signatures remain allowed to support deliberately-invalid CHECKSIG paths.
    if (vchSig.empty()) {
        return true;
    }

    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 &&
        vchSig.size() != ML_DSA_44_SIG_SIZE + 1) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }

    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }

    return true;
}

bool static CheckPubKeyEncoding(const valtype &vchPubKey, script_verify_flags flags, const SigVersion &sigversion, ScriptError *serror)
{
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 &&
        !IsCompressedOrUncompressedPubKey(vchPubKey) &&
        !IsPostQuantumPubKey(vchPubKey))
    {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    // Only compressed keys are accepted in segwit
    if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 &&
        sigversion == SIGVERSION_WITNESS_V0 &&
        !IsCompressedPubKey(vchPubKey) &&
        !IsPostQuantumPubKey(vchPubKey))
    {
        return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
    }
    return true;
}

bool static CheckMinimalPush(const valtype &data, opcodetype opcode)
{
    if (data.size() == 0)
    {
        // Could have used OP_0.
        return opcode == OP_0;
    }
    else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16)
    {
        // Could have used OP_1 .. OP_16.
        return opcode == OP_1 + (data[0] - 1);
    }
    else if (data.size() == 1 && data[0] == 0x81)
    {
        // Could have used OP_1NEGATE.
        return opcode == OP_1NEGATE;
    }
    else if (data.size() <= 75)
    {
        // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    }
    else if (data.size() <= 255)
    {
        // Could have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    }
    else if (data.size() <= 65535)
    {
        // Could have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

bool EvalScript(std::vector<std::vector<unsigned char> > &stack, const CScript &script, script_verify_flags flags, const BaseSignatureChecker &checker, SigVersion sigversion, ScriptError *serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    // static const CScriptNum bnFalse(0);
    // static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    // static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    std::vector<bool> vfExec;
    std::vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if (script.size() > MAX_SCRIPT_SIZE)
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    int nOpCount = 0;
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;

    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > EffectiveMaxScriptElementSize(flags))
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
                return set_error(serror, SCRIPT_ERR_OP_COUNT);

            // OP_CAT (BIP 347): enabled via SCRIPT_VERIFY_CAT flag
            if (opcode == OP_CAT && (flags & SCRIPT_VERIFY_CAT)) {
                // (x1 x2 -- x1+x2)
                if (stack.size() < 2)
                    return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                valtype& vch1 = stacktop(-2);
                valtype& vch2 = stacktop(-1);

                // Security: concatenation must not exceed the effective per-element size cap.
                // NIP-018: the cap is 3072 when SCRIPT_VERIFY_CHECKSIGFROMSTACK is set, 520 otherwise.
                if (vch1.size() + vch2.size() > EffectiveMaxScriptElementSize(flags))
                    return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

                // Concatenate vch2 onto vch1
                vch1.insert(vch1.end(), vch2.begin(), vch2.end());

                // Remove vch2 from stack
                popstack(stack);

                // OP_CAT was handled here — skip the main opcode switch below
                // (which would fall through to `default: BAD_OPCODE` since OP_CAT
                //  has no case statement there).
                continue;
            }
            else if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                (opcode == OP_MUL && !(flags & SCRIPT_VERIFY_64BIT_INTEGERS)) ||
                (opcode == OP_DIV && !(flags & SCRIPT_VERIFY_64BIT_INTEGERS)) ||
                (opcode == OP_MOD && !(flags & SCRIPT_VERIFY_64BIT_INTEGERS)) ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes.

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4)
            {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode))
                {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            }
            else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            {
                const size_t nMaxNum = (flags & SCRIPT_VERIFY_64BIT_INTEGERS)
                    ? 8
                    : CScriptNum::nDefaultMaxNumSize;

                switch (opcode)
                {
                    //
                    // Push value
                    //
                    case OP_1NEGATE:
                    case OP_1:
                    case OP_2:
                    case OP_3:
                    case OP_4:
                    case OP_5:
                    case OP_6:
                    case OP_7:
                    case OP_8:
                    case OP_9:
                    case OP_10:
                    case OP_11:
                    case OP_12:
                    case OP_13:
                    case OP_14:
                    case OP_15:
                    case OP_16:
                    {
                        // ( -- value)
                        CScriptNum bn((int) opcode - (int) (OP_1 - 1));
                        stack.push_back(bn.getvch());
                        // The result of these opcodes should always be the minimal way to push the data
                        // they push, so no need for a CheckMinimalPush here.
                    }
                        break;

                        //
                        // Control
                        //
                    case OP_NOP:
                        break;
                    case OP_CHECKLOCKTIMEVERIFY:
                    {
                        if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY))
                        {
                            // not enabled; treat as a NOP2
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            {
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            }
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        // Note that elsewhere numeric opcodes are limited to
                        // operands in the range -2**31+1 to 2**31-1, however it is
                        // legal for opcodes to produce results exceeding that
                        // range. This limitation is implemented by CScriptNum's
                        // default 4-byte limit.
                        //
                        // If we kept to that limit we'd have a year 2038 problem,
                        // even though the nLockTime field in transactions
                        // themselves is uint32 which only becomes meaningless
                        // after the year 2106.
                        //
                        // Thus as a special case we tell CScriptNum to accept up
                        // to 5-byte bignums, which are good until 2**39-1, well
                        // beyond the 2**32-1 limit of the nLockTime field itself.
                        const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                        // In the rare event that the argument may be < 0 due to
                        // some arithmetic being done first, you can always use
                        // 0 MAX CHECKLOCKTIMEVERIFY.
                        if (nLockTime < 0)
                            return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                        // Actually compare the specified lock time with the transaction.
                        if (!checker.CheckLockTime(nLockTime))
                            return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                        break;
                    }
                    case OP_CHECKSEQUENCEVERIFY:
                    {
                        if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY))
                        {
                            // not enabled; treat as a NOP3
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            {
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            }
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        // nSequence, like nLockTime, is a 32-bit unsigned integer
                        // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                        // 5-byte numeric operands.
                        const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                        // In the rare event that the argument may be < 0 due to
                        // some arithmetic being done first, you can always use
                        // 0 MAX CHECKSEQUENCEVERIFY.
                        if (nSequence < 0)
                            return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                        // To provide for future soft-fork extensibility, if the
                        // operand has the disabled lock-time flag set,
                        // CHECKSEQUENCEVERIFY behaves as a NOP.
                        if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                            break;

                        // Compare the specified sequence number with the input.
                        if (!checker.CheckSequence(nSequence))
                            return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                        break;
                    }
                    case OP_CHECKTEMPLATEVERIFY:
                    {
                        if (!(flags & SCRIPT_VERIFY_CHECKTEMPLATEVERIFY))
                        {
                            // not enabled; treat as a NOP4
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            {
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            }
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchHash = stacktop(-1);

                        // BIP 119: if the argument is not exactly 32 bytes, treat as NOP
                        // (future upgrade path). Under DISCOURAGE_UPGRADABLE_NOPS, reject
                        // by policy (standardness) but NOT by consensus.
                        if (vchHash.size() != 32)
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (!checker.CheckTemplateVerify(vchHash))
                            return set_error(serror, SCRIPT_ERR_CHECKTEMPLATEVERIFY);

                        // NOP-upgrade semantics: do NOT pop the hash from the stack
                        break;
                    }
                    case OP_CHECKSIGFROMSTACK:
                    {
                        if (!(flags & SCRIPT_VERIFY_CHECKSIGFROMSTACK))
                        {
                            // not enabled; treat as a NOP5
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            {
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            }
                            break;
                        }

                        // (sig msg pubkey -- bool)
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        valtype& vchSig = stacktop(-3);
                        valtype& vchMsg = stacktop(-2);
                        valtype& vchPubKey = stacktop(-1);

                        // Validate signature and pubkey encoding (same rules as OP_CHECKSIG)
                        if (!CheckSignatureEncodingForPubKey(vchSig, vchPubKey, flags, serror) ||
                            !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
                        {
                            // serror is set
                            return false;
                        }

                        bool fSuccess = checker.CheckSigFromStack(vchSig, vchMsg, vchPubKey);

                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fSuccess ? vchTrue : vchFalse);
                    }
                        break;

                    case OP_TXHASH:
                    {
                        if (!(flags & SCRIPT_VERIFY_TXHASH))
                        {
                            // not enabled; treat as a NOP6
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            {
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            }
                            break;
                        }

                        // (field_selector -- hash)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_TXHASH);

                        unsigned char fieldSelector = vchSelector[0];
                        valtype vchHash;
                        if (!checker.GetTxFieldHash(fieldSelector, vchHash))
                            return set_error(serror, SCRIPT_ERR_TXHASH);

                        popstack(stack);
                        stack.push_back(vchHash);
                    }
                        break;

                    case OP_TXFIELD:    // NOP7 = 0xb6
                    {
                        if (!(flags & SCRIPT_VERIFY_TXFIELD))
                        {
                            // Not activated: treat as NOP7
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        // (selector -- raw_field_bytes)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_TXFIELD);

                        unsigned char fieldSelector = vchSelector[0];
                        valtype vchField;
                        if (!checker.GetTxField(fieldSelector, vchField))
                            return set_error(serror, SCRIPT_ERR_TXFIELD);

                        // NIP-018: size check lifted from the checker; keep
                        // SCRIPT_ERR_TXFIELD to preserve opcode semantics.
                        if (vchField.size() > EffectiveMaxScriptElementSize(flags))
                            return set_error(serror, SCRIPT_ERR_TXFIELD);

                        popstack(stack);
                        stack.push_back(vchField);
                    }
                        break;

                    case OP_SPLIT:      // NOP8 = 0xb7
                    {
                        if (!(flags & SCRIPT_VERIFY_SPLIT))
                        {
                            // Not activated: treat as NOP8
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        // (data n -- data[0..n-1] data[n..])
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        // Read split position as CScriptNum (same as OP_PICK/OP_ROLL)
                        const int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        popstack(stack);

                        const valtype& vchData = stacktop(-1);

                        // Validate range: 0 <= n <= len(data)
                        if (n < 0 || n > (int)vchData.size())
                            return set_error(serror, SCRIPT_ERR_SPLIT);

                        // Build the two halves
                        valtype vchLeft(vchData.begin(), vchData.begin() + n);
                        valtype vchRight(vchData.begin() + n, vchData.end());

                        // Replace data on stack with the two fragments
                        popstack(stack);
                        stack.push_back(vchLeft);
                        stack.push_back(vchRight);
                    }
                        break;

                    case OP_REVERSEBYTES:
                    {
                        if (!(flags & SCRIPT_VERIFY_REVERSEBYTES))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        valtype& vch = stacktop(-1);
                        std::reverse(vch.begin(), vch.end());
                    }
                        break;

                    case OP_OUTPUTVALUE:
                    {
                        if (!(flags & SCRIPT_VERIFY_OUTPUTVALUE))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const int nOut = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        if (nOut < 0)
                            return set_error(serror, SCRIPT_ERR_OUTPUTVALUE);

                        valtype vchValue;
                        if (!checker.GetOutputValue((unsigned int)nOut, vchValue))
                            return set_error(serror, SCRIPT_ERR_OUTPUTVALUE);

                        if ((flags & SCRIPT_VERIFY_64BIT_INTEGERS) && vchValue.size() == 8)
                        {
                            int64_t nValue;
                            memcpy(&nValue, vchValue.data(), 8);
                            vchValue = CScriptNum(nValue).getvch();
                        }

                        popstack(stack);
                        stack.push_back(vchValue);
                    }
                        break;

                    case OP_OUTPUTSCRIPT:
                    {
                        if (!(flags & SCRIPT_VERIFY_OUTPUTSCRIPT))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const int nOut = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        if (nOut < 0)
                            return set_error(serror, SCRIPT_ERR_OUTPUTSCRIPT);

                        valtype vchScript;
                        if (!checker.GetOutputScript((unsigned int)nOut, vchScript))
                            return set_error(serror, SCRIPT_ERR_OUTPUTSCRIPT);

                        // NIP-018: size check lifted from the checker; keep
                        // SCRIPT_ERR_OUTPUTSCRIPT to preserve opcode semantics.
                        if (vchScript.size() > EffectiveMaxScriptElementSize(flags))
                            return set_error(serror, SCRIPT_ERR_OUTPUTSCRIPT);

                        popstack(stack);
                        stack.push_back(vchScript);
                    }
                        break;

                    case OP_INPUTVALUE:
                    {
                        // NIP-024: push the XNA satoshi value of a selected
                        // input's prevout (raw 8-byte LE, or CScriptNum under
                        // the 64-bit-integers opt-in). Symmetric to OP_OUTPUTVALUE.
                        if (!(flags & SCRIPT_VERIFY_INPUTVALUE))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const int nInput = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        if (nInput < 0)
                            return set_error(serror, SCRIPT_ERR_INPUTVALUE);

                        valtype vchValue;
                        if (!checker.GetInputValue((unsigned int)nInput, vchValue))
                            return set_error(serror, SCRIPT_ERR_INPUTVALUE);

                        if ((flags & SCRIPT_VERIFY_64BIT_INTEGERS) && vchValue.size() == 8)
                        {
                            int64_t nValue;
                            memcpy(&nValue, vchValue.data(), 8);
                            vchValue = CScriptNum(nValue).getvch();
                        }

                        popstack(stack);
                        stack.push_back(vchValue);
                    }
                        break;

                    case OP_CHAINCONTEXT:
                    {
                        // NIP-026: push a chain-position field (HEIGHT, MTP,
                        // CHAIN_ID) selected by a 1-byte value on the stack.
                        //
                        // Flag-off path MUST fail with BAD_OPCODE — not NOP.
                        // 0xd7 is a newly-allocated opcode byte, so pre-upgrade
                        // nodes reject it via the `default:` branch below. If
                        // we fell through to `break` here, a new node with the
                        // flag off would execute it as NOP, accepting txs that
                        // pre-upgrade nodes reject — a consensus split.
                        // DISCOURAGE_UPGRADABLE_NOPS is policy-only and cannot
                        // protect against a mined block. See NIP-026 §3.7/§3.8.
                        if (!(flags & SCRIPT_VERIFY_CHAINCONTEXT))
                            return set_error(serror, SCRIPT_ERR_BAD_OPCODE);

                        // Hard dependency on SCRIPT_VERIFY_64BIT_INTEGERS:
                        // MTP after 2038 exceeds the 4-byte CScriptNum limit,
                        // and comparison opcodes (OP_GREATERTHAN, ...) reject
                        // values > nMaxNum. Without the 64-bit flag the pushed
                        // value would be unusable by downstream arithmetic.
                        // ApplyConsensusOptIns co-sets the pair (§3.4); this
                        // runtime check is belt-and-braces.
                        if (!(flags & SCRIPT_VERIFY_64BIT_INTEGERS))
                            return set_error(serror, SCRIPT_ERR_CHAINCONTEXT);

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_CHAINCONTEXT_BAD_SELECTOR);
                        const unsigned char selector = vchSelector[0];

                        if (selector < 0x01 || selector > 0x03)
                            return set_error(serror, SCRIPT_ERR_CHAINCONTEXT_BAD_SELECTOR);

                        int64_t value = 0;
                        if (!checker.GetChainContext(selector, value))
                            return set_error(serror, SCRIPT_ERR_CHAINCONTEXT);

                        // Record that this script exercised OP_CHAINCONTEXT.
                        // Mempool admission reads this bit after VerifyScript
                        // to decide whether the entry must be re-validated on
                        // every new tip (§3.9).
                        checker.fChainContextObserved = true;

                        popstack(stack);
                        stack.push_back(CScriptNum(value).getvch());
                    }
                        break;

                    case OP_OUTPUTAUTHCOMMITMENT:
                    {
                        // NIP-023: push the 32-byte AuthScript v1 commitment
                        // from a selected output's scriptPubKey.
                        if (!(flags & SCRIPT_VERIFY_OUTPUTAUTHCOMMITMENT))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const int nOut = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        if (nOut < 0)
                            return set_error(serror, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);

                        valtype vchResult;
                        if (!checker.GetOutputAuthCommitment((unsigned int)nOut, vchResult))
                            return set_error(serror, SCRIPT_ERR_OUTPUTAUTHCOMMITMENT);

                        popstack(stack);
                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_OUTPUTASSETFIELD:
                    {
                        if (!(flags & SCRIPT_VERIFY_OUTPUTASSETFIELD))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_OUTPUTASSETFIELD);
                        const unsigned char selector = vchSelector[0];

                        const int nOut = CScriptNum(stacktop(-2), fRequireMinimal).getint();
                        if (nOut < 0)
                            return set_error(serror, SCRIPT_ERR_OUTPUTASSETFIELD);

                        if (selector == 0x00 || selector >= 0x08)
                            return set_error(serror, SCRIPT_ERR_OUTPUTASSETFIELD);

                        valtype vchResult;
                        if (!checker.GetOutputAssetField(static_cast<unsigned int>(nOut), selector, vchResult))
                            return set_error(serror, SCRIPT_ERR_OUTPUTASSETFIELD);

                        if (selector == 0x02 && (flags & SCRIPT_VERIFY_64BIT_INTEGERS) && vchResult.size() == 8)
                        {
                            int64_t nAmount;
                            memcpy(&nAmount, vchResult.data(), 8);
                            vchResult = CScriptNum(nAmount).getvch();
                        }

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_INPUTASSETFIELD:
                    {
                        if (!(flags & SCRIPT_VERIFY_INPUTASSETFIELD))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_INPUTASSETFIELD);
                        const unsigned char selector = vchSelector[0];

                        const int nInput = CScriptNum(stacktop(-2), fRequireMinimal).getint();
                        if (nInput < 0)
                            return set_error(serror, SCRIPT_ERR_INPUTASSETFIELD);

                        if (selector == 0x00 || selector >= 0x08)
                            return set_error(serror, SCRIPT_ERR_INPUTASSETFIELD);

                        valtype vchResult;
                        if (!checker.GetInputAssetField(static_cast<unsigned int>(nInput), selector, vchResult))
                            return set_error(serror, SCRIPT_ERR_INPUTASSETFIELD);

                        if (selector == 0x02 && (flags & SCRIPT_VERIFY_64BIT_INTEGERS) && vchResult.size() == 8)
                        {
                            int64_t nAmount;
                            memcpy(&nAmount, vchResult.data(), 8);
                            vchResult = CScriptNum(nAmount).getvch();
                        }

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_INPUTCOUNT:
                    {
                        if (!(flags & SCRIPT_VERIFY_INPUTOUTPUTCOUNT))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        valtype vchResult;
                        if (!checker.GetInputCount(vchResult))
                            return set_error(serror, SCRIPT_ERR_INPUTOUTPUTCOUNT);

                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_OUTPUTCOUNT:
                    {
                        if (!(flags & SCRIPT_VERIFY_INPUTOUTPUTCOUNT))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        valtype vchResult;
                        if (!checker.GetOutputCount(vchResult))
                            return set_error(serror, SCRIPT_ERR_INPUTOUTPUTCOUNT);

                        stack.push_back(vchResult);
                    }
                        break;

                    // =====================================================
                    // NIP-017: OP_REFINPUT* family (reference input
                    // introspection, gated by SCRIPT_VERIFY_REFINPUTS)
                    // =====================================================

                    case OP_REFINPUTCOUNT:
                    {
                        if (!(flags & SCRIPT_VERIFY_REFINPUTS))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        valtype vchResult;
                        if (!checker.GetRefInputCount(vchResult))
                            return set_error(serror, SCRIPT_ERR_REFINPUTCOUNT);

                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_REFINPUTFIELD:
                    {
                        if (!(flags & SCRIPT_VERIFY_REFINPUTS))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        // (nRef selector -- field_bytes)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_REFINPUTFIELD);
                        const unsigned char selector = vchSelector[0];

                        const int nRef = CScriptNum(stacktop(-2), fRequireMinimal).getint();
                        if (nRef < 0)
                            return set_error(serror, SCRIPT_ERR_REFINPUTFIELD);

                        // Selectors 0x01-0x03 valid (value, authcommitment, scriptPubKey)
                        if (selector == 0x00 || selector >= 0x04)
                            return set_error(serror, SCRIPT_ERR_REFINPUTFIELD);

                        valtype vchResult;
                        if (!checker.GetRefInputField(static_cast<unsigned int>(nRef), selector, vchResult))
                            return set_error(serror, SCRIPT_ERR_REFINPUTFIELD);

                        // NIP-018: size check lifted from the checker (selector
                        // 0x03 returns a scriptPubKey). Keep SCRIPT_ERR_REFINPUTFIELD
                        // to preserve opcode semantics.
                        if (vchResult.size() > EffectiveMaxScriptElementSize(flags))
                            return set_error(serror, SCRIPT_ERR_REFINPUTFIELD);

                        // Selector 0x01 (nValue): convert to CScriptNum if 64-bit integers enabled
                        if (selector == 0x01 && (flags & SCRIPT_VERIFY_64BIT_INTEGERS) && vchResult.size() == 8)
                        {
                            int64_t nValue;
                            memcpy(&nValue, vchResult.data(), 8);
                            vchResult = CScriptNum(nValue).getvch();
                        }

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_REFINPUTASSETFIELD:
                    {
                        if (!(flags & SCRIPT_VERIFY_REFINPUTS))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        // (nRef selector -- asset_field_bytes)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const valtype& vchSelector = stacktop(-1);
                        if (vchSelector.size() != 1)
                            return set_error(serror, SCRIPT_ERR_REFINPUTASSETFIELD);
                        const unsigned char selector = vchSelector[0];

                        const int nRef = CScriptNum(stacktop(-2), fRequireMinimal).getint();
                        if (nRef < 0)
                            return set_error(serror, SCRIPT_ERR_REFINPUTASSETFIELD);

                        // Selectors 0x01-0x07 valid (same as OP_OUTPUTASSETFIELD)
                        if (selector == 0x00 || selector >= 0x08)
                            return set_error(serror, SCRIPT_ERR_REFINPUTASSETFIELD);

                        valtype vchResult;
                        if (!checker.GetRefInputAssetField(static_cast<unsigned int>(nRef), selector, vchResult))
                            return set_error(serror, SCRIPT_ERR_REFINPUTASSETFIELD);

                        // Selector 0x02 (amount): convert to CScriptNum if 64-bit integers enabled
                        if (selector == 0x02 && (flags & SCRIPT_VERIFY_64BIT_INTEGERS) && vchResult.size() == 8)
                        {
                            int64_t nAmount;
                            memcpy(&nAmount, vchResult.data(), 8);
                            vchResult = CScriptNum(nAmount).getvch();
                        }

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(vchResult);
                    }
                        break;

                    case OP_TXLOCKTIME:
                    {
                        if (!(flags & SCRIPT_VERIFY_TXLOCKTIME))
                        {
                            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                            break;
                        }

                        valtype vchLockTime;
                        if (!checker.GetTxLockTime(vchLockTime))
                            return set_error(serror, SCRIPT_ERR_TXLOCKTIME);

                        stack.push_back(vchLockTime);
                    }
                        break;

                    // NOP1, NOP9, NOP10 remain as generic upgradable NOPs.
                    // NOP7 (OP_TXFIELD) and NOP8 (OP_SPLIT) have their own cases above.
                    case OP_NOP1:
                    case OP_NOP9:
                    case OP_NOP10:
                    {
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                    }
                        break;
                    case OP_IF:
                    case OP_NOTIF:
                    {
                        // <expression> if [statements] [else [statements]] endif
                        bool fValue = false;
                        if (fExec)
                        {
                            if (stack.size() < 1)
                                return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                            valtype &vch = stacktop(-1);
                            if (sigversion == SIGVERSION_WITNESS_V0 && (flags & SCRIPT_VERIFY_MINIMALIF))
                            {
                                if (vch.size() > 1)
                                    return set_error(serror, SCRIPT_ERR_MINIMALIF);
                                if (vch.size() == 1 && vch[0] != 1)
                                    return set_error(serror, SCRIPT_ERR_MINIMALIF);
                            }
                            fValue = CastToBool(vch);
                            if (opcode == OP_NOTIF)
                                fValue = !fValue;
                            popstack(stack);
                        }
                        vfExec.push_back(fValue);
                    }
                        break;
                    case OP_ELSE:
                    {
                        if (vfExec.empty())
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        vfExec.back() = !vfExec.back();
                    }
                        break;

                    case OP_ENDIF:
                    {
                        if (vfExec.empty())
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        vfExec.pop_back();
                    }
                        break;
                    case OP_VERIFY:
                    {
                        // (true -- ) or
                        // (false -- false) and return
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        bool fValue = CastToBool(stacktop(-1));
                        if (fValue)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_VERIFY);
                    }
                        break;
                    case OP_RETURN:
                    {
                        return set_error(serror, SCRIPT_ERR_OP_RETURN);
                    }
                        break;

                        //
                        // Stack ops
                        //
                    case OP_TOALTSTACK:
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        altstack.push_back(stacktop(-1));
                        popstack(stack);
                    }
                        break;
                    case OP_FROMALTSTACK:
                    {
                        if (altstack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                        stack.push_back(altstacktop(-1));
                        popstack(altstack);
                    }
                        break;
                    case OP_2DROP:
                    {
                        // (x1 x2 -- )
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        popstack(stack);
                        popstack(stack);
                    }
                        break;
                    case OP_2DUP:
                    {
                        // (x1 x2 -- x1 x2 x1 x2)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch1 = stacktop(-2);
                        valtype vch2 = stacktop(-1);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                        break;
                    case OP_3DUP:
                    {
                        // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch1 = stacktop(-3);
                        valtype vch2 = stacktop(-2);
                        valtype vch3 = stacktop(-1);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                        stack.push_back(vch3);
                    }
                        break;

                    case OP_2OVER:
                    {
                        // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                        if (stack.size() < 4)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch1 = stacktop(-4);
                        valtype vch2 = stacktop(-3);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                        break;

                    case OP_2ROT:
                    {
                        // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                        if (stack.size() < 6)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch1 = stacktop(-6);
                        valtype vch2 = stacktop(-5);
                        stack.erase(stack.end() - 6, stack.end() - 4);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                        break;

                    case OP_2SWAP:
                    {
                        // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                        if (stack.size() < 4)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        swap(stacktop(-4), stacktop(-2));
                        swap(stacktop(-3), stacktop(-1));
                    }
                        break;

                    case OP_IFDUP:
                    {
                        // (x - 0 | x x)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch = stacktop(-1);
                        if (CastToBool(vch))
                            stack.push_back(vch);
                    }
                        break;

                    case OP_DEPTH:
                    {
                        // -- stacksize
                        CScriptNum bn(stack.size());
                        stack.push_back(bn.getvch());
                    }
                        break;

                    case OP_DROP:
                    {
                        // (x -- )
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        popstack(stack);
                    }
                        break;

                    case OP_DUP:
                    {
                        // (x -- x x)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch = stacktop(-1);
                        stack.push_back(vch);
                    }
                        break;

                    case OP_NIP:
                    {
                        // (x1 x2 -- x2)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        stack.erase(stack.end() - 2);
                    }
                        break;

                    case OP_OVER:
                    {
                        // (x1 x2 -- x1 x2 x1)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch = stacktop(-2);
                        stack.push_back(vch);
                    }
                        break;

                    case OP_PICK:
                    case OP_ROLL:
                    {
                        // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                        // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                        popstack(stack);
                        if (n < 0 || n >= (int) stack.size())
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch = stacktop(-n - 1);
                        if (opcode == OP_ROLL)
                            stack.erase(stack.end() - n - 1);
                        stack.push_back(vch);
                    }
                        break;

                    case OP_ROT:
                    {
                        // (x1 x2 x3 -- x2 x3 x1)
                        //  x2 x1 x3  after first swap
                        //  x2 x3 x1  after second swap
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        swap(stacktop(-3), stacktop(-2));
                        swap(stacktop(-2), stacktop(-1));
                    }
                        break;

                    case OP_SWAP:
                    {
                        // (x1 x2 -- x2 x1)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        swap(stacktop(-2), stacktop(-1));
                    }
                        break;

                    case OP_TUCK:
                    {
                        // (x1 x2 -- x2 x1 x2)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype vch = stacktop(-1);
                        stack.insert(stack.end() - 2, vch);
                    }
                        break;


                    case OP_SIZE:
                    {
                        // (in -- in size)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn(stacktop(-1).size());
                        stack.push_back(bn.getvch());
                    }
                        break;


                        //
                        // Bitwise logic
                        //
                    case OP_EQUAL:
                    case OP_EQUALVERIFY:
                        //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                    {
                        // (x1 x2 - bool)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype &vch1 = stacktop(-2);
                        valtype &vch2 = stacktop(-1);
                        bool fEqual = (vch1 == vch2);
                        // OP_NOTEQUAL is disabled because it would be too easy to say
                        // something like n != 1 and have some wiseguy pass in 1 with extra
                        // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                        //if (opcode == OP_NOTEQUAL)
                        //    fEqual = !fEqual;
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fEqual ? vchTrue : vchFalse);
                        if (opcode == OP_EQUALVERIFY)
                        {
                            if (fEqual)
                                popstack(stack);
                            else
                                return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                        }
                    }
                        break;


                        //
                        // Numeric
                        //
                    case OP_1ADD:
                    case OP_1SUB:
                    case OP_NEGATE:
                    case OP_ABS:
                    case OP_NOT:
                    case OP_0NOTEQUAL:
                    {
                        // (in -- out)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn(stacktop(-1), fRequireMinimal, nMaxNum);
                        if (flags & SCRIPT_VERIFY_64BIT_INTEGERS)
                        {
                            const int64_t v = bn.getint64();
                            int64_t result = 0;
                            switch (opcode)
                            {
                                case OP_1ADD:
                                    if (!AddOverflow64(v, 1, result))
                                        return set_error(serror, SCRIPT_ERR_ADD_OVERFLOW);
                                    break;
                                case OP_1SUB:
                                    if (!SubOverflow64(v, 1, result))
                                        return set_error(serror, SCRIPT_ERR_SUB_OVERFLOW);
                                    break;
                                case OP_NEGATE:
                                    if (v == std::numeric_limits<int64_t>::min())
                                        return set_error(serror, SCRIPT_ERR_NEGATE_OVERFLOW);
                                    result = -v;
                                    break;
                                case OP_ABS:
                                    if (v == std::numeric_limits<int64_t>::min())
                                        return set_error(serror, SCRIPT_ERR_NEGATE_OVERFLOW);
                                    result = (v < 0) ? -v : v;
                                    break;
                                case OP_NOT:
                                    result = (v == 0);
                                    break;
                                case OP_0NOTEQUAL:
                                    result = (v != 0);
                                    break;
                                default:
                                    assert(!"invalid opcode");
                                    break;
                            }
                            popstack(stack);
                            stack.push_back(CScriptNum(result).getvch());
                            break;
                        }
                        switch (opcode)
                        {
                            case OP_1ADD:
                                bn += bnOne;
                                break;
                            case OP_1SUB:
                                bn -= bnOne;
                                break;
                            case OP_NEGATE:
                                bn = -bn;
                                break;
                            case OP_ABS:
                                if (bn < bnZero) bn = -bn;
                                break;
                            case OP_NOT:
                                bn = (bn == bnZero);
                                break;
                            case OP_0NOTEQUAL:
                                bn = (bn != bnZero);
                                break;
                            default:
                                assert(!"invalid opcode");
                                break;
                        }
                        popstack(stack);
                        stack.push_back(bn.getvch());
                    }
                        break;

                    case OP_ADD:
                    case OP_SUB:
                    case OP_BOOLAND:
                    case OP_BOOLOR:
                    case OP_NUMEQUAL:
                    case OP_NUMEQUALVERIFY:
                    case OP_NUMNOTEQUAL:
                    case OP_LESSTHAN:
                    case OP_GREATERTHAN:
                    case OP_LESSTHANOREQUAL:
                    case OP_GREATERTHANOREQUAL:
                    case OP_MIN:
                    case OP_MAX:
                    {
                        // (x1 x2 -- out)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn1(stacktop(-2), fRequireMinimal, nMaxNum);
                        CScriptNum bn2(stacktop(-1), fRequireMinimal, nMaxNum);
                        CScriptNum bn(0);
                        switch (opcode)
                        {
                            case OP_ADD:
                                if (flags & SCRIPT_VERIFY_64BIT_INTEGERS) {
                                    int64_t result;
                                    if (!AddOverflow64(bn1.getint64(), bn2.getint64(), result))
                                        return set_error(serror, SCRIPT_ERR_ADD_OVERFLOW);
                                    bn = CScriptNum(result);
                                } else {
                                    bn = bn1 + bn2;
                                }
                                break;

                            case OP_SUB:
                                if (flags & SCRIPT_VERIFY_64BIT_INTEGERS) {
                                    int64_t result;
                                    if (!SubOverflow64(bn1.getint64(), bn2.getint64(), result))
                                        return set_error(serror, SCRIPT_ERR_SUB_OVERFLOW);
                                    bn = CScriptNum(result);
                                } else {
                                    bn = bn1 - bn2;
                                }
                                break;

                            case OP_BOOLAND:
                                bn = (bn1 != bnZero && bn2 != bnZero);
                                break;
                            case OP_BOOLOR:
                                bn = (bn1 != bnZero || bn2 != bnZero);
                                break;
                            case OP_NUMEQUAL:
                                bn = (bn1 == bn2);
                                break;
                            case OP_NUMEQUALVERIFY:
                                bn = (bn1 == bn2);
                                break;
                            case OP_NUMNOTEQUAL:
                                bn = (bn1 != bn2);
                                break;
                            case OP_LESSTHAN:
                                bn = (bn1 < bn2);
                                break;
                            case OP_GREATERTHAN:
                                bn = (bn1 > bn2);
                                break;
                            case OP_LESSTHANOREQUAL:
                                bn = (bn1 <= bn2);
                                break;
                            case OP_GREATERTHANOREQUAL:
                                bn = (bn1 >= bn2);
                                break;
                            case OP_MIN:
                                bn = (bn1 < bn2 ? bn1 : bn2);
                                break;
                            case OP_MAX:
                                bn = (bn1 > bn2 ? bn1 : bn2);
                                break;
                            default:
                                assert(!"invalid opcode");
                                break;
                        }
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(bn.getvch());

                        if (opcode == OP_NUMEQUALVERIFY)
                        {
                            if (CastToBool(stacktop(-1)))
                                popstack(stack);
                            else
                                return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                        }
                    }
                        break;

                    case OP_WITHIN:
                    {
                        // (x min max -- out)
                        if (stack.size() < 3)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn1(stacktop(-3), fRequireMinimal, nMaxNum);
                        CScriptNum bn2(stacktop(-2), fRequireMinimal, nMaxNum);
                        CScriptNum bn3(stacktop(-1), fRequireMinimal, nMaxNum);
                        bool fValue = (bn2 <= bn1 && bn1 < bn3);
                        popstack(stack);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fValue ? vchTrue : vchFalse);
                    }
                        break;

                    case OP_MUL:
                    {
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn1(stacktop(-2), fRequireMinimal, nMaxNum);
                        CScriptNum bn2(stacktop(-1), fRequireMinimal, nMaxNum);
                        int64_t result;
                        if (!MulOverflow64(bn1.getint64(), bn2.getint64(), result))
                            return set_error(serror, SCRIPT_ERR_MUL_OVERFLOW);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(CScriptNum(result).getvch());
                    }
                        break;

                    case OP_DIV:
                    {
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn1(stacktop(-2), fRequireMinimal, nMaxNum);
                        CScriptNum bn2(stacktop(-1), fRequireMinimal, nMaxNum);
                        const int64_t a = bn1.getint64();
                        const int64_t b = bn2.getint64();
                        if (b == 0)
                            return set_error(serror, SCRIPT_ERR_DIV_BY_ZERO);
                        if (a == std::numeric_limits<int64_t>::min() && b == -1)
                            return set_error(serror, SCRIPT_ERR_DIV_OVERFLOW);
                        const int64_t result = a / b;
                        if (result == std::numeric_limits<int64_t>::min())
                            return set_error(serror, SCRIPT_ERR_DIV_OVERFLOW);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(CScriptNum(result).getvch());
                    }
                        break;

                    case OP_MOD:
                    {
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum bn1(stacktop(-2), fRequireMinimal, nMaxNum);
                        CScriptNum bn2(stacktop(-1), fRequireMinimal, nMaxNum);
                        const int64_t a = bn1.getint64();
                        const int64_t b = bn2.getint64();
                        if (b == 0)
                            return set_error(serror, SCRIPT_ERR_MOD_BY_ZERO);
                        if (a == std::numeric_limits<int64_t>::min() && b == -1)
                            return set_error(serror, SCRIPT_ERR_MOD_OVERFLOW);
                        const int64_t result = a % b;
                        if (result == std::numeric_limits<int64_t>::min())
                            return set_error(serror, SCRIPT_ERR_MOD_OVERFLOW);
                        popstack(stack);
                        popstack(stack);
                        stack.push_back(CScriptNum(result).getvch());
                    }
                        break;


                        //
                        // Crypto
                        //
                    case OP_RIPEMD160:
                    case OP_SHA1:
                    case OP_SHA256:
                    case OP_HASH160:
                    case OP_HASH256:
                    {
                        // (in -- hash)
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        valtype &vch = stacktop(-1);
                        valtype vchHash(
                                (opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                        if (opcode == OP_RIPEMD160)
                            CRIPEMD160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        else if (opcode == OP_SHA1)
                            CSHA1().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        else if (opcode == OP_SHA256)
                            CSHA256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        else if (opcode == OP_HASH160)
                            CHash160().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        else if (opcode == OP_HASH256)
                            CHash256().Write(vch.data(), vch.size()).Finalize(vchHash.data());
                        popstack(stack);
                        stack.push_back(vchHash);
                    }
                        break;

                    case OP_CODESEPARATOR:
                    {
                        // Hash starts after the code separator
                        pbegincodehash = pc;
                    }
                        break;

                    case OP_CHECKSIG:
                    case OP_CHECKSIGVERIFY:
                    {
                        // (sig pubkey -- bool)
                        if (stack.size() < 2)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        valtype &vchSig = stacktop(-2);
                        valtype &vchPubKey = stacktop(-1);

                        // Subset of script starting at the most recent codeseparator
                        CScript scriptCode(pbegincodehash, pend);

                        // Drop the signature in pre-segwit scripts but not segwit scripts
                        if (sigversion == SIGVERSION_BASE)
                        {
                            scriptCode.FindAndDelete(CScript(vchSig));
                        }

                        if (!CheckSignatureEncodingForPubKey(vchSig, vchPubKey, flags, serror) ||
                            !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
                        {
                            //serror is set
                            return false;
                        }
                        bool fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

                        popstack(stack);
                        popstack(stack);
                        stack.push_back(fSuccess ? vchTrue : vchFalse);
                        if (opcode == OP_CHECKSIGVERIFY)
                        {
                            if (fSuccess)
                                popstack(stack);
                            else
                                return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                        }
                    }
                        break;

                    case OP_CHECKMULTISIG:
                    case OP_CHECKMULTISIGVERIFY:
                    {
                        // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                        int i = 1;
                        if ((int) stack.size() < i)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                        if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                            return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                        nOpCount += nKeysCount;
                        if (nOpCount > MAX_OPS_PER_SCRIPT)
                            return set_error(serror, SCRIPT_ERR_OP_COUNT);
                        int ikey = ++i;
                        // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                        // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                        int ikey2 = nKeysCount + 2;
                        i += nKeysCount;
                        if ((int) stack.size() < i)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                        if (nSigsCount < 0 || nSigsCount > nKeysCount)
                            return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                        int isig = ++i;
                        i += nSigsCount;
                        if ((int) stack.size() < i)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        // Subset of script starting at the most recent codeseparator
                        CScript scriptCode(pbegincodehash, pend);

                        // Drop the signature in pre-segwit scripts but not segwit scripts
                        for (int k = 0; k < nSigsCount; k++)
                        {
                            valtype &vchSig = stacktop(-isig - k);
                            if (sigversion == SIGVERSION_BASE)
                            {
                                scriptCode.FindAndDelete(CScript(vchSig));
                            }
                        }

                        bool fSuccess = true;
                        while (fSuccess && nSigsCount > 0)
                        {
                            valtype &vchSig = stacktop(-isig);
                            valtype &vchPubKey = stacktop(-ikey);

                            // Note how this makes the exact order of pubkey/signature evaluation
                            // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                            // See the script_(in)valid tests for details.
                            if (!CheckSignatureEncodingForPubKey(vchSig, vchPubKey, flags, serror) ||
                                !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
                            {
                                // serror is set
                                return false;
                            }

                            // Check signature
                            bool fOk = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion);

                            if (fOk)
                            {
                                isig++;
                                nSigsCount--;
                            }
                            ikey++;
                            nKeysCount--;

                            // If there are more signatures left than keys left,
                            // then too many signatures have failed. Exit early,
                            // without checking any further signatures.
                            if (nSigsCount > nKeysCount)
                                fSuccess = false;
                        }

                        // Clean up stack of actual arguments
                        while (i-- > 1)
                        {
                            // If the operation failed, we require that all signatures must be empty vector
                            if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
                                return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                            if (ikey2 > 0)
                                ikey2--;
                            popstack(stack);
                        }

                        // A bug causes CHECKMULTISIG to consume one extra argument
                        // whose contents were not checked in any way.
                        //
                        // Unfortunately this is a potential source of mutability,
                        // so optionally verify it is exactly equal to zero prior
                        // to removing it from the stack.
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                        popstack(stack);

                        stack.push_back(fSuccess ? vchTrue : vchFalse);

                        if (opcode == OP_CHECKMULTISIGVERIFY)
                        {
                            if (fSuccess)
                                popstack(stack);
                            else
                                return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                        }
                    }
                        break;

                        /** XNA START */
                    case OP_XNA_ASSET:
                        break;
                        /** XNA END */


                    default:
                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                }
            }
            // Size limits
            if (stack.size() + altstack.size() > MAX_STACK_SIZE)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);

            // NIP-018: total stack-bytes cap, enforced only on the CSFS path.
            // Bounds worst-case memory when PQ-sized (3072 B) elements are
            // permitted. Non-CSFS scripts keep the implicit 520 KB bound from
            // MAX_STACK_SIZE × MAX_SCRIPT_ELEMENT_SIZE.
            if (flags & SCRIPT_VERIFY_CHECKSIGFROMSTACK) {
                size_t stack_bytes = 0;
                for (const auto& item : stack)    stack_bytes += item.size();
                for (const auto& item : altstack) stack_bytes += item.size();
                if (stack_bytes > MAX_STACK_BYTES)
                    return set_error(serror, SCRIPT_ERR_STACK_SIZE);
            }
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

namespace
{

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
    class CTransactionSignatureSerializer
    {
    private:
        const CTransaction &txTo;  //!< reference to the spending transaction (the one being serialized)
        const CScript &scriptCode; //!< output script being consumed
        const unsigned int nIn;    //!< input index of txTo being signed
        const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
        const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
        const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

    public:
        CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn)
                :
                txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
                fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
                fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
                fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE)
        {}

        /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
        template<typename S>
        void SerializeScriptCode(S &s) const
        {
            CScript::const_iterator it = scriptCode.begin();
            CScript::const_iterator itBegin = it;
            opcodetype opcode;
            unsigned int nCodeSeparators = 0;
            while (scriptCode.GetOp(it, opcode))
            {
                if (opcode == OP_CODESEPARATOR)
                    nCodeSeparators++;
            }
            ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
            it = itBegin;
            while (scriptCode.GetOp(it, opcode))
            {
                if (opcode == OP_CODESEPARATOR)
                {
                    s.write((char *) &itBegin[0], it - itBegin - 1);
                    itBegin = it;
                }
            }
            if (itBegin != scriptCode.end())
                s.write((char *) &itBegin[0], it - itBegin);
        }

        /** Serialize an input of txTo */
        template<typename S>
        void SerializeInput(S &s, unsigned int nInput) const
        {
            // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
            if (fAnyoneCanPay)
                nInput = nIn;
            // Serialize the prevout
            ::Serialize(s, txTo.vin[nInput].prevout);
            // Serialize the script
            if (nInput != nIn)
                // Blank out other inputs' signatures
                ::Serialize(s, CScript());
            else
                SerializeScriptCode(s);
            // Serialize the nSequence
            if (nInput != nIn && (fHashSingle || fHashNone))
                // let the others update at will
                ::Serialize(s, (int) 0);
            else
                ::Serialize(s, txTo.vin[nInput].nSequence);
        }

        /** Serialize an output of txTo */
        template<typename S>
        void SerializeOutput(S &s, unsigned int nOutput) const
        {
            if (fHashSingle && nOutput != nIn)
                // Do not lock-in the txout payee at other indices as txin
                ::Serialize(s, CTxOut());
            else
                ::Serialize(s, txTo.vout[nOutput]);
        }

        /** Serialize txTo */
        template<typename S>
        void Serialize(S &s) const
        {
            // Serialize nVersion
            ::Serialize(s, txTo.nVersion);
            // Serialize vin
            unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
            ::WriteCompactSize(s, nInputs);
            for (unsigned int nInput = 0; nInput < nInputs; nInput++) SerializeInput(s, nInput);
            // Serialize vout
            unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn + 1 : txTo.vout.size());
            ::WriteCompactSize(s, nOutputs);
            for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++) SerializeOutput(s, nOutput);
            // NIP-014: serialize vrefin for v3 (unconditional — not affected by sighash mode)
            if (txTo.nVersion == 3) {
                ::WriteCompactSize(s, txTo.vrefin.size());
                for (const auto& refin : txTo.vrefin) {
                    ::Serialize(s, refin);
                }
            }
            // Serialize nLockTime
            ::Serialize(s, txTo.nLockTime);
        }
    };

    uint256 GetPrevoutHash(const CTransaction &txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto &txin : txTo.vin)
        {
            ss << txin.prevout;
        }
        return ss.GetHash();
    }

    uint256 GetSequenceHash(const CTransaction &txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto &txin : txTo.vin)
        {
            ss << txin.nSequence;
        }
        return ss.GetHash();
    }

    uint256 GetOutputsHash(const CTransaction &txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto &txout : txTo.vout)
        {
            ss << txout;
        }
        return ss.GetHash();
    }

    // NIP-014: double-SHA256 hash of reference inputs (BIP143 sighash path)
    uint256 GetRefInputsHash(const CTransaction& txTo)
    {
        CHashWriter ss(SER_GETHASH, 0);
        for (const auto& refin : txTo.vrefin) {
            ss << refin;
        }
        return ss.GetHash();
    }

} // namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction &txTo)
{
    // BIP143 cache: calculated only for transactions with witness
    if (txTo.HasWitness())
    {
        hashPrevouts = GetPrevoutHash(txTo);
        hashSequence = GetSequenceHash(txTo);
        hashOutputs = GetOutputsHash(txTo);
        ready = true;
    }

    // BIP119 CTV cache: precompute single-SHA256 sub-hashes to avoid
    // quadratic hashing when multiple inputs each evaluate OP_CTV.
    {
        // Sequences hash (single SHA256)
        CSHA256 seqHasher;
        for (const auto& txin : txTo.vin) {
            uint32_t nSequence = txin.nSequence;
            seqHasher.Write((const unsigned char*)&nSequence, 4);
        }
        seqHasher.Finalize(ctvHashSequences.begin());

        // Outputs hash (single SHA256)
        CSHA256 outHasher;
        for (const auto& txout : txTo.vout) {
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << txout;
            outHasher.Write((const unsigned char*)s.data(), s.size());
        }
        outHasher.Finalize(ctvHashOutputs.begin());

        // ScriptSigs hash (single SHA256, only if any is non-empty)
        ctvHasNonEmptyScriptSig = false;
        for (const auto& txin : txTo.vin) {
            if (txin.scriptSig.size() > 0) {
                ctvHasNonEmptyScriptSig = true;
                break;
            }
        }
        if (ctvHasNonEmptyScriptSig) {
            CSHA256 sigHasher;
            for (const auto& txin : txTo.vin) {
                CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                s << txin.scriptSig;
                sigHasher.Write((const unsigned char*)s.data(), s.size());
            }
            sigHasher.Finalize(ctvHashScriptSigs.begin());
        }

        ctvReady = true;
    }

    // NIP-014: precompute reference input hashes for v3
    if (txTo.nVersion == 3 && !txTo.vrefin.empty()) {
        // BIP143-style double-SHA256
        CHashWriter refHasher(SER_GETHASH, 0);
        for (const auto& refin : txTo.vrefin) {
            refHasher << refin;
        }
        hashRefInputs = refHasher.GetHash();
        refInputsReady = true;

        // CTV-style single-SHA256
        CSHA256 ctvRefHasher;
        for (const auto& refin : txTo.vrefin) {
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << refin;
            ctvRefHasher.Write((const unsigned char*)s.data(), s.size());
        }
        ctvRefHasher.Finalize(ctvHashRefInputs.begin());
        ctvRefInputsReady = true;
    }
}

uint256 SignatureHash(const CScript &scriptCode, const CTransaction &txTo, unsigned int nIn, int nHashType, const CAmount &amount, SigVersion sigversion, const PrecomputedTransactionData *cache, uint8_t authType)
{
    assert(nIn < txTo.vin.size());

    if (sigversion == SIGVERSION_WITNESS_V0 || sigversion == SIGVERSION_AUTHSCRIPT)
    {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;
        const bool cacheready = cache && cache->ready;

        if (!(nHashType & SIGHASH_ANYONECANPAY))
        {
            hashPrevouts = cacheready ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE)
        {
            hashSequence = cacheready ? cache->hashSequence : GetSequenceHash(txTo);
        }


        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE)
        {
            hashOutputs = cacheready ? cache->hashOutputs : GetOutputsHash(txTo);
        }
        else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size())
        {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        ss << txTo.vin[nIn].prevout;
        ss << scriptCode;
        ss << amount;
        ss << txTo.vin[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // NIP-014: commit to reference inputs for v3
        if (txTo.nVersion == 3) {
            uint256 hashRefIns;
            if (cacheready && cache->refInputsReady) {
                hashRefIns = cache->hashRefInputs;
            } else {
                hashRefIns = GetRefInputsHash(txTo);
            }
            ss << hashRefIns;
        }
        // Locktime
        ss << txTo.nLockTime;
        if (sigversion == SIGVERSION_AUTHSCRIPT) {
            ss << authType;
        }
        // Sighash type
        ss << nHashType;

        return ss.GetHash();
    }

    static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        if (nIn >= txTo.vout.size())
        {
            //  nOut out of range
            return one;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCode, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

bool TransactionSignatureChecker::VerifySignature(const std::vector<unsigned char> &vchSig, const CPubKey &pubkey, const uint256 &sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

bool TransactionSignatureChecker::CheckSig(const std::vector<unsigned char> &vchSigIn, const std::vector<unsigned char> &vchPubKey, const CScript &scriptCode, SigVersion sigversion, uint8_t authType) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Hash type is one byte tacked on to the end of the signature
    std::vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    int nHashType = vchSig.back();
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, this->txdata, authType);

    if (!VerifySignature(vchSig, pubkey, sighash))
        return false;

    return true;
}

uint256 TransactionSignatureChecker::GetSigHash(const CScript& scriptCode, int nHashType, SigVersion sigversion, uint8_t authType) const
{
    return SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion, this->txdata, authType);
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum &nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!((txTo->nLockTime < LOCKTIME_THRESHOLD && nLockTime < LOCKTIME_THRESHOLD) || (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t) txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence)
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum &nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t) txTo->vin[nIn].nSequence;

    // Fail if the transaction's version number is not set high
    // enough to trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2)
        return false;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number do not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!(
            (txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
            (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
    ))
    {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
        return false;

    return true;
}

// BIP 119: Compute the default check template verify hash.
// This commits to: nVersion, nLockTime, scriptSigs hash (if any non-empty),
// number of inputs, sequences hash, number of outputs, outputs hash, input index.
// Uses single SHA256 (not double).
//
// When PrecomputedTransactionData is available with ctvReady, the sub-hashes
// for sequences, outputs, and scriptSigs are read from cache (O(1) per input)
// instead of recomputed from scratch (O(n) per input), preventing quadratic
// hashing across multiple inputs.
static uint256 DefaultCheckTemplateVerifyHash(const CTransaction& tx, uint32_t nIn, const PrecomputedTransactionData* txdata)
{
    const bool cacheready = txdata && txdata->ctvReady;
    CSHA256 ss;

    // 1. nVersion (4 bytes LE)
    uint32_t nVersion = tx.nVersion;
    ss.Write((const unsigned char*)&nVersion, 4);

    // 2. nLockTime (4 bytes LE)
    uint32_t nLockTime = tx.nLockTime;
    ss.Write((const unsigned char*)&nLockTime, 4);

    // 3. Hash of scriptSigs (only if any is non-empty)
    if (cacheready) {
        if (txdata->ctvHasNonEmptyScriptSig) {
            ss.Write(txdata->ctvHashScriptSigs.begin(), CSHA256::OUTPUT_SIZE);
        }
    } else {
        bool hasNonEmptyScriptSig = false;
        for (const auto& txin : tx.vin) {
            if (txin.scriptSig.size() > 0) {
                hasNonEmptyScriptSig = true;
                break;
            }
        }
        if (hasNonEmptyScriptSig) {
            CSHA256 scriptSigsHash;
            for (const auto& txin : tx.vin) {
                CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                s << txin.scriptSig;
                scriptSigsHash.Write((const unsigned char*)s.data(), s.size());
            }
            unsigned char scriptSigsResult[CSHA256::OUTPUT_SIZE];
            scriptSigsHash.Finalize(scriptSigsResult);
            ss.Write(scriptSigsResult, CSHA256::OUTPUT_SIZE);
        }
    }

    // 4. Number of inputs (4 bytes LE)
    uint32_t nInputs = tx.vin.size();
    ss.Write((const unsigned char*)&nInputs, 4);

    // 5. Hash of sequences
    if (cacheready) {
        ss.Write(txdata->ctvHashSequences.begin(), CSHA256::OUTPUT_SIZE);
    } else {
        CSHA256 sequencesHash;
        for (const auto& txin : tx.vin) {
            uint32_t nSequence = txin.nSequence;
            sequencesHash.Write((const unsigned char*)&nSequence, 4);
        }
        unsigned char seqResult[CSHA256::OUTPUT_SIZE];
        sequencesHash.Finalize(seqResult);
        ss.Write(seqResult, CSHA256::OUTPUT_SIZE);
    }

    // 6. Number of outputs (4 bytes LE)
    uint32_t nOutputs = tx.vout.size();
    ss.Write((const unsigned char*)&nOutputs, 4);

    // 7. Hash of outputs
    if (cacheready) {
        ss.Write(txdata->ctvHashOutputs.begin(), CSHA256::OUTPUT_SIZE);
    } else {
        CSHA256 outputsHash;
        for (const auto& txout : tx.vout) {
            CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
            s << txout;
            outputsHash.Write((const unsigned char*)s.data(), s.size());
        }
        unsigned char outResult[CSHA256::OUTPUT_SIZE];
        outputsHash.Finalize(outResult);
        ss.Write(outResult, CSHA256::OUTPUT_SIZE);
    }

    // NIP-014: commit to reference inputs for v3
    if (tx.nVersion == 3) {
        uint32_t nRefInputs = tx.vrefin.size();
        ss.Write((const unsigned char*)&nRefInputs, 4);

        if (nRefInputs > 0) {
            if (cacheready && txdata->ctvRefInputsReady) {
                ss.Write(txdata->ctvHashRefInputs.begin(), CSHA256::OUTPUT_SIZE);
            } else {
                CSHA256 refInputsHash;
                for (const auto& refin : tx.vrefin) {
                    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                    s << refin;
                    refInputsHash.Write((const unsigned char*)s.data(), s.size());
                }
                unsigned char refResult[CSHA256::OUTPUT_SIZE];
                refInputsHash.Finalize(refResult);
                ss.Write(refResult, CSHA256::OUTPUT_SIZE);
            }
        }
    }

    // 8. Input index (4 bytes LE)
    uint32_t inputIndex = nIn;
    ss.Write((const unsigned char*)&inputIndex, 4);

    uint256 result;
    ss.Finalize(result.begin());
    return result;
}

bool TransactionSignatureChecker::CheckTemplateVerify(const std::vector<unsigned char>& hash) const
{
    if (hash.size() != 32)
        return false;
    uint256 expectedHash = DefaultCheckTemplateVerifyHash(*txTo, nIn, txdata);
    return memcmp(hash.data(), expectedHash.begin(), 32) == 0;
}

bool TransactionSignatureChecker::CheckSigFromStack(const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& vchMsg, const std::vector<unsigned char>& vchPubKey) const
{
    if (vchSig.empty())
        return false;

    // Hash the message with SHA256 (single, not double)
    uint256 msgHash;
    CSHA256().Write(vchMsg.data(), vchMsg.size()).Finalize(msgHash.begin());

    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    // Convention inherited from OP_CHECKSIG: the last byte of every signature
    // on the stack is a hashtype byte.  OP_CHECKSIG always strips it
    // (interpreter.cpp:1581-1582) regardless of STRICTENC/DERSIG flags;
    // STRICTENC merely validates that the byte is a *recognized* hashtype
    // before CheckSig strips it.
    //
    // CSFS follows the same convention: always strip the trailing byte.
    // For PQ (ML-DSA-44), this is critical because OQS_SIG_verify expects
    // exactly ML_DSA_44_SIG_SIZE bytes.  For ECDSA, ecdsa_signature_parse_der_lax
    // tolerates extra trailing bytes, but stripping keeps behavior consistent.
    //
    // A signature without a trailing hashtype byte will:
    // - Under STRICTENC/DERSIG: be rejected earlier by CheckSignatureEncodingForPubKey
    // - Without STRICTENC/DERSIG: reach here with one fewer byte than expected,
    //   and pop_back() will shorten it further, causing Verify() to fail
    //   (ECDSA DER parse failure or PQ size mismatch) -- returning false,
    //   not crashing.
    std::vector<unsigned char> sig(vchSig);
    sig.pop_back();

    return pubkey.Verify(msgHash, sig);
}

// OP_TXHASH field selector bits.
//
// The field selector is a single byte pushed onto the stack before OP_TXHASH.
// Each bit selects a transaction field to include in the hash:
//
//   Bit 0 (0x01): nVersion     - transaction version (4 bytes LE)
//   Bit 1 (0x02): nLockTime   - transaction locktime (4 bytes LE)
//   Bit 2 (0x04): prevouts    - double-SHA256 of all input prevouts
//   Bit 3 (0x08): sequences   - double-SHA256 of all input sequences
//   Bit 4 (0x10): outputs     - double-SHA256 of all serialized outputs
//   Bit 5 (0x20): cur_prevout - serialized prevout of current input (nIn)
//   Bit 6 (0x40): cur_seq     - sequence number of current input (nIn)
//   Bit 7 (0x80): input_index - index of current input as uint32 LE
//
// The selected fields are concatenated in bit order and hashed with
// double-SHA256 (CHash256), consistent with BIP143/SignatureHash.
// Sub-hashes for prevouts/sequences/outputs also use double-SHA256,
// enabling reuse of PrecomputedTransactionData cache (O(1) vs O(n)).
//
// Selector 0x00 is invalid (returns false). The hash is deterministic:
// same selector + same transaction + same input index = same result.
//
static const unsigned char TXHASH_VERSION       = (1 << 0);  // 0x01
static const unsigned char TXHASH_LOCKTIME      = (1 << 1);  // 0x02
static const unsigned char TXHASH_PREVOUTS      = (1 << 2);  // 0x04
static const unsigned char TXHASH_SEQUENCES     = (1 << 3);  // 0x08
static const unsigned char TXHASH_OUTPUTS       = (1 << 4);  // 0x10
static const unsigned char TXHASH_CUR_PREVOUT   = (1 << 5);  // 0x20
static const unsigned char TXHASH_CUR_SEQUENCE  = (1 << 6);  // 0x40
static const unsigned char TXHASH_INPUT_INDEX   = (1 << 7);  // 0x80

// OP_TXFIELD field selector bytes.
//
// Unlike OP_TXHASH (which hashes selected fields of the spending TX),
// OP_TXFIELD returns the raw bytes of a single field from the UTXO being
// spent (the spent output). Requires m_spentScriptPubKey to be set.
//
//   0x01: nValue of the spent UTXO (int64 little-endian, 8 bytes)
//   0x02: 32-byte AuthScript commitment from OP_1 <32-byte-program> scriptPubKey
//   0x03: full scriptPubKey of the spent UTXO (raw bytes, max 520)
//
// 0x04-0xff reserved for future extensions.
//
static const unsigned char TXFIELD_SPENT_VALUE          = 0x01;
static const unsigned char TXFIELD_SPENT_AUTHCOMMITMENT = 0x02;
static const unsigned char TXFIELD_SPENT_FULLSCRIPT     = 0x03;

bool TransactionSignatureChecker::GetTxFieldHash(unsigned char fieldSelector, std::vector<unsigned char>& result) const
{
    if (fieldSelector == 0)
        return false;

    // Double SHA256 (CHash256) for consistency with BIP143 SignatureHash
    // and PrecomputedTransactionData cache which also uses double SHA256.
    CHash256 ss;

    if (fieldSelector & TXHASH_VERSION) {
        uint32_t nVersion = txTo->nVersion;
        ss.Write((const unsigned char*)&nVersion, 4);
    }

    if (fieldSelector & TXHASH_LOCKTIME) {
        uint32_t nLockTime = txTo->nLockTime;
        ss.Write((const unsigned char*)&nLockTime, 4);
    }

    // Use PrecomputedTransactionData cache when available (O(1) vs O(n)).
    // The cache stores double-SHA256 hashes, matching our CHash256 hasher.
    const bool cacheready = txdata && txdata->ready;

    if (fieldSelector & TXHASH_PREVOUTS) {
        if (cacheready) {
            ss.Write(txdata->hashPrevouts.begin(), CHash256::OUTPUT_SIZE);
        } else {
            CHash256 prevoutsHash;
            for (const auto& txin : txTo->vin) {
                CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                s << txin.prevout;
                prevoutsHash.Write((const unsigned char*)s.data(), s.size());
            }
            unsigned char prevResult[CHash256::OUTPUT_SIZE];
            prevoutsHash.Finalize(prevResult);
            ss.Write(prevResult, CHash256::OUTPUT_SIZE);
        }
    }

    if (fieldSelector & TXHASH_SEQUENCES) {
        if (cacheready) {
            ss.Write(txdata->hashSequence.begin(), CHash256::OUTPUT_SIZE);
        } else {
            CHash256 sequencesHash;
            for (const auto& txin : txTo->vin) {
                uint32_t nSequence = txin.nSequence;
                sequencesHash.Write((const unsigned char*)&nSequence, 4);
            }
            unsigned char seqResult[CHash256::OUTPUT_SIZE];
            sequencesHash.Finalize(seqResult);
            ss.Write(seqResult, CHash256::OUTPUT_SIZE);
        }
    }

    if (fieldSelector & TXHASH_OUTPUTS) {
        if (cacheready) {
            ss.Write(txdata->hashOutputs.begin(), CHash256::OUTPUT_SIZE);
        } else {
            CHash256 outputsHash;
            for (const auto& txout : txTo->vout) {
                CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                s << txout;
                outputsHash.Write((const unsigned char*)s.data(), s.size());
            }
            unsigned char outResult[CHash256::OUTPUT_SIZE];
            outputsHash.Finalize(outResult);
            ss.Write(outResult, CHash256::OUTPUT_SIZE);
        }
    }

    if (fieldSelector & TXHASH_CUR_PREVOUT) {
        if (nIn >= txTo->vin.size())
            return false;
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << txTo->vin[nIn].prevout;
        ss.Write((const unsigned char*)s.data(), s.size());
    }

    if (fieldSelector & TXHASH_CUR_SEQUENCE) {
        if (nIn >= txTo->vin.size())
            return false;
        uint32_t nSequence = txTo->vin[nIn].nSequence;
        ss.Write((const unsigned char*)&nSequence, 4);
    }

    if (fieldSelector & TXHASH_INPUT_INDEX) {
        if (nIn >= txTo->vin.size())
            return false;
        uint32_t inputIndex = nIn;
        ss.Write((const unsigned char*)&inputIndex, 4);
    }

    uint256 hash;
    ss.Finalize(hash.begin());
    result.assign(hash.begin(), hash.end());
    return true;
}

bool TransactionSignatureChecker::GetTxField(unsigned char selector,
                                              std::vector<unsigned char>& result) const
{
    switch (selector) {

    case TXFIELD_SPENT_VALUE: {
        // nValue of the UTXO being spent (8 bytes, int64 little-endian).
        // 'amount' is always available regardless of m_spentScriptPubKey.
        int64_t nValue = (int64_t)amount;
        result.resize(8);
        memcpy(result.data(), &nValue, 8);
        return true;
    }

    case TXFIELD_SPENT_AUTHCOMMITMENT: {
        // Extract the 32-byte AuthScript commitment from the spent scriptPubKey.
        // The scriptPubKey must begin with OP_1 (0x51) + 0x20 + 32 bytes.
        // It may have a trailing OP_XNA_ASSET ... OP_DROP suffix (Option B assets).
        if (!m_spentScriptPubKey)
            return false;
        const CScript& spk = *m_spentScriptPubKey;
        // Minimum: OP_1 (1 byte) + push_32 (1 byte) + 32 bytes = 34 bytes
        if (spk.size() < 34)
            return false;
        const unsigned char* data = spk.data();
        if (data[0] != 0x51)   // OP_1 (witness version 1)
            return false;
        if (data[1] != 0x20)   // push exactly 32 bytes
            return false;
        // Bytes [2..33] are the 32-byte AuthScript commitment
        result.assign(data + 2, data + 34);
        return true;
    }

    case TXFIELD_SPENT_FULLSCRIPT: {
        // Full scriptPubKey of the spent UTXO (raw bytes).
        // NIP-018: size cap is enforced by the caller (OP_TXFIELD) using
        // EffectiveMaxScriptElementSize(flags), so the checker returns the
        // bytes unconditionally and the caller emits SCRIPT_ERR_TXFIELD.
        if (!m_spentScriptPubKey)
            return false;
        const CScript& spk = *m_spentScriptPubKey;
        result.assign(spk.begin(), spk.end());
        return true;
    }

    default:
        return false;
    }
}

bool TransactionSignatureChecker::GetOutputValue(unsigned int nOut,
                                                 std::vector<unsigned char>& result) const
{
    if (!txTo)
        return false;
    if (nOut >= txTo->vout.size())
        return false;

    const int64_t nValue = (int64_t)txTo->vout[nOut].nValue;
    result.resize(8);
    memcpy(result.data(), &nValue, 8);
    return true;
}

// NIP-024: Push the XNA satoshi value of a selected input's prevout as raw
// 8-byte little-endian. Sourced from m_allPrevouts — the same vector that
// backs GetInputAssetField. Fails closed when the checker was not constructed
// with prevouts (e.g. the public libneuraiconsensus entry point; see NIP-024
// §3.10 for the ABI gap).
bool TransactionSignatureChecker::GetInputValue(unsigned int nInput,
                                                std::vector<unsigned char>& result) const
{
    if (!txTo || !m_allPrevouts || nInput >= txTo->vin.size() ||
        nInput >= m_allPrevouts->size())
        return false;

    const int64_t nValue = (int64_t)(*m_allPrevouts)[nInput].nValue;
    result.resize(8);
    memcpy(result.data(), &nValue, 8);
    return true;
}

// NIP-026: resolve a chain-context selector against m_chainContext.
// Fails closed when the checker was constructed without context
// (external callers via libneuraiconsensus, standalone tools).
bool TransactionSignatureChecker::GetChainContext(unsigned char selector,
                                                  int64_t& result) const
{
    if (!m_chainContext.available)
        return false;
    switch (selector) {
        case 0x01: result = m_chainContext.height; return true;
        case 0x02: result = m_chainContext.mtp;    return true;
        case 0x03: result = (int64_t)m_chainContext.chainId; return true;
        default:
            return false;
    }
}

bool TransactionSignatureChecker::GetOutputScript(unsigned int nOut,
                                                  std::vector<unsigned char>& result) const
{
    if (!txTo)
        return false;
    if (nOut >= txTo->vout.size())
        return false;

    // NIP-018: size cap is enforced by the caller (OP_OUTPUTSCRIPT) using
    // EffectiveMaxScriptElementSize(flags). Checker returns bytes
    // unconditionally; caller emits SCRIPT_ERR_OUTPUTSCRIPT on oversize.
    const CScript& spk = txTo->vout[nOut].scriptPubKey;
    result.assign(spk.begin(), spk.end());
    return true;
}

// NIP-023: Extract the 32-byte AuthScript v1 commitment from a selected output.
// Mirrors TXFIELD_SPENT_AUTHCOMMITMENT (interpreter.cpp around line 2791) but
// sourced from txTo->vout[nOut].scriptPubKey instead of the spent scriptPubKey.
// The output's scriptPubKey must begin with OP_1 (0x51) + 0x20 + 32 bytes;
// any trailing OP_XNA_ASSET ... OP_DROP suffix is intentionally ignored.
bool TransactionSignatureChecker::GetOutputAuthCommitment(unsigned int nOut,
                                                          std::vector<unsigned char>& result) const
{
    if (!txTo)
        return false;
    if (nOut >= txTo->vout.size())
        return false;

    const CScript& spk = txTo->vout[nOut].scriptPubKey;
    if (spk.size() < 34)
        return false;
    const unsigned char* data = spk.data();
    if (data[0] != 0x51)   // OP_1 (witness version 1)
        return false;
    if (data[1] != 0x20)   // push exactly 32 bytes
        return false;
    result.assign(data + 2, data + 34);
    return true;
}

bool TransactionSignatureChecker::GetOutputAssetField(unsigned int nOut,
                                                      unsigned char selector,
                                                      std::vector<unsigned char>& result) const
{
    if (!txTo || nOut >= txTo->vout.size())
        return false;

    const CScript& scriptPubKey = txTo->vout[nOut].scriptPubKey;
    std::string strAddress;

    CAssetTransfer transfer;
    if (TransferAssetFromScript(scriptPubKey, transfer, strAddress))
        return ExtractAssetField_Transfer(transfer, selector, result);

    CNewAsset newAsset;
    if (AssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (MsgChannelAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (QualifierAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (RestrictedAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    CReissueAsset reissue;
    if (ReissueAssetFromScript(scriptPubKey, reissue, strAddress))
        return ExtractAssetField_Reissue(reissue, selector, result);

    std::string ownerName;
    if (OwnerAssetFromScript(scriptPubKey, ownerName, strAddress))
        return ExtractAssetField_Owner(ownerName, selector, result);

    return false;
}

bool TransactionSignatureChecker::GetInputAssetField(unsigned int nInput,
                                                     unsigned char selector,
                                                     std::vector<unsigned char>& result) const
{
    if (!txTo || !m_allPrevouts || nInput >= txTo->vin.size() || nInput >= m_allPrevouts->size())
        return false;

    const CScript& scriptPubKey = (*m_allPrevouts)[nInput].scriptPubKey;
    std::string strAddress;

    CAssetTransfer transfer;
    if (TransferAssetFromScript(scriptPubKey, transfer, strAddress))
        return ExtractAssetField_Transfer(transfer, selector, result);

    CNewAsset newAsset;
    if (AssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (MsgChannelAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (QualifierAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (RestrictedAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    CReissueAsset reissue;
    if (ReissueAssetFromScript(scriptPubKey, reissue, strAddress))
        return ExtractAssetField_Reissue(reissue, selector, result);

    std::string ownerName;
    if (OwnerAssetFromScript(scriptPubKey, ownerName, strAddress))
        return ExtractAssetField_Owner(ownerName, selector, result);

    return false;
}

bool TransactionSignatureChecker::GetInputCount(
    std::vector<unsigned char>& result) const
{
    if (!txTo)
        return false;
    result = CScriptNum(txTo->vin.size()).getvch();
    return true;
}

bool TransactionSignatureChecker::GetOutputCount(
    std::vector<unsigned char>& result) const
{
    if (!txTo)
        return false;
    result = CScriptNum(txTo->vout.size()).getvch();
    return true;
}

bool TransactionSignatureChecker::GetTxLockTime(std::vector<unsigned char>& result) const
{
    if (!txTo)
        return false;

    const uint32_t nLockTime = txTo->nLockTime;
    result.resize(4);
    memcpy(result.data(), &nLockTime, 4);
    return true;
}

// NIP-014: reference input introspection
bool TransactionSignatureChecker::GetRefInputCount(std::vector<unsigned char>& result) const
{
    if (!txTo || !m_refOutputs)
        return false;

    int64_t count = static_cast<int64_t>(m_refOutputs->size());
    CScriptNum num(count);
    result = num.getvch();
    return true;
}

bool TransactionSignatureChecker::GetRefInputField(unsigned int nRef, unsigned char selector,
                                                    std::vector<unsigned char>& result) const
{
    if (!txTo || !m_refOutputs)
        return false;
    if (nRef >= m_refOutputs->size())
        return false;

    const CTxOut& refOut = (*m_refOutputs)[nRef];

    switch (selector) {
        case 0x01: { // nValue (8 bytes LE) — matches TXFIELD_SPENT_VALUE
            int64_t val = refOut.nValue;
            result.resize(8);
            memcpy(result.data(), &val, 8);
            return true;
        }
        case 0x02: { // AuthScript commitment (32 bytes) — matches TXFIELD_SPENT_AUTHCOMMITMENT
            const CScript& spk = refOut.scriptPubKey;
            if (spk.size() < 34)
                return false;
            const unsigned char* data = spk.data();
            if (data[0] != 0x51)   // OP_1 (witness version 1)
                return false;
            if (data[1] != 0x20)   // push exactly 32 bytes
                return false;
            result.assign(data + 2, data + 34);
            return true;
        }
        case 0x03: { // Full scriptPubKey (raw bytes) — matches TXFIELD_SPENT_FULLSCRIPT
            // NIP-018: size cap is enforced by the caller (OP_REFINPUTFIELD)
            // using EffectiveMaxScriptElementSize(flags). Checker returns
            // bytes unconditionally; caller emits SCRIPT_ERR_REFINPUTFIELD.
            const CScript& spk = refOut.scriptPubKey;
            result.assign(spk.begin(), spk.end());
            return true;
        }
        default:
            return false;
    }
}

bool TransactionSignatureChecker::GetRefInputAssetField(unsigned int nRef, unsigned char selector,
                                                         std::vector<unsigned char>& result) const
{
    if (!txTo || !m_refOutputs)
        return false;
    if (nRef >= m_refOutputs->size())
        return false;

    const CScript& scriptPubKey = (*m_refOutputs)[nRef].scriptPubKey;
    std::string strAddress;

    CAssetTransfer transfer;
    if (TransferAssetFromScript(scriptPubKey, transfer, strAddress))
        return ExtractAssetField_Transfer(transfer, selector, result);

    CNewAsset newAsset;
    if (AssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (MsgChannelAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (QualifierAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    if (RestrictedAssetFromScript(scriptPubKey, newAsset, strAddress))
        return ExtractAssetField_New(newAsset, selector, result);

    CReissueAsset reissue;
    if (ReissueAssetFromScript(scriptPubKey, reissue, strAddress))
        return ExtractAssetField_Reissue(reissue, selector, result);

    std::string ownerName;
    if (OwnerAssetFromScript(scriptPubKey, ownerName, strAddress))
        return ExtractAssetField_Owner(ownerName, selector, result);

    return false;
}

static bool VerifyAuthScriptCore(const CScriptWitness& witness, const std::vector<unsigned char>& program, script_verify_flags flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    if (program.size() != 32 || (flags & SCRIPT_VERIFY_AUTHSCRIPT) == 0) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    if (witness.stack.size() < 2) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
    if (witness.stack[0].size() != 1) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    const uint8_t authType = witness.stack[0][0];
    const valtype& witnessScriptBytes = witness.stack.back();
    CScript witnessScript(witnessScriptBytes.begin(), witnessScriptBytes.end());
    CPubKey authPubKey;
    const valtype* authSig = nullptr;
    size_t argsOffset = 0;

    switch (authType) {
    case 0x00:
        argsOffset = 1;
        break;
    case 0x01:
    case 0x02:
        if (witness.stack.size() < 4) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }
        authSig = &witness.stack[1];
        authPubKey = CPubKey(witness.stack[2]);
        if (!authPubKey.IsValid()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }
        if (authType == 0x01 && !authPubKey.IsPQ()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }
        if (authType == 0x02 && authPubKey.IsPQ()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }
        argsOffset = 3;
        break;
    default:
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    const CPubKey* authPubKeyPtr = (authType == 0x00) ? nullptr : &authPubKey;
    const uint256 expectedCommitment = GetAuthScriptCommitment(authType, authPubKeyPtr, witnessScript);
    if (memcmp(expectedCommitment.begin(), program.data(), program.size()) != 0) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }

    if (authType != 0x00) {
        if (!CheckPubKeyEncoding(witness.stack[2], flags, SIGVERSION_AUTHSCRIPT, serror) ||
            !CheckSignatureEncodingForPubKey(*authSig, witness.stack[2], flags, serror)) {
            return false;
        }
        if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && authType == 0x02 && !IsCompressedPubKey(witness.stack[2])) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
        }
        if (!checker.CheckSig(*authSig, witness.stack[2], witnessScript, SIGVERSION_AUTHSCRIPT, authType)) {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        }
    }

    std::vector<std::vector<unsigned char>> stack;
    stack.reserve(witness.stack.size() - argsOffset);
    for (size_t i = argsOffset; i + 1 < witness.stack.size(); ++i) {
        if (witness.stack[i].size() > EffectiveMaxScriptElementSize(flags)) {
            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
        }
        stack.push_back(witness.stack[i]);
    }

    if (witnessScript.size() > MAX_SCRIPT_SIZE) {
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    }
    if (!EvalScript(stack, witnessScript, flags, checker, SIGVERSION_AUTHSCRIPT, serror)) {
        return false;
    }
    if (stack.size() != 1) {
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }
    if (!CastToBool(stack.back())) {
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    }
    return set_success(serror);
}

static bool VerifyWitnessProgram(const CScriptWitness &witness, int witversion, const std::vector<unsigned char> &program, script_verify_flags flags, const BaseSignatureChecker &checker, ScriptError *serror)
{
    std::vector<std::vector<unsigned char> > stack;
    CScript scriptPubKey;

    if (witversion == 0)
    {
        if (program.size() == 32)
        {
            // Version 0 segregated witness program: SHA256(CScript) inside the program, CScript + inputs in witness
            if (witness.stack.size() == 0)
            {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
            }
            scriptPubKey = CScript(witness.stack.back().begin(), witness.stack.back().end());
            stack = std::vector<std::vector<unsigned char> >(witness.stack.begin(), witness.stack.end() - 1);
            uint256 hashScriptPubKey;
            CSHA256().Write(&scriptPubKey[0], scriptPubKey.size()).Finalize(hashScriptPubKey.begin());
            if (memcmp(hashScriptPubKey.begin(), program.data(), 32))
            {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
        }
        else if (program.size() == 20)
        {
            // Special case for pay-to-pubkeyhash; signature + pubkey in witness
            if (witness.stack.size() != 2)
            {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
            }
            scriptPubKey << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            stack = witness.stack;
        }
        else
        {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
        }
    }
    else if (witversion == 1 && program.size() == 32 && (flags & SCRIPT_VERIFY_AUTHSCRIPT))
    {
        return VerifyAuthScriptCore(witness, program, flags, checker, serror);
    }
    else if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
    {
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    }
    else
    {
        // Higher version witness scripts return true for future softfork compatibility
        return set_success(serror);
    }

    // Disallow stack item size > effective per-element cap in witness stack.
    // NIP-018: effective cap is 3072 when SCRIPT_VERIFY_CHECKSIGFROMSTACK is set.
    for (unsigned int i = 0; i < stack.size(); i++)
    {
        if (stack.at(i).size() > EffectiveMaxScriptElementSize(flags))
            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }

    if (!EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_WITNESS_V0, serror))
    {
        return false;
    }

    // Scripts inside witness implicitly require cleanstack behaviour
    if (stack.size() != 1)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (!CastToBool(stack.back()))
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    return true;
}

static bool VerifyAssetWitnessProgram(const CScriptWitness& witness, int witversion, const std::vector<unsigned char>& program, const std::vector<unsigned char>& assetData, script_verify_flags flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    if (witversion == 1 && program.size() == 32 && (flags & SCRIPT_VERIFY_AUTHSCRIPT)) {
        (void)assetData;
        return VerifyAuthScriptCore(witness, program, flags, checker, serror);
    }

    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    }

    return set_success(serror);
}


bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey, const CScriptWitness *witness, script_verify_flags flags, const BaseSignatureChecker &checker, ScriptError *serror)
{
    static const CScriptWitness emptyWitness;
    if (witness == nullptr)
    {
        witness = &emptyWitness;
    }
    bool hadWitness = false;

    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly())
    {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    int assetWitnessVersion = 0;
    std::vector<unsigned char> assetWitnessProgram;
    std::vector<unsigned char> assetData;
    if (GetAssetScriptWitnessProgram(scriptPubKey, assetWitnessVersion, assetWitnessProgram, &assetData)) {
        if ((flags & SCRIPT_VERIFY_WITNESS) == 0) {
            return set_error(serror, SCRIPT_ERR_WITNESS_UNEXPECTED);
        }
        if (scriptSig.size() != 0) {
            return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED);
        }
        if (!VerifyAssetWitnessProgram(*witness, assetWitnessVersion, assetWitnessProgram, assetData, flags, checker, serror)) {
            return false;
        }
        return set_success(serror);
    }

    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, SIGVERSION_BASE, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_BASE, serror))
    {
        // mney - changed from if(serror). This code wasn't in Bitcoin. It caused a spewing of script error
        //        messages when running the unit tests (src/test/test_runner).  Uncomment for additional debug messages
        //std::string str;
        //str.assign(ScriptErrorString(*serror));
        //std::cout << str << std::endl;
        return false;
    }
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

    // Bare witness programs
    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (flags & SCRIPT_VERIFY_WITNESS)
    {
        if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram))
        {
            hadWitness = true;
            if (scriptSig.size() != 0)
            {
                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED);
            }
            if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror))
            {
                return false;
            }
            // Bypass the cleanstack check at the end. The actual stack is obviously not clean
            // for witness programs.
            stack.resize(1);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());

        const valtype &pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);

        if (!EvalScript(stack, pubKey2, flags, checker, SIGVERSION_BASE, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

        // P2SH witness program
        if (flags & SCRIPT_VERIFY_WITNESS)
        {
            if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram))
            {
                hadWitness = true;
                if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end()))
                {
                    // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    // reintroduce malleability.
                    return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
                }
                if (!VerifyWitnessProgram(*witness, witnessversion, witnessprogram, flags, checker, serror))
                {
                    return false;
                }
                // Bypass the cleanstack check at the end. The actual stack is obviously not clean
                // for witness programs.
                stack.resize(1);
            }
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0)
    {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        assert((flags & SCRIPT_VERIFY_WITNESS) != 0);
        if (stack.size() != 1)
        {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    if (flags & SCRIPT_VERIFY_WITNESS)
    {
        // We can't check for correct unexpected witness data if P2SH was off, so require
        // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        // possible, which is not a softfork.
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (!hadWitness && !witness->IsNull())
        {
            return set_error(serror, SCRIPT_ERR_WITNESS_UNEXPECTED);
        }
    }

    return set_success(serror);
}

size_t static WitnessSigOps(int witversion, const std::vector<unsigned char> &witprogram, const CScriptWitness &witness, script_verify_flags flags)
{
    if (witversion == 0)
    {
        if (witprogram.size() == 20)
            return 1;

        if (witprogram.size() == 32 && witness.stack.size() > 0)
        {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            return subscript.GetSigOpCount(true);
        }
    }

    if (witversion == 1 && witprogram.size() == 32 && (flags & SCRIPT_VERIFY_AUTHSCRIPT)) {
        if (witness.stack.empty()) {
            return 0;
        }
        size_t sigops = 0;
        if (witness.stack.size() > 1) {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            sigops = subscript.GetSigOpCount(true);
        }
        if (witness.stack[0].size() == 1 && witness.stack[0][0] != 0x00) {
            sigops += 1;
        }
        return sigops;
    }

    // Future flags may be implemented here.
    return 0;
}

size_t CountWitnessSigOps(const CScript &scriptSig, const CScript &scriptPubKey, const CScriptWitness *witness, script_verify_flags flags)
{
    static const CScriptWitness witnessEmpty;

    if ((flags & SCRIPT_VERIFY_WITNESS) == 0)
    {
        return 0;
    }
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram))
    {
        return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }

    if (GetAssetScriptWitnessProgram(scriptPubKey, witnessversion, witnessprogram)) {
        return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }

    if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly())
    {
        CScript::const_iterator pc = scriptSig.begin();
        std::vector<unsigned char> data;
        while (pc < scriptSig.end())
        {
            opcodetype opcode;
            scriptSig.GetOp(pc, opcode, data);
        }
        CScript subscript(data.begin(), data.end());
        if (subscript.IsWitnessProgram(witnessversion, witnessprogram))
        {
            return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
        }
    }

    return 0;
}
