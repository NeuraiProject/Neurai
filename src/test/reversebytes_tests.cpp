// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha256.h"
#include "script/standard.h"
#include "utilstrencodings.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags REVERSEBYTES_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_REVERSEBYTES;
static constexpr script_verify_flags NO_REVERSEBYTES_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_REVERSEBYTES_FLAGS_DISCOURAGE =
    NO_REVERSEBYTES_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags SPLIT_REVERSEBYTES_FLAGS =
    REVERSEBYTES_FLAGS | SCRIPT_VERIFY_SPLIT;
static constexpr script_verify_flags CAT_SPLIT_REVERSEBYTES_FLAGS =
    SPLIT_REVERSEBYTES_FLAGS | SCRIPT_VERIFY_CAT;

namespace {

bool RunScript(const CScript& script, script_verify_flags flags,
               std::vector<std::vector<unsigned char>> initialStack,
               std::vector<std::vector<unsigned char>>& resultStack,
               ScriptError* errOut = nullptr)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    vin.prevout.n = 0;
    mtx.vin.push_back(vin);
    CTxOut vout;
    vout.nValue = 1000;
    mtx.vout.push_back(vout);
    CTransaction tx(mtx);

    TransactionSignatureChecker checker(&tx, 0, 1000);
    ScriptError serror = SCRIPT_ERR_OK;

    std::vector<std::vector<unsigned char>> stack = initialStack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);

    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::vector<unsigned char> HexBytes(std::initializer_list<unsigned char> bytes)
{
    return std::vector<unsigned char>(bytes);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(reversebytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reversebytes_disabled_is_bad_opcode)
{
    // flag off -> BAD_OPCODE (fail-closed, not NOP)
    CScript script;
    script << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, NO_REVERSEBYTES_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(reversebytes_disabled_discourage_still_bad_opcode)
{
    // flag off -> BAD_OPCODE even with DISCOURAGE_UPGRADABLE_NOPS set (fail-closed)
    CScript script;
    script << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, NO_REVERSEBYTES_FLAGS_DISCOURAGE, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(reversebytes_empty_stack_fails)
{
    CScript script;
    script << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, REVERSEBYTES_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(reversebytes_empty_vector_roundtrip)
{
    CScript script;
    script << std::vector<unsigned char>() << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0].empty());
}

BOOST_AUTO_TEST_CASE(reversebytes_single_byte_unchanged)
{
    CScript script;
    script << HexBytes({0x42}) << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == HexBytes({0x42}));
}

BOOST_AUTO_TEST_CASE(reversebytes_even_length)
{
    CScript script;
    script << Bytes("abcd") << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("dcba"));
}

BOOST_AUTO_TEST_CASE(reversebytes_odd_length)
{
    CScript script;
    script << Bytes("abcde") << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("edcba"));
}

BOOST_AUTO_TEST_CASE(reversebytes_32_byte_hash)
{
    std::vector<unsigned char> hash;
    for (unsigned char i = 0; i < 32; ++i) {
        hash.push_back(i);
    }
    std::vector<unsigned char> reversed(hash.rbegin(), hash.rend());

    CScript script;
    script << hash << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == reversed);
}

BOOST_AUTO_TEST_CASE(reversebytes_8_byte_amount)
{
    std::vector<unsigned char> amountLe = HexBytes({0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11});
    std::vector<unsigned char> amountBe = HexBytes({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});

    CScript script;
    script << amountLe << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == amountBe);
}

BOOST_AUTO_TEST_CASE(reversebytes_double_reverse_restores_original)
{
    std::vector<unsigned char> payload = Bytes("Neurai");
    CScript script;
    script << payload << OP_REVERSEBYTES << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == payload);
}

BOOST_AUTO_TEST_CASE(reversebytes_split_reverse_cat_roundtrip)
{
    std::vector<unsigned char> payload = Bytes("abcdef");
    CScript script;
    script << payload
           << CScriptNum(2) << OP_SPLIT
           << OP_REVERSEBYTES << OP_SWAP << OP_REVERSEBYTES
           << OP_CAT << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, CAT_SPLIT_REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == payload);
}

BOOST_AUTO_TEST_CASE(reversebytes_split_extract_middle_prefix)
{
    std::vector<unsigned char> payload = Bytes("abcdef");
    CScript script;
    script << payload
           << CScriptNum(2) << OP_SPLIT
           << OP_NIP
           << OP_REVERSEBYTES
           << CScriptNum(2) << OP_SPLIT
           << OP_NIP
           << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, SPLIT_REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("cd"));
}

BOOST_AUTO_TEST_SUITE_END()

// Phase 10: byte-level destination operations through actual script wrappers.
namespace {
using ReviewBytes = std::vector<unsigned char>;
const script_verify_flags REVIEW_BYTES_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_AUTHSCRIPT | SCRIPT_VERIFY_CAT | SCRIPT_VERIFY_SPLIT | SCRIPT_VERIFY_REVERSEBYTES;

ReviewBytes ReviewPayload(size_t size)
{
    ReviewBytes result(size);
    for (size_t i = 0; i < size; ++i) result[i] = i & 0xff;
    return result;
}

// Legacy bare script, P2WSH and NoAuth v1. No signature mock is involved.
// v2/v3 are destinations/data here, never arbitrary-script execution contexts.
void ReviewWrappedScript(const CScript& script, script_verify_flags flags, ScriptError expected)
{
    for (int wrapper = 0; wrapper < 3; ++wrapper) {
        BOOST_TEST_CONTEXT("wrapper=" << wrapper) {
            CScript spk = script;
            CScriptWitness witness;
            if (wrapper == 1) {
                ReviewBytes digest(32);
                CSHA256().Write(script.data(), script.size()).Finalize(digest.data());
                spk = CScript() << OP_0 << digest;
                witness.stack = {ReviewBytes(script.begin(), script.end())};
            } else if (wrapper == 2) {
                const auto commitment = GetAuthScriptCommitment(0x00, nullptr, script);
                spk = CScript() << OP_1 << ReviewBytes(commitment.begin(), commitment.end());
                witness.stack = {ReviewBytes{0x00}, ReviewBytes(script.begin(), script.end())};
            }
            ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
            bool ok = VerifyScript(CScript(), spk, &witness, flags, BaseSignatureChecker(), &error);
            BOOST_CHECK_EQUAL(ok, expected == SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(error, expected);
        }
    }
}
}

BOOST_FIXTURE_TEST_SUITE(opcode_bytes_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(versioned_destination_roundtrip)
{
    const auto commitment = ReviewPayload(32);
    for (unsigned char version : {1, 2, 3}) {
        ReviewBytes destination{version};
        destination.insert(destination.end(), commitment.begin(), commitment.end());
        CScript script;
        script << destination << OP_SIZE << 33 << OP_EQUALVERIFY
               << 1 << OP_SPLIT << commitment << OP_EQUALVERIFY
               << ReviewBytes{version} << OP_EQUALVERIFY
               << ReviewBytes{version} << commitment << OP_CAT
               << OP_REVERSEBYTES << OP_REVERSEBYTES << destination << OP_EQUAL;
        ReviewWrappedScript(script, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
        // Comparing the same program with another version must fail.
        destination[0] = version == 3 ? 1 : version + 1;
        ReviewWrappedScript(CScript() << ReviewBytes{version} << commitment << OP_CAT
                            << destination << OP_EQUAL, REVIEW_BYTES_FLAGS, SCRIPT_ERR_EVAL_FALSE);
        for (int position : {0, 1, 32, 33}) {
            ReviewWrappedScript(CScript() << destination << position << OP_SPLIT << OP_CAT
                                << destination << OP_EQUAL, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
        }
        for (int position : {-1, 34}) {
            ReviewWrappedScript(CScript() << destination << position << OP_SPLIT,
                                REVIEW_BYTES_FLAGS, SCRIPT_ERR_SPLIT);
        }
    }
}

BOOST_AUTO_TEST_CASE(byte_opcode_flags_and_underflow)
{
    for (auto opcode : {OP_CAT, OP_SPLIT, OP_REVERSEBYTES, OP_SIZE, OP_EQUAL, OP_EQUALVERIFY,
                       OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256}) {
        ReviewWrappedScript(CScript() << opcode, REVIEW_BYTES_FLAGS, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    ReviewWrappedScript(CScript() << OP_0 << OP_IF << OP_CAT << OP_ENDIF << OP_TRUE,
                        REVIEW_BYTES_FLAGS & ~SCRIPT_VERIFY_CAT, SCRIPT_ERR_DISABLED_OPCODE);
    ReviewWrappedScript(CScript() << OP_REVERSEBYTES,
                        REVIEW_BYTES_FLAGS & ~SCRIPT_VERIFY_REVERSEBYTES, SCRIPT_ERR_BAD_OPCODE);
    ReviewWrappedScript(CScript() << OP_0 << OP_IF << OP_REVERSEBYTES << OP_ENDIF << OP_TRUE,
                        REVIEW_BYTES_FLAGS & ~SCRIPT_VERIFY_REVERSEBYTES, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript() << OP_SPLIT << OP_TRUE,
                        REVIEW_BYTES_FLAGS & ~SCRIPT_VERIFY_SPLIT, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript() << OP_SPLIT << OP_TRUE,
                        (REVIEW_BYTES_FLAGS & ~SCRIPT_VERIFY_SPLIT) | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
                        SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(element_caps_and_pq_sized_bytes)
{
    for (script_verify_flags widening : std::vector<script_verify_flags>{script_verify_flags{}, SCRIPT_VERIFY_CHECKSIGFROMSTACK,
                                        SCRIPT_VERIFY_MERKLE_INCLUSION, SCRIPT_VERIFY_CHECKSIGADD}) {
        const auto flags = REVIEW_BYTES_FLAGS | widening;
        const size_t cap = widening ? 3072 : 520;
        for (size_t size : {size_t(32), size_t(33), size_t(520), size_t(521), size_t(1313),
                            size_t(2420), size_t(3072), size_t(3073)}) {
            const auto payload = ReviewPayload(size);
            // Check the cap on pushes and independently on a concatenation of legal pushes.
            CScript pushed;
            pushed << payload << OP_REVERSEBYTES << OP_REVERSEBYTES << OP_SIZE
                   << int64_t(size) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;
            ReviewWrappedScript(pushed, flags, size <= cap ? SCRIPT_ERR_OK : SCRIPT_ERR_PUSH_SIZE);
            if (size / 2 <= cap && size - size / 2 <= cap) {
                CScript joined;
                joined << ReviewBytes(payload.begin(), payload.begin() + size / 2)
                       << ReviewBytes(payload.begin() + size / 2, payload.end()) << OP_CAT
                       << OP_SIZE << int64_t(size) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;
                ReviewWrappedScript(joined, flags, size <= cap ? SCRIPT_ERR_OK : SCRIPT_ERR_PUSH_SIZE);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(independent_hash_vectors)
{
    // Literal expected digests calculated with Python hashlib/OpenSSL, not node crypto.
    // Inputs are byte i modulo 256, covering empty, commitment, destination and PQ sizes.
    struct Vector { size_t size; opcodetype opcode; const char* hex; };
    const Vector vectors[] = {
        {0, OP_RIPEMD160, "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
        {0, OP_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {0, OP_SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {0, OP_HASH160, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"},
        {0, OP_HASH256, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"},
        {32, OP_RIPEMD160, "e6babb9619d7a81272711fc546a16b211dd93957"},
        {32, OP_SHA1, "ae5bd8efea5322c4d9986d06680a781392f9a642"},
        {32, OP_SHA256, "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"},
        {32, OP_HASH160, "ea4beb47def8492389a1e16634795441e1b87245"},
        {32, OP_HASH256, "2f287b4d3d4910f6cada9e1bd1b4648099e8c52c81aa4a6aebfa6fc86f19834e"},
        {33, OP_RIPEMD160, "1e374ab924a652fa36b395d654d226bf901b6a04"},
        {33, OP_SHA1, "eb90bce364635c4c23b49f493f0043579bc85c17"},
        {33, OP_SHA256, "5d8fcfefa9aeeb711fb8ed1e4b7d5c8a9bafa46e8e76e68aa18adce5a10df6ab"},
        {33, OP_HASH160, "c31b1d87d352c7f17bc1e24942b05bdd4c3387ea"},
        {33, OP_HASH256, "240c77492ba62ab011374a7438a4ee6e393ff06865bcb117c60c8b5234ffa0e3"},
        {1313, OP_RIPEMD160, "c523368fd411eeb2000246add755fae636fd28da"},
        {1313, OP_SHA1, "1d4e51214b8e788ecee9bf131228f75f623b1ede"},
        {1313, OP_SHA256, "176109fabeed4f0a5f97d7ffd8ef97ffa1b5721b993cafc09ccbe5d8e4d15671"},
        {1313, OP_HASH160, "17c64d32fb5cae62bf24ec4f0253f068f300c0dc"},
        {1313, OP_HASH256, "552319f15c6f0ef753003d72f416dd6da417e197ccd09362efa1decc34600814"},
        {2420, OP_RIPEMD160, "e5531f24c80602339947818352487839bd749695"},
        {2420, OP_SHA1, "15184e55150ae82da4747f1b3cbebe899c02cdb1"},
        {2420, OP_SHA256, "5c45d6d4a62fa2b41163f5b9509e1d646b0f59bf9e300ac558d73c69c5cd2500"},
        {2420, OP_HASH160, "1819cb495ab6f7ac38fa538faa06807266a6fb6f"},
        {2420, OP_HASH256, "654904d0b727ffd4eebbd8f9930f6fbd492b21b93a47eb23ff30dae63690378e"},
    };
    for (const auto& vector : vectors) {
        BOOST_TEST_CONTEXT("size=" << vector.size << " opcode=" << int(vector.opcode)) {
            ReviewWrappedScript(CScript() << ReviewPayload(vector.size) << vector.opcode
                                << ParseHex(vector.hex) << OP_EQUAL,
                                REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_CHECKSIGFROMSTACK, SCRIPT_ERR_OK);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
