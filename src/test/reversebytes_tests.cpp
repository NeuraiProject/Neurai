// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha256.h"
#include "hash.h"
#include "chain.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
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
void ReviewWrappedScript(const CScript& script, script_verify_flags flags, ScriptError expected,
                         const BaseSignatureChecker& checker = BaseSignatureChecker())
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
            bool ok = VerifyScript(CScript(), spk, &witness, flags, checker, &error);
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

BOOST_FIXTURE_TEST_SUITE(modern_hash_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(independent_modern_vectors_and_composition)
{
    struct Vector { size_t size; opcodetype opcode; const char* hex; };
    // @noble/hashes oracle: scripts/generate-modern-hash-vectors.mjs.
    const Vector vectors[] = {
        {0, OP_KECCAK256, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
        {0, OP_BLAKE2B, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
        {0, OP_BLAKE3, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
        {0, OP_SHA3_256, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
        {0, OP_SHA512, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {32, OP_KECCAK256, "8ae1aa597fa146ebd3aa2ceddf360668dea5e526567e92b0321816a4e895bd2d"},
        {32, OP_BLAKE2B, "cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6"},
        {32, OP_BLAKE3, "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65"},
        {32, OP_SHA3_256, "050a48733bd5c2756ba95c5828cc83ee16fabcd3c086885b7744f84a0f9e0d94"},
        {32, OP_SHA512, "3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6fa9d71862a3e5746b571be3d187b0041046f52ebd850c7cbd5fde8ee38473b649"},
        {33, OP_KECCAK256, "f08683775f4a25dfef721c487073fb77026d45ac57e423424290e47af9fd2835"},
        {33, OP_BLAKE2B, "b7634fe13c7aca3914ee896e22cfabc9da5b4f13e72a2ccbecb6d44bbda95bcc"},
        {33, OP_BLAKE3, "4f4e6c1dffd3a6c9959876d15aa96b5fb0da8632b995f6ca2e30503f2829fa29"},
        {33, OP_SHA3_256, "f7b83039ff915ee67c8586ba2d4b9c348733d9c75863056efa4581e80a09b66e"},
        {33, OP_SHA512, "301f1cd7b25b097ae4c79a97e92bce359d1289f6754e76b71e7617a06e7783a3cc30f5290209bda3e6af239d0dc0f3d1cd4c5e866f4c5c3209eabbd7aafb8058"},
        {63, OP_KECCAK256, "eed42da65350e8490c201e15dd3bdb8aeaab8618692db71db386a19b6578c59d"},
        {63, OP_BLAKE2B, "29e41a64fbdd2fd27612228623c0702222bf367451e7324287f181cb3dcf7237"},
        {63, OP_BLAKE3, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"},
        {63, OP_SHA3_256, "ba7af58d214bb604bcaad40ad55cca7d9815e7535f1c9837be8fb8fee2519560"},
        {63, OP_SHA512, "9dc9c5598e55dc42955695320839788e353f1d7f6ba74df74c80a8a52f463c0697f57f68835d1418f4ce9b6530cd79bd0f4c6f7e13c93feb1218c0b65c2c0561"},
        {64, OP_KECCAK256, "002030bde3d4cf89919649775cd71875c4d0ab1708a380e03fefc3a28aa24831"},
        {64, OP_BLAKE2B, "10d8e6d534b00939843fe9dcc4dae48cdf008f6b8b2b82b156f5404d874887f5"},
        {64, OP_BLAKE3, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"},
        {64, OP_SHA3_256, "c8ad478f4e1dd9d47dfc3b985708d92db1f8db48fe9cddd459e63c321f490402"},
        {64, OP_SHA512, "ee4320ebaf3fdb4f2c832b137200c08e235e0fa7bbd0eb1740c7063ba8a0d151da77e003398e1714a955d475b05e3e950b639503b452ec185de4229bc4873949"},
        {65, OP_KECCAK256, "64578d7b8ae53c452c57b27375f3827854a7ead6448dc566d77a6673701f50d3"},
        {65, OP_BLAKE2B, "84c04ab082c8ae24206561f77397704b627892089a05887a2a1996472bcfe15d"},
        {65, OP_BLAKE3, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"},
        {65, OP_SHA3_256, "9a11f135d2231be8ee824d1e9d3204018870defc2f469f34ef5969b4815cec3c"},
        {65, OP_SHA512, "02856cef735f9acec6b9e33f0fbc8f9804d2aa54187f382b8ae842e5d3696c07459aad2a5aed25ea5e117eb1c7ba35da6a7a8adce9e6afe3ad79e9fa42d5bba8"},
        {127, OP_KECCAK256, "c52f0bd08793b9e8601b29753539e1bf47f8e483eed0a901e8761982449c9b4c"},
        {127, OP_BLAKE2B, "f2fe67ff342e21b8f45e8f2e0bcd1d9243245d50ee6c78042e9c491388791c72"},
        {127, OP_BLAKE3, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"},
        {127, OP_SHA3_256, "c66018e60c774d770cc6539d42c023fa974c29e3fe2db5925f226b9cc5cf8b05"},
        {127, OP_SHA512, "eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e35724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0"},
        {128, OP_KECCAK256, "ed4c9adc183fb8cb025b1500ec3eeae1b45517314441a187605de1bb8a64726e"},
        {128, OP_BLAKE2B, "c3582f71ebb2be66fa5dd750f80baae97554f3b015663c8be377cfcb2488c1d1"},
        {128, OP_BLAKE3, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"},
        {128, OP_SHA3_256, "bec3ebfba06834f224543cca2a427cb9329147be93e19aeb0e33a7119c7f63ef"},
        {128, OP_SHA512, "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b8351fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7"},
        {129, OP_KECCAK256, "e075544a1759c383a96a47f831194f0cf55c96a46b0656547d2f8c6eb96be8d3"},
        {129, OP_BLAKE2B, "f7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9"},
        {129, OP_BLAKE3, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"},
        {129, OP_SHA3_256, "0f41a20921bcbc39ee382dfb54daf2db373ce6b178833111e22f45266124f3cc"},
        {129, OP_SHA512, "1d9da57fbbdab09afb3506ab2d223d06109d65c1c8ad197f50138f714bc4c3f2fe5787922639c680acad1c651f955990425954ce2cba0c5cc83f2667d878eb0f"},
        {135, OP_KECCAK256, "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62"},
        {135, OP_BLAKE2B, "f7c4efacc0a4cb5836f170ea0bf5dc5ce36fe2d88e76a9f259eaab71aef0ff13"},
        {135, OP_BLAKE3, "69970da32d2e7da251ebf1d4e8324698a43d0bee4099ea1e6c6b6966c1a41c82"},
        {135, OP_SHA3_256, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"},
        {135, OP_SHA512, "9f0ddab7986da54e65ef6b536bb4f7bff468e0f310803de28d3908492343e4caa855b8cac7409e3a8928e63b9c5d1caea7a408ed061809dbae1ab1a67ba1b926"},
        {136, OP_KECCAK256, "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e"},
        {136, OP_BLAKE2B, "6a35d3dadc62dfe7819519f92181b2f8d38f5e0ed3d51a22cf8a133ab628d6f4"},
        {136, OP_BLAKE3, "0af7c61bbfd13f035392da915960078e3290e4774c266a15e63fface4f0d586d"},
        {136, OP_SHA3_256, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"},
        {136, OP_SHA512, "c58867d309ca48af74b4d7e49eced514c89fd433f9dd842f9b50ffaa6c7810bef35348d00d26dcbe28122ba1ce33d4cd00d09ba76f982a598b8f65790368ae59"},
        {137, OP_KECCAK256, "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db"},
        {137, OP_BLAKE2B, "bacecc2948c41beb73c815ca7cee6c7dbf2e4219190936edac5e4680500dd4d2"},
        {137, OP_BLAKE3, "091b697847114ff319e46b1eb7f5d7ad126daa7c5cbb9baa404dfc40791fab9e"},
        {137, OP_SHA3_256, "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca"},
        {137, OP_SHA512, "c8b1d6b4778932bc21eddbbe4e48f7711d7e97ed5354dcf11be98e3110510fb007948c288fd2f7aa71b2e41c86330dbbca2ed472d15b444828c6df4282815879"},
        {1023, OP_KECCAK256, "72c8aceb989f81fe8d56e84707f9bc1ed26711a790ecf07235fed42de910a622"},
        {1023, OP_BLAKE2B, "4cd9948ace2949f8ca457482230c28f3529d3ce3ed144d3d107dbf934ff2dbb5"},
        {1023, OP_BLAKE3, "29977c3bde643558fb32961d899ed2ad487a30cfddb1fb92c1f33f94f2910b11"},
        {1023, OP_SHA3_256, "3905255072f2a94a6ed4decf6b9b78d05ed3bf746537d05d6dd0382a05c8ab7c"},
        {1023, OP_SHA512, "6b6c0eb5310746598e562533f61e472da8a990d59907e7bc114f11c1b10acd2bbcc96980922df06bbb2c22ce58e79509424afbc7da7c1c3f6fded493561316b3"},
        {1024, OP_KECCAK256, "5902e53903be0d0f9656bdbd5b9f0d8c2d815f865645d629eef77f5185f6cd7f"},
        {1024, OP_BLAKE2B, "f1551feeb252c7e60bb362205bd1ac2f70b145260a91d41e8c5d0a187549a5f2"},
        {1024, OP_BLAKE3, "882179b8dbccd285cda241d968cfcccb3156c5edac2fa3761bb6eda7ff8cb172"},
        {1024, OP_SHA3_256, "b6c70631c6ff932b9f380d9cde8750eb9bea393817a9aea410c2119eb7b9b870"},
        {1024, OP_SHA512, "37f652be867f28ed033269cbba201af2112c2b3fd334a89fd2f757938ddee815787cc61d6e24a8a33340d0f7e86ffc058816b88530766ba6e231620a130b566c"},
        {1025, OP_KECCAK256, "3d79417ffcc9bf5c3b70efd014fbc41251613b60c252a054cb0aec5f5c83cc22"},
        {1025, OP_BLAKE2B, "1483c7c7d406e2c43b3feb32af98d9bb401b2d67b219f07fb90d4c6fc6051853"},
        {1025, OP_BLAKE3, "3e85e5a7ffcd07c23794c079d43ebb27372d06bb1f75e4b47732fcaaf1a8cf3d"},
        {1025, OP_SHA3_256, "a4440cd85393fdd288962839479ec2d729ad10f308e582d57e6d537123e3c452"},
        {1025, OP_SHA512, "8da0edfade9deb65227ad6070d933d8cafab77c822e3b8c50b3b392bb4fd5dbed339133cd5f58d82fcf0b0de110479ddfbe0d85fec9b610ece24a48e397807ea"},
        {1313, OP_KECCAK256, "799bbf3c68d214b88439a23a63bcbfb35adcb366b338379bcbc26ad62fc51d67"},
        {1313, OP_BLAKE2B, "e598530616a63380c29540d85fc0bdc2dc44ac6425d8e7d3de82de3de253b82c"},
        {1313, OP_BLAKE3, "3c80071d3f0032978615c2eeb9463a166b98eb882a921f81a98390231d6072fa"},
        {1313, OP_SHA3_256, "83f5926ce3f3578bc763e660812e9cb5fe5fbc09479e9162e23be1a17383fead"},
        {1313, OP_SHA512, "d9d71456bea7d802cdfa86b4627bd8b7fe31b6125f6c100c3562e10693584bab223224a91f14bc6df052513d27ddd44eefe0af9ca81488dc02bd42dd16d7fc2a"},
        {2420, OP_KECCAK256, "fbd0cc4c6b18f7cc90e116813d9a4e661b1f6cb6cdf4a04b4b4b16ecd3111ccb"},
        {2420, OP_BLAKE2B, "b8e24cad7234b962f09e52b8f7e05d1a30d54c4f94ceefdb202a96eb4276aaa2"},
        {2420, OP_BLAKE3, "4f36fd05d5f84d4c62d9daf176b93bbdbd5c8cf655b249869f06cf68fdb33ff0"},
        {2420, OP_SHA3_256, "0560678299c68de2ac1faeb2c049828de590b218228ebb2f20c8a618f2536476"},
        {2420, OP_SHA512, "901658f2546357887d9cd443d0d7ed3d3222e126cb3b739bd14684effe1fadb8d9327c347620f0ad8e3cab2af1c8b6c0c04bac762804cab834379e105d8e77be"},
        {3072, OP_KECCAK256, "b162ab7e4131fa5862215a4263000c08e9a4722745f415cebc1db02f0282026f"},
        {3072, OP_BLAKE2B, "20939d3d9057a2a4d77c7240d60cd2b270f29d1d6514e7b6577e261b9be75ba3"},
        {3072, OP_BLAKE3, "a10998beb5193c47a0c1cf19aa8daaa8dede3d9e5c53f78ecfe5d22e20f7f9bd"},
        {3072, OP_SHA3_256, "f70798eeafb733c988efdbfc9e85650df7885e447afaedb17004c3bc94493096"},
        {3072, OP_SHA512, "d9d60a2e78b04921ffc964dab2e8acbebab93aff3b46c66a397b3f5245d150170ca4d88e768d5aacc55df1ff40208b8c2aadefd4b798bcbd3de012d713ca0d1e"},
    };
    for (const auto& v : vectors) {
        BOOST_TEST_CONTEXT("size=" << v.size << " opcode=" << int(v.opcode)) {
            const auto expected = ParseHex(v.hex);
            const auto ownFlag = (v.opcode == OP_KECCAK256 || v.opcode == OP_BLAKE2B)
                ? SCRIPT_VERIFY_KECCAK_BLAKE2B : SCRIPT_VERIFY_MODERN_HASHES;
            const auto flags = REVIEW_BYTES_FLAGS | ownFlag | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
            // Own flag suffices. SHA512 must keep all 64 bytes, not truncate to 32.
            ReviewWrappedScript(CScript() << ReviewPayload(v.size) << v.opcode << OP_SIZE
                                << int64_t(expected.size()) << OP_EQUALVERIFY
                                << OP_REVERSEBYTES << OP_REVERSEBYTES
                                << expected << OP_EQUAL, flags, SCRIPT_ERR_OK);
            auto altered = expected;
            altered[0] ^= 1;
            ReviewWrappedScript(CScript() << ReviewPayload(v.size) << v.opcode << altered << OP_EQUAL,
                                flags, SCRIPT_ERR_EVAL_FALSE);
            // The input also arrives as an actual v1 witness argument, not only a script push.
            const CScript script = CScript() << v.opcode << expected << OP_EQUAL;
            const auto program = GetAuthScriptCommitment(0x00, nullptr, script);
            const CScript spk = CScript() << OP_1 << ReviewBytes(program.begin(), program.end());
            CScriptWitness witness;
            witness.stack = {ReviewBytes{0}, ReviewPayload(v.size), ReviewBytes(script.begin(), script.end())};
            ScriptError error;
            BOOST_CHECK(VerifyScript(CScript(), spk, &witness, flags, BaseSignatureChecker(), &error));
            BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        }
    }
}

BOOST_AUTO_TEST_CASE(modern_flags_underflow_and_size_limits)
{
    for (auto opcode : {OP_KECCAK256, OP_BLAKE2B, OP_BLAKE3, OP_SHA3_256, OP_SHA512}) {
        const auto ownFlag = (opcode == OP_KECCAK256 || opcode == OP_BLAKE2B)
            ? SCRIPT_VERIFY_KECCAK_BLAKE2B : SCRIPT_VERIFY_MODERN_HASHES;
        const auto otherFlag = (opcode == OP_KECCAK256 || opcode == OP_BLAKE2B)
            ? SCRIPT_VERIFY_MODERN_HASHES : SCRIPT_VERIFY_KECCAK_BLAKE2B;
        BOOST_TEST_CONTEXT("opcode=" << int(opcode)) {
            ReviewWrappedScript(CScript() << opcode, REVIEW_BYTES_FLAGS | ownFlag,
                                SCRIPT_ERR_INVALID_STACK_OPERATION);
            ReviewWrappedScript(CScript() << opcode, REVIEW_BYTES_FLAGS | otherFlag,
                                SCRIPT_ERR_BAD_OPCODE);
            ReviewWrappedScript(CScript() << OP_0 << OP_IF << opcode << OP_ENDIF << OP_TRUE,
                                REVIEW_BYTES_FLAGS | otherFlag, SCRIPT_ERR_OK);
            for (size_t size : {size_t(520), size_t(521), size_t(3072), size_t(3073)}) {
                for (bool wide : {false, true}) {
                    auto flags = REVIEW_BYTES_FLAGS | ownFlag;
                    if (wide) flags |= SCRIPT_VERIFY_CHECKSIGFROMSTACK;
                    const auto expected = size <= (wide ? 3072U : 520U) ? SCRIPT_ERR_OK : SCRIPT_ERR_PUSH_SIZE;
                    ReviewWrappedScript(CScript() << ReviewPayload(size) << opcode << OP_DROP << OP_TRUE,
                                        flags, expected);
                    const CScript script = CScript() << opcode << OP_DROP << OP_TRUE;
                    const auto program = GetAuthScriptCommitment(0x00, nullptr, script);
                    const CScript spk = CScript() << OP_1 << ReviewBytes(program.begin(), program.end());
                    CScriptWitness witness;
                    witness.stack = {ReviewBytes{0}, ReviewPayload(size), ReviewBytes(script.begin(), script.end())};
                    ScriptError error;
                    BOOST_CHECK_EQUAL(VerifyScript(CScript(), spk, &witness, flags, BaseSignatureChecker(), &error),
                                      expected == SCRIPT_ERR_OK);
                    BOOST_CHECK_EQUAL(error, expected);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(poseidon_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(byte_sponge_vectors_and_witness_arguments)
{
    // Python big integers and NIP-036 byte padding, shared pinned RC/MDS constants.
    struct Vector { const char* input; const char* output; };
    const Vector vectors[] = {
        {"", "067761295e881eec953a764e4d72bbccedf07472b57b9a3f754dcb5012441956"},
        {"00", "03e0d2ebfc1f715a436de3d6bf37c9632b33fe6a52c4127a6063ab2a6dc12926"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d", "1fdba9cb5ed5f33da3b2223236cbfc355a47906a1588b6eab00933ae7a1445f5"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e", "14f5046f58397839af50f7b95a50324a97a8ec182660cf85377b026b0ca6d310"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "25b8af87ce603ad9560c89d435b1b4bdf1aa579a5136c479975db18a00d84cf9"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "11f4d35b5bb6f9394b5bc848a1782f6a8a8be5baf2b9f12c7563eb0bd9ed9f64"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c", "23cfd24ca33621e8d72dbe8033f674441626e90c5c5401f1d4e6309df2df740f"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d", "19f817a2c194fd3d02ac4b6929f40f12724279f6016b71519578a16185a1b757"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e", "2752b5df09440108dda14a9180026737c45e314d89f71515d0aa53979596323b"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b", "192b08cca9c1ac64df308e7448d9e0da1d2d16ce7b80b42618acc3e0b5198a6f"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c", "222174e87a474ee008b0a6769bc76261a5f05e731a638414f668d0ded0523f53"},
        {"01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "079460506102d573845c1a79f6daf0b5820a030eb2a9b5f34e2fee6889c8ce88"},
        {"02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "1eac62c7328eb3c5c94401ce37fcefbcdf127d7cb1d5cedd7620010d28b7d363"},
        {"03000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "03a9f9a2c97539633b34b1fb679c4eb0d5055126554598b7ca529aa60c5ddae4"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0d6a41f61e6e7925da46e47726b9d153644e96c02a89947cf2143d718908a9b0"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "1b283a96e318b055af0ce6146333e9b8051dbbc02aa945f878ebdcaf711d1e4a"},
        {"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "253ea0caffc708a991bd491251425a1fdade99dd1bb26f33ea7478dbb415efc9"},
        {"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002", "054f24efe74f468258300b2e87088db8a046ad67306b108df03fd3c8bd624e07"},
    };
    const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_POSEIDON;
    for (const auto& vector : vectors) {
        BOOST_TEST_CONTEXT("input=" << vector.input) {
            const auto input = ParseHex(vector.input);
            const auto output = ParseHex(vector.output);
            ReviewWrappedScript(CScript() << input << OP_POSEIDON << OP_SIZE << 32 << OP_EQUALVERIFY
                                << output << OP_EQUAL, flags, SCRIPT_ERR_OK);
            auto wrong = output;
            wrong[0] ^= 1;
            ReviewWrappedScript(CScript() << input << OP_POSEIDON << wrong << OP_EQUAL,
                                flags, SCRIPT_ERR_EVAL_FALSE);
            const CScript script = CScript() << OP_POSEIDON << output << OP_EQUAL;
            const auto program = GetAuthScriptCommitment(0x00, nullptr, script);
            CScriptWitness witness;
            witness.stack = {ReviewBytes{0}, input, ReviewBytes(script.begin(), script.end())};
            ScriptError error;
            BOOST_CHECK(VerifyScript(CScript(), CScript() << OP_1 << ReviewBytes(program.begin(), program.end()),
                                    &witness, flags, BaseSignatureChecker(), &error));
            BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
        }
    }
}

BOOST_AUTO_TEST_CASE(exact_budget_reset_and_skipped_branch)
{
    const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_POSEIDON | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
    CScript atLimit;
    atLimit << ReviewPayload(3072);
    for (int i = 0; i < 10; ++i) atLimit << OP_DUP << OP_POSEIDON << OP_DROP;
    atLimit << OP_DROP;
    // Scripts remain below MAX_SCRIPT_SIZE: duplicate the payload, do not repeat pushes.
    ReviewWrappedScript(CScript(atLimit) << OP_TRUE, flags, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript(atLimit) << ReviewBytes{1} << OP_POSEIDON,
                        flags, SCRIPT_ERR_POSEIDON_BUDGET); // 30721 bytes, not 11 full payloads
    // Empty input costs zero input bytes but still hashes with padding.
    ReviewWrappedScript(CScript(atLimit) << OP_0 << OP_POSEIDON << OP_DROP << OP_TRUE,
                        flags, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript(atLimit) << OP_0 << OP_IF << ReviewBytes{1} << OP_POSEIDON
                        << OP_DROP << OP_ENDIF << OP_TRUE, flags, SCRIPT_ERR_OK);
    // A failed evaluation cannot leak the consumed budget into the next script.
    ReviewWrappedScript(CScript(atLimit) << OP_TRUE, flags, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(poseidon_flag_and_element_limit_are_independent)
{
    ReviewWrappedScript(CScript() << OP_POSEIDON, REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_MODERN_HASHES,
                        SCRIPT_ERR_BAD_OPCODE);
    ReviewWrappedScript(CScript() << OP_POSEIDON, REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_POSEIDON,
                        SCRIPT_ERR_INVALID_STACK_OPERATION);
    ReviewWrappedScript(CScript() << OP_0 << OP_IF << OP_POSEIDON << OP_ENDIF << OP_TRUE,
                        REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
    for (size_t length : {size_t(520), size_t(521), size_t(3072), size_t(3073)}) {
        for (bool wide : {false, true}) {
            auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_POSEIDON;
            if (wide) flags |= SCRIPT_VERIFY_CHECKSIGFROMSTACK;
            const auto expected = length <= (wide ? 3072U : 520U) ? SCRIPT_ERR_OK : SCRIPT_ERR_PUSH_SIZE;
            ReviewWrappedScript(CScript() << ReviewPayload(length) << OP_POSEIDON << OP_DROP << OP_TRUE,
                                flags, expected);
            const CScript script = CScript() << OP_POSEIDON << OP_DROP << OP_TRUE;
            const auto program = GetAuthScriptCommitment(0x00, nullptr, script);
            CScriptWitness witness;
            witness.stack = {ReviewBytes{0}, ReviewPayload(length), ReviewBytes(script.begin(), script.end())};
            ScriptError error;
            BOOST_CHECK_EQUAL(VerifyScript(CScript(), CScript() << OP_1 << ReviewBytes(program.begin(), program.end()),
                                          &witness, flags, BaseSignatureChecker(), &error), expected == SCRIPT_ERR_OK);
            BOOST_CHECK_EQUAL(error, expected);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

namespace {
ReviewBytes ReviewMerkleProof(unsigned int depth)
{
    ReviewBytes proof{static_cast<unsigned char>(depth)};
    for (unsigned int level = 0; level < depth; ++level)
        for (unsigned int j = 0; j < 32; ++j) proof.push_back((37 * level + j) & 0xff);
    for (unsigned int i = 0; i < (depth + 7) / 8; ++i) proof.push_back(0xa5);
    return proof;
}
CScript ReviewMerkleScript(const ReviewBytes& leaf, const ReviewBytes& scheme,
                          const ReviewBytes& proof, const ReviewBytes& root)
{
    return CScript() << leaf << scheme << proof << root << OP_CHECKMERKLEINCLUSION;
}
}

BOOST_FIXTURE_TEST_SUITE(merkle_opcode_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(independent_roots_destinations_and_mutations)
{
    struct Vector { unsigned char scheme; unsigned int depth; unsigned char version; const char* root; };
    // scripts/generate-merkle-review-vectors.mjs: independent hash/path calculation.
    const Vector vectors[] = {
        {1, 0, 1, "491176b0f443c65a7c7d72df47d6cbc0d04e111fb5a619f60d3e77677ab6f919"},
        {1, 0, 2, "121e01fd47d8c2ecdb10fa6f0a51a97a48cebd0de5231f274f5076a03e371868"},
        {1, 0, 3, "3cea1c8fb8815b13cc24bb320c9b7887ad2a0c76c96bb249720f7c550924d4e6"},
        {1, 1, 1, "a7f27106d4a927dcb3ca1274d79d3d1c8adc3b1293d7af62bb0a74bb1b61c644"},
        {1, 1, 2, "7f8da84fcef42ddd8d5da6cf6216d4c960db13ab571203932715edb62b6d7e1c"},
        {1, 1, 3, "135d98f0b756e17c15e552972fc0c830274374153919327368060c35009f0a2b"},
        {1, 7, 1, "48dc31ffc4a4db7fec6b2de76f1809a5c2b2f605acfaaa6d533d47377fc903ea"},
        {1, 7, 2, "f1a8f5304b98d692742cfd66a53fe3023ea3cfce53e560373c55afb10cc30052"},
        {1, 7, 3, "e2faca14bd668b3a3ab12d196f089a03e7b8a758b20e9723fbbc9bc93a5cd463"},
        {1, 8, 1, "7134ebea93fee12cb559da087a5870aecfe60889c92ca8523a000cdd7739049d"},
        {1, 8, 2, "0f0feafa388bbd3d7fb290277c372fda3c8c57adfd81837c8f63c7f73f92cc57"},
        {1, 8, 3, "063819f020eb0d3435f0404f8a37350f16e2cc3a433d2ffa141e2a549939669f"},
        {1, 9, 1, "51bfd9914faf4bac084edd963c60136e47bfaff38f36d82a55c6268b5ac53558"},
        {1, 9, 2, "cabba54a0a36e20fb6ab55a6544d55146e342e24aaafc96883aef6f376044dc0"},
        {1, 9, 3, "1219af21246e321d86510fe9417b9b04edfd2e232ddae635dc7a53ff9e1b6b34"},
        {1, 16, 1, "ed46db28a967a0db1c8e15c862f9938f0c320820619149524f9094fc45274fdb"},
        {1, 16, 2, "62e3453bf376f013ba4b8a5655238ae4008caf347cfa816f8acee10ac20e7053"},
        {1, 16, 3, "290ee47d3d05d3b44e929361e4e567cd8e6e8938155ef4e407305577fe0c2596"},
        {1, 31, 1, "2c5e606eca178a9262875b33240c5ddd85a989dff428781c9a19803e66667e38"},
        {1, 31, 2, "307fbf854b26dbd19cc458d534051aa805cd8eac307f4078cfd6b609476a73d6"},
        {1, 31, 3, "09bc995fe11d4226ea484735721b34d95ca77d32176ec66fb542e99346ee09ca"},
        {1, 32, 1, "9bde1c9478b24e74acde3893f547c8525848c859a2e7eeca7011586e7e166722"},
        {1, 32, 2, "32a73aa72197073598ad03b333567e4689553a2d5c03f24b674fe905d75de45e"},
        {1, 32, 3, "93ebfd8da7593c0971a0acb4e409d4ee682b2e607cabfb49186e85d84947f896"},
        {2, 0, 1, "491176b0f443c65a7c7d72df47d6cbc0d04e111fb5a619f60d3e77677ab6f919"},
        {2, 0, 2, "121e01fd47d8c2ecdb10fa6f0a51a97a48cebd0de5231f274f5076a03e371868"},
        {2, 0, 3, "3cea1c8fb8815b13cc24bb320c9b7887ad2a0c76c96bb249720f7c550924d4e6"},
        {2, 1, 1, "e14517da9d21ea21d7039633876f22b3e545c0f6102195e044ad0b6a6b94a8dc"},
        {2, 1, 2, "3202f596c1ad3b22e960996f4678c34ea2e55b374d0e0cab451efec948ab5b8a"},
        {2, 1, 3, "6bea2593dbb58c90438ac00827a86b4abdf5686a2523f98c55fdeed2346d6ce3"},
        {2, 7, 1, "596c78bc9a53b735faef333881835d4e53d733e1a6f279b281793e3775642405"},
        {2, 7, 2, "4e92358cafcc0014863b0aafef7c90beb7e35b91223fb6cd21814bc1eaf61ac9"},
        {2, 7, 3, "aad8d448b792b55bb1370cf5fd011abaa88d7046a3c60ecfefa6236cdeb63021"},
        {2, 8, 1, "1dbb07d4c4da5383adc6211ce4ce42b0e8f5920cae4bd4a02e88e6b8ea486bef"},
        {2, 8, 2, "f3e33798884bf20d6e58cfa2182adcbf25afe54efcfea6c4b0b85c0aa45ddeea"},
        {2, 8, 3, "ae6b92fd7609d02e24c240a571887c6d58c28adfcb115b36c09d3ec4bca428ec"},
        {2, 9, 1, "04c42f1ea321b807d5c8377f5313e27b2c52d7d139ecc199e56a683e010c3739"},
        {2, 9, 2, "979025782f58227e0488090d473557c6eb9e059c3fced7702ce37d94bd69c135"},
        {2, 9, 3, "6c77779e373f0310399305583d9682a73895d014cc25d352596474f30eeccaed"},
        {2, 16, 1, "2755cb41f707a82e15e13ca1e4b86091446f099765d1e8040a3f16e5dd67897d"},
        {2, 16, 2, "05250d7d0d782ff0390ebd538a3f9117e6212691fb67f53fda2365d436e02bbe"},
        {2, 16, 3, "a235b48e3d3fcf1e5831734d78316b45bedad2dd7d0df8fad664c1299baf6f67"},
        {2, 31, 1, "de7cf90df430e7ec413195cc1060f6b149ddd0faaea812bd0fd7996815980c20"},
        {2, 31, 2, "f15b725fd9e3ca044ba274f0a462837a119cc1be4e7a09763da4449396508795"},
        {2, 31, 3, "b2ad55598404fb2e853853b3d152596a85aacd567eeaa4834eeb69c256ff0aed"},
        {2, 32, 1, "ddfe5649fb4cb4f0d6cdb8d29682b140cd3e36c7aeb3fe017221559ef2a8f793"},
        {2, 32, 2, "0af920ead7f4e8182571509afaa6bcebdaf0bb947b20d0efd2bca23c94f35933"},
        {2, 32, 3, "5bd1e6680a4187b12dca160298f39f1e80c2fbdf61a6d86f58084d3d9c87e130"},
        {3, 0, 1, "e46e20db49e842154b399b4b5f7200464f9370a5bee4d92a971d96b24d802cfc"},
        {3, 0, 2, "3ff103374c1cebfd660cbe9f9ef14bc42cbabff49026d0ea7d3720f3dfe5b55a"},
        {3, 0, 3, "096634ab32448c364818d2e2dc6cdd759aba16f07cded2b41d9820581b30791c"},
        {3, 1, 1, "0d1cf924bb3487a1cc395ef4825a26e340449f8563c096a31b29ed122ece5d54"},
        {3, 1, 2, "c0e153a803a3a6e6a7d1cac02f44a8989f0d0fb5beb6c5f7aec2f5375319ae8a"},
        {3, 1, 3, "12b3942a8b296128c156e7de11233369fbd9fdef2aecaa9e74ab984d97265723"},
        {3, 7, 1, "67f10a154b2aa11a3612488a8bab41a3bd0b6681c6c4ff191fa913c41d37c1be"},
        {3, 7, 2, "306663ffe8f9a633fe31fd1331eeb5a56d80c56dcfefe1b1ec73a4492716fabd"},
        {3, 7, 3, "19b88b33ee8c68411aeb45a2d0c2a4cdd563821d46cd53d11ec2ad36cb3dbba9"},
        {3, 8, 1, "6ba1e5923c1ff0c0708b2994bd8138067ca28822931aa09309f2584279099f72"},
        {3, 8, 2, "eaebc585ad4065359f4a0c00c096c8fe0c83ebd2990a6cc78b5436972c718623"},
        {3, 8, 3, "5d781f361edffb3149bf6ed3b44c254598594ef741823cfccc8f297647de1ec1"},
        {3, 9, 1, "760816419fe137d5f948c2b9711b93df159ff38bd0dfbac9b1296a8aa5b3c35b"},
        {3, 9, 2, "75f3b4f1d8ab154dc29e3a721a71d6c51958b1ebd4a6138e5b1369b0f6cc8d36"},
        {3, 9, 3, "ffb7ab02eb92a644a4916830f35a12576762337e636fc5074b83eb639ef90e9f"},
        {3, 16, 1, "633e0fbc92b018c24a88f951baf71110849297e8a40f185519773f32e5e6a12e"},
        {3, 16, 2, "4fc1fa70d76d4fb81c76a548b63f527cf3e89e250a99481cb28f55b5b8e44441"},
        {3, 16, 3, "a96563e31aaede282982b3d07d02b4644518bac291df07d36456a58c932af751"},
        {3, 31, 1, "2b34be23f88fbe66bde89f1475c368d25cd71b365b596dd9068baf1385199c35"},
        {3, 31, 2, "c4d2fcdbcd64733118fecb4dcb16da340c9429175012c751f35377d874f5d05c"},
        {3, 31, 3, "5fb52c42b612602dc30f4578ca7091879f17a6b9ebac79c007e299fc26e97000"},
        {3, 32, 1, "eb8560bd63034b6e607d4fcf0f96149838a18813aca5746252eed372875e089a"},
        {3, 32, 2, "46e2e7680222218cdf2f765521cab01402c94f6b1e6d5d4e51ae663527346b0a"},
        {3, 32, 3, "e671a96cd9f84be7939b11ecea2f377cae5f6992ffc2b21b40f0ac4bac8dea2a"},
        {4, 0, 1, "c3e8f071cd73953c3ec0ef9cf9f963edf735449f0b4fe799769a4b9e794e5664"},
        {4, 0, 2, "302abf71c5b4ab901c81429865398872d618d47e6e5b5d76194fd5f7fce7d22b"},
        {4, 0, 3, "b81126497cc5f75b78417e5a269445a17834d80064fdf540eb4f29a394f07ac7"},
        {4, 1, 1, "7200337727dbe2b6ce23413dc06c35485086239dcef638fd08ae034eb1e41cf8"},
        {4, 1, 2, "3d2bd90e95e50df7255c10e8dca3809311a953a3fd047324b6b7dbc19a912a87"},
        {4, 1, 3, "8a113d7c087aa1fb884b55906eb6f3ed3358cd406591a4816371ae1a6a77ce0a"},
        {4, 7, 1, "3136f7f10afb239a1fbc1f89434f0c5ceaaf00ff9971651c060120a7254785c8"},
        {4, 7, 2, "e3de49e0af9e8a409e754499484285128983e7a5e1445a50f42fd7cf825a2655"},
        {4, 7, 3, "09db72ecd6f225182d88bfb0985e85e8c7ac88268fb26b2b4bdbdf38da6a5df7"},
        {4, 8, 1, "b434777c5b964e203a4f538c5133c186567175bc82b7b799383cb60ba8de41a5"},
        {4, 8, 2, "af4ef14219079fe00f58067929cf7f1d907d7f86073050092e5aff6ceedcaaca"},
        {4, 8, 3, "1eb46873d0cd7061a1d0145a81f79e14778abb56705bd25a2b77edf287e2ee20"},
        {4, 9, 1, "ce3f8e1eb467a823052da3dc789436a5e4a814a7fdaad24a765fd58e15408842"},
        {4, 9, 2, "2760575a297871d68eebe9d1e4c504d04bf158a12152f9df8ae7a17c6b4cca44"},
        {4, 9, 3, "09722587f886f9e9d911df9469a39f8a0846637038f78762dc59d2dcf1e3d2ac"},
        {4, 16, 1, "83a0840953926aae48f755a68d0c95a4b99be52a2bb60fce4175ab174b3349b3"},
        {4, 16, 2, "5d946e16396be5c913df6286cbfbb481ec7a058eb0696927e4541b9bdfeff47d"},
        {4, 16, 3, "a41b6f7bfa2ec08d7d5cd7f771935e924083281a48445851798575f684b99fa8"},
        {4, 31, 1, "04b95758e584a0242fd45846cf83a291c86acd336eb1598b9228320085c3ebba"},
        {4, 31, 2, "c2f344ec1e4d7405b151b0f3477e3f7822b3cc8fddc51ef33c2c0f3c273ad0bf"},
        {4, 31, 3, "53c44b2b5d5531152eb24e862ac8a021b7117f079c48933c2da736b534023593"},
        {4, 32, 1, "6fbcdff44e7d510b8af397d15ca882a5347baae614faa5a43b5a3c89c90e44e3"},
        {4, 32, 2, "910f1e6c2370bfe1461ff947fdae21196fa4743f807b10805c99e7e57e3cd36b"},
        {4, 32, 3, "b2baed86b62039e23ff932d5d050b9bf4c7c74ccb7247bb5f6922e8c48d5706a"},
    };
    const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_MERKLE_INCLUSION | SCRIPT_VERIFY_KECCAK_BLAKE2B;
    for (const auto& v : vectors) {
        BOOST_TEST_CONTEXT("scheme=" << int(v.scheme) << " depth=" << v.depth << " version=" << int(v.version)) {
            ReviewBytes leaf{v.version};
            const auto commitment = ReviewPayload(32);
            leaf.insert(leaf.end(), commitment.begin(), commitment.end());
            if (v.scheme == 1) {
                ReviewBytes digest(32);
                CSHA256().Write(leaf.data(), leaf.size()).Finalize(digest.data());
                leaf = digest;
            }
            const auto proof = ReviewMerkleProof(v.depth);
            const auto root = ParseHex(v.root);
            ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, proof, root), flags, SCRIPT_ERR_OK);
            // Check actual v1 witness arguments, including the 1029-byte depth-32 proof.
            const CScript script = CScript() << OP_CHECKMERKLEINCLUSION;
            const auto program = GetAuthScriptCommitment(0x00, nullptr, script);
            CScriptWitness witness;
            witness.stack = {ReviewBytes{0}, leaf, ReviewBytes{v.scheme}, proof, root,
                             ReviewBytes(script.begin(), script.end())};
            ScriptError error;
            BOOST_CHECK(VerifyScript(CScript(), CScript() << OP_1 << ReviewBytes(program.begin(), program.end()),
                                    &witness, flags, BaseSignatureChecker(), &error));
            BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
            auto changed = leaf;
            changed[0] ^= 1;
            ReviewWrappedScript(ReviewMerkleScript(changed, {v.scheme}, proof, root), flags, SCRIPT_ERR_EVAL_FALSE);
            auto badRoot = root;
            badRoot[0] ^= 1;
            ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, proof, badRoot), flags, SCRIPT_ERR_EVAL_FALSE);
            for (bool append : {false, true}) {
                auto malformed = proof;
                if (append) malformed.push_back(0); else malformed.pop_back();
                // Malformed proof produces false, not an opcode exception: OP_NOT must succeed.
                ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, malformed, root) << OP_NOT,
                                    flags, SCRIPT_ERR_OK);
            }
            if (v.depth) {
                auto sibling = proof;
                sibling[1] ^= 1;
                ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, sibling, root), flags, SCRIPT_ERR_EVAL_FALSE);
                auto direction = proof;
                direction[1 + 32 * v.depth] ^= 1;
                ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, direction, root), flags, SCRIPT_ERR_EVAL_FALSE);
                if (v.depth % 8) {
                    // Existing format ignores unused high bitmap bits; do not tighten consensus here.
                    auto unused = proof;
                    unused.back() ^= 0x80;
                    ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, unused, root), flags, SCRIPT_ERR_OK);
                }
            }
            // SHA schemes need only NIP-031; Keccak/BLAKE2b also require NIP-030.
            ReviewWrappedScript(ReviewMerkleScript(leaf, {v.scheme}, proof, root),
                                flags & ~SCRIPT_VERIFY_KECCAK_BLAKE2B,
                                v.scheme <= 2 ? SCRIPT_ERR_OK : SCRIPT_ERR_EVAL_FALSE);
        }
    }
}

BOOST_AUTO_TEST_CASE(format_depth_and_flag_rejections)
{
    const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_MERKLE_INCLUSION | SCRIPT_VERIFY_KECCAK_BLAKE2B;
    const auto leaf = ReviewPayload(32);
    for (const auto& scheme : std::vector<ReviewBytes>{{}, {0}, {5}, {255}, {1,0}}) {
        ReviewWrappedScript(ReviewMerkleScript(leaf, scheme, {0}, leaf) << OP_NOT, flags, SCRIPT_ERR_OK);
    }
    for (size_t size : {size_t(0),size_t(31),size_t(33)}) {
        ReviewWrappedScript(ReviewMerkleScript(leaf, {1}, {0}, ReviewPayload(size)) << OP_NOT, flags, SCRIPT_ERR_OK);
        ReviewWrappedScript(ReviewMerkleScript(ReviewPayload(size), {1}, {0}, leaf) << OP_NOT, flags, SCRIPT_ERR_OK);
    }
    ReviewWrappedScript(ReviewMerkleScript(leaf, {1}, ReviewMerkleProof(33), leaf) << OP_NOT, flags, SCRIPT_ERR_OK);
    for (int count = 0; count < 4; ++count) {
        CScript script;
        for (int i = 0; i < count; ++i) script << leaf;
        ReviewWrappedScript(script << OP_CHECKMERKLEINCLUSION, flags, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    ReviewWrappedScript(CScript() << OP_CHECKMERKLEINCLUSION, flags & ~SCRIPT_VERIFY_MERKLE_INCLUSION,
                        SCRIPT_ERR_BAD_OPCODE);
    ReviewWrappedScript(CScript() << OP_0 << OP_IF << OP_CHECKMERKLEINCLUSION << OP_ENDIF << OP_TRUE,
                        flags & ~SCRIPT_VERIFY_MERKLE_INCLUSION, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(arithmetic_opcode_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(independent_integer_results_and_errors)
{
    // Python arbitrary precision, truncation toward zero and independent ScriptNum encoding.
    struct Vector { const char* script; const char* expected; ScriptError error; };
    const Vector vectors[] = {
        {"000093", "", SCRIPT_ERR_OK},
        {"000094", "", SCRIPT_ERR_OK},
        {"000095", "", SCRIPT_ERR_OK},
        {"00009a", "", SCRIPT_ERR_OK},
        {"00009b", "", SCRIPT_ERR_OK},
        {"00009c", "01", SCRIPT_ERR_OK},
        {"00009e", "", SCRIPT_ERR_OK},
        {"00009f", "", SCRIPT_ERR_OK},
        {"0000a0", "", SCRIPT_ERR_OK},
        {"0000a1", "01", SCRIPT_ERR_OK},
        {"0000a2", "01", SCRIPT_ERR_OK},
        {"0000a3", "", SCRIPT_ERR_OK},
        {"0000a4", "", SCRIPT_ERR_OK},
        {"000096", "", SCRIPT_ERR_DIV_BY_ZERO},
        {"000097", "", SCRIPT_ERR_MOD_BY_ZERO},
        {"575393", "0a", SCRIPT_ERR_OK},
        {"575394", "04", SCRIPT_ERR_OK},
        {"575395", "15", SCRIPT_ERR_OK},
        {"57539a", "01", SCRIPT_ERR_OK},
        {"57539b", "01", SCRIPT_ERR_OK},
        {"57539c", "", SCRIPT_ERR_OK},
        {"57539e", "01", SCRIPT_ERR_OK},
        {"57539f", "", SCRIPT_ERR_OK},
        {"5753a0", "01", SCRIPT_ERR_OK},
        {"5753a1", "", SCRIPT_ERR_OK},
        {"5753a2", "01", SCRIPT_ERR_OK},
        {"5753a3", "03", SCRIPT_ERR_OK},
        {"5753a4", "07", SCRIPT_ERR_OK},
        {"575396", "02", SCRIPT_ERR_OK},
        {"575397", "01", SCRIPT_ERR_OK},
        {"01875393", "84", SCRIPT_ERR_OK},
        {"01875394", "8a", SCRIPT_ERR_OK},
        {"01875395", "95", SCRIPT_ERR_OK},
        {"0187539a", "01", SCRIPT_ERR_OK},
        {"0187539b", "01", SCRIPT_ERR_OK},
        {"0187539c", "", SCRIPT_ERR_OK},
        {"0187539e", "01", SCRIPT_ERR_OK},
        {"0187539f", "01", SCRIPT_ERR_OK},
        {"018753a0", "", SCRIPT_ERR_OK},
        {"018753a1", "01", SCRIPT_ERR_OK},
        {"018753a2", "", SCRIPT_ERR_OK},
        {"018753a3", "87", SCRIPT_ERR_OK},
        {"018753a4", "03", SCRIPT_ERR_OK},
        {"01875396", "82", SCRIPT_ERR_OK},
        {"01875397", "81", SCRIPT_ERR_OK},
        {"57018393", "04", SCRIPT_ERR_OK},
        {"57018394", "0a", SCRIPT_ERR_OK},
        {"57018395", "95", SCRIPT_ERR_OK},
        {"5701839a", "01", SCRIPT_ERR_OK},
        {"5701839b", "01", SCRIPT_ERR_OK},
        {"5701839c", "", SCRIPT_ERR_OK},
        {"5701839e", "01", SCRIPT_ERR_OK},
        {"5701839f", "", SCRIPT_ERR_OK},
        {"570183a0", "01", SCRIPT_ERR_OK},
        {"570183a1", "", SCRIPT_ERR_OK},
        {"570183a2", "01", SCRIPT_ERR_OK},
        {"570183a3", "83", SCRIPT_ERR_OK},
        {"570183a4", "07", SCRIPT_ERR_OK},
        {"57018396", "82", SCRIPT_ERR_OK},
        {"57018397", "01", SCRIPT_ERR_OK},
        {"0187018393", "8a", SCRIPT_ERR_OK},
        {"0187018394", "84", SCRIPT_ERR_OK},
        {"0187018395", "15", SCRIPT_ERR_OK},
        {"018701839a", "01", SCRIPT_ERR_OK},
        {"018701839b", "01", SCRIPT_ERR_OK},
        {"018701839c", "", SCRIPT_ERR_OK},
        {"018701839e", "01", SCRIPT_ERR_OK},
        {"018701839f", "01", SCRIPT_ERR_OK},
        {"01870183a0", "", SCRIPT_ERR_OK},
        {"01870183a1", "01", SCRIPT_ERR_OK},
        {"01870183a2", "", SCRIPT_ERR_OK},
        {"01870183a3", "87", SCRIPT_ERR_OK},
        {"01870183a4", "83", SCRIPT_ERR_OK},
        {"0187018396", "02", SCRIPT_ERR_OK},
        {"0187018397", "81", SCRIPT_ERR_OK},
        {"04ffffff7f5193", "0000008000", SCRIPT_ERR_OK},
        {"04ffffff7f5194", "feffff7f", SCRIPT_ERR_OK},
        {"04ffffff7f5195", "ffffff7f", SCRIPT_ERR_OK},
        {"04ffffff7f519a", "01", SCRIPT_ERR_OK},
        {"04ffffff7f519b", "01", SCRIPT_ERR_OK},
        {"04ffffff7f519c", "", SCRIPT_ERR_OK},
        {"04ffffff7f519e", "01", SCRIPT_ERR_OK},
        {"04ffffff7f519f", "", SCRIPT_ERR_OK},
        {"04ffffff7f51a0", "01", SCRIPT_ERR_OK},
        {"04ffffff7f51a1", "", SCRIPT_ERR_OK},
        {"04ffffff7f51a2", "01", SCRIPT_ERR_OK},
        {"04ffffff7f51a3", "01", SCRIPT_ERR_OK},
        {"04ffffff7f51a4", "ffffff7f", SCRIPT_ERR_OK},
        {"04ffffff7f5196", "ffffff7f", SCRIPT_ERR_OK},
        {"04ffffff7f5197", "", SCRIPT_ERR_OK},
        {"0500000080005293", "0200008000", SCRIPT_ERR_OK},
        {"0500000080005294", "feffff7f", SCRIPT_ERR_OK},
        {"0500000080005295", "0000000001", SCRIPT_ERR_OK},
        {"050000008000529a", "01", SCRIPT_ERR_OK},
        {"050000008000529b", "01", SCRIPT_ERR_OK},
        {"050000008000529c", "", SCRIPT_ERR_OK},
        {"050000008000529e", "01", SCRIPT_ERR_OK},
        {"050000008000529f", "", SCRIPT_ERR_OK},
        {"05000000800052a0", "01", SCRIPT_ERR_OK},
        {"05000000800052a1", "", SCRIPT_ERR_OK},
        {"05000000800052a2", "01", SCRIPT_ERR_OK},
        {"05000000800052a3", "02", SCRIPT_ERR_OK},
        {"05000000800052a4", "0000008000", SCRIPT_ERR_OK},
        {"0500000080005296", "00000040", SCRIPT_ERR_OK},
        {"0500000080005297", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f5193", "", SCRIPT_ERR_ADD_OVERFLOW},
        {"08ffffffffffffff7f5194", "feffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f5195", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f519a", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f519b", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f519c", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f519e", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f519f", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f51a0", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f51a1", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f51a2", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f51a3", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f51a4", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f5196", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f5197", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f93", "", SCRIPT_ERR_ADD_OVERFLOW},
        {"08ffffffffffffffff4f94", "feffffffffffffff", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f95", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f9a", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f9b", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f9c", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f9e", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f9f", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4fa0", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4fa1", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4fa2", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4fa3", "ffffffffffffffff", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4fa4", "81", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f96", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffffff4f97", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f93", "", SCRIPT_ERR_ADD_OVERFLOW},
        {"08ffffffffffffff7f08ffffffffffffff7f94", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f95", "", SCRIPT_ERR_MUL_OVERFLOW},
        {"08ffffffffffffff7f08ffffffffffffff7f9a", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f9b", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f9c", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f9e", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f9f", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7fa0", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7fa1", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7fa2", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7fa3", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7fa4", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f96", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffff7f97", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f93", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f94", "", SCRIPT_ERR_SUB_OVERFLOW},
        {"08ffffffffffffffff08ffffffffffffff7f95", "", SCRIPT_ERR_MUL_OVERFLOW},
        {"08ffffffffffffffff08ffffffffffffff7f9a", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f9b", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f9c", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f9e", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f9f", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7fa0", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7fa1", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7fa2", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7fa3", "ffffffffffffffff", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7fa4", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f96", "81", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffff7f97", "", SCRIPT_ERR_OK},
        {"05000000000105000000800093", "0000008001", SCRIPT_ERR_OK},
        {"05000000000105000000800094", "0000008000", SCRIPT_ERR_OK},
        {"05000000000105000000800095", "", SCRIPT_ERR_MUL_OVERFLOW},
        {"0500000000010500000080009a", "01", SCRIPT_ERR_OK},
        {"0500000000010500000080009b", "01", SCRIPT_ERR_OK},
        {"0500000000010500000080009c", "", SCRIPT_ERR_OK},
        {"0500000000010500000080009e", "01", SCRIPT_ERR_OK},
        {"0500000000010500000080009f", "", SCRIPT_ERR_OK},
        {"050000000001050000008000a0", "01", SCRIPT_ERR_OK},
        {"050000000001050000008000a1", "", SCRIPT_ERR_OK},
        {"050000000001050000008000a2", "01", SCRIPT_ERR_OK},
        {"050000000001050000008000a3", "0000008000", SCRIPT_ERR_OK},
        {"050000000001050000008000a4", "0000000001", SCRIPT_ERR_OK},
        {"05000000000105000000800096", "02", SCRIPT_ERR_OK},
        {"05000000000105000000800097", "", SCRIPT_ERR_OK},
        {"05000000008105000000800093", "0000008080", SCRIPT_ERR_OK},
        {"05000000008105000000800094", "0000008081", SCRIPT_ERR_OK},
        {"05000000008105000000800095", "", SCRIPT_ERR_MUL_OVERFLOW},
        {"0500000000810500000080009a", "01", SCRIPT_ERR_OK},
        {"0500000000810500000080009b", "01", SCRIPT_ERR_OK},
        {"0500000000810500000080009c", "", SCRIPT_ERR_OK},
        {"0500000000810500000080009e", "01", SCRIPT_ERR_OK},
        {"0500000000810500000080009f", "01", SCRIPT_ERR_OK},
        {"050000000081050000008000a0", "", SCRIPT_ERR_OK},
        {"050000000081050000008000a1", "01", SCRIPT_ERR_OK},
        {"050000000081050000008000a2", "", SCRIPT_ERR_OK},
        {"050000000081050000008000a3", "0000000081", SCRIPT_ERR_OK},
        {"050000000081050000008000a4", "0000008000", SCRIPT_ERR_OK},
        {"05000000008105000000800096", "82", SCRIPT_ERR_OK},
        {"05000000008105000000800097", "", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b50093", "66e6096a01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b50094", "", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b50095", "29dca19efeffff7f", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b5009a", "01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b5009b", "01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b5009c", "01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b5009e", "", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b5009f", "", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b500a0", "", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b500a1", "01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b500a2", "01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b500a3", "33f304b500", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b500a4", "33f304b500", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b50096", "01", SCRIPT_ERR_OK},
        {"0533f304b5000533f304b50097", "", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b50093", "68e6096a01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b50094", "", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b50095", "", SCRIPT_ERR_MUL_OVERFLOW},
        {"0534f304b5000534f304b5009a", "01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b5009b", "01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b5009c", "01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b5009e", "", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b5009f", "", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b500a0", "", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b500a1", "01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b500a2", "01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b500a3", "34f304b500", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b500a4", "34f304b500", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b50096", "01", SCRIPT_ERR_OK},
        {"0534f304b5000534f304b50097", "", SCRIPT_ERR_OK},
        {"008b", "01", SCRIPT_ERR_OK},
        {"008c", "81", SCRIPT_ERR_OK},
        {"008f", "", SCRIPT_ERR_OK},
        {"0090", "", SCRIPT_ERR_OK},
        {"0091", "01", SCRIPT_ERR_OK},
        {"0092", "", SCRIPT_ERR_OK},
        {"518b", "02", SCRIPT_ERR_OK},
        {"518c", "", SCRIPT_ERR_OK},
        {"518f", "81", SCRIPT_ERR_OK},
        {"5190", "01", SCRIPT_ERR_OK},
        {"5191", "", SCRIPT_ERR_OK},
        {"5192", "01", SCRIPT_ERR_OK},
        {"4f8b", "", SCRIPT_ERR_OK},
        {"4f8c", "82", SCRIPT_ERR_OK},
        {"4f8f", "01", SCRIPT_ERR_OK},
        {"4f90", "01", SCRIPT_ERR_OK},
        {"4f91", "", SCRIPT_ERR_OK},
        {"4f92", "01", SCRIPT_ERR_OK},
        {"04ffffff7f8b", "0000008000", SCRIPT_ERR_OK},
        {"04ffffff7f8c", "feffff7f", SCRIPT_ERR_OK},
        {"04ffffff7f8f", "ffffffff", SCRIPT_ERR_OK},
        {"04ffffff7f90", "ffffff7f", SCRIPT_ERR_OK},
        {"04ffffff7f91", "", SCRIPT_ERR_OK},
        {"04ffffff7f92", "01", SCRIPT_ERR_OK},
        {"04ffffffff8b", "feffffff", SCRIPT_ERR_OK},
        {"04ffffffff8c", "0000008080", SCRIPT_ERR_OK},
        {"04ffffffff8f", "ffffff7f", SCRIPT_ERR_OK},
        {"04ffffffff90", "ffffff7f", SCRIPT_ERR_OK},
        {"04ffffffff91", "", SCRIPT_ERR_OK},
        {"04ffffffff92", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f8b", "", SCRIPT_ERR_ADD_OVERFLOW},
        {"08ffffffffffffff7f8c", "feffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f8f", "ffffffffffffffff", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f90", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f91", "", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f92", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffffff8b", "feffffffffffffff", SCRIPT_ERR_OK},
        {"08ffffffffffffffff8c", "", SCRIPT_ERR_SUB_OVERFLOW},
        {"08ffffffffffffffff8f", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffffff90", "ffffffffffffff7f", SCRIPT_ERR_OK},
        {"08ffffffffffffffff91", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff92", "01", SCRIPT_ERR_OK},
        {"000051a5", "01", SCRIPT_ERR_OK},
        {"510051a5", "", SCRIPT_ERR_OK},
        {"08ffffffffffffffff08ffffffffffffffff08ffffffffffffff7fa5", "01", SCRIPT_ERR_OK},
        {"08ffffffffffffff7f08ffffffffffffffff08ffffffffffffff7fa5", "", SCRIPT_ERR_OK},
        {"05000000000100050100000001a5", "01", SCRIPT_ERR_OK},
        {"525351a5", "", SCRIPT_ERR_OK},
    };
    const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_64BIT_INTEGERS | SCRIPT_VERIFY_MINIMALDATA;
    for (const auto& v : vectors) {
        BOOST_TEST_CONTEXT("script=" << v.script) {
            const auto bytes = ParseHex(v.script);
            CScript script(bytes.begin(), bytes.end());
            if (v.error == SCRIPT_ERR_OK) {
                const auto expected = ParseHex(v.expected);
                // Push the independently encoded result minimally as well.
                if (expected.size() == 1 && expected[0] >= 1 && expected[0] <= 16)
                    script << int64_t(expected[0]);
                else if (expected.size() == 1 && expected[0] == 0x81)
                    script << OP_1NEGATE;
                else
                    script << expected;
                script << OP_EQUAL;
            }
            ReviewWrappedScript(script, flags, v.error);
        }
    }
}

BOOST_AUTO_TEST_CASE(numeric_encoding_and_historical_rules)
{
    const auto wide = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_64BIT_INTEGERS;
    for (const auto& hex : {"80", "0000", "0080"}) {
        // Non-minimal zero is numerically zero, but rejected with MINIMALDATA.
        ReviewWrappedScript(CScript() << ParseHex(hex) << OP_NOT, wide, SCRIPT_ERR_OK);
        ReviewWrappedScript(CScript() << ParseHex(hex) << OP_NOT, wide | SCRIPT_VERIFY_MINIMALDATA,
                            SCRIPT_ERR_UNKNOWN_ERROR);
    }
    // ScriptNum excludes INT64_MIN: 8-byte sign/magnitude instead of two's complement.
    const auto max = ParseHex("ffffffffffffff7f");
    const auto min = ParseHex("ffffffffffffffff");
    ReviewWrappedScript(CScript() << min << OP_NEGATE << max << OP_EQUAL, wide, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript() << ParseHex("000000000000008080") << OP_NOT, wide, SCRIPT_ERR_UNKNOWN_ERROR);
    // Old 4-byte inputs may produce a 5-byte result, but may not reuse it numerically.
    const CScript overflow32 = CScript() << ParseHex("ffffff7f") << OP_1ADD;
    ReviewWrappedScript(CScript(overflow32) << ParseHex("0000008000") << OP_EQUAL,
                        REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript(overflow32) << OP_1ADD, REVIEW_BYTES_FLAGS, SCRIPT_ERR_UNKNOWN_ERROR);
    ReviewWrappedScript(CScript(overflow32) << OP_1ADD << ParseHex("0100008000") << OP_EQUAL,
                        wide, SCRIPT_ERR_OK);
    for (auto opcode : {OP_MUL, OP_DIV, OP_MOD}) {
        ReviewWrappedScript(CScript() << OP_0 << OP_IF << opcode << OP_ENDIF << OP_TRUE,
                            REVIEW_BYTES_FLAGS, SCRIPT_ERR_DISABLED_OPCODE);
        ReviewWrappedScript(CScript() << OP_0 << OP_IF << opcode << OP_ENDIF << OP_TRUE,
                            wide, SCRIPT_ERR_OK);
    }
    for (auto opcode : {OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL,
                        OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_BOOLAND, OP_BOOLOR,
                        OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN,
                        OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL,
                        OP_MIN, OP_MAX, OP_WITHIN}) {
        ReviewWrappedScript(CScript() << opcode, wide, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    ReviewWrappedScript(CScript() << max << max << OP_NUMEQUALVERIFY << OP_TRUE, wide, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript() << max << min << OP_NUMEQUALVERIFY << OP_TRUE, wide, SCRIPT_ERR_NUMEQUALVERIFY);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(timelock_opcode_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(real_transaction_locktime_and_sequence)
{
    struct Vector {
        opcodetype opcode;
        int64_t operand;
        uint32_t locktime, sequence;
        int32_t version;
        ScriptError error;
    };
    const Vector vectors[] = {
        {OP_CHECKLOCKTIMEVERIFY, 0, 0, 0, 2, SCRIPT_ERR_OK},
        {OP_CHECKLOCKTIMEVERIFY, 100, 100, 0xfffffffe, 2, SCRIPT_ERR_OK},
        {OP_CHECKLOCKTIMEVERIFY, 100, 101, 0xfffffffe, 2, SCRIPT_ERR_OK},
        {OP_CHECKLOCKTIMEVERIFY, 100, 99, 0xfffffffe, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKLOCKTIMEVERIFY, 100, 100, 0xffffffff, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKLOCKTIMEVERIFY, 499999999, 500000000, 0, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKLOCKTIMEVERIFY, 500000000, 499999999, 0, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKLOCKTIMEVERIFY, 500000000, 500000000, 0, 1, SCRIPT_ERR_OK},
        {OP_CHECKLOCKTIMEVERIFY, 0xffffffffLL, 0xffffffff, 0, 2, SCRIPT_ERR_OK},
        {OP_CHECKLOCKTIMEVERIFY, 0x100000000LL, 0xffffffff, 0, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKLOCKTIMEVERIFY, -1, 100, 0, 2, SCRIPT_ERR_NEGATIVE_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 0, 0, 0, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 10, 0, 10, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 10, 0, 11, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 10, 0, 9, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 0, 0, 10, 1, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 0, 0, 0x80000000, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 0x80000000LL, 0, 0xffffffff, 1, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 0xffffffffLL, 0, 0, 1, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 0x400001, 0, 0x400001, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 0x400001, 0, 0x400002, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 0x400002, 0, 0x400001, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 1, 0, 0x400001, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 0x400001, 0, 1, 2, SCRIPT_ERR_UNSATISFIED_LOCKTIME},
        {OP_CHECKSEQUENCEVERIFY, 0xffff, 0, 0xffff, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 0x10001, 0, 1, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 1, 0, 0x10001, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, 0x100000001LL, 0, 1, 2, SCRIPT_ERR_OK},
        {OP_CHECKSEQUENCEVERIFY, -1, 0, 0, 2, SCRIPT_ERR_NEGATIVE_LOCKTIME},
    };
    for (const auto& v : vectors) {
        BOOST_TEST_CONTEXT("opcode=" << int(v.opcode) << " operand=" << v.operand
                           << " locktime=" << v.locktime << " sequence=" << v.sequence) {
            CMutableTransaction mtx;
            mtx.nVersion = v.version;
            mtx.nLockTime = v.locktime;
            mtx.vin.resize(1);
            mtx.vin[0].nSequence = v.sequence;
            const CTransaction tx(mtx);
            TransactionSignatureChecker checker(&tx, 0, 1000);
            for (bool wide : {false, true}) {
                const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_MINIMALDATA |
                    (wide ? SCRIPT_VERIFY_64BIT_INTEGERS : script_verify_flags{});
                ReviewWrappedScript(CScript() << v.operand << v.opcode << OP_DROP << OP_TRUE,
                                    flags, v.error, checker);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(flags_encoding_and_unexecuted_branches)
{
    for (auto opcode : {OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY}) {
        const auto active = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                            SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        // Disabled opcodes are NOPs; policy can discourage their executed use.
        ReviewWrappedScript(CScript() << opcode << OP_TRUE, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
        ReviewWrappedScript(CScript() << opcode << OP_TRUE,
                            REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
                            SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
        ReviewWrappedScript(CScript() << opcode << OP_TRUE, active, SCRIPT_ERR_INVALID_STACK_OPERATION);
        for (auto flags : {active, REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS}) {
            ReviewWrappedScript(CScript() << OP_0 << OP_IF << opcode << OP_ENDIF << OP_TRUE,
                                flags, SCRIPT_ERR_OK);
        }
        for (bool wide : {false, true}) {
            const auto flags = active | (wide ? SCRIPT_VERIFY_64BIT_INTEGERS : script_verify_flags{});
            ReviewWrappedScript(CScript() << int64_t(1LL << 39) << opcode,
                                flags, SCRIPT_ERR_UNKNOWN_ERROR); // Six bytes, even with 64-bit arithmetic.
            ReviewWrappedScript(CScript() << ParseHex("0000") << opcode,
                                flags | SCRIPT_VERIFY_MINIMALDATA, SCRIPT_ERR_UNKNOWN_ERROR);
        }
    }
}

BOOST_AUTO_TEST_CASE(finality_and_relative_age_boundaries)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].nSequence = 10;
    mtx.nLockTime = 100;
    BOOST_CHECK(!IsFinalTx(CTransaction(mtx), 100, 600000000));
    BOOST_CHECK(IsFinalTx(CTransaction(mtx), 101, 600000000));
    mtx.nLockTime = 500000000;
    BOOST_CHECK(!IsFinalTx(CTransaction(mtx), 101, 500000000));
    BOOST_CHECK(IsFinalTx(CTransaction(mtx), 101, 500000001));
    mtx.vin[0].nSequence = 0xffffffff;
    BOOST_CHECK(IsFinalTx(CTransaction(mtx), 1, 1));
    mtx.nLockTime = 0;
    mtx.vin[0].nSequence = 10;
    BOOST_CHECK(IsFinalTx(CTransaction(mtx), 1, 1));

    CBlockIndex history[12];
    for (int i = 0; i < 12; ++i) {
        history[i].nHeight = i;
        history[i].nTime = 600000000 + i * 100;
        if (i) history[i].pprev = &history[i - 1];
        history[i].BuildSkip();
    }
    std::vector<int> heights{6};
    auto locks = CalculateSequenceLocks(CTransaction(mtx), LOCKTIME_VERIFY_SEQUENCE, &heights, history[11]);
    BOOST_CHECK_EQUAL(locks.first, 15); // Coin height 6 plus 10, minus one.
    BOOST_CHECK_EQUAL(locks.second, -1);
    CBlockIndex parent, candidate;
    parent.nTime = 600002000;
    candidate.pprev = &parent;
    candidate.nHeight = 15;
    BOOST_CHECK(!EvaluateSequenceLocks(candidate, locks));
    candidate.nHeight = 16;
    BOOST_CHECK(EvaluateSequenceLocks(candidate, locks));

    mtx.vin[0].nSequence = 0x400002; // Two units of 512 seconds.
    locks = CalculateSequenceLocks(CTransaction(mtx), LOCKTIME_VERIFY_SEQUENCE, &heights, history[11]);
    BOOST_CHECK_EQUAL(locks.first, -1);
    // MTP of heights 0..5 is timestamp at index 3: 600000300.
    BOOST_CHECK_EQUAL(locks.second, 600001323);
    parent.nTime = 600001323;
    BOOST_CHECK(!EvaluateSequenceLocks(candidate, locks));
    parent.nTime = 600001324;
    BOOST_CHECK(EvaluateSequenceLocks(candidate, locks));

    for (int mode = 0; mode < 3; ++mode) {
        mtx.nVersion = mode == 0 ? 1 : 2;
        mtx.vin[0].nSequence = mode == 1 ? 0x80000001 : 1;
        heights[0] = 6;
        locks = CalculateSequenceLocks(CTransaction(mtx), mode == 2 ? 0 : LOCKTIME_VERIFY_SEQUENCE,
                                       &heights, history[11]);
        BOOST_CHECK_EQUAL(locks.first, -1);
        BOOST_CHECK_EQUAL(locks.second, -1);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(stack_control_opcode_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(exact_stack_permutations)
{
    struct Vector { opcodetype opcode; std::vector<int> order; unsigned needed; };
    const Vector vectors[] = {
        {OP_2DROP, {0,1,2,3}, 2}, {OP_2DUP, {0,1,2,3,4,5,4,5}, 2},
        {OP_3DUP, {0,1,2,3,4,5,3,4,5}, 3}, {OP_2OVER, {0,1,2,3,4,5,2,3}, 4},
        {OP_2ROT, {2,3,4,5,0,1}, 6}, {OP_2SWAP, {0,1,4,5,2,3}, 4},
        {OP_IFDUP, {0,1,2,3,4,5,5}, 1}, {OP_DROP, {0,1,2,3,4}, 1},
        {OP_DUP, {0,1,2,3,4,5,5}, 1}, {OP_NIP, {0,1,2,3,5}, 2},
        {OP_OVER, {0,1,2,3,4,5,4}, 2}, {OP_ROT, {0,1,2,4,5,3}, 3},
        {OP_SWAP, {0,1,2,3,5,4}, 2}, {OP_TUCK, {0,1,2,3,5,4,5}, 2},
    };
    const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_CHECKSIGFROMSTACK;
    for (size_t size : {1, 32, 33, 520, 1312, 2420, 3072}) {
        std::vector<ReviewBytes> original;
        for (int i = 0; i < 6; ++i) original.emplace_back(size, static_cast<unsigned char>(i + 1));
        for (auto sigversion : {SIGVERSION_BASE, SIGVERSION_WITNESS_V0, SIGVERSION_AUTHSCRIPT}) {
            for (const auto& v : vectors) {
                BOOST_TEST_CONTEXT("size=" << size << " opcode=" << int(v.opcode) << " context=" << int(sigversion)) {
                    auto stack = original;
                    ScriptError error;
                    BOOST_CHECK(EvalScript(stack, CScript() << v.opcode, flags, BaseSignatureChecker(), sigversion, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
                    std::vector<ReviewBytes> expected;
                    for (int index : v.order) expected.push_back(original[index]);
                    BOOST_CHECK(stack == expected);
                    stack.assign(v.needed - 1, ReviewBytes{1});
                    BOOST_CHECK(!EvalScript(stack, CScript() << v.opcode, flags, BaseSignatureChecker(), sigversion, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_INVALID_STACK_OPERATION);
                }
            }
            for (auto opcode : {OP_PICK, OP_ROLL}) {
                for (int index : {0, 2, 5}) {
                    auto stack = original;
                    stack.push_back(CScriptNum(index).getvch());
                    auto expected = original;
                    if (opcode == OP_ROLL) expected.erase(expected.end() - 1 - index);
                    expected.push_back(original[5 - index]);
                    ScriptError error;
                    BOOST_CHECK(EvalScript(stack, CScript() << opcode, flags, BaseSignatureChecker(), sigversion, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
                    BOOST_CHECK(stack == expected);
                }
                for (int index : {-1, 6}) {
                    auto stack = original;
                    stack.push_back(CScriptNum(index).getvch());
                    ScriptError error;
                    BOOST_CHECK(!EvalScript(stack, CScript() << opcode, flags, BaseSignatureChecker(), sigversion, &error));
                    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_INVALID_STACK_OPERATION);
                }
            }
            auto stack = original;
            ScriptError error;
            BOOST_CHECK(EvalScript(stack, CScript() << OP_TOALTSTACK << OP_TOALTSTACK << OP_FROMALTSTACK << OP_FROMALTSTACK,
                                   flags, BaseSignatureChecker(), sigversion, &error));
            BOOST_CHECK(stack == original);
            BOOST_CHECK(EvalScript(stack, CScript() << OP_DEPTH, flags, BaseSignatureChecker(), sigversion, &error));
            BOOST_CHECK(stack.back() == CScriptNum(6).getvch());
        }
    }
    for (auto opcode : {OP_TOALTSTACK, OP_FROMALTSTACK, OP_PICK, OP_ROLL}) {
        ReviewWrappedScript(CScript() << opcode, flags,
                            opcode == OP_FROMALTSTACK ? SCRIPT_ERR_INVALID_ALTSTACK_OPERATION : SCRIPT_ERR_INVALID_STACK_OPERATION);
    }
    for (const auto& zero : {ReviewBytes{}, ReviewBytes{0x80}, ReviewBytes{0,0}}) {
        ReviewWrappedScript(CScript() << zero << OP_IFDUP << OP_DEPTH << OP_1 << OP_EQUALVERIFY << OP_DROP << OP_TRUE,
                            flags, SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(conditionals_and_reserved_opcodes)
{
    for (const auto& script : {CScript() << OP_IF, CScript() << OP_NOTIF, CScript() << OP_ELSE,
                               CScript() << OP_ENDIF, CScript() << OP_TRUE << OP_IF << OP_TRUE}) {
        ReviewWrappedScript(script, REVIEW_BYTES_FLAGS, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
    }
    ReviewWrappedScript(CScript() << OP_TRUE << OP_IF << OP_0 << OP_IF << OP_RETURN << OP_ENDIF
                        << OP_TRUE << OP_ELSE << OP_RETURN << OP_ENDIF, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
    // Repeated ELSE toggles the same condition and is historically allowed.
    ReviewWrappedScript(CScript() << OP_TRUE << OP_IF << OP_ELSE << OP_RETURN << OP_ELSE << OP_TRUE << OP_ENDIF,
                        REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
    for (auto opcode : {OP_RESERVED, OP_VER, OP_RESERVED1, OP_RESERVED2, OP_VERIF, OP_VERNOTIF}) {
        ReviewWrappedScript(CScript() << opcode << OP_TRUE, REVIEW_BYTES_FLAGS, SCRIPT_ERR_BAD_OPCODE);
        ReviewWrappedScript(CScript() << OP_0 << OP_IF << opcode << OP_ENDIF << OP_TRUE, REVIEW_BYTES_FLAGS,
                            opcode == OP_VERIF || opcode == OP_VERNOTIF ? SCRIPT_ERR_BAD_OPCODE : SCRIPT_ERR_OK);
    }
    ReviewWrappedScript(CScript() << OP_NOP << OP_TRUE << OP_VERIFY << OP_TRUE, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
    ReviewWrappedScript(CScript() << OP_VERIFY, REVIEW_BYTES_FLAGS, SCRIPT_ERR_INVALID_STACK_OPERATION);
    ReviewWrappedScript(CScript() << OP_0 << OP_VERIFY, REVIEW_BYTES_FLAGS, SCRIPT_ERR_VERIFY);
    ReviewWrappedScript(CScript() << OP_RETURN, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OP_RETURN);
    ReviewWrappedScript(CScript() << OP_0 << OP_IF << OP_RETURN << OP_ENDIF << OP_TRUE, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
    for (auto sigversion : {SIGVERSION_BASE, SIGVERSION_WITNESS_V0, SIGVERSION_AUTHSCRIPT}) {
        for (auto opcode : {OP_IF, OP_NOTIF}) {
            for (const auto& value : {ReviewBytes{}, ReviewBytes{1}, ReviewBytes{0}, ReviewBytes{2}, ReviewBytes{0x80}, ReviewBytes{1,0}}) {
                for (bool minimal : {false, true}) {
                    std::vector<ReviewBytes> stack{value};
                    ScriptError error;
                    const bool invalid = minimal && sigversion == SIGVERSION_WITNESS_V0 && value != ReviewBytes{} && value != ReviewBytes{1};
                    const auto flags = REVIEW_BYTES_FLAGS | (minimal ? SCRIPT_VERIFY_MINIMALIF : script_verify_flags{});
                    const bool ok = EvalScript(stack, CScript() << opcode << OP_TRUE << OP_ELSE << OP_TRUE << OP_ENDIF,
                                               flags, BaseSignatureChecker(), sigversion, &error);
                    BOOST_CHECK_EQUAL(ok, !invalid);
                    BOOST_CHECK_EQUAL(error, invalid ? SCRIPT_ERR_MINIMALIF : SCRIPT_ERR_OK);
                    if (ok) BOOST_CHECK(stack == std::vector<ReviewBytes>{ReviewBytes{1}});
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(combined_stack_limits)
{
    for (auto sigversion : {SIGVERSION_BASE, SIGVERSION_WITNESS_V0, SIGVERSION_AUTHSCRIPT}) {
        for (size_t count : {1000, 1001}) {
            std::vector<ReviewBytes> stack(count, ReviewBytes{1});
            ScriptError error;
            const bool ok = EvalScript(stack, CScript() << OP_TOALTSTACK, REVIEW_BYTES_FLAGS,
                                       BaseSignatureChecker(), sigversion, &error);
            BOOST_CHECK_EQUAL(ok, count == 1000);
            BOOST_CHECK_EQUAL(error, count == 1000 ? SCRIPT_ERR_OK : SCRIPT_ERR_STACK_SIZE);
        }
        std::vector<ReviewBytes> stack(1000, ReviewBytes{1});
        ScriptError error;
        BOOST_CHECK(!EvalScript(stack, CScript() << OP_DUP, REVIEW_BYTES_FLAGS, BaseSignatureChecker(), sigversion, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_STACK_SIZE);
        for (auto gate : {SCRIPT_VERIFY_CHECKSIGFROMSTACK, SCRIPT_VERIFY_MERKLE_INCLUSION, SCRIPT_VERIFY_CHECKSIGADD}) {
            for (size_t excess : {0, 1}) {
                // 85 * 3072 + 1024 = 256 KiB. Moving data to altstack must not evade the cap.
                stack.assign(85, ReviewBytes(3072, 1));
                stack.emplace_back(1024 + excess, 2);
                const bool ok = EvalScript(stack, CScript() << OP_TOALTSTACK, REVIEW_BYTES_FLAGS | gate,
                                           BaseSignatureChecker(), sigversion, &error);
                BOOST_CHECK_EQUAL(ok, excess == 0);
                BOOST_CHECK_EQUAL(error, excess == 0 ? SCRIPT_ERR_OK : SCRIPT_ERR_STACK_SIZE);
            }
        }
        // Altstack is local to one EvalScript call; it cannot leak into the next.
        stack = {ReviewBytes{1}};
        BOOST_CHECK(EvalScript(stack, CScript() << OP_TOALTSTACK, REVIEW_BYTES_FLAGS, BaseSignatureChecker(), sigversion, &error));
        BOOST_CHECK(!EvalScript(stack, CScript() << OP_FROMALTSTACK, REVIEW_BYTES_FLAGS, BaseSignatureChecker(), sigversion, &error));
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(push_witness_limits_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(push_encodings_and_truncation)
{
    for (size_t size = 1; size <= 75; ++size) {
        const ReviewBytes data(size, 0x42);
        CScript script;
        script.push_back(size);
        script.insert(script.end(), data.begin(), data.end());
        script << data << OP_EQUAL;
        ReviewWrappedScript(script, REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_MINIMALDATA, SCRIPT_ERR_OK);
    }
    for (size_t size : {0, 1, 75, 76, 255, 256, 520}) {
        for (auto opcode : {OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4}) {
            CScript script;
            script.push_back(opcode);
            const size_t width = opcode == OP_PUSHDATA1 ? 1 : (opcode == OP_PUSHDATA2 ? 2 : 4);
            if (width == 1 && size > 255) continue;
            for (size_t i = 0; i < width; ++i) script.push_back((size >> (8 * i)) & 0xff);
            script.insert(script.end(), size, 0x42);
            script << OP_DROP << OP_TRUE;
            const bool minimal = (opcode == OP_PUSHDATA1 && size >= 76 && size <= 255) ||
                                 (opcode == OP_PUSHDATA2 && size >= 256);
            ReviewWrappedScript(script, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
            ReviewWrappedScript(script, REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_MINIMALDATA,
                                minimal ? SCRIPT_ERR_OK : SCRIPT_ERR_MINIMALDATA);
        }
    }
    for (const auto& hex : {"01", "0242", "4c", "4c02ff", "4d", "4d01", "4d020042",
                            "4e", "4e010000", "4e0200000042", "4effffffff"}) {
        const auto raw = ParseHex(hex);
        const CScript truncated(raw.begin(), raw.end());
        ReviewWrappedScript(truncated, REVIEW_BYTES_FLAGS, SCRIPT_ERR_BAD_OPCODE);
        CScript skipped = CScript() << OP_0 << OP_IF;
        skipped += truncated;
        // Leave truncated data at EOF, so ENDIF cannot accidentally complete a push.
        ReviewWrappedScript(skipped, REVIEW_BYTES_FLAGS, SCRIPT_ERR_BAD_OPCODE);
    }
    for (size_t size : {520, 521, 3072, 3073}) {
        for (bool wide : {false, true}) {
            const auto flags = REVIEW_BYTES_FLAGS | (wide ? SCRIPT_VERIFY_CHECKSIGFROMSTACK : script_verify_flags{});
            const auto error = size <= (wide ? 3072U : 520U) ? SCRIPT_ERR_OK : SCRIPT_ERR_PUSH_SIZE;
            ReviewWrappedScript(CScript() << ReviewBytes(size, 0x42) << OP_DROP << OP_TRUE, flags, error);
            ReviewWrappedScript(CScript() << OP_0 << OP_IF << ReviewBytes(size, 0x42) << OP_ENDIF << OP_TRUE,
                                flags, error);
        }
    }
}

BOOST_AUTO_TEST_CASE(script_and_opcode_boundaries)
{
    for (size_t extra : {0, 1}) {
        CScript script = CScript() << OP_0 << OP_IF;
        for (int i = 0; i < 19; ++i) script << ReviewBytes(520, 0x42);
        script << ReviewBytes(58 + extra, 0x42) << OP_ENDIF << OP_TRUE;
        BOOST_CHECK_EQUAL(script.size(), 10000 + extra);
        ReviewWrappedScript(script, REVIEW_BYTES_FLAGS, extra ? SCRIPT_ERR_SCRIPT_SIZE : SCRIPT_ERR_OK);
    }
    for (int count : {201, 202}) {
        CScript script;
        for (int i = 0; i < count; ++i) script << OP_NOP;
        script << OP_TRUE;
        ReviewWrappedScript(script, REVIEW_BYTES_FLAGS, count == 201 ? SCRIPT_ERR_OK : SCRIPT_ERR_OP_COUNT);
        script = CScript() << OP_0 << OP_IF;
        for (int i = 0; i < count - 2; ++i) script << OP_NOP;
        script << OP_ENDIF << OP_TRUE;
        ReviewWrappedScript(script, REVIEW_BYTES_FLAGS, count == 201 ? SCRIPT_ERR_OK : SCRIPT_ERR_OP_COUNT);
    }
}

BOOST_AUTO_TEST_CASE(complete_witness_argument_limits)
{
    const auto verify = [](const CScript& script, const std::vector<ReviewBytes>& args,
                           script_verify_flags flags, ScriptError expected) {
        for (int version : {0, 1}) {
            BOOST_TEST_CONTEXT("version=" << version << " argc=" << args.size()) {
                CScriptWitness witness;
                ReviewBytes digest(32);
                if (version == 0) {
                    CSHA256().Write(script.data(), script.size()).Finalize(digest.data());
                } else {
                    const auto commitment = GetAuthScriptCommitment(0, nullptr, script);
                    digest.assign(commitment.begin(), commitment.end());
                    witness.stack.push_back(ReviewBytes{0});
                }
                witness.stack.insert(witness.stack.end(), args.begin(), args.end());
                witness.stack.emplace_back(script.begin(), script.end());
                const CScript spk = CScript() << (version == 0 ? OP_0 : OP_1) << digest;
                ScriptError error;
                const bool ok = VerifyScript(CScript(), spk, &witness, flags, BaseSignatureChecker(), &error);
                BOOST_CHECK_EQUAL(ok, expected == SCRIPT_ERR_OK);
                BOOST_CHECK_EQUAL(error, expected);
            }
        }
    };
    for (auto gate : {script_verify_flags{}, script_verify_flags{SCRIPT_VERIFY_CHECKSIGFROMSTACK},
                     script_verify_flags{SCRIPT_VERIFY_MERKLE_INCLUSION}, script_verify_flags{SCRIPT_VERIFY_CHECKSIGADD}}) {
        const auto flags = REVIEW_BYTES_FLAGS | gate;
        const size_t cap = gate == script_verify_flags{} ? 520 : 3072;
        verify(CScript() << OP_DROP << OP_TRUE, {ReviewBytes(cap, 1)}, flags, SCRIPT_ERR_OK);
        verify(CScript() << OP_DROP << OP_TRUE, {ReviewBytes(cap + 1, 1)}, flags, SCRIPT_ERR_PUSH_SIZE);
        if (cap == 3072) {
            for (size_t excess : {0, 1}) {
                std::vector<ReviewBytes> args(85, ReviewBytes(3072, 1));
                args.emplace_back(1024 + excess, 1);
                CScript script = CScript() << OP_NOP;
                for (int i = 0; i < 43; ++i) script << OP_2DROP;
                script << OP_TRUE;
                verify(script, args, flags, excess ? SCRIPT_ERR_STACK_SIZE : SCRIPT_ERR_OK);
            }
        }
    }
    for (size_t count : {1000, 1001}) {
        verify(CScript() << OP_NOP << OP_RETURN, std::vector<ReviewBytes>(count, ReviewBytes{1}),
               REVIEW_BYTES_FLAGS, count == 1000 ? SCRIPT_ERR_OP_RETURN : SCRIPT_ERR_STACK_SIZE);
    }
    // The historical element-count check occurs after executing an opcode.
    verify(CScript() << OP_DROP << OP_RETURN, std::vector<ReviewBytes>(1001, ReviewBytes{1}),
           REVIEW_BYTES_FLAGS, SCRIPT_ERR_OP_RETURN);
    verify(CScript() << OP_TRUE, {ReviewBytes{1}}, REVIEW_BYTES_FLAGS, SCRIPT_ERR_EVAL_FALSE);
    verify(CScript() << OP_DROP << OP_TRUE, {ReviewBytes{1}}, REVIEW_BYTES_FLAGS, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(p2sh_witness_review_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(redeemscript_and_scriptsig_exact_shape)
{
    const CScript script = CScript() << OP_TRUE;
    for (int version : {0, 1}) {
        ReviewBytes digest(32);
        CScriptWitness witness;
        if (version == 0) {
            CSHA256().Write(script.data(), script.size()).Finalize(digest.data());
        } else {
            const auto commitment = GetAuthScriptCommitment(0, nullptr, script);
            digest.assign(commitment.begin(), commitment.end());
            witness.stack.push_back(ReviewBytes{0});
        }
        witness.stack.emplace_back(script.begin(), script.end());
        const CScript redeem = CScript() << (version ? OP_1 : OP_0) << digest;
        const ReviewBytes bytes(redeem.begin(), redeem.end());
        const auto hash = Hash160(redeem);
        const CScript p2sh = CScript() << OP_HASH160 << ToByteVector(hash) << OP_EQUAL;
        const auto check = [&](const CScript& sig, const CScript& output, const CScriptWitness& w,
                               script_verify_flags flags, ScriptError expected) {
            BOOST_TEST_CONTEXT("version=" << version << " scriptSig=" << HexStr(sig)) {
                ScriptError error;
                const bool ok = VerifyScript(sig, output, &w, flags, BaseSignatureChecker(), &error);
                BOOST_CHECK_EQUAL(ok, expected == SCRIPT_ERR_OK);
                BOOST_CHECK_EQUAL(error, expected);
            }
        };
        const auto flags = REVIEW_BYTES_FLAGS | SCRIPT_VERIFY_CLEANSTACK;
        check(CScript(), redeem, witness, flags, SCRIPT_ERR_OK);
        check(CScript() << bytes, p2sh, witness, flags, SCRIPT_ERR_OK);
        check(CScript() << OP_0, redeem, witness, flags, SCRIPT_ERR_WITNESS_MALLEATED);
        check(CScript() << OP_0 << bytes, p2sh, witness, flags, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
        check(CScript() << OP_NOP << bytes, p2sh, witness, flags, SCRIPT_ERR_SIG_PUSHONLY);
        CScript nonminimal;
        nonminimal << OP_PUSHDATA1;
        nonminimal.push_back(bytes.size());
        nonminimal.insert(nonminimal.end(), bytes.begin(), bytes.end());
        check(nonminimal, p2sh, witness, flags, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
        check(nonminimal, p2sh, witness, flags | SCRIPT_VERIFY_MINIMALDATA, SCRIPT_ERR_MINIMALDATA);
        auto wrong = bytes;
        wrong.back() ^= 1;
        check(CScript() << wrong, p2sh, witness, flags, SCRIPT_ERR_EVAL_FALSE);
        check(CScript(), p2sh, witness, flags, SCRIPT_ERR_INVALID_STACK_OPERATION);
        auto wrongWitness = witness;
        wrongWitness.stack.back() = ReviewBytes{OP_0};
        check(CScript() << bytes, p2sh, wrongWitness, flags, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        CScriptWitness empty;
        check(CScript() << bytes, p2sh, empty, flags, version == 0 ?
              SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY : SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
        // A P2SH contract that is not a witness program cannot consume witness data.
        const auto legacyHash = Hash160(script);
        check(CScript() << ReviewBytes(script.begin(), script.end()),
              CScript() << OP_HASH160 << ToByteVector(legacyHash) << OP_EQUAL, witness, flags,
              SCRIPT_ERR_WITNESS_UNEXPECTED);
    }
}

BOOST_AUTO_TEST_SUITE_END()
