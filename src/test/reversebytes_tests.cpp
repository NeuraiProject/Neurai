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
