// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/pq_sanity.h"

#include "crypto/sha256.h"
#include "key.h"
#include "pubkey.h"
#include "utilstrencodings.h"

#include <memory>
#include <vector>
#include <oqs/oqs.h>

namespace {
// Public compatibility vector: seed = 32 zero bytes, message = 32 zero bytes,
// empty ML-DSA context. Raw private/public key SHA256 values also appear in
// key_tests. Captured signature generated and verified with liboqs 0.15.0
// (pqcrystals backend), then verified here with the installed implementation.
// Signing is randomized: verify this fixed signature, never require a newly
// generated signature to match its bytes.
constexpr char EXPECTED_SECRET_HASH[] = "0f9086044d77b6d610c7e92418d9f70a398c69febc7e99f8254aaea98dcfbe77";
constexpr char EXPECTED_PUBLIC_HASH[] = "eb4e7302842153b0fa19e8620739ad258af4929c26dd89079a7ec7d4282208e1";
constexpr char KNOWN_SIGNATURE[] =
    "fa8c81863fa8300ce2bbafe918a4bbe99516ce651b2e219dc298c7d1f6621f500ac4d385f563cb85761493c3a170d16c"
    "50258b947dd392b45f4f8b141183b368b7fa8a4999f86b868f5a8dcde276a3c6b6066a3fb35f26109ac95e7ff540bf59"
    "717172e5915d48a202be9d49a0406e6ae0e914459e66c9ec6efba7c377cc13ce98938c634f08e7480d871f6f8ac66f07"
    "bbbd56eaa8459c3de4f236d7fd0ce52700a0fde5b4d7651549e133ca1438aee83ec4e1394ed0db96c9e0c35d0bda7a3a"
    "c30a273945120ed7c5f8a619b0a3d801c4e28e8b50a5bd45a2ce9b3b054d78b583c5a1dc9693f63af9af3b260830f869"
    "58125dada15a0e6dcb7d6fa853dad91c38f95737b0f9ac36ddc7db9ef1d8c0eee37cacfc3282ed36dcd46a8af2167c14"
    "3fceee455b6c874529f7ad741e307b24e68e32415c2f9c75964e1534a0615ca1aeba11267d8a10a083664e0fbffa0eb2"
    "680994a0b0790e77ec180b2056b1a51541e91308cd0e3d844e8332d0c998a7d02ee367c40cd6c52ae05491e0b3982e98"
    "5f065e09b59cea1d43f72ff3b20b50a4d03026a205ed24e1be8207774b1464bbcdd392ce719ad7feb03dc00a88a6c986"
    "69d31d9c4648f01606d77d3f8be3ad228fbc80e0a094905f42010a9cfee221720c729cc6ca0ea10b31eaa61ccb787069"
    "79f7b77d08a6e846b1fffc55fcd2b23f2813b787b39d04bcdf7d8bf0895c9b2c55fb0c95230978b45e6b2b8393a7b456"
    "aa40df259dd7d5a0b082021cb18107a35be2a7a2be4acba557d1e7a8e6023e1f39a76c83406b4ad02d9bca2e688c0e82"
    "3c02714eb9c7b45572515d299d394fc3114c262ed2b966de26675673a2f7fa9ac49150e7a465f374e48641c8e2dd1ee1"
    "52962d3607aa156294fbd04c239d72d9a52f3d58f7b58d15d2a33ebc7be134ee2811666792f8b8a44d8481b06b6dfc85"
    "76d19be5eff27171a11881cc67d68a35f0a8ff4718d314c7cd2bfdacb8775fce78658b28aa4af049c6c93433b3f8c5b4"
    "04f0f1822ac46144c5408bc0d9cd676cd200475eab4f4079eefddea5a5033fb32218c9495290459ce5ce575e9e9bbaca"
    "5fad70fd931cd6bd919df536a702d189c91eee5c8735be09d4ff632a9e54f4cee1df621b4fe4e60b61afddbb723565dd"
    "60fd52290ddbb6002ebc2f4d778e5e2b25a647c5ca4e3ed0ab8d750db023c7e188543a6a61dd4f896046f4daf762bf09"
    "9a354d623f46be9ee4e5805212b76cc184284a4a2d7191ee8b189f350961242d92a22d482b24debe28a3ffed5192079d"
    "f613b846d34720d6f9f11d3d6e46049eb39b613a7f0b31d4b505aae4dff935d670af9ba760ca67152f996edc9af5ceda"
    "c3691af989550e57a5e31a2e238fb8b326ed3a78cfa8f40d7828f21e6a801adeb223c451e71e0850088ccacebdb609b2"
    "8a7504503570e66454982db6f15095effdf75cd2921667e252607f7361b57aabeca4d3046ab06186ad46f9c2634e85e1"
    "e59e9f071f51b03d89842d8bb52d4413badd3fcbdbe48dd2d81b8c88aa481d6242dc9b567026bb8d1514aa8c9a6c428b"
    "1f23a10880ae9b079e4f128f7c199774c3e82d24a886836e6c1eaa787d41d49b3ea51d4265d099550d3ee8b388c70492"
    "9f588656b00596af42a4c897b56df1bb6661d428150957b8a139a2d2d2b5ccb9983e7515310e04bc5388fe8ed1610941"
    "40e89c70d882a6c47fe7bdc2be9b743539d0922cad5ef15efc2dbe917f37a67912048522ec0fe9db35230a488781a0b0"
    "f02bb6bbbf4e77d2874b912bed458c7386efb0b47ffdebe0ee12605b0e812b8be04d156ebe08cce2f3f53e2218426909"
    "162dbe1913d323d7cdfcecb6f8c78ca0c8d770487cf417ed33f1104f63d320be5632a86b237386ec6a6aae34054993ea"
    "2a9da64ec1806e2b89acecea9caab4e2b8edd4c1e999151fb69e6da15ebbea1a9bdac125b56f088e2ec96e54eaa13323"
    "008fe65704df8b283c8c41a34147bc0531918465672d70cd7290954bac127605cda66b572984f93f450d1866b2d4f328"
    "66f3b15ba1299f21ac9f05dc261b929568f5df423e9a62825784fc8bceae2a88d9b101fbde57e79f5db31c6203c6a109"
    "65ae68177c13926023bcd9faeadb13e88fc13af861ad6943a59a8fca88d870ad38ac9a15c5ed0c1a7e8178b1af7053dc"
    "c22a3d97e5c9c30ccf31d57aab35b005c59357354da187afb5fd55b2db1f8eaaa52959a7c4f472b11fb7956c1a5e62b8"
    "937bbd19face44837deb67b23b0183b4cf8fd86ff68d6e13cc037aafc5b84494e493ad6b69e2fbbfc146bb5eeb5b7013"
    "c35a7c38b333503d46e4e242449dd8be4f88c4f7398b60a7f71a7ee39722fe83051c38282fa24fcd4ce0cbcd2f6a3f23"
    "28763126b8ea1c86d2979277435f2b60d4a7bb0c30e1580405a4a7bd97864cbdf7a4d8993d918ff2652581fa5e5d0687"
    "4be548c68295fe290cbb7fc38879467f9a3e01fc4bccdcd983b0158bd8ea486ed915aa9b7369598b54df35867e6f36b2"
    "c24d78961772287499318ff0236dbc192c62a727783777e828ce818005c445ee59765d533b5cb6edecc7bfe8f34610a3"
    "8e76b04729768e046211216af2b53cf461e5e69a63f7b42476d02d331cb37c2e751054693bcf138796edd36cb6ecc6ff"
    "94ae40a9fd0cc05d7049633e5cfe98a55bdedd87421e8dc3e4515c98a39ef65af6a92da5fcd323363c7e6f52530d6bb3"
    "7de7a159fbaac50c97701d1e3cd74521700a3a9108546dd792132e3bf867632840ae5fd1860297c178e42eecd150d965"
    "9c660395a758f7530013c7c9c66fa1cab2ca72024f902ea7371f1460c1e50cdc2da30a4f4515b4db9fbf32637187e1f5"
    "5f7f3b33cce268e732d46d9813ab1659eab4bea092ab236e8f2d902e0b57469d35513a1f3ac9213e9521393caf5a4f73"
    "c655cb05e05771f5a033739f00bc455674e78b905d82fc3b7c77e9a28bd3d8a6d1581396a64b5a2f5f541371122b4739"
    "9d002e265be4918f6d7f8f94e739e4a5b933c32bffc75c3856a188e087ba43814792958a0ba6c971f3739d22706830f3"
    "ad67f55eab760eb53f265e8d766cea6b2153bff27e32959cc4c88c48ecda385ee5cb3560534a05c17f1140eef0b97cb6"
    "b09e020a9ea19af670aa33e42a60a39dbc02681ac9c789c983e041577d7c30e2431c2e4bcefb8e2f140693200d6c6854"
    "d18325c819b4d3b0352f08d2842027fc0c0c1ee471f8ecd552057b80470c8a258549a3465f906f11746ead6f44f6b65f"
    "663b9b75b32788756ea612ad660f88065bd186b45709b878343c38c44c8d00c8002b5969707c8ecad3dee6e81214263b"
    "414d515355565a5b6465677fa8cbccd0dbe30b272c2d3c5e7c8ca0acb9c2c7e5f104243d40596d728691a8c9de000000"
    "000000000000000000000000000000000c22313d";
} // namespace

bool PQ_InitSanityCheck() noexcept
{
    try {
        // Check availability and parameter sizes before the CKey wrappers,
        // which assume the required algorithm exists and use assertions.
        const std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> algorithm(
            OQS_SIG_new(OQS_SIG_alg_ml_dsa_44), OQS_SIG_free);
        if (!algorithm || algorithm->length_secret_key != ML_DSA_44_PRIVKEY_SIZE ||
            algorithm->length_public_key != ML_DSA_44_PUBKEY_SIZE ||
            algorithm->length_signature != ML_DSA_44_SIG_SIZE) {
            return false;
        }

        CKey key;
        key.MakeNewKeyPQ(std::vector<unsigned char>(32, 0));
        if (!key.IsValid() || key.size() != ML_DSA_44_KEYDATA_SIZE) return false;

        unsigned char digest[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(key.begin(), ML_DSA_44_PRIVKEY_SIZE).Finalize(digest);
        if (HexStr(digest, digest + sizeof(digest)) != EXPECTED_SECRET_HASH) return false;

        const CPubKey pubkey = key.GetPubKey();
        if (!pubkey.IsValid() || !pubkey.IsPQ()) return false;
        CSHA256().Write(pubkey.begin() + 1, ML_DSA_44_PUBKEY_SIZE).Finalize(digest);
        if (HexStr(digest, digest + sizeof(digest)) != EXPECTED_PUBLIC_HASH) return false;

        const uint256 message;
        auto signature = ParseHex(KNOWN_SIGNATURE);
        if (signature.size() != ML_DSA_44_SIG_SIZE || !pubkey.Verify(message, signature)) return false;
        uint256 alteredMessage = message;
        alteredMessage.begin()[0] ^= 1;
        if (pubkey.Verify(alteredMessage, signature)) return false;
        signature[0] ^= 1;
        if (pubkey.Verify(message, signature)) return false;

        // Exercise the signing API and the installed RNG too, without touching
        // its configuration. CKey keeps the synthetic private key in secure memory.
        std::vector<unsigned char> freshSignature;
        return key.Sign(message, freshSignature) &&
               freshSignature.size() == ML_DSA_44_SIG_SIZE &&
               pubkey.Verify(message, freshSignature);
    } catch (...) {
        return false;
    }
}
