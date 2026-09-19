// Standalone test-only signer. Keys are disposable and never mainnet wallet keys.
// Build against the pinned dependencies already used by the Docker node.
#include <oqs/oqs.h>
#include <secp256k1.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <iomanip>
using Bytes = std::vector<unsigned char>;
Bytes unhex(const std::string& s) {
    if (s.size() % 2) throw std::runtime_error("odd hex");
    Bytes out;
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned int x;
        std::istringstream in(s.substr(i, 2));
        if (!(in >> std::hex >> x)) throw std::runtime_error("bad hex");
        out.push_back(x);
    }
    return out;
}
void hex(const Bytes& bytes) {
    for (auto c : bytes) std::cout << std::hex << std::setfill('0') << std::setw(2) << unsigned(c);
    std::cout << '\n';
}
int main(int argc, char** argv) {
    try {
        if (argc != 3) throw std::runtime_error("keygen|sign pq|ecdsa");
        const bool pq = std::string(argv[2]) == "pq";
        OQS_SIG* oqs = pq ? OQS_SIG_new(OQS_SIG_alg_ml_dsa_44) : nullptr;
        auto* ctx = pq ? nullptr : secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (pq && !oqs) throw std::runtime_error("ML-DSA unavailable");
        if (std::string(argv[1]) == "keygen") {
            Bytes pub(pq ? oqs->length_public_key : 33), secret(pq ? oqs->length_secret_key : 32);
            if (pq) {
                if (OQS_SIG_keypair(oqs, pub.data(), secret.data()) != OQS_SUCCESS) throw std::runtime_error("keypair");
                pub.insert(pub.begin(), 5);
            } else {
                // Public test scalar, not suitable for real funds.
                secret.back() = 7;
                secp256k1_pubkey key;
                if (!secp256k1_ec_pubkey_create(ctx, &key, secret.data())) throw std::runtime_error("pubkey");
                size_t length = pub.size();
                secp256k1_ec_pubkey_serialize(ctx, pub.data(), &length, &key, SECP256K1_EC_COMPRESSED);
            }
            hex(pub); hex(secret);
        } else if (std::string(argv[1]) == "sign") {
            std::string key, msg;
            if (!(std::cin >> key >> msg)) throw std::runtime_error("missing key/hash");
            const auto secret = unhex(key), hash = unhex(msg);
            if (hash.size() != 32 || secret.size() != (pq ? oqs->length_secret_key : 32)) throw std::runtime_error("size");
            Bytes sig(pq ? oqs->length_signature : 72);
            size_t length = sig.size();
            if (pq) {
                if (OQS_SIG_sign(oqs, sig.data(), &length, hash.data(), hash.size(), secret.data()) != OQS_SUCCESS)
                    throw std::runtime_error("sign");
            } else {
                secp256k1_ecdsa_signature signature;
                if (!secp256k1_ecdsa_sign(ctx, &signature, hash.data(), secret.data(), nullptr, nullptr)) throw std::runtime_error("sign");
                secp256k1_ecdsa_signature_serialize_der(ctx, sig.data(), &length, &signature);
            }
            sig.resize(length); sig.push_back(1); // SIGHASH_ALL
            hex(sig);
        } else throw std::runtime_error("unknown command");
        if (oqs) OQS_SIG_free(oqs);
        if (ctx) secp256k1_context_destroy(ctx);
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
