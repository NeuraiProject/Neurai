// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/circom_witness.h"

#include <univalue.h>

extern "C" {
#include "wasm3/wasm3.h"
}

#include <memory>

namespace privacy {
namespace {

// Circom 2 field elements are exchanged as 32-bit words, least significant first.
constexpr int FIELD_WORDS = 8;
constexpr uint32_t WASM_STACK_BYTES = 1 << 20;

/** Parses a non-negative decimal integer below 2^256. */
bool DecimalToLE(const std::string& text, FieldLE& out)
{
    if (text.empty() || text.size() > 78) return false;
    std::array<uint32_t, FIELD_WORDS + 1> words{};
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        uint64_t carry = static_cast<uint64_t>(c - '0');
        for (uint32_t& word : words) {
            const uint64_t value = static_cast<uint64_t>(word) * 10 + carry;
            word = static_cast<uint32_t>(value);
            carry = value >> 32;
        }
        if (carry || words[FIELD_WORDS]) return false;
    }
    for (int i = 0; i < FIELD_WORDS; ++i) {
        for (int b = 0; b < 4; ++b) out[i * 4 + b] = static_cast<uint8_t>(words[i] >> (8 * b));
    }
    return true;
}

bool Flatten(const UniValue& value, std::vector<FieldLE>& out)
{
    if (value.isArray()) {
        for (size_t i = 0; i < value.size(); ++i) {
            if (!Flatten(value[i], out)) return false;
        }
        return true;
    }
    FieldLE element{};
    if (value.isNum() || value.isStr()) {
        if (!DecimalToLE(value.getValStr(), element)) return false;
        out.push_back(element);
        return true;
    }
    return false;
}

/** 64-bit FNV-1a of the signal name, as used by circom to address inputs. */
uint64_t SignalHash(const std::string& name)
{
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (unsigned char c : name) {
        hash ^= c;
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

int Compare(const FieldLE& a, const FieldLE& b)
{
    for (int i = 31; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

struct HostState {
    int32_t exception = 0;
};

m3ApiRawFunction(ExceptionHandler)
{
    m3ApiGetArg(int32_t, code);
    static_cast<HostState*>(_ctx->userdata)->exception = code;
    m3ApiTrap("circom runtime exception");
}

m3ApiRawFunction(Ignore)
{
    m3ApiSuccess();
}

struct Wasm3Deleter {
    void operator()(M3Environment* env) const { m3_FreeEnvironment(env); }
    void operator()(M3Runtime* runtime) const { m3_FreeRuntime(runtime); }
};

const char* CircomError(int32_t code)
{
    switch (code) {
    case 1: return "signal not found";
    case 2: return "too many values for an input signal";
    case 3: return "input signal already set";
    case 4: return "circuit assertion failed";
    case 5: return "witness generator out of memory";
    case 6: return "input signal index out of range";
    default: return "unknown circom exception";
    }
}

} // namespace

bool ParseCircuitInputs(const UniValue& json, std::vector<CircuitInput>& out, std::string& error)
{
    if (!json.isObject()) {
        error = "circuit input must be a JSON object";
        return false;
    }
    out.clear();
    for (const std::string& key : json.getKeys()) {
        CircuitInput input{key, {}};
        if (!Flatten(json[key], input.second)) {
            error = "invalid value for circuit input " + key;
            return false;
        }
        out.push_back(std::move(input));
    }
    return true;
}

bool ComputeWitness(const std::vector<uint8_t>& wasm, const std::vector<CircuitInput>& inputs,
                    std::vector<FieldLE>& witness, std::string& error)
{
    std::unique_ptr<M3Environment, Wasm3Deleter> env(m3_NewEnvironment());
    if (!env) {
        error = "cannot create the WebAssembly environment";
        return false;
    }
    HostState host;
    std::unique_ptr<M3Runtime, Wasm3Deleter> runtime(m3_NewRuntime(env.get(), WASM_STACK_BYTES, &host));
    if (!runtime) {
        error = "cannot create the WebAssembly runtime";
        return false;
    }

    IM3Module module = nullptr;
    M3Result result = m3_ParseModule(env.get(), &module, wasm.data(), static_cast<uint32_t>(wasm.size()));
    if (result) {
        error = std::string("invalid witness generator: ") + result;
        return false;
    }
    result = m3_LoadModule(runtime.get(), module);
    if (result) {
        m3_FreeModule(module);
        error = std::string("cannot load the witness generator: ") + result;
        return false;
    }
    // Messages printed by the circuit are diagnostics only; failures arrive through
    // exceptionHandler with an error code.
    m3_LinkRawFunctionEx(module, "runtime", "exceptionHandler", "v(i)", &ExceptionHandler, &host);
    m3_LinkRawFunction(module, "runtime", "printErrorMessage", "v()", &Ignore);
    m3_LinkRawFunction(module, "runtime", "writeBufferMessage", "v()", &Ignore);
    m3_LinkRawFunction(module, "runtime", "showSharedRWMemory", "v()", &Ignore);

    auto find = [&](const char* name) {
        IM3Function function = nullptr;
        if (m3_FindFunction(&function, runtime.get(), name)) function = nullptr;
        return function;
    };
    IM3Function fnNumLen = find("getFieldNumLen32"), fnRawPrime = find("getRawPrime"),
                fnRead = find("readSharedRWMemory"), fnWrite = find("writeSharedRWMemory"),
                fnInit = find("init"), fnSignalSize = find("getInputSignalSize"),
                fnSetInput = find("setInputSignal"), fnInputSize = find("getInputSize"),
                fnWitnessSize = find("getWitnessSize"), fnGetWitness = find("getWitness");
    if (!fnNumLen || !fnRawPrime || !fnRead || !fnWrite || !fnInit || !fnSignalSize || !fnSetInput ||
        !fnInputSize || !fnWitnessSize || !fnGetWitness) {
        error = "not a circom 2 witness generator";
        return false;
    }

    auto failed = [&](M3Result call) {
        if (!call) return false;
        error = host.exception ? CircomError(host.exception) : std::string("witness generator failed: ") + call;
        return true;
    };
    auto readWord = [&](int32_t index, uint32_t& word) {
        int32_t value = 0;
        if (failed(m3_CallV(fnRead, index)) || failed(m3_GetResultsV(fnRead, &value))) return false;
        word = static_cast<uint32_t>(value);
        return true;
    };
    auto readField = [&](FieldLE& out) {
        for (int i = 0; i < FIELD_WORDS; ++i) {
            uint32_t word;
            if (!readWord(i, word)) return false;
            for (int b = 0; b < 4; ++b) out[i * 4 + b] = static_cast<uint8_t>(word >> (8 * b));
        }
        return true;
    };

    int32_t words = 0;
    if (failed(m3_CallV(fnNumLen)) || failed(m3_GetResultsV(fnNumLen, &words))) return false;
    if (words != FIELD_WORDS) {
        error = "unsupported field size in witness generator";
        return false;
    }
    FieldLE prime{};
    if (failed(m3_CallV(fnRawPrime)) || !readField(prime)) return false;

    if (failed(m3_CallV(fnInit, 0))) return false;
    int32_t provided = 0;
    for (const CircuitInput& input : inputs) {
        const uint64_t hash = SignalHash(input.first);
        const int32_t msb = static_cast<int32_t>(hash >> 32), lsb = static_cast<int32_t>(hash & 0xffffffffULL);
        int32_t size = 0;
        if (failed(m3_CallV(fnSignalSize, msb, lsb)) || failed(m3_GetResultsV(fnSignalSize, &size))) return false;
        if (size < 0) {
            error = "unknown circuit input " + input.first;
            return false;
        }
        if (static_cast<size_t>(size) != input.second.size()) {
            error = "wrong number of values for circuit input " + input.first;
            return false;
        }
        for (size_t pos = 0; pos < input.second.size(); ++pos) {
            const FieldLE& value = input.second[pos];
            if (Compare(value, prime) >= 0) {
                error = "non-canonical value for circuit input " + input.first;
                return false;
            }
            for (int i = 0; i < FIELD_WORDS; ++i) {
                uint32_t word = 0;
                for (int b = 0; b < 4; ++b) word |= static_cast<uint32_t>(value[i * 4 + b]) << (8 * b);
                if (failed(m3_CallV(fnWrite, i, static_cast<int32_t>(word)))) return false;
            }
            if (failed(m3_CallV(fnSetInput, msb, lsb, static_cast<int32_t>(pos)))) return false;
            ++provided;
        }
    }
    int32_t expected = 0;
    if (failed(m3_CallV(fnInputSize)) || failed(m3_GetResultsV(fnInputSize, &expected))) return false;
    if (provided != expected) {
        error = "not all circuit inputs were provided";
        return false;
    }

    int32_t size = 0;
    if (failed(m3_CallV(fnWitnessSize)) || failed(m3_GetResultsV(fnWitnessSize, &size))) return false;
    if (size <= 0) {
        error = "empty witness";
        return false;
    }
    witness.assign(size, FieldLE{});
    for (int32_t i = 0; i < size; ++i) {
        if (failed(m3_CallV(fnGetWitness, i)) || !readField(witness[i])) return false;
    }
    return true;
}

} // namespace privacy
