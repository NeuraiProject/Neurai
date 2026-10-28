// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// DEPIN transfer state (CLOSED / OPEN / SEALED).
//
// A DEPIN asset "&X" is soulbound by default (CLOSED): moving it requires
// spending and re-emitting the owner token "&X!" in the same transaction.
// The owner can OPEN it (holders move it like a regular asset, except from
// frozen or self-revoked addresses), CLOSE it again, or SEAL it from CLOSED,
// which is irreversible. The operation is a global null data output
// (OP_XNA_ASSET OP_RESERVED OP_RESERVED <asset, flag>) escorted by a transfer
// of "&X!", activated by height, judged against the connected tip, and
// limited to one per asset per block.
//
// Two fixtures: BasicTestingSetup for the purely structural and transition
// rules, and a 100-block regtest chain with in-memory asset databases for
// everything that needs AreAssetsDeployed(), real blocks, undo and the
// mempool. Asset UTXOs are seeded straight into the UTXO set: issuance is
// not the subject here, and address balances are only tracked with
// -assetindex, which is off.

#include "amount.h"

#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "txmempool.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

const std::string ASSET = "&DEVICE";
const std::string OWNER = "&DEVICE!";
const std::string OTHER_ASSET = "&SENSOR";

// Regtest is xna-native from height 1 (NIP-040), and every candidate height
// used here is >= 1.
const AssetMarker MARKER = AssetMarker::NEURAI_XNA;

const char* kNotByOwner = "bad-txns-depin-transfer-not-by-owner";
const char* kFromRestricted = "bad-txns-depin-transfer-from-restricted-address";

// RAII guard for the activation height (regtest default is 1).
struct DepinStateHeightGuard {
    explicit DepinStateHeightGuard(int nHeight) { UpdateDepinTransferStateHeight(nHeight); }
    ~DepinStateHeightGuard() { UpdateDepinTransferStateHeight(1); }
};

std::string AddressOf(const CKey& key)
{
    return EncodeDestination(key.GetPubKey().GetID());
}

CScript TransferScript(const std::string& name, CAmount amount, const std::string& address)
{
    CAssetTransfer transfer(name, amount);
    CScript script = GetScriptForDestination(DecodeDestination(address));
    transfer.ConstructTransaction(script, MARKER);
    return script;
}

CScript OwnerTransferScript(const std::string& address)
{
    return TransferScript(OWNER, OWNER_ASSET_AMOUNT, address);
}

// The asset as it leaves issuance (TX_NEW_ASSET), the usual shape of a
// soulbound token's UTXO.
CScript IssuanceScript(const std::string& name, CAmount amount, const std::string& address)
{
    CNewAsset asset(name, amount, DEPIN_ASSET_UNITS, 0, 0, "");
    CScript script = GetScriptForDestination(DecodeDestination(address));
    asset.ConstructTransaction(script, MARKER);
    return script;
}

// Per-address null data (owner freeze / unfreeze, holder self-revocation).
CScript NullDataScript(const std::string& name, int flag, const std::string& address)
{
    CNullAssetTxData data(name, flag);
    CScript script = GetScriptForNullAssetDataDestination(DecodeDestination(address));
    data.ConstructTransaction(script);
    return script;
}

// Global null data: the transfer state operation itself.
CScript StateScript(const std::string& name, int flag)
{
    CNullAssetTxData data(name, flag);
    CScript script;
    data.ConstructGlobalRestrictionTransaction(script);
    return script;
}

COutPoint FakeOutPoint(unsigned int n)
{
    std::vector<unsigned char> bytes(32, 0x33);
    bytes[0] = (unsigned char)(n & 0xff);
    bytes[1] = (unsigned char)((n >> 8) & 0xff);
    return COutPoint(uint256(bytes), 0);
}

// ---------------------------------------------------------------------------
// Fixture 1: no chain. passets is a local cache so the state lookups have
// somewhere to fall through to; no databases (the lookups tolerate null).
struct DepinStateSetup : public BasicTestingSetup {
    CAssetsCache globalAssetsCache;
    CAssetsCache* prevAssets;

    DepinStateSetup() : BasicTestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssets = passets;
        passets = &globalAssetsCache;
    }

    ~DepinStateSetup()
    {
        passets = prevAssets;
    }
};

bool Structural(const CMutableTransaction& mut, std::string& reason)
{
    CValidationState state;
    const bool ok = CheckTransaction(CTransaction(mut), state, true, false, false);
    reason = state.GetRejectReason();
    return ok;
}

// A structurally complete state operation: one dummy input, the owner
// transfer named by `ownerName`, and the state output.
CMutableTransaction StateOperationTx(const std::string& asset, int flag, const std::string& ownerName)
{
    CKey key;
    key.MakeNewKey(true);
    CMutableTransaction mut;
    mut.vin.emplace_back(FakeOutPoint(1));
    if (!ownerName.empty())
        mut.vout.emplace_back(0, TransferScript(ownerName, OWNER_ASSET_AMOUNT, AddressOf(key)));
    mut.vout.emplace_back(0, StateScript(asset, flag));
    return mut;
}

// ---------------------------------------------------------------------------
// Fixture 2: a real 100-block regtest chain (assets and RIP5 active from
// height 1 on regtest) with in-memory asset databases, so ConnectBlock,
// DisconnectBlock and FlushStateToDisk have everything they touch.
struct DepinStateChainSetup : public TestChain100Setup {
    CBasicKeyStore keystore;
    CKey ownerKey, holderKey, holder2Key, recipientKey;
    std::string ownerAddr, holderAddr, holder2Addr, recipientAddr;
    unsigned int nNextSeed = 0;
    unsigned int nBlockSalt = 0;

    DepinStateChainSetup() : TestChain100Setup()
    {
        // The assets exist as far as the metadata lookups are concerned
        // (the mempool path resolves units through them for transfers whose
        // inputs are not issuance outputs)
        for (const std::string& name : {ASSET, OTHER_ASSET}) {
            BOOST_REQUIRE(passetsdb->WriteAssetData(CNewAsset(name, 1000 * COIN, DEPIN_ASSET_UNITS, 1, 0, ""),
                                                    chainActive.Height(), chainActive.Tip()->GetBlockHash()));
        }

        keystore.AddKey(coinbaseKey);
        for (CKey* key : {&ownerKey, &holderKey, &holder2Key, &recipientKey}) {
            key->MakeNewKey(true);
            keystore.AddKey(*key);
        }
        ownerAddr = AddressOf(ownerKey);
        holderAddr = AddressOf(holderKey);
        holder2Addr = AddressOf(holder2Key);
        recipientAddr = AddressOf(recipientKey);
    }

    // Seed an asset UTXO straight into the UTXO set.
    COutPoint Seed(const CScript& script)
    {
        const COutPoint out = FakeOutPoint(0x1000 + nNextSeed++);
        pcoinsTip->AddCoin(out, Coin(CTxOut(0, script), chainActive.Height(), false), false);
        return out;
    }

    CTxOut PrevOut(const COutPoint& out, const std::map<COutPoint, CTxOut>& extra) const
    {
        auto it = extra.find(out);
        if (it != extra.end())
            return it->second;
        const Coin& coin = pcoinsTip->AccessCoin(out);
        BOOST_REQUIRE(!coin.IsSpent());
        return coin.out;
    }

    // Sign every input with the fixture keys. `extra` supplies outputs of
    // transactions that are not (yet) in the UTXO set.
    void Sign(CMutableTransaction& mut, const std::map<COutPoint, CTxOut>& extra = {}) const
    {
        for (unsigned int i = 0; i < mut.vin.size(); i++) {
            const CTxOut prev = PrevOut(mut.vin[i].prevout, extra);
            BOOST_REQUIRE(SignSignature(keystore, prev.scriptPubKey, mut, i, prev.nValue, SIGHASH_ALL));
        }
    }

    // The state operation `flag` on ASSET, spending the owner token at
    // `ownerOut` and re-emitting it to ownerAddr.
    CMutableTransaction StateOp(const COutPoint& ownerOut, int flag, const std::map<COutPoint, CTxOut>& extra = {})
    {
        CMutableTransaction mut;
        mut.vin.emplace_back(ownerOut);
        mut.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
        mut.vout.emplace_back(0, StateScript(ASSET, flag));
        Sign(mut, extra);
        return mut;
    }

    // A holder transfer: spend `assetOut` (amount `amount`) and pay it all to `to`.
    CMutableTransaction HolderTransfer(const COutPoint& assetOut, CAmount amount, const std::string& to,
                                       const std::map<COutPoint, CTxOut>& extra = {})
    {
        CMutableTransaction mut;
        mut.vin.emplace_back(assetOut);
        mut.vout.emplace_back(0, TransferScript(ASSET, amount, to));
        Sign(mut, extra);
        return mut;
    }

    // Owner freeze (flag 1) or unfreeze (flag 0) of `addr`, escorting the owner
    // token at `ownerOut` back to ownerAddr (output 0).
    CMutableTransaction OwnerRestriction(const COutPoint& ownerOut, int flag, const std::string& addr,
                                         const std::map<COutPoint, CTxOut>& extra = {})
    {
        CMutableTransaction mut;
        mut.vin.emplace_back(ownerOut);
        mut.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
        mut.vout.emplace_back(0, NullDataScript(ASSET, flag, addr));
        Sign(mut, extra);
        return mut;
    }

    // Self-revocation by `addr`, which holds `amount` of ASSET at `assetOut`.
    CMutableTransaction SelfRevoke(const COutPoint& assetOut, CAmount amount, const std::string& addr,
                                   const std::map<COutPoint, CTxOut>& extra = {})
    {
        CMutableTransaction mut;
        mut.vin.emplace_back(assetOut);
        mut.vout.emplace_back(0, TransferScript(ASSET, amount, addr));
        mut.vout.emplace_back(0, NullDataScript(ASSET, 1, addr));
        Sign(mut, extra);
        return mut;
    }

    bool OwnerFrozen(const std::string& addr) const { return passets->CheckForAddressRestriction(ASSET, addr); }
    bool SelfRevoked(const std::string& addr) const { return passets->CheckForDEPINSelfRestriction(ASSET, addr); }

    // Consensus verdict of a transaction for the next block, against the
    // connected tip and the live asset cache.
    bool Verdict(const CMutableTransaction& mut, std::string& reason, const std::map<COutPoint, CTxOut>& extra = {}) const
    {
        CCoinsViewCache view(pcoinsTip);
        for (const auto& item : extra)
            view.AddCoin(item.first, Coin(item.second, chainActive.Height() + 1, false), false);
        CValidationState state;
        std::vector<std::pair<std::string, uint256>> vReissue;
        const bool ok = Consensus::CheckTxAssets(CTransaction(mut), state, view, passets,
                                                 chainActive.Height() + 1, false, vReissue,
                                                 true, nullptr, 0, nullptr);
        reason = state.GetRejectReason();
        return ok;
    }

    // Build a block with `txns` on the current tip without processing it.
    // The template committed to its own (empty) transaction list, so the
    // witness commitment is rebuilt for ours; segwit is active on regtest
    // and ContextualCheckBlock rejects a stale one (bad-witness-merkle-match).
    CBlock BuildBlock(const std::vector<CMutableTransaction>& txns)
    {
        CScript coinbaseScript = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(GetParams()).CreateNewBlock(coinbaseScript);
        CBlock block = pblocktemplate->block;
        block.vtx.resize(1);
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));

        CMutableTransaction coinbase(*block.vtx[0]);
        for (size_t i = 0; i < coinbase.vout.size(); i++) {
            const CScript& script = coinbase.vout[i].scriptPubKey;
            if (script.size() >= 38 && script[0] == OP_RETURN && script[1] == 0x24 &&
                script[2] == 0xaa && script[3] == 0x21 && script[4] == 0xa9 && script[5] == 0xed) {
                coinbase.vout.erase(coinbase.vout.begin() + i);
                break;
            }
        }
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), GetParams().GetConsensus());

        // A fresh extra nonce per block: after a disconnect, re-mining the
        // same transactions on the same parent must not rebuild the very
        // block that was just marked invalid.
        unsigned int extraNonce = ++nBlockSalt;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        return block;
    }

    // Mine `txns` into a block; true when the tip advanced to it.
    bool Mine(const std::vector<CMutableTransaction>& txns)
    {
        const int nPrev = chainActive.Height();
        CBlock block = BuildBlock(txns);
        uint256 mix_hash;
        while (!CheckProofOfWork(block.GetHashFull(mix_hash), block.nBits, GetParams().GetConsensus())) {
            ++block.nNonce64;
            ++block.nNonce;
        }
        block.mix_hash = mix_hash;
        ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr);
        return chainActive.Height() == nPrev + 1 && chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    // Consensus verdict of a whole block via the fJustCheck path.
    bool BlockVerdict(const std::vector<CMutableTransaction>& txns, std::string& reason)
    {
        const CBlock block = BuildBlock(txns);
        CValidationState state;
        bool ok;
        {
            // TestBlockValidity() requires cs_main.
            LOCK(cs_main);
            ok = TestBlockValidity(state, GetParams(), block, chainActive.Tip(), false, true);
        }
        reason = state.GetRejectReason();
        return ok;
    }

    // Disconnect the tip (a one-block reorg). The disconnected transactions
    // are resurrected into the mempool by UpdateMempoolForReorg; the tests
    // that do not want them there clear it explicitly.
    void UndoTip()
    {
        CValidationState state;
        {
            // InvalidateBlock() requires cs_main, as the invalidateblock RPC holds it.
            LOCK(cs_main);
            BOOST_REQUIRE(InvalidateBlock(state, GetParams(), chainActive.Tip()));
        }
        BOOST_REQUIRE(state.IsValid());
    }

    DepinTransferState State() const
    {
        return passets->GetDepinTransferState(ASSET);
    }

    bool ToMempool(const CMutableTransaction& mut, std::string& reason, bool test_accept = false)
    {
        CValidationState state;
        bool ok;
        {
            // AcceptToMemoryPool() requires cs_main.
            LOCK(cs_main);
            ok = AcceptToMemoryPool(mempool, state, MakeTransactionRef(mut), nullptr,
                                    true /* bypass_limits */, 0, test_accept);
        }
        reason = state.GetRejectReason();
        return ok;
    }

    size_t HolderTransfersTracked() const
    {
        LOCK(mempool.cs);
        auto it = mempool.mapDepinHolderTransfers.find(ASSET);
        return it == mempool.mapDepinHolderTransfers.end() ? 0 : it->second.size();
    }

    size_t StateOpsTracked() const
    {
        LOCK(mempool.cs);
        auto it = mempool.mapDepinStateChanges.find(ASSET);
        return it == mempool.mapDepinStateChanges.end() ? 0 : it->second.size();
    }
};

} // namespace

// ===========================================================================
BOOST_FIXTURE_TEST_SUITE(depin_transfer_state_tests, DepinStateSetup)

// (1) Structural: the flag range differs by name family, and a DEPIN state
// operation must be escorted by a transfer of &X! (not X!).
BOOST_AUTO_TEST_CASE(structural_flag_and_owner_escort)
{
    std::string reason;

    for (int flag : {0, 1, 2}) {
        BOOST_CHECK_MESSAGE(Structural(StateOperationTx(ASSET, flag, OWNER), reason),
                            "flag " << flag << " rejected: " << reason);
    }
    BOOST_CHECK(!Structural(StateOperationTx(ASSET, 3, OWNER), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-flag-must-be-0-1-or-2");
    BOOST_CHECK(!Structural(StateOperationTx(ASSET, -1, OWNER), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-flag-must-be-0-1-or-2");

    // '$' names keep the two-valued global freeze flag
    BOOST_CHECK(!Structural(StateOperationTx("$TOKEN", 2, "TOKEN!"), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-null-data-flag-must-be-0-or-1");
    BOOST_CHECK(Structural(StateOperationTx("$TOKEN", 1, "TOKEN!"), reason));

    // No owner transfer at all, or the owner of an unrelated root asset
    BOOST_CHECK(!Structural(StateOperationTx(ASSET, 1, ""), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-tx-contains-depin-state-null-tx-without-owner-transfer");
    BOOST_CHECK(!Structural(StateOperationTx(ASSET, 1, "DEVICE!"), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-tx-contains-depin-state-null-tx-without-owner-transfer");

    // Two operations for the same asset in one transaction
    CMutableTransaction two = StateOperationTx(ASSET, 1, OWNER);
    two.vout.emplace_back(0, StateScript(ASSET, 2));
    BOOST_CHECK(!Structural(two, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-null-data-only-one-global-change-per-asset-name");
}

// (2) The transition table, judged against passets (the connected tip).
BOOST_AUTO_TEST_CASE(transition_table)
{
    CAssetsCache cache;
    std::string err;
    const int H = 1;

    auto verdict = [&](int flag, std::string& out) {
        return VerifyDepinTransferStateChange(cache, CNullAssetTxData(ASSET, flag), H, out);
    };

    // CLOSED: OPEN and SEAL are valid, CLOSE is a null transition
    BOOST_CHECK_EQUAL((int)passets->GetDepinTransferState(ASSET), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(verdict(1, err));
    BOOST_CHECK(verdict(2, err));
    BOOST_CHECK(!verdict(0, err));
    BOOST_CHECK_EQUAL(err, "bad-txns-depin-state-already-closed");

    // OPEN: only CLOSE is valid; SEAL needs CLOSED first
    passets->AddDepinTransferState(ASSET, DepinTransferState::OPEN);
    BOOST_CHECK_EQUAL((int)passets->GetDepinTransferState(ASSET), (int)DepinTransferState::OPEN);
    BOOST_CHECK(verdict(0, err));
    BOOST_CHECK(!verdict(1, err));
    BOOST_CHECK_EQUAL(err, "bad-txns-depin-state-already-open");
    BOOST_CHECK(!verdict(2, err));
    BOOST_CHECK_EQUAL(err, "bad-txns-depin-state-seal-requires-closed");

    // SEALED: nothing is ever accepted again
    passets->AddDepinTransferState(ASSET, DepinTransferState::SEALED);
    BOOST_CHECK_EQUAL((int)passets->GetDepinTransferState(ASSET), (int)DepinTransferState::SEALED);
    for (int flag : {0, 1, 2}) {
        BOOST_CHECK(!verdict(flag, err));
        BOOST_CHECK_EQUAL(err, "bad-txns-depin-state-sealed");
    }

    // Overwrite-by-name: one entry per asset in the set, the last write wins
    BOOST_CHECK_EQUAL(passets->setNewDepinStateToAdd.size(), 1U);

    // The dirty sets of the cache being built are NOT consulted (snapshot):
    // a pending OPEN in `cache` does not turn a second OPEN into a duplicate
    passets->ClearDirtyCache();
    cache.AddDepinTransferState(ASSET, DepinTransferState::OPEN);
    BOOST_CHECK(verdict(1, err));
    BOOST_CHECK_EQUAL((int)cache.GetDepinTransferState(ASSET, true), (int)DepinTransferState::CLOSED);
    BOOST_CHECK_EQUAL((int)cache.GetDepinTransferState(ASSET, false), (int)DepinTransferState::OPEN);
}

// (3) Activation by height, with the INT_MAX sentinel explicitly inactive.
BOOST_AUTO_TEST_CASE(activation_height)
{
    const Consensus::Params& params = GetParams().GetConsensus();
    CAssetsCache cache;
    std::string err;

    {
        DepinStateHeightGuard guard(50);
        BOOST_CHECK(!IsDepinTransferStateActive(49, params));
        BOOST_CHECK(IsDepinTransferStateActive(50, params));
        BOOST_CHECK(!VerifyDepinTransferStateChange(cache, CNullAssetTxData(ASSET, 1), 49, err));
        BOOST_CHECK_EQUAL(err, "bad-txns-depin-state-before-activation");
        BOOST_CHECK(VerifyDepinTransferStateChange(cache, CNullAssetTxData(ASSET, 1), 50, err));
    }
    {
        DepinStateHeightGuard guard(std::numeric_limits<int>::max());
        BOOST_CHECK(!IsDepinTransferStateActive(std::numeric_limits<int>::max(), params));
        BOOST_CHECK(!VerifyDepinTransferStateChange(cache, CNullAssetTxData(ASSET, 1), std::numeric_limits<int>::max(), err));
        BOOST_CHECK_EQUAL(err, "bad-txns-depin-state-before-activation");
    }
    // Guard restored the regtest default
    BOOST_CHECK(IsDepinTransferStateActive(1, params));
}

// Cache undo semantics (8, in memory): Add + Remove restores the previous
// state for every transition, including two operations flushed in order and
// undone in reverse.
BOOST_AUTO_TEST_CASE(cache_add_remove_restores_previous_state)
{
    auto stateNow = [&]() { return (int)passets->GetDepinTransferState(ASSET); };

    // OPEN then undo
    {
        CAssetsCache block;
        block.AddDepinTransferState(ASSET, DepinTransferState::OPEN);
        BOOST_CHECK(block.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::OPEN);
    {
        CAssetsCache undo;
        undo.RemoveDepinTransferState(ASSET, DepinTransferState::OPEN);
        BOOST_CHECK(undo.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::CLOSED);

    // OPEN (block N), CLOSE (block N+1), then undo N+1 and N in that order
    {
        CAssetsCache blockN;
        blockN.AddDepinTransferState(ASSET, DepinTransferState::OPEN);
        BOOST_CHECK(blockN.Flush());
        CAssetsCache blockN1;
        blockN1.AddDepinTransferState(ASSET, DepinTransferState::CLOSED);
        BOOST_CHECK(blockN1.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::CLOSED);
    {
        CAssetsCache undoN1;
        undoN1.RemoveDepinTransferState(ASSET, DepinTransferState::CLOSED);
        BOOST_CHECK(undoN1.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::OPEN);
    {
        CAssetsCache undoN;
        undoN.RemoveDepinTransferState(ASSET, DepinTransferState::OPEN);
        BOOST_CHECK(undoN.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::CLOSED);

    // SEAL then undo
    {
        CAssetsCache block;
        block.AddDepinTransferState(ASSET, DepinTransferState::SEALED);
        BOOST_CHECK(block.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::SEALED);
    {
        CAssetsCache undo;
        undo.RemoveDepinTransferState(ASSET, DepinTransferState::SEALED);
        BOOST_CHECK(undo.Flush());
    }
    BOOST_CHECK_EQUAL(stateNow(), (int)DepinTransferState::CLOSED);

    // Within one block: a disconnect visits transactions in reverse, so the
    // last restoration written is the first change of the block. Overwrite
    // by name keeps exactly that one.
    {
        CAssetsCache undo;
        undo.RemoveDepinTransferState(ASSET, DepinTransferState::SEALED); // later tx in the block
        undo.RemoveDepinTransferState(ASSET, DepinTransferState::OPEN);   // earlier tx in the block
        BOOST_CHECK_EQUAL(undo.setNewDepinStateToRemove.size(), 1U);
        BOOST_CHECK_EQUAL((int)undo.setNewDepinStateToRemove.begin()->state, (int)DepinTransferState::OPEN);
    }
}

// The per-transaction context is order-independent and classifies owner
// tokens, holder transfers and null data correctly, including inputs that
// only exist in the supplied coins view (mempool ancestors).
BOOST_AUTO_TEST_CASE(tx_context_classification)
{
    CKey ownerKey, holderKey;
    ownerKey.MakeNewKey(true);
    holderKey.MakeNewKey(true);
    const std::string ownerAddr = AddressOf(ownerKey);
    const std::string holderAddr = AddressOf(holderKey);

    CCoinsView base;
    CCoinsViewCache view(&base);

    // Escorted move by the owner, null data output listed BEFORE the transfers
    {
        CMutableTransaction mut;
        const COutPoint ownerOut = FakeOutPoint(10), assetOut = FakeOutPoint(11);
        view.AddCoin(ownerOut, Coin(CTxOut(0, OwnerTransferScript(ownerAddr)), 1, false), false);
        view.AddCoin(assetOut, Coin(CTxOut(0, IssuanceScript(ASSET, 5 * COIN, holderAddr)), 1, false), false);
        mut.vin.emplace_back(ownerOut);
        mut.vin.emplace_back(assetOut);
        mut.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
        mut.vout.emplace_back(0, TransferScript(ASSET, 5 * COIN, ownerAddr));
        mut.vout.emplace_back(0, OwnerTransferScript(ownerAddr));

        std::map<std::string, DepinTxContext> ctx;
        BuildDepinTxContext(CTransaction(mut), view, nullptr, ctx);
        BOOST_REQUIRE_EQUAL(ctx.size(), 1U);
        BOOST_CHECK(ctx.count(ASSET));
        BOOST_CHECK(!ctx.count(OWNER));
        BOOST_CHECK(ctx[ASSET].Escorted());
        BOOST_CHECK(ctx[ASSET].spendsOwnerToken && ctx[ASSET].transfersOwnerToken);
        BOOST_CHECK(ctx[ASSET].transfersAsset && ctx[ASSET].spendsAsset && ctx[ASSET].hasNullData);
    }

    // Holder transfer whose input is an unconfirmed output (only in the view)
    {
        CMutableTransaction mut;
        const COutPoint unconfirmed = FakeOutPoint(12);
        view.AddCoin(unconfirmed, Coin(CTxOut(0, TransferScript(ASSET, 2 * COIN, holderAddr)), MEMPOOL_HEIGHT, false), false);
        mut.vin.emplace_back(unconfirmed);
        mut.vout.emplace_back(0, TransferScript(ASSET, 2 * COIN, ownerAddr));

        std::map<std::string, DepinTxContext> ctx;
        BuildDepinTxContext(CTransaction(mut), view, passets, ctx);
        BOOST_REQUIRE_EQUAL(ctx.size(), 1U);
        BOOST_CHECK(!ctx[ASSET].Escorted());
        BOOST_CHECK(ctx[ASSET].transfersAsset && ctx[ASSET].spendsAsset);
        BOOST_CHECK(!ctx[ASSET].hasNullData);
        BOOST_CHECK_EQUAL((int)ctx[ASSET].state, (int)DepinTransferState::CLOSED);
    }

    // Two assets, one escorted and one not, stay separate; '$' and plain
    // names never appear
    {
        CMutableTransaction mut;
        const COutPoint a = FakeOutPoint(13), b = FakeOutPoint(14), o = FakeOutPoint(15), r = FakeOutPoint(16);
        view.AddCoin(a, Coin(CTxOut(0, TransferScript(ASSET, COIN, holderAddr)), 1, false), false);
        view.AddCoin(b, Coin(CTxOut(0, TransferScript(OTHER_ASSET, COIN, holderAddr)), 1, false), false);
        view.AddCoin(o, Coin(CTxOut(0, TransferScript(OTHER_ASSET + OWNER_TAG, OWNER_ASSET_AMOUNT, ownerAddr)), 1, false), false);
        view.AddCoin(r, Coin(CTxOut(0, TransferScript("$RESTRICTED", COIN, holderAddr)), 1, false), false);
        mut.vin = {CTxIn(a), CTxIn(b), CTxIn(o), CTxIn(r)};
        mut.vout.emplace_back(0, TransferScript(ASSET, COIN, ownerAddr));
        mut.vout.emplace_back(0, TransferScript(OTHER_ASSET, COIN, ownerAddr));
        mut.vout.emplace_back(0, TransferScript(OTHER_ASSET + OWNER_TAG, OWNER_ASSET_AMOUNT, ownerAddr));
        mut.vout.emplace_back(0, TransferScript("$RESTRICTED", COIN, ownerAddr));

        std::map<std::string, DepinTxContext> ctx;
        BuildDepinTxContext(CTransaction(mut), view, nullptr, ctx);
        BOOST_REQUIRE_EQUAL(ctx.size(), 2U);
        BOOST_CHECK(!ctx[ASSET].Escorted());
        BOOST_CHECK(ctx[OTHER_ASSET].Escorted());
    }

    // State operations are found by name family only
    {
        CMutableTransaction mut = StateOperationTx(ASSET, 2, OWNER);
        mut.vout.emplace_back(0, StateScript("$RESTRICTED", 1));
        std::set<std::string> ops;
        GetDepinStateOperations(CTransaction(mut), ops);
        BOOST_CHECK_EQUAL(ops.size(), 1U);
        BOOST_CHECK(ops.count(ASSET));
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ===========================================================================
BOOST_FIXTURE_TEST_SUITE(depin_transfer_state_chain_tests, DepinStateChainSetup)

// (4)(9) A holder transfer is rejected while CLOSED, accepted while OPEN
// (with the balance rule and the NIP-040 marker rule untouched), rejected
// again after CLOSE and after SEAL; nothing is accepted on a sealed asset.
BOOST_AUTO_TEST_CASE(holder_transfer_follows_the_state)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, 10 * COIN, holderAddr));

    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(!Verdict(HolderTransfer(holderOut, 10 * COIN, recipientAddr), reason));
    BOOST_CHECK(reason.find(kNotByOwner) == 0);

    // OPEN
    CMutableTransaction op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    BOOST_CHECK_MESSAGE(Verdict(HolderTransfer(holderOut, 10 * COIN, recipientAddr), reason), reason);

    // Amount conservation still applies to a holder transfer
    BOOST_CHECK(!Verdict(HolderTransfer(holderOut, 9 * COIN, recipientAddr), reason));
    BOOST_CHECK(reason.find(kNotByOwner) != 0);

    // NIP-040: the legacy marker stays invalid after the fork
    {
        CMutableTransaction legacy;
        legacy.vin.emplace_back(holderOut);
        CAssetTransfer transfer(ASSET, 10 * COIN);
        CScript script = GetScriptForDestination(DecodeDestination(recipientAddr));
        transfer.ConstructTransaction(script, AssetMarker::LEGACY_RVN);
        legacy.vout.emplace_back(0, script);
        Sign(legacy);
        BOOST_CHECK(!Verdict(legacy, reason));
        BOOST_CHECK_EQUAL(reason, "bad-txns-legacy-asset-marker-after-nip040");
    }

    // CLOSE
    op = StateOp(ownerOut, 0);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(!Verdict(HolderTransfer(holderOut, 10 * COIN, recipientAddr), reason));
    BOOST_CHECK(reason.find(kNotByOwner) == 0);

    // OPEN -> SEALED is not a transition: close first
    op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_CHECK(!Verdict(StateOp(ownerOut, 2), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-seal-requires-closed");
    BOOST_CHECK(!Mine({StateOp(ownerOut, 2)}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    op = StateOp(ownerOut, 0);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);

    // SEAL from CLOSED; then nothing else is ever accepted
    op = StateOp(ownerOut, 2);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::SEALED);
    BOOST_CHECK(!Verdict(HolderTransfer(holderOut, 10 * COIN, recipientAddr), reason));
    BOOST_CHECK(reason.find(kNotByOwner) == 0);

    for (int flag : {0, 1, 2}) {
        BOOST_CHECK(!Verdict(StateOp(ownerOut, flag), reason));
        BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-sealed");
        BOOST_CHECK(!BlockVerdict({StateOp(ownerOut, flag)}, reason));
        BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-sealed");
    }
    BOOST_CHECK(!Mine({StateOp(ownerOut, 1)}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::SEALED);

    // The owner can still move the asset with the escort on a sealed asset
    {
        CMutableTransaction escorted;
        escorted.vin.emplace_back(holderOut);
        escorted.vin.emplace_back(ownerOut);
        escorted.vout.emplace_back(0, TransferScript(ASSET, 10 * COIN, recipientAddr));
        escorted.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
        Sign(escorted);
        BOOST_CHECK_MESSAGE(Verdict(escorted, reason), reason);
    }
}

// (5) While OPEN, an unescorted move from an address the owner froze or
// that revoked itself is rejected; the owner, escorting &X!, moves it from
// a frozen address regardless.
BOOST_AUTO_TEST_CASE(restricted_inputs_while_open)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint frozenOut = Seed(IssuanceScript(ASSET, 3 * COIN, holderAddr));
    const COutPoint revokedOut = Seed(IssuanceScript(ASSET, 4 * COIN, holder2Addr));

    CMutableTransaction op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_REQUIRE_EQUAL((int)State(), (int)DepinTransferState::OPEN);

    // Owner freezes holderAddr
    {
        CMutableTransaction freeze;
        freeze.vin.emplace_back(ownerOut);
        freeze.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
        freeze.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
        Sign(freeze);
        BOOST_REQUIRE(Mine({freeze}));
        ownerOut = COutPoint(freeze.GetHash(), 0);
    }
    BOOST_REQUIRE(passets->CheckForDEPINRestriction(ASSET, holderAddr));

    // holder2Addr revokes itself (a self-relocation with the flag-1 null data)
    {
        CMutableTransaction revoke;
        revoke.vin.emplace_back(revokedOut);
        revoke.vout.emplace_back(0, TransferScript(ASSET, 4 * COIN, holder2Addr));
        revoke.vout.emplace_back(0, NullDataScript(ASSET, 1, holder2Addr));
        Sign(revoke);
        BOOST_CHECK_MESSAGE(Verdict(revoke, reason), reason);
        BOOST_REQUIRE(Mine({revoke}));
    }
    BOOST_REQUIRE(passets->CheckForDEPINRestriction(ASSET, holder2Addr));
    const COutPoint revokedNow = Seed(TransferScript(ASSET, 4 * COIN, holder2Addr));

    BOOST_CHECK(!Verdict(HolderTransfer(frozenOut, 3 * COIN, recipientAddr), reason));
    BOOST_CHECK_EQUAL(reason, kFromRestricted);
    BOOST_CHECK(!Verdict(HolderTransfer(revokedNow, 4 * COIN, recipientAddr), reason));
    BOOST_CHECK_EQUAL(reason, kFromRestricted);
    BOOST_CHECK(!Mine({HolderTransfer(frozenOut, 3 * COIN, recipientAddr)}));

    // A clean address still moves freely
    const COutPoint cleanOut = Seed(TransferScript(ASSET, 2 * COIN, recipientAddr));
    BOOST_CHECK_MESSAGE(Verdict(HolderTransfer(cleanOut, 2 * COIN, holderAddr), reason), reason);

    // The owner recovers from the frozen address with the escort
    {
        CMutableTransaction escorted;
        escorted.vin.emplace_back(frozenOut);
        escorted.vin.emplace_back(ownerOut);
        escorted.vout.emplace_back(0, TransferScript(ASSET, 3 * COIN, recipientAddr));
        escorted.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
        Sign(escorted);
        BOOST_CHECK_MESSAGE(Verdict(escorted, reason), reason);
        BOOST_REQUIRE(Mine({escorted}));
    }
}

// (6) Self-revocation keeps its guarantees in every state: the valid form
// is accepted, and while OPEN a self-revocation null data attached to a
// transfer elsewhere, or naming another address, is rejected.
BOOST_AUTO_TEST_CASE(self_revocation_in_each_state)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));

    auto validRevoke = [&](const COutPoint& out, CAmount amount, const std::string& addr) {
        CMutableTransaction mut;
        mut.vin.emplace_back(out);
        mut.vout.emplace_back(0, TransferScript(ASSET, amount, addr));
        mut.vout.emplace_back(0, NullDataScript(ASSET, 1, addr));
        Sign(mut);
        return mut;
    };

    // CLOSED
    BOOST_CHECK_MESSAGE(Verdict(validRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr), reason), reason);

    // OPEN
    CMutableTransaction op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_CHECK_MESSAGE(Verdict(validRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr), reason), reason);
    {
        // Transfer to another address with a self-revocation attached
        CMutableTransaction mut;
        mut.vin.emplace_back(Seed(IssuanceScript(ASSET, COIN, holderAddr)));
        mut.vout.emplace_back(0, TransferScript(ASSET, COIN, recipientAddr));
        mut.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
        Sign(mut);
        BOOST_CHECK(!Verdict(mut, reason));
        BOOST_CHECK(reason.find(kNotByOwner) == 0);
    }
    {
        // Self-transfer, but the null data names an address that does not spend
        CMutableTransaction mut;
        mut.vin.emplace_back(Seed(IssuanceScript(ASSET, COIN, holderAddr)));
        mut.vout.emplace_back(0, TransferScript(ASSET, COIN, holderAddr));
        mut.vout.emplace_back(0, NullDataScript(ASSET, 1, recipientAddr));
        Sign(mut);
        BOOST_CHECK(!Verdict(mut, reason));
        BOOST_CHECK(reason.find(kNotByOwner) == 0);
    }
    {
        // A holder cannot un-revoke (flag 0) while moving the asset
        CMutableTransaction mut;
        mut.vin.emplace_back(Seed(IssuanceScript(ASSET, COIN, holderAddr)));
        mut.vout.emplace_back(0, TransferScript(ASSET, COIN, holderAddr));
        mut.vout.emplace_back(0, NullDataScript(ASSET, 0, holderAddr));
        Sign(mut);
        BOOST_CHECK(!Verdict(mut, reason));
        BOOST_CHECK(reason.find(kNotByOwner) == 0);
    }

    // SEALED (via CLOSE)
    op = StateOp(ownerOut, 0);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    op = StateOp(ownerOut, 2);
    BOOST_REQUIRE(Mine({op}));
    BOOST_REQUIRE_EQUAL((int)State(), (int)DepinTransferState::SEALED);
    BOOST_CHECK_MESSAGE(Verdict(validRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr), reason), reason);
}

// (7) Snapshot semantics inside a block, both directions: an OPEN and a
// holder transfer in the same block reject the transfer (it sees CLOSED); a
// CLOSE and a holder transfer in the same block accept it (it sees OPEN).
BOOST_AUTO_TEST_CASE(same_block_snapshot_semantics)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, 10 * COIN, holderAddr));

    // Transaction level: a pending OPEN in the cache being built is not seen
    {
        CAssetsCache building;
        building.AddDepinTransferState(ASSET, DepinTransferState::OPEN);
        CCoinsViewCache view(pcoinsTip);
        CValidationState state;
        std::vector<std::pair<std::string, uint256>> vReissue;
        BOOST_CHECK(!Consensus::CheckTxAssets(CTransaction(HolderTransfer(holderOut, 10 * COIN, recipientAddr)), state, view,
                                              &building, chainActive.Height() + 1, false, vReissue, true, nullptr, 0, nullptr));
        BOOST_CHECK(state.GetRejectReason().find(kNotByOwner) == 0);
    }

    // Block level: [OPEN, holder transfer] is invalid as a whole
    CMutableTransaction open = StateOp(ownerOut, 1);
    BOOST_CHECK(!BlockVerdict({open, HolderTransfer(holderOut, 10 * COIN, recipientAddr)}, reason));
    BOOST_CHECK(reason.find(kNotByOwner) == 0);
    BOOST_CHECK(!Mine({open, HolderTransfer(holderOut, 10 * COIN, recipientAddr)}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);

    // OPEN alone, then [CLOSE, holder transfer] is valid: the transfer sees OPEN
    BOOST_REQUIRE(Mine({open}));
    ownerOut = COutPoint(open.GetHash(), 0);
    BOOST_REQUIRE_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    CMutableTransaction close = StateOp(ownerOut, 0);
    BOOST_CHECK_MESSAGE(BlockVerdict({close, HolderTransfer(holderOut, 10 * COIN, recipientAddr)}, reason), reason);
    BOOST_REQUIRE(Mine({close, HolderTransfer(holderOut, 10 * COIN, recipientAddr)}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(pcoinsTip->AccessCoin(holderOut).IsSpent());
}

// (10) Two operations on the same asset in one block invalidate the whole
// block, through the fJustCheck path (TestBlockValidity) without touching
// the asset cache or the UTXO set, and through ProcessNewBlock.
BOOST_AUTO_TEST_CASE(two_state_operations_in_one_block_invalidate_it)
{
    std::string reason;
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));

    // OPEN and SEAL are both valid from CLOSED on their own; chained so the
    // second spends the owner output of the first.
    CMutableTransaction open = StateOp(ownerOut, 1);
    std::map<COutPoint, CTxOut> extra = {{COutPoint(open.GetHash(), 0), open.vout[0]}};
    CMutableTransaction seal = StateOp(COutPoint(open.GetHash(), 0), 2, extra);

    BOOST_CHECK_MESSAGE(Verdict(open, reason), reason);
    BOOST_CHECK_MESSAGE(Verdict(seal, reason, extra), reason);

    BOOST_CHECK(!BlockVerdict({open, seal}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-multiple-changes-per-block");
    BOOST_CHECK(passets->setNewDepinStateToAdd.empty());
    BOOST_CHECK(!pcoinsTip->AccessCoin(ownerOut).IsSpent());
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);

    const int nHeight = chainActive.Height();
    BOOST_CHECK(!Mine({open, seal}));
    BOOST_CHECK_EQUAL(chainActive.Height(), nHeight);
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(!pcoinsTip->AccessCoin(ownerOut).IsSpent());

    // Either one alone is fine
    BOOST_CHECK_MESSAGE(BlockVerdict({open}, reason), reason);
    BOOST_REQUIRE(Mine({open}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
}

// (8) Reorg and persistence: after every transition the block is
// disconnected and the previous state comes back, in the cache, in the LRU
// and in the database; two operations in consecutive blocks undo in reverse.
BOOST_AUTO_TEST_CASE(reorg_restores_previous_state_and_persists)
{
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));

    auto dbState = [&]() {
        int8_t v = 0;
        return prestricteddb->ReadDepinTransferState(ASSET, v) ? (int)v : (int)DepinTransferState::CLOSED;
    };
    auto lruAgrees = [&]() {
        if (!passetsDepinTransferStateCache->Exists(ASSET))
            return true; // absent is allowed; present must agree with the database
        return (int)passetsDepinTransferStateCache->Get(ASSET) == dbState();
    };

    // OPEN, persist, undo, persist
    CMutableTransaction op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(dbState(), (int)DepinTransferState::OPEN);
    BOOST_CHECK(lruAgrees());
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    UndoTip();
    mempool.clear();
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(dbState(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(lruAgrees());
    BOOST_CHECK(!pcoinsTip->AccessCoin(ownerOut).IsSpent());

    // OPEN again (new block at the same height), then CLOSE, undo CLOSE
    op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    op = StateOp(ownerOut, 0);
    BOOST_REQUIRE(Mine({op}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(dbState(), (int)DepinTransferState::CLOSED);
    UndoTip();
    mempool.clear();
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(dbState(), (int)DepinTransferState::OPEN);
    BOOST_CHECK(lruAgrees());

    // CLOSE, SEAL, undo SEAL (-> CLOSED), undo CLOSE (-> OPEN)
    op = StateOp(ownerOut, 0);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    op = StateOp(ownerOut, 2);
    BOOST_REQUIRE(Mine({op}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::SEALED);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(dbState(), (int)DepinTransferState::SEALED);
    UndoTip();
    mempool.clear();
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    UndoTip();
    mempool.clear();
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(dbState(), (int)DepinTransferState::OPEN);
    BOOST_CHECK(lruAgrees());

    // Holder transfers validate again according to the restored state
    std::string reason;
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    BOOST_CHECK_MESSAGE(Verdict(HolderTransfer(holderOut, COIN, recipientAddr), reason), reason);
}

// (11) Mempool: holder transfers are tracked from the mempool view (an
// input from an unconfirmed ancestor counts), one pending state operation
// per asset (a chained second one is rejected without being inserted, also
// under test_accept; conflicts are always rejected), and a connected CLOSE
// evicts the holder transfers and leaves no references behind.
BOOST_AUTO_TEST_CASE(mempool_bookkeeping_and_eviction)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, 10 * COIN, holderAddr));

    CMutableTransaction op = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({op}));
    ownerOut = COutPoint(op.GetHash(), 0);
    BOOST_REQUIRE_EQUAL((int)State(), (int)DepinTransferState::OPEN);

    // Holder transfer A, then B spending A's unconfirmed output
    CMutableTransaction a = HolderTransfer(holderOut, 10 * COIN, recipientAddr);
    BOOST_REQUIRE_MESSAGE(ToMempool(a, reason), reason);
    BOOST_CHECK_EQUAL(HolderTransfersTracked(), 1U);
    std::map<COutPoint, CTxOut> extra = {{COutPoint(a.GetHash(), 0), a.vout[0]}};
    CMutableTransaction b = HolderTransfer(COutPoint(a.GetHash(), 0), 10 * COIN, holder2Addr, extra);
    BOOST_REQUIRE_MESSAGE(ToMempool(b, reason), reason);
    BOOST_CHECK_EQUAL(HolderTransfersTracked(), 2U);

    // An escorted move by the owner is not a holder transfer
    const COutPoint ownerHeld = Seed(IssuanceScript(ASSET, COIN, ownerAddr));
    CMutableTransaction escorted;
    escorted.vin.emplace_back(ownerHeld);
    escorted.vin.emplace_back(ownerOut);
    escorted.vout.emplace_back(0, TransferScript(ASSET, COIN, recipientAddr));
    escorted.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    Sign(escorted);
    BOOST_REQUIRE_MESSAGE(ToMempool(escorted, reason), reason);
    BOOST_CHECK_EQUAL(HolderTransfersTracked(), 2U);
    ownerOut = COutPoint(escorted.GetHash(), 1);
    extra[ownerOut] = escorted.vout[1];

    // CLOSE pending; a chained second CLOSE (spending its owner output --
    // the only operation the tip snapshot, still OPEN, would accept) is
    // rejected and never inserted, with test_accept and for real
    CMutableTransaction close = StateOp(ownerOut, 0, extra);
    BOOST_REQUIRE_MESSAGE(ToMempool(close, reason), reason);
    BOOST_CHECK_EQUAL(StateOpsTracked(), 1U);
    std::map<COutPoint, CTxOut> extra2 = {{COutPoint(close.GetHash(), 0), close.vout[0]}};
    CMutableTransaction chained = StateOp(COutPoint(close.GetHash(), 0), 0, extra2);
    BOOST_CHECK(!ToMempool(chained, reason, true));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-change-already-in-mempool");
    BOOST_CHECK(!ToMempool(chained, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-change-already-in-mempool");
    BOOST_CHECK(!mempool.exists(chained.GetHash()));
    BOOST_CHECK_EQUAL(StateOpsTracked(), 1U);

    // Mining the CLOSE (with the escorted move it spends from) evicts A and
    // B and leaves no bookkeeping behind
    BOOST_REQUIRE(Mine({escorted, close}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(!mempool.exists(a.GetHash()));
    BOOST_CHECK(!mempool.exists(b.GetHash()));
    BOOST_CHECK(!mempool.exists(escorted.GetHash()));
    BOOST_CHECK(!mempool.exists(close.GetHash()));
    BOOST_CHECK_EQUAL(HolderTransfersTracked(), 0U);
    BOOST_CHECK_EQUAL(StateOpsTracked(), 0U);
    {
        LOCK(mempool.cs);
        BOOST_CHECK(mempool.mapHashDepinHolderTransfers.empty());
        BOOST_CHECK(mempool.mapHashDepinStateChanges.empty());
    }
    mempool.clear();

    // A holder transfer cannot enter the mempool while CLOSED
    const COutPoint holderOut2 = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    BOOST_CHECK(!ToMempool(HolderTransfer(holderOut2, COIN, recipientAddr), reason));
    BOOST_CHECK(reason.find(kNotByOwner) == 0);
}

// (11b) A pending asset operation cannot be replaced. Transaction replacement
// was removed: a conflicting operation is rejected even with the same owner
// input and a higher fee, and a replaceability signal is rejected by the
// no-RBF sequence rule. A disconnected OPEN evicts holder transfers that were
// admitted on the strength of it.
BOOST_AUTO_TEST_CASE(mempool_replacement_and_reorg_eviction)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, 10 * COIN, holderAddr));

    // Fees come from a mature coinbase
    const COutPoint coinbaseOut(coinbaseTxns[0].GetHash(), 0);
    const CAmount coinbaseValue = coinbaseTxns[0].vout[0].nValue;
    auto feeOp = [&](int flag, CAmount fee, uint32_t nSequence) {
        CMutableTransaction mut;
        mut.vin.emplace_back(ownerOut, CScript(), nSequence);
        mut.vin.emplace_back(coinbaseOut, CScript(), nSequence);
        mut.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
        mut.vout.emplace_back(0, StateScript(ASSET, flag));
        mut.vout.emplace_back(coinbaseValue - fee, GetScriptForDestination(coinbaseKey.GetPubKey().GetID()));
        Sign(mut);
        return mut;
    };

    CMutableTransaction first = feeOp(1, COIN, CTxIn::SEQUENCE_FINAL - 1);
    BOOST_REQUIRE_MESSAGE(ToMempool(first, reason), reason);
    BOOST_CHECK_EQUAL(StateOpsTracked(), 1U);

    CMutableTransaction conflicting = feeOp(2, 2 * COIN, CTxIn::SEQUENCE_FINAL - 1);
    BOOST_CHECK(!ToMempool(conflicting, reason, true));
    BOOST_CHECK_EQUAL(reason, "txn-mempool-conflict");
    BOOST_CHECK(!ToMempool(conflicting, reason));
    BOOST_CHECK_EQUAL(reason, "txn-mempool-conflict");
    CMutableTransaction signaling = feeOp(2, 2 * COIN, 0xfffffffd);
    BOOST_CHECK(!ToMempool(signaling, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-rbf-sequence");
    BOOST_CHECK(mempool.exists(first.GetHash()));
    BOOST_CHECK(!mempool.exists(conflicting.GetHash()));
    BOOST_CHECK(!mempool.exists(signaling.GetHash()));
    BOOST_CHECK_EQUAL(StateOpsTracked(), 1U);
    mempool.clear();

    // OPEN mined, a holder transfer admitted and a CLOSE pending on the
    // OPEN's owner output, then the OPEN is disconnected
    CMutableTransaction open = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({open}));
    CMutableTransaction a = HolderTransfer(holderOut, 10 * COIN, recipientAddr);
    BOOST_REQUIRE_MESSAGE(ToMempool(a, reason), reason);
    BOOST_CHECK_EQUAL(HolderTransfersTracked(), 1U);
    CMutableTransaction pendingClose = StateOp(COutPoint(open.GetHash(), 0), 0);
    BOOST_REQUIRE_MESSAGE(ToMempool(pendingClose, reason), reason);
    BOOST_CHECK_EQUAL(StateOpsTracked(), 1U);
    UndoTip();
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::CLOSED);
    BOOST_CHECK(!mempool.exists(a.GetHash()));
    BOOST_CHECK_EQUAL(HolderTransfersTracked(), 0U);
    // The OPEN itself was resurrected (still a valid transition from CLOSED)
    // even though its own child was pending under the same asset when it
    // came back; the child, a CLOSE from CLOSED, was dropped instead
    BOOST_CHECK(mempool.exists(open.GetHash()));
    BOOST_CHECK(!mempool.exists(pendingClose.GetHash()));
    BOOST_CHECK_EQUAL(StateOpsTracked(), 1U);
    mempool.clear();
}

// (3) Activation frontier in blocks and in the mempool: H-1 rejects, H accepts.
BOOST_AUTO_TEST_CASE(activation_frontier_in_blocks)
{
    std::string reason;
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const int H = chainActive.Height() + 3;
    DepinStateHeightGuard guard(H);

    // Next block is H-2
    BOOST_CHECK(!Verdict(StateOp(ownerOut, 1), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-before-activation");
    BOOST_CHECK(!BlockVerdict({StateOp(ownerOut, 1)}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-before-activation");
    BOOST_CHECK(!Mine({StateOp(ownerOut, 1)}));
    BOOST_REQUIRE(Mine({}));

    // Next block is H-1
    BOOST_CHECK(!ToMempool(StateOp(ownerOut, 1), reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-depin-state-before-activation");
    BOOST_CHECK(!Mine({StateOp(ownerOut, 1)}));
    BOOST_REQUIRE(Mine({}));

    // Next block is H
    BOOST_CHECK_EQUAL(chainActive.Height() + 1, H);
    BOOST_CHECK_MESSAGE(Verdict(StateOp(ownerOut, 1), reason), reason);
    BOOST_CHECK_MESSAGE(ToMempool(StateOp(ownerOut, 1), reason, true), reason);
    BOOST_REQUIRE(Mine({StateOp(ownerOut, 1)}));
    BOOST_CHECK_EQUAL((int)State(), (int)DepinTransferState::OPEN);
}

// Regressions from an external review of DEPIN freezes and self-revocations:
// cache-dependent verdicts, inexact undo and stale mempool entries.
BOOST_AUTO_TEST_CASE(review_self_restriction_cache_cannot_change_owner_freeze_verdict)
{
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(holderAddr, ASSET));
    BOOST_REQUIRE(!passets->CheckForAddressRestriction(ASSET, holderAddr));
    std::string coldError, warmError;
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    CMutableTransaction freeze;
    freeze.vin.emplace_back(ownerOut);
    freeze.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    freeze.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
    Sign(freeze);
    const bool cold = Verdict(freeze, coldError);
    BOOST_REQUIRE(passets->CheckForDEPINSelfRestriction(ASSET, holderAddr));
    const bool warm = Verdict(freeze, warmError);
    BOOST_CHECK_MESSAGE(cold == warm, "cache changed consensus verdict: cold=" << cold << " warm=" << warm << " error=" << warmError);
    BOOST_CHECK_MESSAGE(!passets->CheckForAddressRestriction(ASSET, holderAddr), "self revocation became an owner freeze through the shared LRU");
}

BOOST_AUTO_TEST_CASE(review_persisted_self_revoke_is_undone_immediately)
{
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    CMutableTransaction revoke;
    revoke.vin.emplace_back(holderOut);
    revoke.vout.emplace_back(0, TransferScript(ASSET, COIN, holderAddr));
    revoke.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
    Sign(revoke);
    BOOST_REQUIRE(Mine({revoke}));
    FlushStateToDisk();
    BOOST_REQUIRE(prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
    UndoTip();
    mempool.clear();
    BOOST_CHECK_MESSAGE(!passets->CheckForDEPINSelfRestriction(ASSET, holderAddr), "persisted self revocation survived its block disconnect before a disk flush");
    FlushStateToDisk();
    BOOST_CHECK(!passets->CheckForDEPINSelfRestriction(ASSET, holderAddr));
}

BOOST_AUTO_TEST_CASE(review_undo_unfreeze_preserves_owner_only_restriction)
{
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    CMutableTransaction freeze;
    freeze.vin.emplace_back(ownerOut);
    freeze.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    freeze.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
    Sign(freeze);
    BOOST_REQUIRE(Mine({freeze}));
    ownerOut = COutPoint(freeze.GetHash(), 0);
    FlushStateToDisk();
    BOOST_REQUIRE(prestricteddb->ReadRestrictedAddress(holderAddr, ASSET));
    BOOST_REQUIRE(!prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
    CMutableTransaction unfreeze;
    unfreeze.vin.emplace_back(ownerOut);
    unfreeze.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    unfreeze.vout.emplace_back(0, NullDataScript(ASSET, 0, holderAddr));
    Sign(unfreeze);
    BOOST_REQUIRE(Mine({unfreeze}));
    FlushStateToDisk();
    BOOST_REQUIRE(!passets->CheckForDEPINRestriction(ASSET, holderAddr));
    UndoTip();
    mempool.clear();
    FlushStateToDisk();
    BOOST_CHECK(prestricteddb->ReadRestrictedAddress(holderAddr, ASSET));
    BOOST_CHECK_MESSAGE(!prestricteddb->ReadSelfRestriction(holderAddr, ASSET), "undo of an owner-only unfreeze invented a self revocation");
    UndoTip();
    mempool.clear();
    FlushStateToDisk();
    BOOST_CHECK_MESSAGE(!passets->CheckForDEPINRestriction(ASSET, holderAddr), "address is still blocked after undoing both freeze and unfreeze");
}

BOOST_AUTO_TEST_CASE(review_undo_unfreeze_preserves_self_only_restriction)
{
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    CMutableTransaction revoke;
    revoke.vin.emplace_back(holderOut);
    revoke.vout.emplace_back(0, TransferScript(ASSET, COIN, holderAddr));
    revoke.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
    Sign(revoke);
    BOOST_REQUIRE(Mine({revoke}));
    FlushStateToDisk();
    BOOST_REQUIRE(!prestricteddb->ReadRestrictedAddress(holderAddr, ASSET));
    BOOST_REQUIRE(prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
    CMutableTransaction unfreeze;
    unfreeze.vin.emplace_back(ownerOut);
    unfreeze.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    unfreeze.vout.emplace_back(0, NullDataScript(ASSET, 0, holderAddr));
    Sign(unfreeze);
    BOOST_REQUIRE(Mine({unfreeze}));
    FlushStateToDisk();
    BOOST_REQUIRE(!passets->CheckForDEPINRestriction(ASSET, holderAddr));
    UndoTip();
    mempool.clear();
    FlushStateToDisk();
    BOOST_CHECK_MESSAGE(!prestricteddb->ReadRestrictedAddress(holderAddr, ASSET), "undo of a self-only unfreeze invented an owner freeze");
    BOOST_CHECK(prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
}

BOOST_AUTO_TEST_CASE(review_freeze_evicts_pending_open_holder_transfer)
{
    // Observe the stale entry rather than aborting in the fixture's sanity check.
    mempool.setSanityCheck(0.0);
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    const CMutableTransaction open = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({open}));
    ownerOut = COutPoint(open.GetHash(), 0);
    const CMutableTransaction move = HolderTransfer(holderOut, COIN, recipientAddr);
    std::string reason;
    BOOST_REQUIRE_MESSAGE(ToMempool(move, reason), reason);
    BOOST_REQUIRE(mempool.exists(move.GetHash()));
    CMutableTransaction freeze;
    freeze.vin.emplace_back(ownerOut);
    freeze.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    freeze.vout.emplace_back(0, NullDataScript(ASSET, 1, holderAddr));
    Sign(freeze);
    BOOST_REQUIRE(Mine({freeze}));
    BOOST_REQUIRE(passets->CheckForDEPINRestriction(ASSET, holderAddr));
    BOOST_CHECK_MESSAGE(!mempool.exists(move.GetHash()), "confirmed freeze left a now-invalid holder transfer in the mempool");
}

// Two operations on one address inside a block keep the result they have
// always had, and undoing the block restores the state before it exactly.
BOOST_AUTO_TEST_CASE(same_block_successive_restrictions_undo_exactly)
{
    std::string reason;
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    BOOST_REQUIRE(Mine({SelfRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr)}));
    BOOST_REQUIRE(SelfRevoked(holderAddr) && !OwnerFrozen(holderAddr));

    // Both are judged against the tip: the freeze because the owner has not
    // frozen the address, the unfreeze because the address is self-revoked
    const CMutableTransaction freeze = OwnerRestriction(ownerOut, 1, holderAddr);
    const COutPoint freezeOwnerOut(freeze.GetHash(), 0);
    const CMutableTransaction unfreeze = OwnerRestriction(freezeOwnerOut, 0, holderAddr, {{freezeOwnerOut, freeze.vout[0]}});
    BOOST_REQUIRE_MESSAGE(BlockVerdict({freeze, unfreeze}, reason), reason);
    BOOST_REQUIRE(Mine({freeze, unfreeze}));
    // The unfreeze, applied last, clears both kinds
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(!SelfRevoked(holderAddr));

    UndoTip();
    mempool.clear();
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(SelfRevoked(holderAddr));
    FlushStateToDisk();
    BOOST_CHECK(!prestricteddb->ReadRestrictedAddress(holderAddr, ASSET));
    BOOST_CHECK(prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
}

// A self-revoked address frozen and unfrozen in one block, in both orders: the
// result follows the order, the undo restores the self-revocation only.
BOOST_AUTO_TEST_CASE(same_block_order_and_exact_undo)
{
    std::string reason;
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    BOOST_REQUIRE(Mine({SelfRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr)}));
    BOOST_REQUIRE(SelfRevoked(holderAddr) && !OwnerFrozen(holderAddr));

    // Unfreeze first: it clears the self-revocation, then the freeze stays
    const CMutableTransaction unfreeze = OwnerRestriction(ownerOut, 0, holderAddr);
    const COutPoint unfreezeOwnerOut(unfreeze.GetHash(), 0);
    const CMutableTransaction freeze = OwnerRestriction(unfreezeOwnerOut, 1, holderAddr, {{unfreezeOwnerOut, unfreeze.vout[0]}});
    BOOST_REQUIRE_MESSAGE(BlockVerdict({unfreeze, freeze}, reason), reason);
    BOOST_REQUIRE(Mine({unfreeze, freeze}));
    BOOST_CHECK(OwnerFrozen(holderAddr));
    BOOST_CHECK(!SelfRevoked(holderAddr));
    UndoTip();
    mempool.clear();
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(SelfRevoked(holderAddr));

    // Freeze first: the unfreeze, applied last, clears both
    const CMutableTransaction freeze2 = OwnerRestriction(ownerOut, 1, holderAddr);
    const COutPoint freezeOwnerOut(freeze2.GetHash(), 0);
    const CMutableTransaction unfreeze2 = OwnerRestriction(freezeOwnerOut, 0, holderAddr, {{freezeOwnerOut, freeze2.vout[0]}});
    BOOST_REQUIRE(Mine({freeze2, unfreeze2}));
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(!SelfRevoked(holderAddr));
    UndoTip();
    mempool.clear();
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(SelfRevoked(holderAddr));
}

// Frozen and self-revoked: the unfreeze clears both, its undo brings both back.
BOOST_AUTO_TEST_CASE(undo_unfreeze_restores_both_restrictions)
{
    const CMutableTransaction freeze = OwnerRestriction(Seed(OwnerTransferScript(ownerAddr)), 1, holderAddr);
    BOOST_REQUIRE(Mine({freeze, SelfRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr)}));
    FlushStateToDisk();
    BOOST_REQUIRE(OwnerFrozen(holderAddr) && SelfRevoked(holderAddr));

    BOOST_REQUIRE(Mine({OwnerRestriction(COutPoint(freeze.GetHash(), 0), 0, holderAddr)}));
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(!SelfRevoked(holderAddr));
    UndoTip();
    mempool.clear();
    BOOST_CHECK(OwnerFrozen(holderAddr));
    BOOST_CHECK(SelfRevoked(holderAddr));
    FlushStateToDisk();
    BOOST_CHECK(prestricteddb->ReadRestrictedAddress(holderAddr, ASSET));
    BOOST_CHECK(prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
}

// The record lists exactly the pairs the block changes, each once.
BOOST_AUTO_TEST_CASE(several_addresses_in_one_block_undo_exactly)
{
    const CMutableTransaction freeze = OwnerRestriction(Seed(OwnerTransferScript(ownerAddr)), 1, holderAddr);
    const CMutableTransaction revoke = SelfRevoke(Seed(IssuanceScript(ASSET, COIN, holder2Addr)), COIN, holder2Addr);
    BOOST_REQUIRE(Mine({freeze, revoke}));
    BOOST_CHECK(OwnerFrozen(holderAddr) && !SelfRevoked(holderAddr));
    BOOST_CHECK(!OwnerFrozen(holder2Addr) && SelfRevoked(holder2Addr));

    std::vector<CDepinRestrictionUndo> undo;
    BOOST_REQUIRE(passetsdb->ReadBlockUndoDepinRestrictions(chainActive.Tip()->GetBlockHash(), undo));
    std::set<std::string> addresses;
    for (const auto& item : undo) {
        BOOST_CHECK_EQUAL(item.assetName, ASSET);
        BOOST_CHECK(!item.fOwnerFrozen && !item.fSelfRevoked);
        addresses.insert(item.address);
    }
    BOOST_CHECK_EQUAL(undo.size(), 2U);
    BOOST_CHECK(addresses == std::set<std::string>({holderAddr, holder2Addr}));

    UndoTip();
    mempool.clear();
    for (const std::string& addr : {holderAddr, holder2Addr}) {
        BOOST_CHECK(!OwnerFrozen(addr));
        BOOST_CHECK(!SelfRevoked(addr));
    }
}

// Without a record that lists exactly the block's pairs the block is not
// disconnected, and nothing is restored by default.
BOOST_AUTO_TEST_CASE(missing_or_corrupt_restriction_undo_refuses_disconnect)
{
    BOOST_REQUIRE(Mine({OwnerRestriction(Seed(OwnerTransferScript(ownerAddr)), 1, holderAddr)}));
    const uint256 hash = chainActive.Tip()->GetBlockHash();
    // Key of BLOCK_DEPIN_RESTRICTION_UNDO_DATA in assetdb.cpp
    const auto key = std::make_pair('D', hash);
    std::vector<CDepinRestrictionUndo> good;
    BOOST_REQUIRE(passetsdb->ReadBlockUndoDepinRestrictions(hash, good));
    BOOST_REQUIRE_EQUAL(good.size(), 1U);

    auto disconnectRefused = [&]() {
        CValidationState state;
        bool ok;
        {
            LOCK(cs_main);
            ok = InvalidateBlock(state, GetParams(), chainActive.Tip());
        }
        return !ok && chainActive.Tip()->GetBlockHash() == hash && OwnerFrozen(holderAddr);
    };

    BOOST_REQUIRE(passetsdb->Erase(key));
    BOOST_CHECK_MESSAGE(disconnectRefused(), "missing record");

    BOOST_REQUIRE(passetsdb->Write(key, std::string("not a restriction undo record")));
    BOOST_CHECK_MESSAGE(disconnectRefused(), "unreadable record");

    BOOST_REQUIRE(passetsdb->WriteBlockUndoDepinRestrictions(hash, {}));
    BOOST_CHECK_MESSAGE(disconnectRefused(), "record without the block's pair");

    BOOST_REQUIRE(passetsdb->WriteBlockUndoDepinRestrictions(hash, {good[0], good[0]}));
    BOOST_CHECK_MESSAGE(disconnectRefused(), "record listing the pair twice");

    BOOST_REQUIRE(passetsdb->WriteBlockUndoDepinRestrictions(hash, good));
    UndoTip();
    mempool.clear();
    BOOST_CHECK(!OwnerFrozen(holderAddr));
}

// The record is written on every real connection, so a rebuilt chainstate gets
// it back; a TestBlockValidity check computes it without writing it.
BOOST_AUTO_TEST_CASE(restriction_undo_written_on_every_connection)
{
    const CMutableTransaction freeze = OwnerRestriction(Seed(OwnerTransferScript(ownerAddr)), 1, holderAddr);
    std::vector<CDepinRestrictionUndo> undo;

    const CBlock checked = BuildBlock({freeze});
    {
        CValidationState state;
        LOCK(cs_main);
        BOOST_REQUIRE(TestBlockValidity(state, GetParams(), checked, chainActive.Tip(), false, true));
    }
    BOOST_CHECK(!passetsdb->ReadBlockUndoDepinRestrictions(checked.GetHash(), undo));

    BOOST_REQUIRE(Mine({freeze}));
    CBlockIndex* pindex = chainActive.Tip();
    UndoTip();
    mempool.clear();
    // As -reindex-chainstate does, wipe the record while the block undo stays
    BOOST_REQUIRE(passetsdb->Erase(std::make_pair('D', pindex->GetBlockHash())));
    {
        LOCK(cs_main);
        ResetBlockFailureFlags(pindex);
    }
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
    BOOST_REQUIRE(chainActive.Tip() == pindex);
    BOOST_CHECK(passetsdb->ReadBlockUndoDepinRestrictions(pindex->GetBlockHash(), undo));
    BOOST_CHECK(OwnerFrozen(holderAddr));
    UndoTip();
    mempool.clear();
    BOOST_CHECK(!OwnerFrozen(holderAddr));
}

// Undo entries pending a flush, across several disconnected blocks.
BOOST_AUTO_TEST_CASE(several_disconnects_before_a_flush)
{
    const COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    BOOST_REQUIRE(Mine({SelfRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr)}));
    FlushStateToDisk();
    const CMutableTransaction unfreeze = OwnerRestriction(ownerOut, 0, holderAddr);
    BOOST_REQUIRE(Mine({unfreeze}));
    BOOST_REQUIRE(Mine({OwnerRestriction(COutPoint(unfreeze.GetHash(), 0), 1, holderAddr)}));
    BOOST_REQUIRE(OwnerFrozen(holderAddr) && !SelfRevoked(holderAddr));

    UndoTip();
    UndoTip();
    mempool.clear();
    BOOST_CHECK(!OwnerFrozen(holderAddr));
    BOOST_CHECK(SelfRevoked(holderAddr));
    UndoTip();
    mempool.clear();
    BOOST_CHECK(!SelfRevoked(holderAddr));
    FlushStateToDisk();
    BOOST_CHECK(!prestricteddb->ReadSelfRestriction(holderAddr, ASSET));
    BOOST_CHECK(!prestricteddb->ReadRestrictedAddress(holderAddr, ASSET));
}

// The unfreeze counterpart of the first review regression.
BOOST_AUTO_TEST_CASE(self_restriction_cache_cannot_change_owner_unfreeze_verdict)
{
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(holderAddr, ASSET));
    const CMutableTransaction unfreeze = OwnerRestriction(Seed(OwnerTransferScript(ownerAddr)), 0, holderAddr);
    std::string coldError, warmError;
    const bool cold = Verdict(unfreeze, coldError);
    BOOST_REQUIRE(passets->CheckForDEPINSelfRestriction(ASSET, holderAddr));
    const bool warm = Verdict(unfreeze, warmError);
    BOOST_CHECK_MESSAGE(cold && warm, "cold=" << cold << " " << coldError << " warm=" << warm << " " << warmError);
    BOOST_CHECK(!passets->CheckForAddressRestriction(ASSET, holderAddr));
}

// A confirmed freeze evicts a holder transfer whose input comes from an
// unconfirmed parent, and keeps the parent, which is still valid.
BOOST_AUTO_TEST_CASE(freeze_evicts_transfer_with_unconfirmed_parent)
{
    std::string reason;
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    const CMutableTransaction open = StateOp(Seed(OwnerTransferScript(ownerAddr)), 1);
    BOOST_REQUIRE(Mine({open}));

    const CMutableTransaction parent = HolderTransfer(holderOut, COIN, holder2Addr);
    BOOST_REQUIRE_MESSAGE(ToMempool(parent, reason), reason);
    const COutPoint parentOut(parent.GetHash(), 0);
    const CMutableTransaction child = HolderTransfer(parentOut, COIN, recipientAddr, {{parentOut, parent.vout[0]}});
    BOOST_REQUIRE_MESSAGE(ToMempool(child, reason), reason);

    BOOST_REQUIRE(Mine({OwnerRestriction(COutPoint(open.GetHash(), 0), 1, holder2Addr)}));
    BOOST_REQUIRE(OwnerFrozen(holder2Addr));
    BOOST_CHECK(mempool.exists(parent.GetHash()));
    BOOST_CHECK(!mempool.exists(child.GetHash()));
}

// The owner may still move the asset from an address it froze: a confirmed
// freeze keeps such an escorted transfer in the mempool.
BOOST_AUTO_TEST_CASE(freeze_keeps_escorted_transfer)
{
    std::string reason;
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    const CMutableTransaction freeze = OwnerRestriction(Seed(OwnerTransferScript(ownerAddr)), 1, holderAddr);
    BOOST_REQUIRE_MESSAGE(ToMempool(freeze, reason), reason);

    const COutPoint freezeOwnerOut(freeze.GetHash(), 0);
    CMutableTransaction escorted;
    escorted.vin.emplace_back(freezeOwnerOut);
    escorted.vin.emplace_back(holderOut);
    escorted.vout.emplace_back(0, OwnerTransferScript(ownerAddr));
    escorted.vout.emplace_back(0, TransferScript(ASSET, COIN, recipientAddr));
    Sign(escorted, {{freezeOwnerOut, freeze.vout[0]}});
    BOOST_REQUIRE_MESSAGE(ToMempool(escorted, reason), reason);

    BOOST_REQUIRE(Mine({freeze}));
    BOOST_REQUIRE(OwnerFrozen(holderAddr));
    BOOST_CHECK(mempool.exists(escorted.GetHash()));
    BOOST_CHECK_MESSAGE(Verdict(escorted, reason), reason);
}

// Self-revocations are valid in every state: neither a reorg with the asset
// CLOSED nor a confirmed CLOSE or SEAL evicts a pending one.
BOOST_AUTO_TEST_CASE(state_changes_and_reorgs_keep_pending_self_revocation)
{
    std::string reason;
    COutPoint ownerOut = Seed(OwnerTransferScript(ownerAddr));
    const CMutableTransaction revoke = SelfRevoke(Seed(IssuanceScript(ASSET, COIN, holderAddr)), COIN, holderAddr);
    BOOST_REQUIRE_MESSAGE(ToMempool(revoke, reason), reason);
    BOOST_REQUIRE_EQUAL(HolderTransfersTracked(), 1U);

    BOOST_REQUIRE(Mine({}));
    UndoTip();
    BOOST_CHECK(mempool.exists(revoke.GetHash()));

    const CMutableTransaction open = StateOp(ownerOut, 1);
    BOOST_REQUIRE(Mine({open}));
    const CMutableTransaction close = StateOp(COutPoint(open.GetHash(), 0), 0);
    BOOST_REQUIRE(Mine({close}));
    BOOST_CHECK(mempool.exists(revoke.GetHash()));

    BOOST_REQUIRE(Mine({StateOp(COutPoint(close.GetHash(), 0), 2)}));
    BOOST_REQUIRE_EQUAL((int)State(), (int)DepinTransferState::SEALED);
    BOOST_CHECK(mempool.exists(revoke.GetHash()));
}

// Undoing an unfreeze freezes the address again: the reorg evicts the holder
// transfers that became invalid.
BOOST_AUTO_TEST_CASE(reorg_undoing_unfreeze_evicts_holder_transfer)
{
    std::string reason;
    const COutPoint holderOut = Seed(IssuanceScript(ASSET, COIN, holderAddr));
    const CMutableTransaction open = StateOp(Seed(OwnerTransferScript(ownerAddr)), 1);
    BOOST_REQUIRE(Mine({open}));
    const CMutableTransaction freeze = OwnerRestriction(COutPoint(open.GetHash(), 0), 1, holderAddr);
    BOOST_REQUIRE(Mine({freeze}));
    BOOST_REQUIRE(Mine({OwnerRestriction(COutPoint(freeze.GetHash(), 0), 0, holderAddr)}));
    BOOST_REQUIRE(!OwnerFrozen(holderAddr));

    const CMutableTransaction move = HolderTransfer(holderOut, COIN, recipientAddr);
    BOOST_REQUIRE_MESSAGE(ToMempool(move, reason), reason);
    UndoTip();
    BOOST_CHECK(OwnerFrozen(holderAddr));
    BOOST_CHECK(!mempool.exists(move.GetHash()));
}

BOOST_AUTO_TEST_SUITE_END()
