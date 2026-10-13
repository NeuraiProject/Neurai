// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "qt/privacypoolmodel.h"

#include "qt/clientmodel.h"
#include "qt/walletmodel.h"

#include "base58.h"
#include "chainparams.h"
#include "core_io.h"
#include "init.h"
#include "net.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "privacy/c6_config.h"
#include "privacy/c6_ops.h"
#include "privacy/c6_scan.h"
#include "privacy/c6_wallet.h"
#include "privacy/nzk.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "script/standard.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "wallet/bip39.h"
#include "wallet/coincontrol.h"
#include "wallet/fees.h"
#include "wallet/wallet.h"

#include <univalue.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>

#include <map>
#include <optional>
#include <set>

namespace privacy {

namespace {

const char* const CONFIG_FILE = "c6-testnet.json";

bool ReadFile(const QString& path, std::vector<uint8_t>& out)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return false;
    const QByteArray data = file.readAll();
    out.assign(data.begin(), data.end());
    return true;
}

/** Where the pool config and proving artifacts live: -privacypooldir, the
 *  network data directory, or next to the executable. */
QString FindPoolDirectory()
{
    QStringList candidates;
    const std::string arg = gArgs.GetArg("-privacypooldir", "");
    if (!arg.empty()) candidates << QString::fromStdString(arg);
    candidates << QString::fromStdString((GetDataDir() / "privacy-c6").string());
    candidates << QCoreApplication::applicationDirPath() + "/privacy-c6";
    for (const QString& dir : candidates) {
        if (QFile::exists(dir + "/" + CONFIG_FILE)) return dir;
    }
    return QString();
}

UniValue CallRPC(const std::string& method, const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    request.fHelp = false;
    return tableRPC.execute(request);
}

std::string RPCError(const UniValue& error)
{
    const UniValue& message = find_value(error, "message");
    return message.isStr() ? message.get_str() : error.write();
}

/** An exact, spendable wallet coin of `value` at a standard destination. */
bool FindFundingCoin(CWallet* wallet, CAmount value, int minDepth, COutPoint& point, CScript& script)
{
    LOCK2(cs_main, wallet->cs_wallet);
    for (const auto& entry : wallet->mapWallet) {
        const CWalletTx& wtx = entry.second;
        if (wtx.IsCoinBase()) continue;
        const int depth = wtx.GetDepthInMainChain();
        if (depth < minDepth || depth < 0 || (depth == 0 && !wtx.InMempool())) continue;
        for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
            const CTxOut& out = wtx.tx->vout[i];
            if (out.nValue != value || out.scriptPubKey.IsAssetScript()) continue;
            if (!IsC6Destination(Bytes(out.scriptPubKey.begin(), out.scriptPubKey.end()))) continue;
            if (!(wallet->IsMine(out) & ISMINE_SPENDABLE) || wallet->IsSpent(wtx.GetHash(), i)) continue;
            point = COutPoint(wtx.GetHash(), i);
            script = out.scriptPubKey;
            return true;
        }
    }
    return false;
}

} // namespace

/** Pool state, keys and proving artifacts. Used only on the worker thread. */
class C6Engine
{
public:
    C6Engine(CWallet* wallet, const QString& dir, const C6Config& config) : m_wallet(wallet), m_dir(dir), m_config(config) {}

    bool Open(const uint8_t seed[64], const std::string& zkPassphrase, NzkFamily family, std::string& error)
    {
        uint8_t root[64];
        if (!NzkRoot(seed, zkPassphrase, root)) {
            error = "cannot derive the private wallet (out of memory?)";
            return false;
        }
        m_account = std::make_unique<NzkAccount>(root, family, 0, m_config.domain, m_config.assetId);
        Wipe(root, sizeof(root));
        m_recovery = std::make_unique<C6Recovery>(*m_account);
        m_scanner = std::make_unique<C6ChainScanner>(m_config);
        m_reserved.clear();
        m_pending.clear();
        return true;
    }

    void Close()
    {
        m_recovery.reset();
        m_account.reset();
        m_scanner.reset();
        m_reserved.clear();
        m_pending.clear();
    }

    bool IsOpen() const { return m_account != nullptr; }

    bool Refresh(std::string& error, const std::function<bool(int, int)>& progress)
    {
        if (!IsOpen()) {
            error = "the private wallet is closed";
            return false;
        }
        if (!m_scanner->Update(error, progress)) return false;
        m_recovery->Update(m_scanner->State().records);
        // Settle broadcast operations: confirmed, still in the mempool, or dropped.
        for (auto it = m_pending.begin(); it != m_pending.end();) {
            const bool confirmed = m_scanner->State().transitionTxids.count(it->txid) > 0;
            if (confirmed || !mempool.exists(it->txid)) {
                if (it->nf) m_reserved.erase(*it->nf);
                it = m_pending.erase(it);
            } else {
                ++it;
            }
        }
        return true;
    }

    PrivacySnapshot Snapshot() const
    {
        PrivacySnapshot snapshot;
        if (!IsOpen() || !m_scanner->Ready()) return snapshot;
        const C6PoolState& state = m_scanner->State();
        snapshot.height = state.height;
        snapshot.poolReserve = state.reserve;
        const int eligible = m_scanner->EligibleRoot();
        const uint32_t mature = eligible >= 0 ? state.world.RootCounts()[eligible] : 0;
        for (const C6OwnedNote& note : m_recovery->Notes()) {
            if (state.world.IsSpent(note.nf)) continue;
            PrivacyNoteRow row;
            row.index = note.index;
            row.amount = static_cast<CAmount>(note.amount);
            row.height = note.height;
            row.reserved = m_reserved.count(note.nf) > 0;
            row.spendable = note.index < mature && !row.reserved;
            snapshot.balance += row.amount;
            if (row.spendable) snapshot.spendable += row.amount;
            snapshot.notes << row;
        }
        const std::string hrp = NzkHrp(GetParams().NetworkIDString());
        snapshot.receiveAddress = QString::fromStdString(
            EncodeNzkAddress(m_account->RecipientAt(NZK_CHAIN_RECEIVING, m_recovery->CurrentIndex()), hrp));
        for (const Pending& op : m_pending) snapshot.pending << QString::fromStdString(op.txid.GetHex());
        return snapshot;
    }

    bool Deposit(CAmount amount, CAmount fee, std::string& txid, std::string& error, const std::function<void(const std::string&)>& stage)
    {
        COutPoint funding;
        CScript fundingScript;
        if (!FindFundingCoin(m_wallet, amount + fee, 1, funding, fundingScript)) {
            error = "no confirmed funding coin of exactly the deposit amount plus fee";
            return false;
        }
        C6Prepared prepared;
        const Recipient self = m_account->RecipientAt(NZK_CHAIN_CHANGE, 0);
        if (!PrepareC6Deposit(m_config, self, amount, fee, funding, amount + fee, prepared, error) ||
            !CheckNetworkFee(prepared, &fundingScript, error)) {
            return false;
        }
        std::array<uint8_t, 128> proof;
        if (!Prove(prepared, proof, error, stage)) return false;
        CMutableTransaction mtx;
        int fundingInput;
        std::string form;
        if (!BuildC6Transaction(m_config, m_scanner->State(), prepared, proof, mtx, fundingInput, form, error)) return false;
        stage("signing");
        {
            LOCK2(cs_main, m_wallet->cs_wallet);
            if (m_wallet->IsLocked()) {
                error = "the wallet is locked";
                return false;
            }
            const CTransaction unsignedTx(mtx);
            SignatureData sigdata;
            if (!ProduceSignature(TransactionSignatureCreator(m_wallet, &unsignedTx, fundingInput, amount + fee, SIGHASH_ALL),
                                  fundingScript, sigdata)) {
                error = "cannot sign the funding input";
                return false;
            }
            UpdateTransaction(mtx, fundingInput, sigdata);
        }
        if (!Broadcast(mtx, txid, error, stage)) return false;
        {
            LOCK(m_wallet->cs_wallet);
            m_wallet->UnlockCoin(funding);
        }
        m_pending.push_back({uint256S(txid), std::nullopt});
        return true;
    }

    bool Withdraw(uint32_t index, CAmount amount, CAmount fee, const CScript& payout, std::string& txid, std::string& error,
                  const std::function<void(const std::string&)>& stage)
    {
        C6Spend spend;
        NzkAddressKeys keys;
        Bytes32 nf;
        C6Prepared prepared;
        if (!SpendNote(index, spend, keys, nf, error) ||
            !PrepareC6Withdrawal(m_config, spend, keys.spendSecret, amount, fee, Bytes(payout.begin(), payout.end()), prepared, error)) {
            return false;
        }
        return ProveAndSend(prepared, nf, txid, error, stage);
    }

    bool Transfer(uint32_t index, const std::vector<C6Payment>& payments, CAmount fee, std::string& txid, std::string& error,
                  const std::function<void(const std::string&)>& stage)
    {
        C6Spend spend;
        NzkAddressKeys keys;
        Bytes32 nf;
        C6Prepared prepared;
        if (!SpendNote(index, spend, keys, nf, error) ||
            !PrepareC6Transfer(m_config, spend, keys.spendSecret, payments, fee, prepared, error)) {
            return false;
        }
        return ProveAndSend(prepared, nf, txid, error, stage);
    }

private:
    struct Pending {
        uint256 txid;
        std::optional<Bytes32> nf;
    };

    /** An owned, mature, unreserved note with its membership path and keys. */
    bool SpendNote(uint32_t index, C6Spend& spend, NzkAddressKeys& keys, Bytes32& nf, std::string& error)
    {
        const C6PoolState& state = m_scanner->State();
        const C6OwnedNote* owned = nullptr;
        for (const C6OwnedNote& note : m_recovery->Notes()) {
            if (note.index == index && !state.world.IsSpent(note.nf) && !m_reserved.count(note.nf)) owned = &note;
        }
        if (!owned) {
            error = "the note is spent, pending or not yours";
            return false;
        }
        const int eligible = m_scanner->EligibleRoot();
        if (eligible < 0 || index >= state.world.RootCounts()[eligible]) {
            error = "the note needs two confirmations before it can be spent";
            return false;
        }
        spend.note = owned->note;
        spend.index = index;
        SparseSnapshot(state.world.Leaves(), state.world.RootCounts()[eligible], index, spend.root, spend.path);
        if (spend.root != state.world.Roots()[eligible]) {
            error = "internal error: membership root mismatch";
            return false;
        }
        if (!m_recovery->KeysFor(*owned, keys)) {
            error = "cannot derive the note's spending key";
            return false;
        }
        nf = owned->nf;
        return true;
    }

    /** Proves a spend, builds it on the scanned state and broadcasts it; the spent
     *  note stays reserved until the transaction confirms or leaves the mempool. */
    bool ProveAndSend(const C6Prepared& prepared, const Bytes32& nf, std::string& txid, std::string& error,
                      const std::function<void(const std::string&)>& stage)
    {
        if (!CheckNetworkFee(prepared, nullptr, error)) return false;
        std::array<uint8_t, 128> proof;
        if (!Prove(prepared, proof, error, stage)) return false;
        CMutableTransaction mtx;
        int fundingInput;
        std::string form;
        if (!BuildC6Transaction(m_config, m_scanner->State(), prepared, proof, mtx, fundingInput, form, error)) return false;
        if (!Broadcast(mtx, txid, error, stage)) return false;
        m_reserved.insert(nf);
        m_pending.push_back({uint256S(txid), nf});
        return true;
    }
    struct Artifacts {
        std::vector<uint8_t> wasm;
        ProvingKey key;
    };

    bool LoadArtifacts(const std::string& op, std::string& error)
    {
        if (m_artifacts.count(op)) return true;
        const auto pin = m_config.artifacts.find(op);
        if (pin == m_config.artifacts.end()) {
            error = "the pool config has no artifacts for " + op;
            return false;
        }
        Artifacts artifacts;
        std::vector<uint8_t> zkey;
        if (!ReadFile(m_dir + "/" + QString::fromStdString(pin->second.wasm), artifacts.wasm) ||
            !ReadFile(m_dir + "/" + QString::fromStdString(pin->second.zkey), zkey)) {
            error = "missing proving files " + pin->second.wasm + " / " + pin->second.zkey + " in " + m_dir.toStdString();
            return false;
        }
        if (artifacts.wasm.size() != pin->second.wasmBytes || Sha256(artifacts.wasm) != pin->second.wasmSha256 ||
            zkey.size() != pin->second.zkeyBytes || Sha256(zkey) != pin->second.zkeySha256) {
            error = "proving files for " + op + " do not match the pinned digests";
            return false;
        }
        if (!LoadProvingKey(std::move(zkey), artifacts.key, error)) return false;
        m_artifacts.emplace(op, std::move(artifacts));
        return true;
    }

    /** Builds the transaction with a placeholder proof (same size) and checks that
     *  the pool fee covers the network fee the node asks for now. Done before
     *  proving, so a too-low level fails at once. */
    bool CheckNetworkFee(const C6Prepared& prepared, const CScript* fundingScript, std::string& error)
    {
        std::array<uint8_t, 128> placeholder{};
        CMutableTransaction mtx;
        int fundingInput;
        std::string form;
        if (!BuildC6Transaction(m_config, m_scanner->State(), prepared, placeholder, mtx, fundingInput, form, error)) return false;
        int64_t vsize = GetVirtualTransactionSize(CTransaction(mtx));
        if (fundingScript) vsize += FundingSignatureVsize(*fundingScript);
        const CAmount needed = GetMinimumFee(static_cast<unsigned int>(vsize), CCoinControl(), ::mempool, ::feeEstimator, nullptr);
        if (static_cast<CAmount>(prepared.fee) < needed) {
            error = strprintf("the pool fee (%s XNA) does not cover the network fee this %s transaction needs now (%s XNA "
                              "for %d vbytes); choose a higher fee", FormatMoney(prepared.fee), form, FormatMoney(needed), vsize);
            return false;
        }
        return true;
    }

    /** Virtual size the funding input's signature adds once signed. */
    static int64_t FundingSignatureVsize(const CScript& script)
    {
        if (!script.empty() && script[0] == 0x52) return 1000; // strict PQ: ML-DSA-44 signature and key in the witness
        if (!script.empty() && script[0] == 0x53) return 30;   // strict ECDSA: witness signature and key
        return 110;                                            // P2PKH: signature and key in scriptSig
    }

    bool Prove(const C6Prepared& prepared, std::array<uint8_t, 128>& proof, std::string& error,
               const std::function<void(const std::string&)>& stage)
    {
        stage("loading");
        if (!LoadArtifacts(prepared.operation, error)) return false;
        const Artifacts& artifacts = m_artifacts.at(prepared.operation);
        return ProveC6(m_config, prepared, artifacts.wasm, artifacts.key, proof, error, stage);
    }

    bool Broadcast(const CMutableTransaction& mtx, std::string& txid, std::string& error,
                   const std::function<void(const std::string&)>& stage)
    {
        const std::string hex = EncodeHexTx(CTransaction(mtx));
        try {
            stage("checking");
            UniValue txs(UniValue::VARR);
            txs.push_back(hex);
            UniValue params(UniValue::VARR);
            params.push_back(txs);
            const UniValue result = CallRPC("testmempoolaccept", params);
            // "allowed" is serialised as a number by this node's RPC.
            const UniValue& allowed = result.isArray() && !result.empty() ? find_value(result[0], "allowed") : NullUniValue;
            if (!(allowed.isBool() ? allowed.get_bool() : allowed.isNum() && allowed.get_int64() == 1)) {
                const UniValue& reason = find_value(result[0], "reject-reason");
                error = "the node rejects the pool transaction: " + (reason.isStr() ? reason.get_str() : result.write());
                if (error.find("conflict") != std::string::npos || error.find("missing-inputs") != std::string::npos) {
                    error += " (another pool transaction is pending; retry after the next block)";
                }
                return false;
            }
            stage("broadcasting");
            UniValue send(UniValue::VARR);
            send.push_back(hex);
            txid = CallRPC("sendrawtransaction", send).get_str();
        } catch (const UniValue& e) {
            error = RPCError(e);
            return false;
        } catch (const std::exception& e) {
            error = e.what();
            return false;
        }
        return true;
    }

    CWallet* m_wallet;
    QString m_dir;
    C6Config m_config;
    std::unique_ptr<NzkAccount> m_account;
    std::unique_ptr<C6Recovery> m_recovery;
    std::unique_ptr<C6ChainScanner> m_scanner;
    std::map<std::string, Artifacts> m_artifacts;
    std::set<Bytes32> m_reserved;
    std::vector<Pending> m_pending;
};

} // namespace privacy

struct PrivacyPoolModel::Unlock {
    // Built in place: copying an UnlockContext recurses (CopyFrom assigns *this).
    explicit Unlock(WalletModel* model) : context(model->requestUnlock()) {}
    WalletModel::UnlockContext context;
};

PrivacyPoolModel::PrivacyPoolModel(WalletModel* walletModel, QObject* parent)
    : QObject(parent), m_walletModel(walletModel), m_cancel(std::make_shared<std::atomic<bool>>(false))
{
    const std::string network = GetParams().NetworkIDString();
    if (network != CBaseChainParams::TESTNET) {
        m_unavailable = tr("The privacy pool is available on testnet only.");
        return;
    }
    const QString dir = privacy::FindPoolDirectory();
    if (dir.isEmpty()) {
        m_unavailable = tr("Privacy pool files not found. Copy the privacy-c6 folder (pool config and proving files) "
                           "next to the executable or into the testnet data directory.");
        return;
    }
    std::vector<uint8_t> json;
    privacy::C6Config config;
    std::string error;
    if (!privacy::ReadFile(dir + "/" + privacy::CONFIG_FILE, json) ||
        !privacy::LoadC6Config(std::string(json.begin(), json.end()), config, error)) {
        m_unavailable = tr("Invalid privacy pool config: %1").arg(QString::fromStdString(error));
        return;
    }
    if (config.genesis != privacy::Bytes32{} &&
        uint256(std::vector<unsigned char>(config.genesis.begin(), config.genesis.end())) != GetParams().GenesisBlock().GetHash()) {
        m_unavailable = tr("The privacy pool config belongs to another network.");
        return;
    }
    m_poolName = QString::fromStdString(config.identity);
    m_domain = config.domain;
    m_assetId = config.assetId;
    m_hrp = privacy::NzkHrp(network);
    m_engine = std::make_unique<privacy::C6Engine>(walletModel->getWallet(), dir, config);
    m_worker = new QObject;
    m_worker->moveToThread(&m_thread);
    connect(&m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    m_thread.setObjectName("privacy-pool");
    m_thread.start();
    m_state = State::Closed;
}

PrivacyPoolModel::~PrivacyPoolModel()
{
    m_cancel->store(true);
    if (m_thread.isRunning()) {
        // Wipe the keys on the worker thread, after any running job.
        privacy::C6Engine* engine = m_engine.get();
        QMetaObject::invokeMethod(m_worker, [engine] { engine->Close(); }, Qt::QueuedConnection);
        m_thread.quit();
        m_thread.wait();
    }
}

void PrivacyPoolModel::setClientModel(ClientModel* clientModel)
{
    m_clientModel = clientModel;
    if (clientModel) {
        connect(clientModel, &ClientModel::numBlocksChanged, this,
                [this](int, const QDateTime&, double, bool header) { if (!header) blocksChanged(); });
    }
}

QList<CAmount> PrivacyPoolModel::feeLevels(const QString& operation) const
{
    // The pinned manifest offers the same levels for every operation.
    Q_UNUSED(operation);
    return {10000000, 20000000, 50000000};
}

CFeeRate PrivacyPoolModel::networkFeeRate() const
{
    // Same source as the wallet's own sends: smart estimate or fallback, never
    // below the mempool floor or the relay minimum. Then 10% for congestion.
    const CAmount perKb = GetMinimumFee(1000, CCoinControl(), ::mempool, ::feeEstimator, nullptr);
    return CFeeRate(perKb + perKb / 10);
}

CAmount PrivacyPoolModel::requiredPoolFee(const QString& operation) const
{
    // Virtual sizes of the pool transactions measured on testnet (they depend
    // only on the form), rounded up; deposits include a signed funding input.
    int64_t vsize = 4800;
    if (operation == "D") vsize = 4100;
    else if (operation == "T1") vsize = 4600;
    else if (operation == "T2") vsize = 5400;
    else if (operation == "T3") vsize = 6200;
    if (operation == "D" && m_walletModel->getWallet()->GetAddressType() == WalletAddressType::PQ) vsize += 1000;
    return networkFeeRate().GetFee(static_cast<size_t>(vsize));
}

PrivacyPoolModel::Funding PrivacyPoolModel::fundingState(CAmount value) const
{
    if (m_state == State::Unavailable || value <= 0) return Funding::None;
    COutPoint point;
    CScript script;
    CWallet* wallet = m_walletModel->getWallet();
    if (privacy::FindFundingCoin(wallet, value, 1, point, script)) return Funding::Ready;
    if (privacy::FindFundingCoin(wallet, value, 0, point, script)) return Funding::Unconfirmed;
    return Funding::None;
}

void PrivacyPoolModel::setActivity(const QString& text)
{
    m_activity = text;
    Q_EMIT changed();
}

void PrivacyPoolModel::applySnapshot(const PrivacySnapshot& snapshot)
{
    m_snapshot = snapshot;
    if (snapshot.height >= 0) m_lastHeight = snapshot.height;
    Q_EMIT changed();
}

bool PrivacyPoolModel::post(std::function<void()> job, bool unlockWallet)
{
    if (unlockWallet) {
        // Held until the job ends: signing needs the unlocked keys.
        m_unlock = std::make_unique<Unlock>(m_walletModel);
        if (!m_unlock->context.isValid()) {
            m_unlock.reset();
            return false;
        }
    }
    m_busy = true;
    Q_EMIT changed();
    QMetaObject::invokeMethod(m_worker, std::move(job), Qt::QueuedConnection);
    return true;
}

void PrivacyPoolModel::finishJob()
{
    m_unlock.reset();
    m_busy = false;
    Q_EMIT changed();
    if (m_refreshQueued) {
        m_refreshQueued = false;
        refresh();
    }
}

void PrivacyPoolModel::open(const QString& zkPassphrase)
{
    if (m_state != State::Closed || m_busy) return;
    CWallet* wallet = m_walletModel->getWallet();
    if (!wallet->GetHDChain().IsBip44()) {
        Q_EMIT operationFinished(false, tr("This wallet was not created from recovery words, so it cannot open a private wallet."));
        return;
    }
    WalletModel::UnlockContext context(m_walletModel->requestUnlock());
    if (!context.isValid()) return;

    uint256 hash;
    SecureVector words, passphrase, walletSeed;
    wallet->GetBip39Data(hash, words, passphrase, walletSeed);
    // NeuraiZK/v2 uses NFKD-normalised English words and passphrases, as NeuraiWallet does.
    const QString mnemonic = QString::fromUtf8(reinterpret_cast<const char*>(words.data()), words.size()).normalized(QString::NormalizationForm_KD);
    const QString pass = QString::fromUtf8(reinterpret_cast<const char*>(passphrase.data()), passphrase.size()).normalized(QString::NormalizationForm_KD);
    const QByteArray mnemonicUtf8 = mnemonic.toUtf8();
    if (mnemonicUtf8.isEmpty() || !CMnemonic::Check(SecureString(mnemonicUtf8.begin(), mnemonicUtf8.end()), 0)) {
        Q_EMIT operationFinished(false, tr("The private wallet needs English recovery words."));
        return;
    }
    auto seed = std::make_shared<std::array<uint8_t, 64>>();
    privacy::NzkWalletSeed(mnemonicUtf8.toStdString(), pass.toUtf8().toStdString(), seed->data());
    const std::string zk = zkPassphrase.normalized(QString::NormalizationForm_KD).toUtf8().toStdString();

    privacy::NzkFamily family = privacy::NzkFamily::LEGACY;
    if (wallet->GetAddressType() == WalletAddressType::PQ) family = privacy::NzkFamily::PQ;
    if (wallet->GetAddressType() == WalletAddressType::ECDSA) family = privacy::NzkFamily::ECDSA;

    m_state = State::Opening;
    setActivity(tr("Deriving the private wallet…"));
    privacy::C6Engine* engine = m_engine.get();
    auto cancel = m_cancel;
    post([this, engine, seed, zk, family, cancel] {
        std::string error;
        bool ok = engine->Open(seed->data(), zk, family, error);
        privacy::Wipe(*seed);
        if (ok) {
            QMetaObject::invokeMethod(this, [this] { setActivity(tr("Scanning the pool…")); }, Qt::QueuedConnection);
            ok = engine->Refresh(error, [this, cancel](int height, int tip) {
                QMetaObject::invokeMethod(this, [this, height, tip] { setActivity(tr("Scanning block %1 of %2…").arg(height).arg(tip)); }, Qt::QueuedConnection);
                return !cancel->load() && !ShutdownRequested();
            });
        }
        const PrivacySnapshot snapshot = engine->Snapshot();
        if (!ok) engine->Close();
        QMetaObject::invokeMethod(this, [this, ok, error, snapshot] {
            m_state = ok ? State::Ready : State::Closed;
            applySnapshot(snapshot);
            setActivity(QString());
            finishJob();
            if (!ok) Q_EMIT operationFinished(false, QString::fromStdString(error));
        }, Qt::QueuedConnection);
    });
}

void PrivacyPoolModel::close()
{
    if (m_state != State::Ready) return;
    privacy::C6Engine* engine = m_engine.get();
    QMetaObject::invokeMethod(m_worker, [engine] { engine->Close(); }, Qt::QueuedConnection);
    m_state = State::Closed;
    m_snapshot = PrivacySnapshot();
    setActivity(QString());
}

void PrivacyPoolModel::blocksChanged()
{
    if (m_state != State::Ready || !m_clientModel || m_clientModel->inInitialBlockDownload()) return;
    if (m_clientModel->getNumBlocks() == m_lastHeight) return;
    refresh();
}

void PrivacyPoolModel::refresh()
{
    if (m_state != State::Ready) return;
    if (m_busy) {
        m_refreshQueued = true;
        return;
    }
    privacy::C6Engine* engine = m_engine.get();
    auto cancel = m_cancel;
    post([this, engine, cancel] {
        std::string error;
        const bool ok = engine->Refresh(error, [cancel](int, int) { return !cancel->load() && !ShutdownRequested(); });
        const PrivacySnapshot snapshot = engine->Snapshot();
        QMetaObject::invokeMethod(this, [this, ok, error, snapshot] {
            applySnapshot(snapshot);
            setActivity(ok ? QString() : tr("Scan failed: %1").arg(QString::fromStdString(error)));
            finishJob();
        }, Qt::QueuedConnection);
    });
}

QString PrivacyPoolModel::newWalletAddress(QString& error)
{
    CWallet* wallet = m_walletModel->getWallet();
    CTxDestination dest;
    std::string err;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        if (!wallet->GetNewDestination(false, dest, err)) {
            error = QString::fromStdString(err);
            return QString();
        }
        wallet->SetAddressBook(dest, "", "receive");
    }
    return QString::fromStdString(EncodeDestination(dest));
}

bool PrivacyPoolModel::prepareFunding(CAmount amount, CAmount fee, QString& error)
{
    WalletModel::UnlockContext context(m_walletModel->requestUnlock());
    if (!context.isValid()) {
        error = tr("Wallet unlock was cancelled.");
        return false;
    }
    const QString address = newWalletAddress(error);
    if (address.isEmpty()) return false;
    CWallet* wallet = m_walletModel->getWallet();
    const CScript script = GetScriptForDestination(DecodeDestination(address.toStdString()));
    const CAmount value = amount + fee;
    std::vector<CRecipient> recipients = {{script, value, false}};
    CWalletTx wtx;
    CReserveKey reservekey(wallet);
    CAmount networkFee;
    int changePosition = -1;
    std::string failure;
    CCoinControl coinControl;
    coinControl.m_feerate = networkFeeRate();
    if (!wallet->CreateTransaction(recipients, wtx, reservekey, networkFee, changePosition, failure, coinControl)) {
        error = QString::fromStdString(failure);
        return false;
    }
    CValidationState state;
    if (!wallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        error = tr("The funding transaction was rejected: %1").arg(QString::fromStdString(state.GetRejectReason()));
        return false;
    }
    // Keep ordinary sends away from the coin the deposit will spend.
    LOCK2(cs_main, wallet->cs_wallet);
    for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
        if (wtx.tx->vout[i].scriptPubKey == script && wtx.tx->vout[i].nValue == value) wallet->LockCoin(COutPoint(wtx.GetHash(), i));
    }
    return true;
}

void PrivacyPoolModel::deposit(CAmount amount, CAmount fee)
{
    if (m_state != State::Ready || m_busy) return;
    privacy::C6Engine* engine = m_engine.get();
    auto cancel = m_cancel;
    const bool started = post([this, engine, cancel, amount, fee] {
        std::string error, txid;
        auto stage = [this](const std::string& s) {
            QMetaObject::invokeMethod(this, [this, s] { setActivity(tr("Deposit: %1…").arg(QString::fromStdString(s))); }, Qt::QueuedConnection);
        };
        bool ok = engine->Refresh(error, [cancel](int, int) { return !cancel->load() && !ShutdownRequested(); }) &&
                  engine->Deposit(amount, fee, txid, error, stage);
        const PrivacySnapshot snapshot = engine->Snapshot();
        QMetaObject::invokeMethod(this, [this, ok, error, txid, snapshot] {
            applySnapshot(snapshot);
            setActivity(QString());
            finishJob();
            Q_EMIT operationFinished(ok, ok ? tr("Deposit broadcast: %1").arg(QString::fromStdString(txid)) : QString::fromStdString(error));
        }, Qt::QueuedConnection);
    }, true);
    if (!started) Q_EMIT operationFinished(false, tr("Wallet unlock was cancelled."));
}

void PrivacyPoolModel::withdraw(quint32 noteIndex, CAmount amount, CAmount fee, const QString& address)
{
    if (m_state != State::Ready || m_busy) return;
    const CTxDestination dest = DecodeDestination(address.toStdString());
    if (!IsValidDestination(dest)) {
        Q_EMIT operationFinished(false, tr("Invalid destination address."));
        return;
    }
    const CScript payout = GetScriptForDestination(dest);
    privacy::C6Engine* engine = m_engine.get();
    auto cancel = m_cancel;
    post([this, engine, cancel, noteIndex, amount, fee, payout] {
        std::string error, txid;
        auto stage = [this](const std::string& s) {
            QMetaObject::invokeMethod(this, [this, s] { setActivity(tr("Withdrawal: %1…").arg(QString::fromStdString(s))); }, Qt::QueuedConnection);
        };
        bool ok = engine->Refresh(error, [cancel](int, int) { return !cancel->load() && !ShutdownRequested(); }) &&
                  engine->Withdraw(noteIndex, amount, fee, payout, txid, error, stage);
        const PrivacySnapshot snapshot = engine->Snapshot();
        QMetaObject::invokeMethod(this, [this, ok, error, txid, snapshot] {
            applySnapshot(snapshot);
            setActivity(QString());
            finishJob();
            Q_EMIT operationFinished(ok, ok ? tr("Withdrawal broadcast: %1").arg(QString::fromStdString(txid)) : QString::fromStdString(error));
        }, Qt::QueuedConnection);
    });
}

bool PrivacyPoolModel::validatePrivateAddress(const QString& address, QString& error) const
{
    privacy::Recipient recipient;
    std::string err;
    if (m_state == State::Unavailable ||
        !privacy::DecodeNzkAddress(address.trimmed().toStdString(), m_hrp, m_domain, m_assetId, recipient, err)) {
        error = QString::fromStdString(err);
        return false;
    }
    return true;
}

void PrivacyPoolModel::transfer(quint32 noteIndex, const QList<QPair<QString, CAmount>>& recipients, CAmount fee)
{
    if (m_state != State::Ready || m_busy) return;
    std::vector<privacy::C6Payment> payments;
    for (const auto& row : recipients) {
        privacy::C6Payment payment;
        std::string error;
        if (!privacy::DecodeNzkAddress(row.first.trimmed().toStdString(), m_hrp, m_domain, m_assetId, payment.recipient, error)) {
            Q_EMIT operationFinished(false, tr("Invalid private address: %1").arg(QString::fromStdString(error)));
            return;
        }
        payment.amount = static_cast<uint64_t>(row.second);
        payments.push_back(payment);
    }
    privacy::C6Engine* engine = m_engine.get();
    auto cancel = m_cancel;
    post([this, engine, cancel, noteIndex, payments, fee] {
        std::string error, txid;
        auto stage = [this](const std::string& s) {
            QMetaObject::invokeMethod(this, [this, s] { setActivity(tr("Private transfer: %1…").arg(QString::fromStdString(s))); }, Qt::QueuedConnection);
        };
        bool ok = engine->Refresh(error, [cancel](int, int) { return !cancel->load() && !ShutdownRequested(); }) &&
                  engine->Transfer(noteIndex, payments, fee, txid, error, stage);
        const PrivacySnapshot snapshot = engine->Snapshot();
        QMetaObject::invokeMethod(this, [this, ok, error, txid, snapshot] {
            applySnapshot(snapshot);
            setActivity(QString());
            finishJob();
            Q_EMIT operationFinished(ok, ok ? tr("Private transfer broadcast: %1").arg(QString::fromStdString(txid)) : QString::fromStdString(error));
        }, Qt::QueuedConnection);
    });
}
