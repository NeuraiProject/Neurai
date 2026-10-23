// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_PRIVACYPOOLMODEL_H
#define NEURAI_QT_PRIVACYPOOLMODEL_H

#include "amount.h"
#include "policy/feerate.h"

#include <QList>
#include <QObject>
#include <QString>
#include <QThread>

#include <QPair>

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <string>

class ClientModel;
class WalletModel;

namespace privacy { class C6Engine; }

/** One private note shown by the Privacy page. */
struct PrivacyNoteRow {
    quint32 index = 0;
    CAmount amount = 0;
    bool spendable = false; //!< in a root with two confirmations and not reserved
    bool reserved = false;  //!< spent by a broadcast, unconfirmed withdrawal
    int height = 0;
};

/** Public and private state of the opened pool wallet. */
struct PrivacySnapshot {
    int height = -1;
    CAmount balance = 0;
    CAmount spendable = 0;
    CAmount poolReserve = 0;
    QList<PrivacyNoteRow> notes;
    QString receiveAddress;
    QList<QString> pending; //!< txids of broadcast operations not confirmed yet
};

/** C6 or C7 XNA privacy pool for one wallet (testnet; C7 also on regtest). Scanning and proving run on a
 *  worker thread; the private keys stay in memory until close(). */
class PrivacyPoolModel : public QObject
{
    Q_OBJECT

public:
    enum class State { Unavailable, Closed, Opening, Ready };

    explicit PrivacyPoolModel(WalletModel* walletModel, QObject* parent = nullptr);
    ~PrivacyPoolModel();

    void setClientModel(ClientModel* clientModel);

    State state() const { return m_state; }
    bool busy() const { return m_busy; }
    /** Why the pool cannot be used, when state() is Unavailable. */
    QString unavailableReason() const { return m_unavailable; }
    QString poolName() const { return m_poolName; }
    /** "C7 XNA · NAME#POOL · testnet" (or C6), for the page header. */
    QString poolLabel() const { return m_poolLabel; }
    QString activity() const { return m_activity; }
    const PrivacySnapshot& snapshot() const { return m_snapshot; }
    QList<CAmount> feeLevels(const QString& operation) const;
    /** Fee rate the node asks for now (estimate, mempool floor or relay minimum)
     *  plus a 10% margin against congestion. */
    CFeeRate networkFeeRate() const;
    /** Pool fee an operation needs ("D", "W", "T1".."T3") to cover the network fee
     *  of its transaction at networkFeeRate(). */
    CAmount requiredPoolFee(const QString& operation) const;
    /** Exact wallet coin (amount + fee) that a deposit spends, if any. */
    enum class Funding { None, Unconfirmed, Ready };
    Funding fundingState(CAmount value) const;

    /** Derive the private wallet from the recovery words (asks to unlock). */
    void open(const QString& zkPassphrase);
    void close();
    void refresh();
    /** Sends amount + fee to an own address: the exact coin a deposit spends. */
    bool prepareFunding(CAmount amount, CAmount fee, QString& error);
    void deposit(CAmount amount, CAmount fee);
    void withdraw(quint32 noteIndex, CAmount amount, CAmount fee, const QString& address);
    /** Private transfer of one note to one to three private (tnzk) addresses. */
    void transfer(quint32 noteIndex, const QList<QPair<QString, CAmount>>& recipients, CAmount fee);
    /** Checks a private address of this pool instance and network. */
    bool validatePrivateAddress(const QString& address, QString& error) const;
    /** A fresh receiving address of the transparent wallet. */
    QString newWalletAddress(QString& error);

Q_SIGNALS:
    void changed();
    void operationFinished(bool success, const QString& text);

private:
    bool post(std::function<void()> job, bool unlockWallet = false);
    void finishJob();
    void setActivity(const QString& text);
    void applySnapshot(const PrivacySnapshot& snapshot);
    void blocksChanged();

    WalletModel* m_walletModel;
    ClientModel* m_clientModel = nullptr;
    QThread m_thread;
    QObject* m_worker = nullptr;
    std::unique_ptr<privacy::C6Engine> m_engine;
    std::shared_ptr<std::atomic<bool>> m_cancel;
    struct Unlock;
    std::unique_ptr<Unlock> m_unlock;

    State m_state = State::Unavailable;
    bool m_busy = false;
    bool m_refreshQueued = false;
    int m_lastHeight = -1;
    QString m_unavailable;
    QString m_poolName;
    QString m_poolLabel;
    std::array<uint8_t, 32> m_domain{};
    std::array<uint8_t, 32> m_assetId{};
    std::string m_hrp;
    bool m_c7 = false;
    QString m_activity;
    PrivacySnapshot m_snapshot;
};

#endif // NEURAI_QT_PRIVACYPOOLMODEL_H
