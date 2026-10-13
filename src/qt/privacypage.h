// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_PRIVACYPAGE_H
#define NEURAI_QT_PRIVACYPAGE_H

#include "amount.h"

#include <QLabel>
#include <QList>
#include <QPair>
#include <QWidget>

#include <vector>

class ClientModel;
class PlatformStyle;
class PrivacyPoolModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QButtonGroup;
class QComboBox;
class QFrame;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QVBoxLayout;
QT_END_NAMESPACE

/** Label for one long word (an address): splits it into the fewest lines that
 *  fit a given width, all of the same length, and is exactly as wide as them. */
class BalancedTextLabel : public QLabel
{
public:
    explicit BalancedTextLabel(QWidget* parent = nullptr);
    void setFullText(const QString& text);
    const QString& fullText() const { return m_full; }
    /** Lays the text out for at most `width` pixels. */
    void fitTo(int width);

private:
    void relayout();
    QString m_full;
    int m_available = 0;
};

/** Privacy section: the C6 XNA pool (testnet) — private balance, deposits,
 *  private transfers and withdrawals, as in NeuraiWallet. */
class PrivacyPage : public QWidget
{
    Q_OBJECT

public:
    explicit PrivacyPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

Q_SIGNALS:
    void message(const QString& title, const QString& text, unsigned int style);

private Q_SLOTS:
    void updateView();
    void updateFunding();
    void openClicked();
    void depositClicked();
    void withdrawClicked();
    void transferClicked();
    void addRecipient();
    void updateTransfer();
    void maxClicked();
    void ownAddressClicked();
    void copyAddressClicked();
    void operationFinished(bool success, const QString& text);

private:
    QString formatAmount(CAmount amount) const;
    bool parseAmount(const QLineEdit* field, CAmount& amount) const;
    /** Selectable chips (fee levels, quick amounts) in one row. */
    struct Chips {
        QWidget* widget = nullptr;
        QButtonGroup* group = nullptr;
    };
    Chips makeChips(bool exclusive);
    void addChip(Chips& chips, const QString& text, qlonglong value, bool checked);
    CAmount selectedFee(const Chips& chips) const;
    void fillFees(Chips& chips);
    /** Enables the pool fee levels that cover the network fee of an operation now
     *  (10% margin) and selects the cheapest one if the current level falls short. */
    void updateFeeLevels(Chips& chips, QLabel* hint, const QString& operation);
    /** Deposit steps: 1 funding coin, 2 deposit; waiting = funding coin unconfirmed. */
    void setDepositStep(int step, bool waiting);
    void updateQr(const QString& address);
    /** Amount of an unspent note, or 0. */
    CAmount noteAmount(quint32 index) const;
    /** Recipients of the transfer form; false (with a reason) if one is incomplete or invalid. */
    bool transferRecipients(QList<QPair<QString, CAmount>>& recipients, QString& reason) const;

    const PlatformStyle* m_platformStyle;
    WalletModel* m_walletModel = nullptr;
    PrivacyPoolModel* m_pool = nullptr;
    ClientModel* m_clientModel = nullptr;

    QLabel* m_poolChip;
    QFrame* m_unavailableCard;
    QLabel* m_unavailableText;
    QFrame* m_openCard;
    QLineEdit* m_zkPassphrase;
    QPushButton* m_openButton;
    QLabel* m_openStatus;
    QWidget* m_balanceCard; //!< balance card and QR card, side by side
    QLabel* m_balance;
    QLabel* m_spendable;
    QLabel* m_status;
    BalancedTextLabel* m_address;
    QWidget* m_addressRow;
    QPushButton* m_copyIcon;
    void fitAddress();
    QLabel* m_qr;
    QString m_qrAddress;
    QPushButton* m_closeButton;
    QWidget* m_operations;
    QLineEdit* m_depositAmount;
    Chips m_quickAmounts;
    Chips m_depositFee;
    QLabel* m_stepDot[2];
    QLabel* m_stepText[2];
    QFrame* m_stepLine;
    QLabel* m_depositFeeHint;
    QLabel* m_fundingStatus;
    QPushButton* m_depositButton;
    bool m_depositEnabled = false;
    QComboBox* m_withdrawNote;
    QLineEdit* m_withdrawAmount;
    QLineEdit* m_withdrawAddress;
    Chips m_withdrawFee;
    QLabel* m_withdrawFeeHint;
    QPushButton* m_withdrawButton;
    struct RecipientRow {
        QWidget* widget;
        QLineEdit* address;
        QLineEdit* amount;
    };
    QFrame* m_transferCard;
    QComboBox* m_transferNote;
    QVBoxLayout* m_recipientLayout;
    std::vector<RecipientRow> m_recipients;
    QPushButton* m_addRecipient;
    Chips m_transferFee;
    QLabel* m_transferFeeHint;
    QLabel* m_transferSummary;
    QPushButton* m_transferButton;
    QFrame* m_notesCard;
    QTableWidget* m_notes;
};

#endif // NEURAI_QT_PRIVACYPAGE_H
