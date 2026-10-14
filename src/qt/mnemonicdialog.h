// Copyright (c) 2020 Hans Schmidt
// Copyright (c) 2017-2018 The Particl Core developers
// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_MNEMONICDIALOG_H
#define NEURAI_QT_MNEMONICDIALOG_H

#include "crypto/sha512.h"
#include "support/allocators/secure.h"

#include <QDialog>
#include <QElapsedTimer>
#include <QList>

#include <string>

class QCheckBox;
class QComboBox;
class QFrame;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QStackedWidget;
class QTimer;

/** First-run wallet setup: create a wallet from new BIP39 words or restore one.
 *  On success it fills my_words, my_passphrase and my_address_type (wallet.h)
 *  and closes. Closing it without finishing lets the wallet generate its own
 *  words with the default address type. */
class MnemonicDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MnemonicDialog(QWidget *parent = nullptr);
    ~MnemonicDialog();

private Q_SLOTS:
    /** Starts two seconds of extra randomness collection; the words follow. */
    void generateWords();
    void collectEntropy();
    /** Shows the words of the current entropy in the selected language. */
    void showWords();
    void createWallet();
    void restoreWallet();
    void updateRestoreState();
    void updateCreateButton();

private:
    QWidget *createWelcomePage();
    QWidget *createNewWalletPage();
    QWidget *createRestorePage();
    /** Address type chooser; cards receives its three cards (Legacy, PQ, ECDSA). */
    QWidget *createAddressTypeChooser(QList<QFrame*>& cards, int& selected);
    QWidget *createPassphraseField(QLineEdit*& edit, const QString& hint);
    void showPage(int index);
    void selectAddressType(QList<QFrame*>& cards, int& selected, int index);

    QStackedWidget *pages = nullptr;

    // New wallet page
    QComboBox *createLanguage = nullptr;
    QPushButton *generateButton = nullptr;
    QProgressBar *entropyBar = nullptr;
    QLabel *entropyNote = nullptr;
    QTimer *entropyTimer = nullptr;
    QElapsedTimer entropyClock;
    CSHA512 entropyPool;
    SecureVector entropy; //!< seed of the shown words (BIP39 uses the first 16 bytes)
    QList<QLabel*> wordLabels;
    QLineEdit *createPassphrase = nullptr;
    QList<QFrame*> createTypeCards;
    int createType = 0;
    QCheckBox *confirmBackup = nullptr;
    QPushButton *createButton = nullptr;
    QLabel *createError = nullptr;
    std::string generatedWords;

    // Restore page
    QComboBox *restoreLanguage = nullptr;
    QPlainTextEdit *restoreWords = nullptr;
    QLabel *restoreCounter = nullptr;
    QLineEdit *restorePassphrase = nullptr;
    QList<QFrame*> restoreTypeCards;
    int restoreType = 0;
    QPushButton *restoreButton = nullptr;
    QLabel *restoreError = nullptr;
};

#endif // NEURAI_QT_MNEMONICDIALOG_H
