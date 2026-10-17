// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_TEST_SILENTPAYMENTTESTS_H
#define NEURAI_QT_TEST_SILENTPAYMENTTESTS_H

#include <QObject>
#include <QTest>

/** NIP-047 GUI flows: send to a payment code, errors and the code dialog. */
class SilentPaymentTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void silentPaymentTests();
};

#endif // NEURAI_QT_TEST_SILENTPAYMENTTESTS_H
