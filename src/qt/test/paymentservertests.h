// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_TEST_PAYMENTSERVERTESTS_H
#define NEURAI_QT_TEST_PAYMENTSERVERTESTS_H

#include "../paymentserver.h"

#include <QObject>
#include <QTest>

class PaymentServerTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void paymentServerTests();
};

// Dummy class to receive paymentserver signals.
// If SendCoinsRecipient was a proper QObject, then
// we could use QSignalSpy... but it's not.
class RecipientCatcher : public QObject
{
    Q_OBJECT

public Q_SLOTS:
    void getRecipient(const SendCoinsRecipient& r);

public:
    SendCoinsRecipient recipient;
};

#endif // NEURAI_QT_TEST_PAYMENTSERVERTESTS_H
