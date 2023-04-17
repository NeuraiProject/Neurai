#ifndef NEURAI_QT_TEST_WALLETTESTS_H
#define NEURAI_QT_TEST_WALLETTESTS_H

#include <QObject>
#include <QTest>

class WalletTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void walletTests();
};

#endif // NEURAI_QT_TEST_WALLETTESTS_H
