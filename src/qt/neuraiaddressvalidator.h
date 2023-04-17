// Copyright (c) 2011-2014 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_NEURAIADDRESSVALIDATOR_H
#define NEURAI_QT_NEURAIADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class NeuraiAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit NeuraiAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** Neurai address widget validator, checks for a valid neurai address.
 */
class NeuraiAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit NeuraiAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // NEURAI_QT_NEURAIADDRESSVALIDATOR_H
