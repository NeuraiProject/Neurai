// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "neuraiunits.h"

#include "primitives/transaction.h"

#include <QStringList>

NeuraiUnits::NeuraiUnits(QObject *parent):
        QAbstractListModel(parent),
        unitlist(availableUnits())
{
}

QList<NeuraiUnits::Unit> NeuraiUnits::availableUnits()
{
    QList<NeuraiUnits::Unit> unitlist;
    unitlist.append(XNA);
    unitlist.append(mXNA);
    unitlist.append(uXNA);
    unitlist.append(Neuron);
    return unitlist;
}

bool NeuraiUnits::valid(int unit)
{
    switch(unit)
    {
    case XNA:
    case mXNA:
    case uXNA:
    case Neuron:
        return true;
    default:
        return false;
    }
}

QString NeuraiUnits::name(int unit)
{
    switch(unit)
    {
    case XNA: return QString("XNA");
    case mXNA: return QString("mXNA");
    case uXNA: return QString::fromUtf8("μXNA");
    case Neuron: return QString::fromUtf8("Neuron");
    default: return QString("???");
    }
}

QString NeuraiUnits::description(int unit)
{
    switch(unit)
    {
    case XNA: return QString("Neurais");
    case mXNA: return QString("Milli-Neurais (1 / 1" THIN_SP_UTF8 "000)");
    case uXNA: return QString("Micro-Neurais (1 / 1" THIN_SP_UTF8 "000" THIN_SP_UTF8 "000)");
    case Neuron: return QString("Micro-Neurais (1 / 1" THIN_SP_UTF8 "000" THIN_SP_UTF8 "000)");
    default: return QString("???");
    }
}

qint64 NeuraiUnits::factor(int unit)
{
    switch(unit)
    {
    case XNA:  return 100000000;
    case mXNA: return 100000;
    case uXNA: return 100;
    case Neuron: return 1;
    default:   return 100000000;
    }
}

qint64 NeuraiUnits::factorAsset(int unit)
{
    switch(unit)
    {
        case 0:  return 1;
        case 1: return 10;
        case 2: return 100;
        case 3: return 1000;
        case 4: return 10000;
        case 5: return 100000;
        case 6: return 1000000;
        case 7: return 10000000;
        case 8: return 100000000;
        default:   return 100000000;
    }
}

int NeuraiUnits::decimals(int unit)
{
    switch(unit)
    {
    case XNA: return 8;
    case mXNA: return 5;
    case uXNA: return 2;
    case Neuron: return 0;
    default: return 0;
    }
}

QString NeuraiUnits::format(int unit, const CAmount& nIn, bool fPlus, SeparatorStyle separators, const int nAssetUnit)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    if((nAssetUnit < 0 || nAssetUnit > 8) && !valid(unit))
        return QString(); // Refuse to format invalid unit
    qint64 n = (qint64)nIn;
    qint64 coin = nAssetUnit >= 0 ? factorAsset(nAssetUnit) : factor(unit);
    int num_decimals = nAssetUnit >= 0 ? nAssetUnit : decimals(unit);
    qint64 n_abs = (n > 0 ? n : -n);
    qint64 quotient = n_abs / coin;
    qint64 remainder = n_abs % coin;
    QString quotient_str = QString::number(quotient);
    QString remainder_str = QString::number(remainder).rightJustified(num_decimals, '0');

    // Use SI-style thi
    // n space separators as these are locale independent and can't be
    // confused with the decimal marker.
    QChar thin_sp(THIN_SP_CP);
    int q_size = quotient_str.size();
    if (separators == separatorAlways || (separators == separatorStandard && q_size > 4))
        for (int i = 3; i < q_size; i += 3)
            quotient_str.insert(q_size - i, thin_sp);

    if (n < 0)
        quotient_str.insert(0, '-');
    else if (fPlus && n > 0)
        quotient_str.insert(0, '+');

    if (nAssetUnit == MIN_ASSET_UNITS)
        return quotient_str;


    return quotient_str + QString(".") + remainder_str;
}


// NOTE: Using formatWithUnit in an HTML context risks wrapping
// quantities at the thousands separator. More subtly, it also results
// in a standard space rather than a thin space, due to a bug in Qt's
// XML whitespace canonicalisation
//
// Please take care to use formatHtmlWithUnit instead, when
// appropriate.

QString NeuraiUnits::formatWithUnit(int unit, const CAmount& amount, bool plussign, SeparatorStyle separators)
{
    return format(unit, amount, plussign, separators) + QString(" ") + name(unit);
}

QString NeuraiUnits::formatWithCustomName(QString customName, const CAmount& amount, int unit, bool plussign, SeparatorStyle separators)
{
    return format(XNA, amount / factorAsset(MAX_ASSET_UNITS - unit), plussign, separators, unit) + QString(" ") + customName;
}

QString NeuraiUnits::formatHtmlWithUnit(int unit, const CAmount& amount, bool plussign, SeparatorStyle separators)
{
    QString str(formatWithUnit(unit, amount, plussign, separators));
    str.replace(QChar(THIN_SP_CP), QString(THIN_SP_HTML));
    return QString("<span style='white-space: nowrap;'>%1</span>").arg(str);
}


bool NeuraiUnits::parse(int unit, const QString &value, CAmount *val_out)
{
    if(!valid(unit) || value.isEmpty())
        return false; // Refuse to parse invalid unit or empty string
    int num_decimals = decimals(unit);

    // Ignore spaces and thin spaces when parsing
    QStringList parts = removeSpaces(value).split(".");

    if(parts.size() > 2)
    {
        return false; // More than one dot
    }
    QString whole = parts[0];
    QString decimals;

    if(parts.size() > 1)
    {
        decimals = parts[1];
    }
    if(decimals.size() > num_decimals)
    {
        return false; // Exceeds max precision
    }
    bool ok = false;
    QString str = whole + decimals.leftJustified(num_decimals, '0');

    if(str.size() > 18)
    {
        return false; // Longer numbers will exceed 63 bits
    }
    CAmount retvalue(str.toLongLong(&ok));
    if(val_out)
    {
        *val_out = retvalue;
    }
    return ok;
}

bool NeuraiUnits::assetParse(int assetUnit, const QString &value, CAmount *val_out)
{
    if(!(assetUnit >= 0 && assetUnit <= 8) || value.isEmpty())
        return false; // Refuse to parse invalid unit or empty string
    int num_decimals = assetUnit;

    // Ignore spaces and thin spaces when parsing
    QStringList parts = removeSpaces(value).split(".");

    if(parts.size() > 2)
    {
        return false; // More than one dot
    }
    QString whole = parts[0];
    QString decimals;

    if(parts.size() > 1)
    {
        decimals = parts[1];
    }
    if(decimals.size() > num_decimals)
    {
        return false; // Exceeds max precision
    }
    bool ok = false;
    QString str = whole + decimals.leftJustified(num_decimals, '0');

    if(str.size() > 18)
    {
        return false; // Longer numbers will exceed 63 bits
    }
    CAmount retvalue(str.toLongLong(&ok));
    if(val_out)
    {
        *val_out = retvalue;
    }
    return ok;
}

QString NeuraiUnits::getAmountColumnTitle(int unit)
{
    QString amountTitle = QObject::tr("Amount");
    if (NeuraiUnits::valid(unit))
    {
        amountTitle += " ("+NeuraiUnits::name(unit) + ")";
    }
    return amountTitle;
}

int NeuraiUnits::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return unitlist.size();
}

QVariant NeuraiUnits::data(const QModelIndex &index, int role) const
{
    int row = index.row();
    if(row >= 0 && row < unitlist.size())
    {
        Unit unit = unitlist.at(row);
        switch(role)
        {
        case Qt::EditRole:
        case Qt::DisplayRole:
            return QVariant(name(unit));
        case Qt::ToolTipRole:
            return QVariant(description(unit));
        case UnitRole:
            return QVariant(static_cast<int>(unit));
        }
    }
    return QVariant();
}

CAmount NeuraiUnits::maxMoney()
{
    return MAX_MONEY;
}
