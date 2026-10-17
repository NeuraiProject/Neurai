// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receiverequestdialog.h"
#include "ui_receiverequestdialog.h"

#include "neuraiunits.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "qrimage.h"
#include "walletmodel.h"

#include <QClipboard>
#include <QDrag>
#include <QMenu>
#include <QMimeData>
#include <QMouseEvent>
#include <QPixmap>
#if QT_VERSION < 0x050000
#include <QUrl>
#endif

#if defined(HAVE_CONFIG_H)
#include "config/neurai-config.h" /* for USE_QRCODE */
#endif


QRImageWidget::QRImageWidget(QWidget *parent):
    QLabel(parent), contextMenu(0)
{
    contextMenu = new QMenu(this);
    QAction *saveImageAction = new QAction(tr("&Save Image..."), this);
    connect(saveImageAction, SIGNAL(triggered()), this, SLOT(saveImage()));
    contextMenu->addAction(saveImageAction);
    QAction *copyImageAction = new QAction(tr("&Copy Image"), this);
    connect(copyImageAction, SIGNAL(triggered()), this, SLOT(copyImage()));
    contextMenu->addAction(copyImageAction);
}

QImage QRImageWidget::exportImage()
{
    return GUIUtil::GetImage(this);
}

void QRImageWidget::mousePressEvent(QMouseEvent *event)
{
    if(event->button() == Qt::LeftButton && GUIUtil::HasPixmap(this))
    {
        event->accept();
        QMimeData *mimeData = new QMimeData;
        mimeData->setImageData(exportImage());

        QDrag *drag = new QDrag(this);
        drag->setMimeData(mimeData);
        drag->setPixmap(QPixmap::fromImage(exportImage().scaled(100, 100, Qt::KeepAspectRatio)));
        drag->exec();
    } else {
        QLabel::mousePressEvent(event);
    }
}

void QRImageWidget::saveImage()
{
    if(!GUIUtil::HasPixmap(this))
        return;
    QString fn = GUIUtil::getSaveFileName(this, tr("Save QR Code"), QString(), tr("PNG Image (*.png)"), nullptr);
    if (!fn.isEmpty())
    {
        exportImage().save(fn);
    }
}

void QRImageWidget::copyImage()
{
    if(!GUIUtil::HasPixmap(this))
        return;
    QApplication::clipboard()->setImage(exportImage());
}

void QRImageWidget::contextMenuEvent(QContextMenuEvent *event)
{
    if(!GUIUtil::HasPixmap(this))
        return;
    contextMenu->exec(event->globalPos());
}

ReceiveRequestDialog::ReceiveRequestDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveRequestDialog),
    model(0)
{
    ui->setupUi(this);

#ifndef USE_QRCODE
    ui->btnSaveAs->setVisible(false);
    ui->lblQRCode->setVisible(false);
#endif

    connect(ui->btnSaveAs, SIGNAL(clicked()), ui->lblQRCode, SLOT(saveImage()));

    ui->outUri->setFont(GUIUtil::getSubLabelFont());
    ui->btnCopyURI->setFont(GUIUtil::getSubLabelFont());
    ui->btnCopyAddress->setFont(GUIUtil::getSubLabelFont());
    ui->btnSaveAs->setFont(GUIUtil::getSubLabelFont());
    ui->buttonBox->setFont(GUIUtil::getSubLabelFont());
}

ReceiveRequestDialog::~ReceiveRequestDialog()
{
    delete ui;
}

void ReceiveRequestDialog::setModel(OptionsModel *_model)
{
    this->model = _model;

    if (_model)
        connect(_model, SIGNAL(displayUnitChanged(int)), this, SLOT(update()));

    // update the display unit if necessary
    update();
}

void ReceiveRequestDialog::setInfo(const SendCoinsRecipient &_info)
{
    this->info = _info;
    update();
}

void ReceiveRequestDialog::update()
{
    if(!model)
        return;
    QString target = info.label;
    if(target.isEmpty())
        target = info.address;
    setWindowTitle(tr("Request payment to %1").arg(target));

    QString uri = GUIUtil::formatNeuraiURI(info);
    ui->btnSaveAs->setEnabled(false);
    QString html;
    html += "<html><font face='verdana, arial, helvetica, sans-serif'>";
    html += "<b>"+tr("Payment information")+"</b><br>";
    html += "<b>"+tr("URI")+"</b>: ";
    html += "<a href=\""+uri+"\">" + GUIUtil::HtmlEscape(uri) + "</a><br>";
    if (info.address.startsWith("nsp1") || info.address.startsWith("tnsp1")) {
        html += "<b>"+tr("Silent payment code")+"</b>: " + GUIUtil::HtmlEscape(info.address) + "<br>";
        html += tr("Reusable: every payment to this code arrives at a new strict ECDSA address that only this wallet links to it.") + "<br>";
    } else {
        html += "<b>"+tr("Address")+"</b>: " + GUIUtil::HtmlEscape(info.address) + "<br>";
    }
    if(info.amount)
        html += "<b>"+tr("Amount")+"</b>: " + NeuraiUnits::formatHtmlWithUnit(model->getDisplayUnit(), info.amount) + "<br>";
    if(!info.label.isEmpty())
        html += "<b>"+tr("Label")+"</b>: " + GUIUtil::HtmlEscape(info.label) + "<br>";
    if(!info.message.isEmpty())
        html += "<b>"+tr("Message")+"</b>: " + GUIUtil::HtmlEscape(info.message) + "<br>";
    ui->outUri->setText(html);

#ifdef USE_QRCODE
    ui->lblQRCode->setText("");
    if(!uri.isEmpty())
    {
        // limit URI length
        if (uri.length() > MAX_URI_LENGTH)
        {
            ui->lblQRCode->setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        } else {
            QString error;
            const QImage image = NeuraiQRImage(uri, QR_IMAGE_SIZE, error, info.address, devicePixelRatioF());
            if (image.isNull())
            {
                ui->lblQRCode->setText(error);
                return;
            }
            ui->lblQRCode->setPixmap(QPixmap::fromImage(image));
            ui->btnSaveAs->setEnabled(true);
        }
    }
#endif
}

void ReceiveRequestDialog::on_btnCopyURI_clicked()
{
    GUIUtil::setClipboard(GUIUtil::formatNeuraiURI(info));
}

void ReceiveRequestDialog::on_btnCopyAddress_clicked()
{
    GUIUtil::setClipboard(info.address);
}
