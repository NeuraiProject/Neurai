// Copyright (c) 2020 Hans Schmidt
// Copyright (c) 2017-2018 The Particl Core developers
// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mnemonicdialog.h>

#include <qt/guitheme.h>
#include <random.h>
#include <support/cleanse.h>
#include <util.h>
#include <wallet/bip39.h>
#include <wallet/wallet.h>

#include <QCheckBox>
#include <QComboBox>
#include <QCursor>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScreen>
#include <QScrollArea>
#include <QStackedWidget>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <chrono>
#include <functional>

namespace {

const int NUM_WORDS = 12;
// Extra randomness is collected for this long before new words are shown.
const int ENTROPY_MS = 2000;
const int ENTROPY_TICK_MS = 15;

int64_t HighResolutionTicks()
{
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
}

// Address types in the order of the chooser cards
const std::array<WalletAddressType, 3> ADDRESS_TYPES = {WalletAddressType::LEGACY, WalletAddressType::PQ, WalletAddressType::ECDSA};

// The address type the dialog starts with: -addresstype, Legacy by default.
int PresetAddressTypeIndex()
{
    WalletAddressType type = DEFAULT_WALLET_ADDRESS_TYPE;
    ParseWalletAddressType(gArgs.GetArg("-addresstype", WalletAddressTypeName(DEFAULT_WALLET_ADDRESS_TYPE)), type);
    for (size_t i = 0; i < ADDRESS_TYPES.size(); ++i) {
        if (ADDRESS_TYPES[i] == type) return i;
    }
    return 0;
}

QString CssColor(const QColor& color)
{
    return QString("rgba(%1, %2, %3, %4)").arg(color.red()).arg(color.green()).arg(color.blue()).arg(color.alpha());
}

QColor WithAlpha(QColor color, int alpha)
{
    color.setAlpha(alpha);
    return color;
}

/** Single colour icon from one of the monochrome resource images. */
QPixmap TintedIcon(const QString& file, const QColor& color, int size, qreal dpr)
{
    QPixmap pixmap = QIcon(file).pixmap(QSize(size, size), dpr);
    QPainter painter(&pixmap);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(pixmap.rect(), color);
    return pixmap;
}

QLabel* MakeLabel(const QString& text, const char* objectName, QWidget* parent = nullptr)
{
    QLabel* label = new QLabel(text, parent);
    label->setObjectName(objectName);
    label->setWordWrap(true);
    return label;
}

/** Clickable card with an optional icon, a title and a description. */
class ChoiceCard : public QFrame
{
public:
    ChoiceCard(const QString& title, const QString& description, const QString& iconFile, bool chevron, std::function<void()> onClick, QWidget* parent = nullptr)
        : QFrame(parent), m_onClick(std::move(onClick))
    {
        setObjectName("choiceCard");
        setAttribute(Qt::WA_Hover);
        setFocusPolicy(Qt::StrongFocus);
        setCursor(Qt::PointingHandCursor);

        const GUITheme::Tokens& theme = GUITheme::tokens();
        QHBoxLayout* layout = new QHBoxLayout(this);
        layout->setContentsMargins(16, 14, 16, 14);
        layout->setSpacing(14);
        if (!iconFile.isEmpty()) {
            QLabel* icon = new QLabel(this);
            icon->setObjectName("cardIcon");
            icon->setFixedSize(44, 44);
            icon->setAlignment(Qt::AlignCenter);
            icon->setPixmap(TintedIcon(iconFile, theme.primary, 22, devicePixelRatioF()));
            layout->addWidget(icon, 0, Qt::AlignVCenter);
        }
        QVBoxLayout* text = new QVBoxLayout();
        text->setSpacing(3);
        text->addWidget(MakeLabel(title, "cardTitle", this));
        text->addWidget(MakeLabel(description, "cardText", this));
        layout->addLayout(text, 1);
        if (chevron) {
            QLabel* arrow = new QLabel(this);
            arrow->setPixmap(TintedIcon(":/icons/ui_chevron_right", theme.textMuted, 18, devicePixelRatioF()));
            layout->addWidget(arrow, 0, Qt::AlignVCenter);
        }
    }

    void setSelected(bool selected)
    {
        setProperty("selected", selected);
        style()->unpolish(this);
        style()->polish(this);
    }

protected:
    void mouseReleaseEvent(QMouseEvent* event) override
    {
        if (event->button() == Qt::LeftButton && rect().contains(event->position().toPoint()))
            m_onClick();
        QFrame::mouseReleaseEvent(event);
    }

    void keyPressEvent(QKeyEvent* event) override
    {
        if (event->key() == Qt::Key_Space || event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
            m_onClick();
            return;
        }
        QFrame::keyPressEvent(event);
    }

private:
    std::function<void()> m_onClick;
};

QString SetupStyleSheet()
{
    const GUITheme::Tokens& t = GUITheme::tokens();
    return QString(
        "QDialog#walletSetup { background-color: %1; }"
        "QWidget#setupPage { background: transparent; }"
        "QLabel#setupTitle { color: %2; font-size: 24px; font-weight: 700; }"
        "QLabel#setupSubtitle { color: %3; font-size: 14px; }"
        "QLabel#sectionLabel { color: %2; font-size: 13px; font-weight: 600; }"
        "QLabel#hintText { color: %3; font-size: 12px; }"
        "QLabel#errorText { color: %7; font-size: 13px; font-weight: 600; }"
        "QFrame#choiceCard { background-color: %1; border: 1px solid %4; border-radius: 12px; }"
        "QFrame#choiceCard:hover, QFrame#choiceCard:focus { border-color: %5; }"
        "QFrame#choiceCard[selected=\"true\"] { border: 2px solid %5; background-color: %6; }"
        "QLabel#cardIcon { background-color: %6; border-radius: 12px; }"
        "QLabel#cardTitle { color: %2; font-size: 15px; font-weight: 600; background: transparent; }"
        "QLabel#cardText { color: %3; font-size: 12px; background: transparent; }"
        "QFrame#wordChip { background-color: %8; border: 1px solid %4; border-radius: 8px; }"
        "QLabel#wordIndex { color: %3; font-size: 12px; background: transparent; }"
        "QLabel#wordText { color: %2; font-size: 14px; font-weight: 600; background: transparent; }"
        "QFrame#warningBox { background-color: %9; border: 1px solid %10; border-radius: 10px; }"
        "QLabel#warningText { color: %2; font-size: 13px; background: transparent; }")
        .arg(CssColor(t.surface), CssColor(t.text), CssColor(t.textMuted), CssColor(t.border), CssColor(t.primary),
             CssColor(t.accent), CssColor(t.error), CssColor(t.surfaceAlt), CssColor(WithAlpha(t.warning, 30)))
        .arg(CssColor(WithAlpha(t.warning, 110)));
}

/** Page container that scrolls when the screen is too small for it. */
QWidget* Scrollable(QWidget* page)
{
    QScrollArea* scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setObjectName("setupScroll");
    scroll->setStyleSheet("QScrollArea#setupScroll { background: transparent; border: none; }");
    scroll->viewport()->setAutoFillBackground(false);
    scroll->setWidget(page);
    return scroll;
}

QWidget* NewPage(QVBoxLayout*& layout)
{
    QWidget* page = new QWidget();
    page->setObjectName("setupPage");
    layout = new QVBoxLayout(page);
    layout->setContentsMargins(36, 26, 36, 22);
    layout->setSpacing(11);
    return page;
}

QComboBox* LanguageCombo()
{
    QComboBox* combo = new QComboBox();
    const auto languages = CMnemonic::GetLanguagesDetails();
    for (const auto& language : languages) {
        combo->addItem(language.label);
    }
    return combo;
}

/** Words as typed by the user: single spaces, lower case. Any other
 *  spelling of a valid phrase would fail CMnemonic::Check anyway. */
QString NormalizedWords(const QString& text)
{
    return text.simplified().toLower();
}

} // namespace

MnemonicDialog::MnemonicDialog(QWidget *parent) :
    QDialog(parent)
{
    setObjectName("walletSetup");
    setWindowTitle(tr("Wallet Setup"));
    setStyleSheet(SetupStyleSheet());

    createType = restoreType = PresetAddressTypeIndex();

    pages = new QStackedWidget(this);
    pages->addWidget(Scrollable(createWelcomePage()));
    pages->addWidget(Scrollable(createNewWalletPage()));
    pages->addWidget(Scrollable(createRestorePage()));

    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(pages);

    // Tall enough for the longest page, but never taller than the screen (pages scroll)
    const QRect available = screen()->availableGeometry();
    resize(QSize(720, 760).boundedTo(available.size() * 0.92));
    showPage(0);
}

MnemonicDialog::~MnemonicDialog()
{
    // Do not leave the generated words lying around in memory longer than needed
    std::fill(generatedWords.begin(), generatedWords.end(), '\0');
}

void MnemonicDialog::showPage(int index)
{
    // The words are generated only when the user asks for them.
    pages->setCurrentIndex(index);
}

QWidget* MnemonicDialog::createWelcomePage()
{
    QVBoxLayout* layout;
    QWidget* page = NewPage(layout);
    layout->setContentsMargins(48, 48, 48, 40);

    QLabel* logo = new QLabel();
    logo->setPixmap(QIcon(":/icons/neurai").pixmap(QSize(80, 80), devicePixelRatioF()));
    logo->setAlignment(Qt::AlignCenter);

    QLabel* title = MakeLabel(tr("Welcome to Neurai"), "setupTitle");
    title->setAlignment(Qt::AlignCenter);
    QLabel* subtitle = MakeLabel(tr("No wallet was found in this data directory, so a new one will be created. "
                                    "Choose how you want to set it up."), "setupSubtitle");
    subtitle->setAlignment(Qt::AlignCenter);

    ChoiceCard* create = new ChoiceCard(tr("Create a new wallet"),
                                        tr("Generate a new set of 12 recovery words (BIP39)."),
                                        ":/icons/setup_create", true, [this] { showPage(1); });
    ChoiceCard* restore = new ChoiceCard(tr("Restore a wallet"),
                                         tr("Use the recovery words of a wallet you already have."),
                                         ":/icons/setup_restore", true, [this] { showPage(2); });

    layout->addStretch(1);
    layout->addWidget(logo);
    layout->addSpacing(6);
    layout->addWidget(title);
    layout->addWidget(subtitle);
    layout->addSpacing(22);
    layout->addWidget(create);
    layout->addWidget(restore);
    layout->addStretch(2);
    return page;
}

QWidget* MnemonicDialog::createAddressTypeChooser(QList<QFrame*>& cards, int& selected)
{
    QWidget* chooser = new QWidget();
    QHBoxLayout* row = new QHBoxLayout(chooser);
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(10);

    const QString titles[] = {tr("Legacy"), tr("Post-Quantum"), tr("ECDSA")};
    const QString descriptions[] = {
        tr("Classic Base58 addresses (secp256k1). Default."),
        tr("Quantum-resistant ML-DSA-44 (FIPS 204), witness v2."),
        tr("secp256k1 signatures, strict witness v3 addresses."),
    };
    for (int i = 0; i < 3; ++i) {
        ChoiceCard* card = new ChoiceCard(titles[i], descriptions[i], QString(), false,
                                          [this, &cards, &selected, i] { selectAddressType(cards, selected, i); });
        cards << card;
        row->addWidget(card, 1);
    }
    selectAddressType(cards, selected, selected);
    return chooser;
}

void MnemonicDialog::selectAddressType(QList<QFrame*>& cards, int& selected, int index)
{
    selected = index;
    for (int i = 0; i < cards.size(); ++i) {
        static_cast<ChoiceCard*>(cards[i])->setSelected(i == index);
    }
}

QWidget* MnemonicDialog::createPassphraseField(QLineEdit*& edit, const QString& hint)
{
    QWidget* field = new QWidget();
    QVBoxLayout* layout = new QVBoxLayout(field);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    edit = new QLineEdit();
    edit->setPlaceholderText(tr("Seed extension word (optional)"));
    edit->setToolTip(tr("The Seed Extension Word is like adding a password to your seed phrase. If someone finds your "
                        "12 words but you have chosen an extension word, they will not be able to access your wallet. "
                        "Without it, the wallet cannot be restored."));
    layout->addWidget(MakeLabel(tr("Seed extension word"), "sectionLabel"));
    layout->addWidget(edit);
    layout->addWidget(MakeLabel(hint, "hintText"));
    return field;
}

QWidget* MnemonicDialog::createNewWalletPage()
{
    QVBoxLayout* layout;
    QWidget* page = NewPage(layout);

    layout->addWidget(MakeLabel(tr("Your recovery words"), "setupTitle"));
    layout->addWidget(MakeLabel(tr("Press Generate words to create your 12 recovery words, then write them down in order "
                                   "and keep them somewhere safe. They are the only way to restore your wallet."), "setupSubtitle"));

    // Language and generate
    createLanguage = LanguageCombo();
    generateButton = new QPushButton(tr("Generate words"));
    generateButton->setProperty("primary", true);
    generateButton->setAutoDefault(false);
    QHBoxLayout* toolbar = new QHBoxLayout();
    toolbar->addWidget(createLanguage);
    toolbar->addStretch();
    toolbar->addWidget(generateButton);
    layout->addLayout(toolbar);
    connect(generateButton, &QPushButton::clicked, this, &MnemonicDialog::generateWords);
    // Another language shows the same words (same entropy) in that word list.
    connect(createLanguage, qOverload<int>(&QComboBox::currentIndexChanged), this, &MnemonicDialog::showWords);

    // Extra randomness collection, shown while it runs
    entropyBar = new QProgressBar();
    entropyBar->setRange(0, 100);
    entropyBar->setTextVisible(false);
    entropyBar->setFixedHeight(8);
    entropyBar->setStyleSheet(QString("QProgressBar { min-height: 8px; max-height: 8px; border-radius: 4px; background-color: %1; }"
                                      "QProgressBar::chunk { border-radius: 4px; background-color: %2; }")
                                  .arg(CssColor(GUITheme::tokens().border), CssColor(GUITheme::tokens().primary)));
    entropyBar->hide();
    layout->addWidget(entropyBar);
    entropyNote = MakeLabel(tr("Adding extra randomness from timing jitter and mouse movement to the system random generator…"),
                            "hintText");
    entropyNote->hide();
    layout->addWidget(entropyNote);
    entropyTimer = new QTimer(this);
    entropyTimer->setInterval(ENTROPY_TICK_MS);
    connect(entropyTimer, &QTimer::timeout, this, &MnemonicDialog::collectEntropy);

    // Words as numbered chips, 4 columns x 3 rows
    QGridLayout* grid = new QGridLayout();
    grid->setHorizontalSpacing(8);
    grid->setVerticalSpacing(8);
    for (int i = 0; i < NUM_WORDS; ++i) {
        QFrame* chip = new QFrame();
        chip->setObjectName("wordChip");
        QHBoxLayout* chipLayout = new QHBoxLayout(chip);
        chipLayout->setContentsMargins(10, 8, 10, 8);
        chipLayout->setSpacing(8);
        QLabel* index = new QLabel(QString::number(i + 1));
        index->setObjectName("wordIndex");
        index->setFixedWidth(18);
        index->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        QLabel* word = new QLabel();
        word->setObjectName("wordText");
        word->setTextInteractionFlags(Qt::NoTextInteraction);
        chipLayout->addWidget(index);
        chipLayout->addWidget(word, 1);
        wordLabels << word;
        grid->addWidget(chip, i / 4, i % 4);
    }
    layout->addLayout(grid);

    // Warning
    QFrame* warning = new QFrame();
    warning->setObjectName("warningBox");
    QHBoxLayout* warningLayout = new QHBoxLayout(warning);
    warningLayout->setContentsMargins(14, 10, 14, 10);
    warningLayout->setSpacing(12);
    QLabel* warningIcon = new QLabel();
    warningIcon->setPixmap(TintedIcon(":/icons/setup_warning", GUITheme::tokens().warning, 20, devicePixelRatioF()));
    warningLayout->addWidget(warningIcon, 0, Qt::AlignTop);
    warningLayout->addWidget(MakeLabel(tr("Anyone with these words can take your funds: never share them. "
                                          "If you lose them, together with the optional extension word, the wallet cannot be recovered."),
                                       "warningText"), 1);
    layout->addWidget(warning);

    layout->addWidget(MakeLabel(tr("Address type"), "sectionLabel"));
    layout->addWidget(createAddressTypeChooser(createTypeCards, createType));
    layout->addWidget(MakeLabel(tr("The address type is stored in the wallet when it is created and cannot be changed later. "
                                   "Post-Quantum and ECDSA addresses can only be used once the network activates them."),
                                "hintText"));

    layout->addWidget(createPassphraseField(createPassphrase,
        tr("An extra word you choose and remember, which protects the 12 words. Write it down too.")));

    createError = MakeLabel(QString(), "errorText");
    createError->hide();
    layout->addWidget(createError);

    confirmBackup = new QCheckBox(tr("I have written down my recovery words and will keep them safe"));
    connect(confirmBackup, &QCheckBox::toggled, this, &MnemonicDialog::updateCreateButton);
    layout->addSpacing(4);
    layout->addWidget(confirmBackup);

    QPushButton* back = new QPushButton(tr("Back"));
    back->setAutoDefault(false);
    createButton = new QPushButton(tr("Create wallet"));
    createButton->setProperty("primary", true);
    createButton->setAutoDefault(false);
    createButton->setEnabled(false);
    connect(back, &QPushButton::clicked, this, [this] { showPage(0); });
    connect(createButton, &QPushButton::clicked, this, &MnemonicDialog::createWallet);
    QHBoxLayout* buttons = new QHBoxLayout();
    buttons->addWidget(back);
    buttons->addStretch();
    buttons->addWidget(createButton);
    layout->addStretch(1);
    layout->addLayout(buttons);
    return page;
}

QWidget* MnemonicDialog::createRestorePage()
{
    QVBoxLayout* layout;
    QWidget* page = NewPage(layout);

    layout->addWidget(MakeLabel(tr("Restore a wallet"), "setupTitle"));
    layout->addWidget(MakeLabel(tr("Enter the recovery words of your wallet in order, separated by spaces."), "setupSubtitle"));

    restoreLanguage = LanguageCombo();
    QHBoxLayout* toolbar = new QHBoxLayout();
    toolbar->addWidget(restoreLanguage);
    toolbar->addStretch();
    layout->addLayout(toolbar);
    connect(restoreLanguage, qOverload<int>(&QComboBox::currentIndexChanged), this, &MnemonicDialog::updateRestoreState);

    restoreWords = new QPlainTextEdit();
    restoreWords->setPlaceholderText(tr("word1 word2 word3 ..."));
    restoreWords->setTabChangesFocus(true);
    restoreWords->setFixedHeight(110);
    layout->addWidget(restoreWords);
    connect(restoreWords, &QPlainTextEdit::textChanged, this, &MnemonicDialog::updateRestoreState);

    restoreCounter = MakeLabel(QString(), "hintText");
    layout->addWidget(restoreCounter);

    layout->addSpacing(4);
    layout->addWidget(MakeLabel(tr("Address type of the wallet being restored"), "sectionLabel"));
    layout->addWidget(createAddressTypeChooser(restoreTypeCards, restoreType));
    layout->addWidget(MakeLabel(tr("Choose the type the wallet was created with: each type derives its own addresses from the seed, "
                                   "so restoring with a different type shows a different wallet."),
                                "hintText"));

    layout->addSpacing(4);
    layout->addWidget(createPassphraseField(restorePassphrase,
        tr("Only if the wallet was created with an extension word.")));

    restoreError = MakeLabel(QString(), "errorText");
    restoreError->hide();
    layout->addWidget(restoreError);

    QPushButton* back = new QPushButton(tr("Back"));
    back->setAutoDefault(false);
    restoreButton = new QPushButton(tr("Restore wallet"));
    restoreButton->setProperty("primary", true);
    restoreButton->setAutoDefault(false);
    connect(back, &QPushButton::clicked, this, [this] { showPage(0); });
    connect(restoreButton, &QPushButton::clicked, this, &MnemonicDialog::restoreWallet);
    QHBoxLayout* buttons = new QHBoxLayout();
    buttons->addWidget(back);
    buttons->addStretch();
    buttons->addWidget(restoreButton);
    layout->addStretch(1);
    layout->addLayout(buttons);

    updateRestoreState();
    return page;
}

void MnemonicDialog::generateWords()
{
    if (entropyTimer->isActive()) return;
    createError->hide();
    // New words invalidate the confirmation given for the previous ones.
    entropy.clear();
    showWords();
    confirmBackup->setChecked(false);
    generateButton->setEnabled(false);
    createLanguage->setEnabled(false);

    entropyPool.Reset();
    const std::string tag = "Neurai/BIP39/extra-entropy/v1";
    entropyPool.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
    entropyClock.start();
    entropyBar->setValue(0);
    entropyBar->show();
    entropyNote->show();
    entropyTimer->start();
}

void MnemonicDialog::collectEntropy()
{
    // CPU timing jitter: how long a short busy loop takes depends on caches,
    // interrupts and the scheduler, so the low bits of each duration are
    // unpredictable. The cursor position adds whatever the user does meanwhile.
    for (int i = 0; i < 64; ++i) {
        const int64_t start = HighResolutionTicks();
        volatile uint64_t x = static_cast<uint64_t>(start);
        for (int k = 0; k < 64 + (start & 31); ++k) x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        const int64_t delta = HighResolutionTicks() - start;
        entropyPool.Write(reinterpret_cast<const unsigned char*>(&delta), sizeof(delta));
    }
    const QPoint cursor = QCursor::pos();
    const int64_t sample[3] = {cursor.x(), cursor.y(), HighResolutionTicks()};
    entropyPool.Write(reinterpret_cast<const unsigned char*>(sample), sizeof(sample));

    const qint64 elapsed = entropyClock.elapsed();
    entropyBar->setValue(static_cast<int>(std::min<qint64>(100, elapsed * 100 / ENTROPY_MS)));
    if (elapsed < ENTROPY_MS) return;
    entropyTimer->stop();

    // Final entropy = SHA-512(tag, system strong randomness, collected samples):
    // as unpredictable as the best of both sources.
    unsigned char system[32], extra[CSHA512::OUTPUT_SIZE], mixed[CSHA512::OUTPUT_SIZE];
    GetStrongRandBytes(system, sizeof(system));
    entropyPool.Finalize(extra);
    const std::string tag = "Neurai/BIP39/entropy/v1";
    CSHA512()
        .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
        .Write(system, sizeof(system))
        .Write(extra, sizeof(extra))
        .Finalize(mixed);
    entropy.assign(mixed, mixed + 32);
    memory_cleanse(system, sizeof(system));
    memory_cleanse(extra, sizeof(extra));
    memory_cleanse(mixed, sizeof(mixed));
    entropyPool.Reset();

    entropyBar->hide();
    entropyNote->hide();
    generateButton->setText(tr("New words"));
    generateButton->setProperty("primary", false);
    generateButton->style()->unpolish(generateButton);
    generateButton->style()->polish(generateButton);
    generateButton->setEnabled(true);
    createLanguage->setEnabled(true);
    showWords();
}

void MnemonicDialog::showWords()
{
    std::fill(generatedWords.begin(), generatedWords.end(), '\0');
    generatedWords.clear();
    if (entropy.size() >= 16) {
        // 128 bits of entropy (plus a 4-bit checksum) give the 12 words.
        const SecureString words = CMnemonic::FromData(entropy, 16, createLanguage->currentIndex());
        generatedWords.assign(words.begin(), words.end());
    }
    const QStringList list = QString::fromStdString(generatedWords).split(' ', Qt::SkipEmptyParts);
    for (int i = 0; i < wordLabels.size(); ++i) {
        wordLabels[i]->setText(i < list.size() ? list[i] : QString());
    }
    updateCreateButton();
}

void MnemonicDialog::updateCreateButton()
{
    createButton->setEnabled(confirmBackup->isChecked() && !generatedWords.empty() && !entropyTimer->isActive());
}

void MnemonicDialog::createWallet()
{
    if (generatedWords.empty()) {
        createError->setText(tr("Generate your recovery words first."));
        createError->show();
        return;
    }
    const SecureString words(generatedWords.begin(), generatedWords.end());
    if (!CMnemonic::Check(words, createLanguage->currentIndex())) {
        createError->setText(tr("Words are not valid, please generate new words and try again."));
        createError->show();
        return;
    }

    my_words = generatedWords;
    my_passphrase = createPassphrase->text().toStdString();
    my_address_type = ADDRESS_TYPES[createType];
    accept();
}

void MnemonicDialog::updateRestoreState()
{
    restoreError->hide();
    const QString words = NormalizedWords(restoreWords->toPlainText());
    const int count = words.isEmpty() ? 0 : words.count(' ') + 1;
    const bool validCount = count == 12 || count == 18 || count == 24;
    const GUITheme::Tokens& theme = GUITheme::tokens();
    const QString counted = count == 1 ? tr("1 word") : tr("%1 words").arg(count);
    restoreCounter->setText(counted + QString::fromUtf8(" · ") + tr("12, 18 or 24 words"));
    restoreCounter->setStyleSheet(validCount ? QString("color: %1;").arg(theme.success.name()) : QString());
    restoreButton->setEnabled(count > 0);
}

void MnemonicDialog::restoreWallet()
{
    const std::string words = NormalizedWords(restoreWords->toPlainText()).toStdString();
    const int language = restoreLanguage->currentIndex();
    const SecureString check(words.begin(), words.end());
    if (!CMnemonic::Check(check, language)) {
        QString message = tr("Words are not valid, please check the words and the language, and try again.");
        restoreError->setText(message);
        restoreError->show();
        return;
    }

    my_words = words;
    my_passphrase = restorePassphrase->text().toStdString();
    my_address_type = ADDRESS_TYPES[restoreType];
    accept();
}
