// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_QT_GUITHEME_H
#define NEURAI_QT_GUITHEME_H

#include <QColor>
#include <QString>

class QApplication;
class QWidget;

/** Visual theme shared with the Neurai web wallet: flat surfaces, rounded
 *  cards and fields, neutral greys and a single orange accent. */
namespace GUITheme
{
    /** Font family used across the GUI. */
    extern const char* const FONT_FAMILY;

    /** Corner radius of cards and of input fields/buttons, in pixels. */
    static const int CARD_RADIUS = 12;
    static const int FIELD_RADIUS = 10;

    struct Tokens {
        QColor page;          //!< window background
        QColor surface;       //!< cards, fields, tables
        QColor surfaceAlt;    //!< hover, alternate rows, read-only fields
        QColor border;        //!< card borders and dividers
        QColor fieldBorder;   //!< input borders
        QColor text;          //!< primary text
        QColor textMuted;     //!< secondary text
        QColor primary;       //!< accent (buttons, active navigation)
        QColor primaryHover;
        QColor primaryText;   //!< text on top of the accent colour
        QColor accent;        //!< tinted surface for selections
        QColor success;
        QColor warning;
        QColor error;
        QColor shadow;
    };

    /** Tokens of the active theme (light or dark, see darkModeEnabled). */
    const Tokens& tokens();

    /** Register the bundled fonts and install style, palette, font and style
     *  sheet on the application. Must run before any window is created. */
    void apply(QApplication& app, bool dark);

    /** Turn a container (frame, scroll area...) into a card: surface colour,
     *  border and rounded corners. The rule targets the widget by object name
     *  so that child frames such as separator lines are left untouched.
     *  extraRules is appended inside the rule, e.g. "padding: 8px;". */
    void makeCard(QWidget* widget, const QString& extraRules = QString());
}

#endif // NEURAI_QT_GUITHEME_H
