Translations
============

The Neurai project has been designed to support multiple localisations. This makes adding new phrases, and completely new languages easily achievable. Translations are kept as Qt `.ts` files in `src/qt/locale/` and are contributed through pull requests.

### Helping to translate
Multiple language support is critical in assisting Neurai's global adoption, and growth. One of Neurai's greatest strengths is cross-border money transfers, any help making that easier is greatly appreciated.

To update a language, open its `src/qt/locale/neurai_<lang>.ts` file in Qt Linguist (included in the Qt SDK, `linguist`), translate the unfinished strings, save the file and open a pull request with it. You can also ask in the [Neurai Discord](https://discord.gg/j2WgJjgj8t).

### Writing code with translations
We use automated scripts to help extract translations in both Qt, and non-Qt source files. It is rarely necessary to manually edit the files in `src/qt/locale/`. The translation source files must adhere to the following format:
`neurai_xx_YY.ts or neurai_xx.ts`

`src/qt/locale/neurai_en.ts` is treated in a special way. It is used as the source for all other translations. Whenever a string in the source code is changed, this file must be updated to reflect those changes. A custom script is used to extract strings from the non-Qt parts. This script makes use of `gettext`, so make sure that utility is installed (ie, `apt-get install gettext` on Ubuntu/Debian). Once this has been updated, `lupdate` (included in the Qt SDK) is used to update `neurai_en.ts`.

To automatically regenerate the `neurai_en.ts` file, run the following commands:
```sh
cd src/
make translate
```

`src/qt/neurai_locale.qrc` takes care of generating `.qm` (binary compiled) files from `.ts` (source files) files. It’s mostly automated, and you shouldn’t need to worry about it.

**Example Qt translation**
```cpp
QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
```

### Creating a pull-request
For general PRs, you shouldn’t include any updates to the translation source files. They will be updated periodically, primarily around pre-releases, allowing time for any new phrases to be translated before public releases. This is also important in avoiding translation related merge conflicts.

A translation PR should only change files in `src/qt/locale/` (and, for a new language, the manifest and Makefile entries described below).

### Synchronising translations
After `neurai_en.ts` has been regenerated with `make translate`, update a
language with `lupdate` so that the new strings appear as unfinished in Qt
Linguist:

    cd src/
    lupdate qt -locations relative -ts qt/locale/neurai_<lang>.ts

When a new language is added:

1. Update `src/qt/neurai_locale.qrc` manually or via
   `ls src/qt/locale/*ts|xargs -n1 basename|sed 's/\(neurai_\(.*\)\).ts/<file alias="\2">locale\/\1.qm<\/file>/'`
2. Update `src/Makefile.qt.include` manually or via
   `ls src/qt/locale/*ts|xargs -n1 basename|sed 's/\(neurai_\(.*\)\).ts/  qt\/locale\/\1.ts \\/'`
3. `git add` the new translation from `src/qt/locale/`

### Handling Plurals (in source files)
When new plurals are added to the source file, it's important to do the following steps:

1. Open `neurai_en.ts` in Qt Linguist (included in the Qt SDK)
2. Search for `%n`, which will take you to the parts in the translation that use plurals
3. Look for empty `English Translation (Singular)` and `English Translation (Plural)` fields
4. Add the appropriate strings for the singular and plural form of the base string
5. Mark the item as done (via the green arrow symbol in the toolbar)
6. Repeat from step 2, until all singular and plural forms are in the source file
7. Save the source file

### Translating a new language
To create a new language template, you will need to edit the languages manifest file `src/qt/neurai_locale.qrc` and add a new entry. Below is an example of the English language entry.

```xml
<qresource prefix="/translations">
    <file alias="en">locale/neurai_en.qm</file>
    ...
</qresource>
```

**Note:** that the language translation file **must end in `.qm`** (the compiled extension), and not `.ts`.

### Questions and general assistance
Ask in the [Neurai Discord](https://discord.gg/j2WgJjgj8t).
