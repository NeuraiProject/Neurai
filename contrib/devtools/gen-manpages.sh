#!/bin/sh

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

NEURAID=${NEURAID:-$SRCDIR/neuraid}
NEURAICLI=${NEURAICLI:-$SRCDIR/neurai-cli}
NEURAITX=${NEURAITX:-$SRCDIR/neurai-tx}
NEURAIQT=${NEURAIQT:-$SRCDIR/qt/neurai-qt}

[ ! -x $NEURAID ] && echo "$NEURAID not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
XNAVER=($($NEURAICLI --version | head -n1 | awk -F'[ -]' '{ print $6, $7 }'))

# Create a footer file with copyright content.
# This gets autodetected fine for neuraid if --version-string is not set,
# but has different outcomes for neurai-qt and neurai-cli.
echo "[COPYRIGHT]" > footer.h2m
$NEURAID --version | sed -n '1!p' >> footer.h2m

for cmd in $NEURAID $NEURAICLI $NEURAITX $NEURAIQT; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${XNAVER[0]} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-${XNAVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
