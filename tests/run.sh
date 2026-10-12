#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# The whole suite, in the order that fails fastest: static checks, then version
# consistency, then unit tests, then the integration tests that need sockets.
# This is what CI runs and what the PKGBUILD's check() calls.
#
#     tests/run.sh            # everything
#     tests/run.sh 0.4.0      # ... and require that version (tag builds)
set -eu

cd "$(dirname "$0")/.."
JENNIFER=${JENNIFER:-jennifer}
# Globbed, not listed: a new topic module - or a module without its overlay -
# must not be able to arrive without the gates seeing it.
SOURCES="$(echo src/*.j) bin/ocsaml tests/mock-gateway.j tests/check-docs.j"
MODULES="$(ls src/*.j | grep -v '_test\.j$')"

# Every module needs a co-located white-box overlay; a missing one is a gap in
# the suite, not a module that happens to need no tests.
missing=''
for m in $MODULES; do
    case $m in src/saml.j) continue;; esac   # the facade has nothing of its own
    t="${m%.j}_test.j"
    [ -f "$t" ] || missing="$missing $t"
done
if [ -n "$missing" ]; then
    printf 'module(s) without a test overlay:%s\n' "$missing" >&2
    exit 1
fi

step() { printf '\n== %s\n' "$1"; }

step 'parse'
for f in $SOURCES; do
    "$JENNIFER" ast "$f" >/dev/null
    printf '  ok %s\n' "$f"
done

step 'format'
unformatted=$("$JENNIFER" fmt -l $SOURCES)
if [ -n "$unformatted" ]; then
    printf 'not formatted (run `jennifer fmt -w`):\n%s\n' "$unformatted" >&2
    exit 1
fi
printf '  ok, all formatted\n'

step 'lint'
# lint exits 0 even with findings, so the findings themselves are the gate.
findings=$("$JENNIFER" lint $SOURCES 2>&1 | grep -cE ': (info|warning|error):' || true)
if [ "$findings" != "0" ]; then
    "$JENNIFER" lint $SOURCES
    printf 'lint reported %s finding(s)\n' "$findings" >&2
    exit 1
fi
printf '  ok, no findings\n'

step 'doc comments'
for m in $MODULES; do
    "$JENNIFER" run tests/check-docs.j "$m"
done
"$JENNIFER" run tests/check-docs.j bin/ocsaml

step 'versions'
if [ $# -ge 1 ]; then
    ./tests/check-versions.sh "$1"
else
    ./tests/check-versions.sh
fi

step 'unit tests'
# One overlay per module, each spliced onto its own module.
unitfail=0
for t in src/*_test.j; do
    printf '\n-- %s\n' "$t"
    "$JENNIFER" test "$t" || unitfail=1
done
[ "$unitfail" = 0 ] || { printf 'unit tests failed\n' >&2; exit 1; }

step 'integration tests'
./tests/integration.sh

printf '\nall checks passed\n'
