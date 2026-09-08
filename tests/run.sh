#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# The whole suite, in the order that fails fastest: static checks, then version
# consistency, then unit tests, then the integration tests that need sockets.
# This is what CI runs and what the PKGBUILD's check() calls.
#
#     tests/run.sh            # everything
#     tests/run.sh 0.3.0      # ... and require that version (tag builds)
set -eu

cd "$(dirname "$0")/.."
JENNIFER=${JENNIFER:-jennifer}
SOURCES='src/saml.j src/saml_test.j bin/openconnect-saml tests/mock-gateway.j tests/check-docs.j'

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
"$JENNIFER" run tests/check-docs.j src/saml.j
"$JENNIFER" run tests/check-docs.j bin/openconnect-saml

step 'versions'
if [ $# -ge 1 ]; then
    ./tests/check-versions.sh "$1"
else
    ./tests/check-versions.sh
fi

step 'unit tests'
"$JENNIFER" test src/saml_test.j

step 'integration tests'
./tests/integration.sh

printf '\nall checks passed\n'
