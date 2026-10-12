#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# One version string, and six places that must agree with it: the two @version
# doc tags, the man page header, the PKGBUILD, the deck manifest that
# `jvc app install` records, and the unit suite's own assertion. They drift
# silently - nothing breaks at runtime when the man page claims a version the
# program does not - so a check is the only thing that keeps them honest.
#
# With an argument, also require that version (used by the tag build, where the
# git tag has to match what the tree says).
#
#     tests/check-versions.sh          # internally consistent?
#     tests/check-versions.sh 0.4.0    # ... and equal to 0.4.0?
set -eu

cd "$(dirname "$0")/.."
status=0

fail() {
    printf 'version mismatch: %s\n' "$1" >&2
    status=1
}

# The module constant is the source of truth.
version=$(sed -n 's/^def const APP_VERSION as string init "\(.*\)";$/\1/p' src/saml.j)
if [ -z "$version" ]; then
    printf 'could not read APP_VERSION from src/saml.j\n' >&2
    exit 1
fi
printf 'APP_VERSION            %s\n' "$version"

check() {
    printf '%-22s %s\n' "$2" "${1:-<missing>}"
    [ "$1" = "$version" ] || fail "$2 is '${1:-<missing>}', expected '$version'"
}

check "$(sed -n 's/^ \* @version \(.*\)$/\1/p' src/saml.j | head -1)" 'src @version'
check "$(sed -n 's/^ \* @version \(.*\)$/\1/p' bin/openconnect-saml | head -1)" 'bin @version'
check "$(sed -n 's/^\.TH .* "openconnect-saml \([^"]*\)".*$/\1/p' man/openconnect-saml.1)" 'man page'
check "$(sed -n 's/^pkgver=\(.*\)$/\1/p' packaging/arch/PKGBUILD)" 'PKGBUILD pkgver'

# deck.toml is what `jvc app install` records as the installed version, so a
# stale one here means jvc reports a version the program does not claim.
check "$(sed -n 's/^version = "\(.*\)"$/\1/p' deck.toml | head -1)" 'deck.toml version'

# The unit suite asserts APP_VERSION too, so it has to be told as well.
check "$(sed -n 's/.*testing.assertEqual(APP_VERSION, "\(.*\)");.*/\1/p' src/saml_test.j)" 'unit test'

if [ $# -ge 1 ]; then
    expected=${1#v}
    printf '%-22s %s\n' 'required' "$expected"
    [ "$version" = "$expected" ] || fail "tree says '$version', asked for '$expected'"
fi

if [ $status -eq 0 ]; then
    printf 'all version strings agree on %s\n' "$version"
fi
exit $status
