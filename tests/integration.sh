#!/bin/bash
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# End-to-end tests: the real command line, against the mock gateway in
# mock-gateway.j. These cover what the unit suite cannot - argument handling,
# the HTTP conversation, and the paths through authenticate() - without needing
# a VPN, root, or a browser.
#
#     tests/integration.sh
set -uo pipefail

cd "$(dirname "$0")/.."
CLI="bin/ocsaml"
JENNIFER=${JENNIFER:-jennifer}
TMP=$(mktemp -d)
PORT_PLAIN=18081
PORT_EXTERNAL=18082
PORT_REFUSE=18083
PORT_DUO=18084
PORT_FACTORS=18085

pass=0
fail=0
skipped=0
pids=()

cleanup() {
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

start_mock() {
    "$JENNIFER" run tests/mock-gateway.j "$1" "$2" >"$TMP/mock-$1.out" 2>"$TMP/mock-$1.err" &
    pids+=($!)
}

wait_for_port() {
    for _ in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- ; return 0; fi
        sleep 0.2
    done
    echo "mock on port $1 never came up" >&2
    return 1
}

# ok NAME EXPECTED-SUBSTRING -- command...
# run the CLI, bounded, with no stdin: a test must never wait for a person.
run_cli() { timeout 60 "$JENNIFER" run "$CLI" "$@" </dev/null; }

# run the CLI, bounded, feeding it one line - for the paste prompt.
run_cli_in() {
    local input=$1; shift
    printf '%s\n' "$input" | timeout 60 "$JENNIFER" run "$CLI" "$@"
}

ok() {
    local name=$1 want=$2; shift 3
    local out; out=$("$@" 2>&1)
    if printf '%s' "$out" | grep -qF -- "$want"; then
        printf 'PASS %s\n' "$name"
        pass=$((pass + 1))
    else
        printf 'FAIL %s\n     wanted: %s\n     got:    %s\n' \
            "$name" "$want" "$(printf '%s' "$out" | tail -3 | tr '\n' '|')"
        fail=$((fail + 1))
    fi
}

# skip NAME REASON
# Reported, not silently dropped: a test that cannot run here is a gap, and the
# summary has to say so.
skip() {
    printf 'SKIP %s (%s)\n' "$1" "$2"
    skipped=$((skipped + 1))
}

# exits NAME EXPECTED-CODE -- command...
exits() {
    local name=$1 want=$2; shift 3
    "$@" >/dev/null 2>&1
    local got=$?
    if [ "$got" = "$want" ]; then
        printf 'PASS %s\n' "$name"
        pass=$((pass + 1))
    else
        printf 'FAIL %s\n     wanted exit %s, got %s\n' "$name" "$want" "$got"
        fail=$((fail + 1))
    fi
}

export OCSAML_CONFIG=/nonexistent

# A stub openconnect, so the suite tests the command line this program builds
# rather than whether a VPN client happens to be installed. It answers the two
# probes (--version, --help) and the --authenticate handoff; it never connects.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/openconnect" <<'STUB'
#!/bin/sh
case "$1" in
  --version) echo "OpenConnect version v9.12"; exit 0;;
  --help)    echo "      --external-browser=BROWSER  Use external browser for SAML"; exit 0;;
esac
for a in "$@"; do
  if [ "$a" = "--authenticate" ]; then
    echo "COOKIE='STUB-COOKIE'"
    echo "HOST='127.0.0.1'"
    echo "CONNECT_URL='http://127.0.0.1/stub'"
    echo "FINGERPRINT='pin-sha256:STUB'"
    exit 0
  fi
done
echo "stub openconnect: $*" >&2
exit 0
STUB
chmod +x "$TMP/bin/openconnect"
export PATH="$TMP/bin:$PATH"

start_mock $PORT_PLAIN plain
start_mock $PORT_EXTERNAL external
start_mock $PORT_REFUSE refuse
start_mock $PORT_DUO duo
start_mock $PORT_FACTORS factors
for p in $PORT_PLAIN $PORT_EXTERNAL $PORT_REFUSE $PORT_DUO $PORT_FACTORS; do
    wait_for_port "$p" || exit 1
done

BASE="http://127.0.0.1:$PORT_PLAIN/saml"

# --- the command line itself -------------------------------------------------
ok    'version prints one'  '.' -- run_cli --version
exits 'help exits 0'        0 -- run_cli --help
exits 'no command exits 2'  2 -- run_cli
exits 'unknown flag exits 2'  2 -- run_cli connect --nosuchflag
exits 'unknown command exits 2' 2 -- run_cli frobnicate
exits 'bad mode exits 2'    2 -- run_cli connect --mode wibble
ok   'unknown flag names it' 'unknown flag --nosuchflag' -- run_cli connect --nosuchflag
ok   'no server configured' 'no gateway URL' -- run_cli probe

# --- refusals that protect a credential --------------------------------------
# A remote http:// gateway is refused outright: the token and the session cookie
# are bearer credentials. Loopback is exempt, which is what the rest of this
# suite relies on, so both halves are checked here.
ok 'plain http is refused' 'refusing to authenticate over plain http' -- \
    run_cli probe --server "http://vpn.example.com/saml"
ok 'loopback http is not refused' 'mock_saml' -- run_cli probe --server "$BASE"
# The password and skipVerify must never combine.
ok 'insecure refuses browserless' 'not allowed together' -- \
    run_cli cookie --mode browserless --user jdoe --insecure --server "$BASE"

# --- probe -------------------------------------------------------------------
ok 'probe reports the tunnel group' 'mock_saml' -- run_cli probe --server "$BASE"
ok 'probe reports the cookie name' 'acSamlv2Token' -- run_cli probe --server "$BASE"
ok 'probe reports the classic flow' 'webview / classic' -- run_cli probe --server "$BASE"
ok 'probe sees an external-browser gateway' 'browser mode       external' -- \
    run_cli probe --server "http://127.0.0.1:$PORT_EXTERNAL/saml"
ok 'probe survives a gateway that refuses the offer' 'refused by this gateway' -- \
    run_cli probe --server "http://127.0.0.1:$PORT_REFUSE/saml"

# --- token mode, pasted ------------------------------------------------------
paste_cookie() { run_cli_in "$1" cookie --server "$2" --browser - --capture paste; }
ok 'paste flow yields a session' "SESSION-abc123" -- paste_cookie THE-SSO-TOKEN "$BASE"
ok 'paste flow reports the pin' "pin-sha256:MOCKHASH" -- paste_cookie THE-SSO-TOKEN "$BASE"
ok 'paste flow rejects a bad token' 'did not complete the login' -- paste_cookie WRONG "$BASE"
ok 'paste accepts a name=value pair' "SESSION-abc123" -- \
    paste_cookie 'acSamlv2Token=THE-SSO-TOKEN' "$BASE"
ok 'refusing gateway still logs in' "SESSION-abc123" -- \
    paste_cookie THE-SSO-TOKEN "http://127.0.0.1:$PORT_REFUSE/saml"

# --- connect --print ---------------------------------------------------------
print_cmd() { run_cli_in THE-SSO-TOKEN connect --server "$BASE" \
    --browser - --capture paste --print; }
ok 'print emits a stdin pipeline' '--cookie-on-stdin' -- print_cmd
ok 'print pins the certificate'   "--servercert' 'pin-sha256:MOCKHASH" -- print_cmd
ok 'print keeps the cookie off the argv' "printf '%s\\n' 'SESSION-abc123'" -- print_cmd

# --- browserless -------------------------------------------------------------
bl() {
    OCSAML_PASSWORD=$1 run_cli cookie --server "$2" \
        --mode browserless --user "${3:-jdoe}"
}
ok 'browserless logs in'        "SESSION-abc123" -- bl hunter2 "$BASE"
ok 'browserless rejects a bad password' 'rejected the credentials' -- bl wrong "$BASE"
ok 'browserless stops at Duo'   'reached Duo' -- bl hunter2 "http://127.0.0.1:$PORT_DUO/saml"
ok 'browserless shows the trail' '1) GET' -- bl hunter2 "http://127.0.0.1:$PORT_DUO/saml"
no_user() { OCSAML_PASSWORD=x run_cli cookie --server "$BASE" --mode browserless; }
ok 'browserless needs a username' 'no username' -- no_user

# --- external-browser handoff ------------------------------------------------
ok 'external mode hands off to openconnect' "STUB-COOKIE" -- \
    run_cli cookie --server "http://127.0.0.1:$PORT_EXTERNAL/saml" --browser chromium
ok 'auto picks external when the gateway offers it' "pin-sha256:STUB" -- \
    run_cli cookie --server "http://127.0.0.1:$PORT_EXTERNAL/saml" --browser chromium

# --- choosing a second factor ------------------------------------------------
FACTORS="http://127.0.0.1:$PORT_FACTORS/saml"
blf() {
    OCSAML_PASSWORD=hunter2 run_cli cookie --server "$FACTORS" \
        --mode browserless --user jdoe "$@"
}
ok 'factor picks the named control' "SESSION-abc123" -- blf --factor passcode
ok 'factor is matched case-insensitively' "SESSION-abc123" -- blf --factor PASSCODE
ok 'the wrong factor goes the wrong way' 'page: Wrong factor' -- blf --factor push
ok 'an unknown factor is refused, not guessed' 'no way to pick' -- blf --factor pigeon
ok 'the refusal lists what is on offer' '"Duo Push", "Passcode", "WebAuthn"' -- \
    blf --factor pigeon
ok 'the refusal says how to pass one' '--factor push' -- blf --factor pigeon
ok 'a two-word factor works quoted' "SESSION-abc123" -- blf --factor 'passcode'
ok 'without a factor the first control wins' 'page: Wrong factor' -- blf

# --- capture selection -------------------------------------------------------
ok 'cdp refuses a browser that cannot do it' 'does not speak the DevTools protocol' -- \
    run_cli cookie --server "$BASE" --capture cdp --browser firefox

# A browser that dies on startup must be reported with its own reason, not as a
# 20-second wait ending in a guess about a stale profile. The name has to look
# Chromium-based for the CDP path to be taken at all.
mkdir -p "$TMP/fakebin"
cat > "$TMP/fakebin/chromium" <<'FAKE'
#!/bin/sh
echo "Running as root without --no-sandbox is not supported." >&2
exit 1
FAKE
chmod +x "$TMP/fakebin/chromium"
# Whether the browser is even reached depends on who we are: as root with no
# SUDO_USER the capture refuses up front, which is a different assertion. CI runs
# this container as root, so both cases are covered, one per euid.
if [ "$(id -u)" = 0 ] && [ -z "${SUDO_USER:-}" ]; then
    skip 'a browser that exits is reported as such' 'needs a non-root euid'
    skip 'and quotes what the browser said' 'needs a non-root euid'
    ok 'as root with no SUDO_USER the capture refuses up front' \
        'SUDO_USER to hand it back to' -- \
        run_cli cookie --server "$BASE" --capture cdp --browser "$TMP/fakebin/chromium"
    ok 'and says to run as your desktop user' 'as your normal desktop user' -- \
        run_cli cookie --server "$BASE" --capture cdp --browser "$TMP/fakebin/chromium"
else
    ok 'a browser that exits is reported as such' 'exited without opening its debug port' -- \
        run_cli cookie --server "$BASE" --capture cdp --browser "$TMP/fakebin/chromium"
    ok 'and quotes what the browser said' 'without --no-sandbox is not supported' -- \
        run_cli cookie --server "$BASE" --capture cdp --browser "$TMP/fakebin/chromium"
    skip 'as root with no SUDO_USER the capture refuses up front' 'needs euid 0'
    skip 'and says to run as your desktop user' 'needs euid 0'
fi

# --- status / disconnect with nothing running --------------------------------
exits 'status down exits 1'      1 -- run_cli status --server "$BASE"
ok    'disconnect finds nothing' 'nothing to disconnect' -- \
    run_cli disconnect --server "$BASE"

printf '\n%d passed, %d failed, %d skipped, %d total\n' \
    "$pass" "$fail" "$skipped" "$((pass + fail + skipped))"
[ "$fail" -eq 0 ]
