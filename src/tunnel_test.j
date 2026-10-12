# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# tunnel_test.j - white-box overlay for tunnel.j, spliced by `jennifer test`.
#
#     jennifer test src/tunnel_test.j
use testing;
use lists;

func fixtureProfile() {
    def p as types.Profile init types.defaultProfile();
    $p.name = "work";
    $p.server = "https://vpn.example.com/saml";
    $p.version = "4.10.05111";
    return $p;
}

func testPidIsOpenconnectRejectsAStranger() {
    # Alive but not openconnect: the stale-pid-file case `disconnect` must not
    # signal.
    testing.assertFalse(pidIsOpenconnect(1));
    testing.assertFalse(pidIsOpenconnect(0));
    testing.assertFalse(pidIsOpenconnect(-1));
}

#
# ------------------------------------------------------- the openconnect side
#

func fixtureSession() {
    return types.Session{
        cookie: "SESSION123",
        connectUrl: "https://vpn.example.com/saml",
        fingerprint: "pin-sha256:AAAA",
        message: ""
    };
}

func testOpenconnectArgv() {
    def argv as list of string init openconnectArgv(fixtureProfile(), fixtureSession(), true);
    testing.assertEqual($argv[0], "openconnect");
    testing.assertContains($argv, "--protocol=anyconnect");
    # The cookie goes over stdin, never on the command line.
    testing.assertContains($argv, "--cookie-on-stdin");
    testing.assertFalse(lists.contains($argv, "SESSION123"));
    testing.assertContains($argv, "--servercert");
    testing.assertContains($argv, "pin-sha256:AAAA");
    testing.assertContains($argv, "--background");
    testing.assertEqual($argv[len($argv) - 1], "https://vpn.example.com/saml");
}

func testOpenconnectArgvForeground() {
    testing.assertFalse(lists.contains(
        openconnectArgv(fixtureProfile(), fixtureSession(), false),
        "--background"));
}

func testOpenconnectArgvCarriesExtraFlags() {
    def p as types.Profile init fixtureProfile();
    $p.extra = ["--no-dtls"];
    testing.assertContains(openconnectArgv($p, fixtureSession(), false), "--no-dtls");
}

func testSudoPrefixIsNonInteractiveOnlyWhenAsked() {
    def p as types.Profile init fixtureProfile();
    testing.assertEqual(sudoPrefix($p, true), ["sudo", "-n"]);
    # A command we only print is typed by hand, where sudo may prompt.
    testing.assertEqual(sudoPrefix($p, false), ["sudo"]);
    $p.sudo = "";
    testing.assertEqual(len(sudoPrefix($p, true)), 0);
}

func testParseAuthenticateOutput() {
    def out as string init "COOKIE='abc'\nHOST='vpn.example.com'\n" +
        "CONNECT_URL='https://vpn.example.com/g'\nFINGERPRINT='pin-sha256:X'\n";
    def f as map of string to string init parseAuthenticateOutput($out);
    testing.assertEqual($f["COOKIE"], "abc");
    testing.assertEqual($f["CONNECT_URL"], "https://vpn.example.com/g");
    testing.assertEqual($f["FINGERPRINT"], "pin-sha256:X");
}
