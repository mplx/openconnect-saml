# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# config_test.j - white-box overlay for config.j, spliced by `jennifer test`.
#
#     jennifer test src/config_test.j
use testing;
use toml;

func fixtureProfile() {
    def p as types.Profile init types.defaultProfile();
    $p.name = "work";
    $p.server = "https://vpn.example.com/saml";
    $p.version = "4.10.05111";
    return $p;
}

func testRunFilePaths() {
    def p as types.Profile init fixtureProfile();
    testing.assertEqual(pidFileFor($p), "/run/ocsaml-work.pid");
    testing.assertEqual(logFileFor($p), "/run/ocsaml-work.log");
}

func testRunFilePathFallsBackToTheHost() {
    def p as types.Profile init fixtureProfile();
    $p.name = "";
    testing.assertEqual(pidFileFor($p), "/run/ocsaml-vpn.example.com.pid");
}

def const CONFIG as string init 'default = "work"

[work]
server = "https://vpn.example.com/saml"
capture = "cdp"
cdpPort = 9444
insecure = true
extra = ["--no-dtls", "--script=/x"]

[lab]
server = "https://lab.example.com"
';

func testProfileNamesSkipsScalars() {
    def names as list of string init profileNames(toml.decode(CONFIG));
    testing.assertEqual($names, ["work", "lab"]);
}

func testNormaliseServerAddsHttpsAndLowersTheScheme() {
    testing.assertEqual(normaliseServer("vpn.example.com"), "https://vpn.example.com");
    testing.assertEqual(normaliseServer("vpn.example.com/saml"), "https://vpn.example.com/saml");
    # Case-insensitive by RFC 3986; folded so the text comparisons downstream
    # see one spelling, and nothing gets a second scheme prepended.
    testing.assertEqual(
        normaliseServer("HTTPS://Vpn.Example.com/saml"),
        "https://Vpn.Example.com/saml");
    testing.assertEqual(normaliseServer("HTTP://vpn.example.com"), "http://vpn.example.com");
    testing.assertEqual(
        normaliseServer("https://vpn.example.com/saml"),
        "https://vpn.example.com/saml");
}

func testRefusesPlainHttpUnlessLoopbackOrInsecure() {
    testing.assertTrue(refusesPlainHttp("http://vpn.example.com/saml", false));
    testing.assertFalse(refusesPlainHttp("http://vpn.example.com/saml", true));
    testing.assertFalse(refusesPlainHttp("http://127.0.0.1:8080/saml", false));
    testing.assertFalse(refusesPlainHttp("http://localhost/saml", false));
    testing.assertFalse(refusesPlainHttp("https://vpn.example.com/saml", false));
    # Userinfo must not stand in for the host.
    testing.assertTrue(refusesPlainHttp("http://127.0.0.1@vpn.example.com/saml", false));
}

func testReadProfileConvertsCaptureTimeoutToMilliseconds() {
    def doc as toml.Value init toml.decode(CONFIG +
        '
[slow]
server = "https://x"
captureTimeout = 42
');
    testing.assertEqual(readProfile($doc, "slow", "cfg").captureTimeoutMs, 42000);
    testing.assertEqual(readProfile($doc, "work", "cfg").captureTimeoutMs, 300000);
}

func throwsOnBadCdpPort() {
    readProfile(toml.decode('[p]
server = "https://x"
cdpPort = 70000
'), "p", "cfg");
}

func testReadProfileRejectsAPortOutOfRange() {
    testing.assertThrows("throwsOnBadCdpPort", "config");
}

func throwsOnZeroCaptureTimeout() {
    readProfile(toml.decode('[p]
server = "https://x"
captureTimeout = 0
'), "p", "cfg");
}

func testReadProfileRejectsAZeroCaptureTimeout() {
    testing.assertThrows("throwsOnZeroCaptureTimeout", "config");
}

func throwsOnUnknownProfile() {
    readProfile(toml.decode(CONFIG), "nope", "cfg");
}

func testReadProfileNamesTheProfilesItFound() {
    testing.assertThrows("throwsOnUnknownProfile", "config");
}

func testTomlReaders() {
    def doc as toml.Value init toml.decode(CONFIG);
    testing.assertEqual(tomlString($doc, "/work/server", "x"), "https://vpn.example.com/saml");
    testing.assertEqual(tomlString($doc, "/work/nothing", "fallback"), "fallback");
    testing.assertEqual(tomlInt($doc, "/work/cdpPort", 9333), 9444);
    testing.assertEqual(tomlInt($doc, "/work/nothing", 7), 7);
    testing.assertTrue(tomlBool($doc, "/work/insecure", false));
    testing.assertEqual(tomlList($doc, "/work/extra"), ["--no-dtls", "--script=/x"]);
    testing.assertEqual(len(tomlList($doc, "/work/nothing")), 0);
}
