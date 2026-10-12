# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# browser_test.j - white-box overlay for browser.j, spliced by `jennifer test`.
#
#     jennifer test src/browser_test.j
use testing;
use lists;
use os;

func fixtureProfile() {
    def p as types.Profile init types.defaultProfile();
    $p.name = "work";
    $p.server = "https://vpn.example.com/saml";
    $p.version = "4.10.05111";
    return $p;
}

#
# --------------------------------------------------------- token extraction
#

func testExtractTokenFromBareValue() {
    testing.assertEqual(extractToken("ABC123", "acSamlv2Token"), "ABC123");
    testing.assertEqual(extractToken("  ABC123  ", "acSamlv2Token"), "ABC123");
}

func testExtractTokenFromNameValuePair() {
    testing.assertEqual(extractToken("acSamlv2Token=ABC123", "acSamlv2Token"), "ABC123");
}

func testExtractTokenFromCookieHeader() {
    testing.assertEqual(
        extractToken("JSESSIONID=x; acSamlv2Token=ABC123; other=y", "acSamlv2Token"),
        "ABC123");
}

func testExtractTokenRejectsAHeaderWithoutTheCookie() {
    # Returning the whole header would post somebody else's cookies to the
    # gateway as a token; "" reaches the caller's "no token given".
    testing.assertEqual(extractToken("JSESSIONID=x; other=y", "acSamlv2Token"), "");
}

func testExtractTokenFromUrlQuery() {
    testing.assertEqual(
        extractToken("https://vpn.example.com/final?acSamlv2Token=ABC123&x=1", "acSamlv2Token"),
        "ABC123");
}

func testExtractTokenFromUrlPathSegment() {
    testing.assertEqual(
        extractToken("https://vpn.example.com/api/sso/ABC123", "acSamlv2Token"),
        "ABC123");
}

func testExtractTokenKeepsBase64Padding() {
    # A base64 token ends in "=" - that must not be mistaken for name=value.
    testing.assertEqual(extractToken("YWJjZGVm==", "acSamlv2Token"), "YWJjZGVm==");
}

func testExtractTokenOfNothing() {
    testing.assertEqual(extractToken("   ", "acSamlv2Token"), "");
}

#
# --------------------------------------------------------------- cookie jars
#

func testDomainCovers() {
    testing.assertTrue(domainCovers("vpn.example.com", "vpn.example.com"));
    testing.assertTrue(domainCovers(".example.com", "vpn.example.com"));
    testing.assertFalse(domainCovers("evil.com", "vpn.example.com"));
    # A suffix that is not a domain boundary must not match.
    testing.assertFalse(domainCovers("ample.com", "vpn.example.com"));
}

func testBrowserSpeaksCdp() {
    testing.assertTrue(browserSpeaksCdp("chromium"));
    testing.assertTrue(browserSpeaksCdp("/usr/bin/google-chrome-stable"));
    testing.assertTrue(browserSpeaksCdp("brave"));
    testing.assertFalse(browserSpeaksCdp("firefox"));
    testing.assertFalse(browserSpeaksCdp("xdg-open"));
}

#
# ------------------------------------------------- handing the browser back
#

# Chromium started as root exits before opening the debug port, so under sudo
# the browser is handed to the invoking user. Two pure halves: where the profile
# lands, and what the launch is prefixed with.

func fixtureOwner() {
    return types.BrowserOwner{name: "jdoe", uid: 1000, home: "/home/jdoe"};
}

func fixtureNobody() {
    return types.BrowserOwner{name: "", uid: -1, home: ""};
}

func testBrowserProfileDirFollowsTheOwner() {
    # An explicit setting wins, whoever the browser runs as.
    def p as types.Profile init fixtureProfile();
    $p.browserProfile = "/tmp/fixed";
    testing.assertEqual(browserProfileDir($p, fixtureNobody()), "/tmp/fixed");
    testing.assertEqual(browserProfileDir($p, fixtureOwner()), "/tmp/fixed");

    # A handoff moves the profile into that user's home, so root never owns the
    # session it reads a cookie out of.
    testing.assertEqual(
        browserProfileDir(fixtureProfile(), fixtureOwner()),
        "/home/jdoe/.cache/" + types.APP + "/browser");
}

func testBrowserLaunchPrefixIsEmptyWhenUnprivileged() {
    # Ordinary case: already the desktop user, so no sudo.
    testing.assertEqual(len(browserLaunchPrefix(fixtureNobody())), 0);
}

func testBrowserLaunchPrefixHandsTheBrowserBack() {
    def argv as list of string init browserLaunchPrefix(fixtureOwner());
    testing.assertEqual($argv[0], "sudo");
    # -n: os.spawn gives the browser no terminal to prompt on.
    testing.assertEqual($argv[1], "-n");
    testing.assertEqual($argv[2], "-u");
    testing.assertEqual($argv[3], "jdoe");
    testing.assertEqual($argv[4], "env");

    # sudo resets the environment, so HOME and the runtime dir are carried back
    # in rather than inherited from root.
    testing.assertTrue(lists.contains($argv, "HOME=/home/jdoe"));
    testing.assertTrue(lists.contains($argv, "XDG_RUNTIME_DIR=/run/user/1000"));
    testing.assertFalse(lists.contains($argv, "HOME=/root"));
}

func testBrowserLaunchPrefixOmitsAnUnknownRuntimeDir() {
    # uid -1 means the password database was unreadable; a made-up
    # /run/user/-1 is worse than no value.
    def owner as types.BrowserOwner init types.BrowserOwner{
        name: "jdoe",
        uid: -1,
        home: "/home/jdoe"
    };
    def argv as list of string init browserLaunchPrefix($owner);
    testing.assertTrue(lists.contains($argv, "HOME=/home/jdoe"));
    testing.assertFalse(lists.contains($argv, "XDG_RUNTIME_DIR=/run/user/-1"));
}
