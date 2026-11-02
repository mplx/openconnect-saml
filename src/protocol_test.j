# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# protocol_test.j - white-box overlay for protocol.j, spliced by `jennifer test`.
#
#     jennifer test src/protocol_test.j
use testing;
use strings;
use xml;

func fixtureProfile() {
    def p as types.Profile init types.defaultProfile();
    $p.name = "work";
    $p.server = "https://vpn.example.com/saml";
    $p.version = "4.10.05111";
    return $p;
}

func testInitXmlIsWellFormedAndCarriesTheGroupUrl() {
    def body as string init initXml(fixtureProfile(), false);
    def root as xml.Value init xml.decode($body);
    testing.assertEqual(xml.tag($root), "config-auth");
    testing.assertEqual(xml.attr($root, "type"), "init");
    testing.assertEqual(xml.attr($root, "aggregate-auth-version"), "2");
    # <group-access> is what selects the tunnel group, so it must carry the
    # whole server URL including its path.
    testing.assertEqual(xml.text(xml.get($root, "group-access")), "https://vpn.example.com/saml");
    testing.assertEqual(xml.text(xml.get($root, "device-id")), "linux-64");
}

func testInitXmlOffersExternalBrowserOnlyWhenAsked() {
    testing.assertFalse(strings.contains(
        initXml(fixtureProfile(), false),
        "single-sign-on-external-browser"));
    testing.assertTrue(strings.contains(
        initXml(fixtureProfile(), true),
        "single-sign-on-external-browser"));
    # sso-v2 is always offered.
    testing.assertTrue(strings.contains(
        initXml(fixtureProfile(), false),
        "<auth-method>single-sign-on-v2</auth-method>"));
}

func testInitXmlEmitsGroupSelectOnlyWhenSet() {
    def p as types.Profile init fixtureProfile();
    testing.assertFalse(strings.contains(initXml($p, false), "group-select"));
    $p.group = "SAML & Co";
    def body as string init initXml($p, false);
    testing.assertTrue(strings.contains($body, "<group-select>SAML &amp; Co</group-select>"));
}

func testReplyXmlEchoesOpaqueVerbatim() {
    def ar as types.AuthRequest init emptyAuthRequest();
    $ar.ssoField = "sso-token";
    $ar.opaqueXml = "<opaque is-for=\"sg\"><tunnel-group>g</tunnel-group></opaque>";
    def body as string init replyXml(fixtureProfile(), $ar, "TOK");
    # The gateway rejects a reply whose opaque block has been altered, so it
    # must survive byte for byte.
    testing.assertContains($body, $ar.opaqueXml);
    def root as xml.Value init xml.decode($body);
    testing.assertEqual(xml.attr($root, "type"), "auth-reply");
    testing.assertEqual(xml.text(xml.get($root, "auth/sso-token")), "TOK");
    testing.assertEqual(xml.text(xml.get($root, "opaque/tunnel-group")), "g");
}

func testReplyXmlUsesTheFieldNameTheGatewayAsked() {
    def ar as types.AuthRequest init emptyAuthRequest();
    $ar.ssoField = "wibble";
    testing.assertContains(replyXml(fixtureProfile(), $ar, "T"), "<wibble>T</wibble>");
}

func testAuthHeadersLookLikeAnyConnect() {
    def h as map of string to string init authHeaders("4.10.05111");
    testing.assertEqual($h["User-Agent"], "AnyConnect Linux_64 4.10.05111");
    testing.assertEqual($h["X-Aggregate-Auth"], "1");
    testing.assertEqual($h["X-Transcend-Version"], "1");
    # AnyConnect really does send this for an XML body; some gateways key on it.
    testing.assertEqual($h["Content-Type"], "application/x-www-form-urlencoded");
}

#
# ------------------------------------------------------------- XML parsing
#

def const AUTH_REQUEST as string init '<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>cp_saml</tunnel-group></opaque>
<auth id="main">
<title>Login</title>
<message>Sign in</message>
<sso-v2-login>https://idp.example.com/sso?ctx=1</sso-v2-login>
<sso-v2-login-final>https://vpn.example.com/final</sso-v2-login-final>
<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
<form><input type="sso" name="sso-token" /></form>
</auth></config-auth>';

func testParseAuthRequest() {
    def ar as types.AuthRequest init parseAuthRequest(AUTH_REQUEST);
    testing.assertEqual($ar.loginUrl, "https://idp.example.com/sso?ctx=1");
    testing.assertEqual($ar.loginFinalUrl, "https://vpn.example.com/final");
    testing.assertEqual($ar.tokenCookieName, "acSamlv2Token");
    testing.assertEqual($ar.ssoField, "sso-token");
    testing.assertEqual($ar.tunnelGroup, "cp_saml");
    testing.assertEqual($ar.browserMode, "");
    testing.assertFalse($ar.externalRefused);
    testing.assertContains($ar.opaqueXml, "<tunnel-group>cp_saml</tunnel-group>");
}

func testParseAuthRequestKeepsTheOpaqueSourceByteForByte() {
    # Single-quoted attributes, odd spacing and an empty element: everything a
    # re-encoding would normalise. The gateway compares what it wrote.
    def raw as string init "<opaque  is-for='sg' x=\"1\"><tunnel-group>cp_saml</tunnel-group>" +
        "<empty></empty><note/></opaque>";
    def xmlSrc as string init strings.replace(
        AUTH_REQUEST,
        '<opaque is-for="sg"><tunnel-group>cp_saml</tunnel-group></opaque>',
        $raw);
    def ar as types.AuthRequest init parseAuthRequest($xmlSrc);
    testing.assertEqual($ar.opaqueXml, $raw);
    testing.assertEqual($ar.tunnelGroup, "cp_saml");
}

func testRawElementHandlesTheEdges() {
    testing.assertEqual(rawElement("<a><opaque/></a>", "opaque"), "<opaque/>");
    testing.assertEqual(rawElement("<a><opaque x='1' /></a>", "opaque"), "<opaque x='1' />");
    # `<opaque-ish>` is a different element.
    testing.assertEqual(
        rawElement("<a><opaque-ish>n</opaque-ish><opaque>y</opaque></a>", "opaque"),
        "<opaque>y</opaque>");
    testing.assertEqual(rawElement("<a>none here</a>", "opaque"), "");
    # Unterminated: nothing rather than a guess, so the caller falls back.
    testing.assertEqual(rawElement("<a><opaque>never closed", "opaque"), "");
}

func testParseAuthRequestDefaultsTheCookieName() {
    def xmlSrc as string init strings.replace(
        AUTH_REQUEST,
        "<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>",
        "");
    testing.assertEqual(parseAuthRequest($xmlSrc).tokenCookieName, "webvpn");
}

func testParseAuthRequestReadsExternalBrowserMode() {
    def xmlSrc as string init strings.replace(
        AUTH_REQUEST,
        "<form>",
        "<sso-v2-browser-mode>external</sso-v2-browser-mode><form>");
    testing.assertEqual(parseAuthRequest($xmlSrc).browserMode, "external");
}

func throwsOnGatewayError() {
    # A refusal arrives as type="complete" carrying a top-level <error>.
    parseAuthRequest('<config-auth type="complete">' +
        '<error id="96">VPN Server internal error.</error></config-auth>');
}

func testParseAuthRequestRejectsAnError() {
    testing.assertThrows("throwsOnGatewayError", "gateway");
}

func throwsOnMissingSsoLogin() {
    parseAuthRequest('<config-auth type="auth-request"><auth id="main">' +
        '<title>x</title></auth></config-auth>');
}

func testParseAuthRequestRejectsANonSamlGateway() {
    testing.assertThrows("throwsOnMissingSsoLogin", "gateway");
}

def const COMPLETE as string init '<?xml version="1.0"?>
<config-auth type="complete" aggregate-auth-version="2">
<session-token>SESSION123</session-token>
<auth id="success"><banner>Welcome</banner></auth>
<config><vpn-base-config>
<server-cert-hash>pin-sha256:AAAA</server-cert-hash>
</vpn-base-config></config>
</config-auth>';

func testParseAuthComplete() {
    def sess as types.Session init parseAuthComplete(fixtureProfile(), COMPLETE);
    testing.assertEqual($sess.cookie, "SESSION123");
    # The gateway reports its own certificate hash; it becomes --servercert.
    testing.assertEqual($sess.fingerprint, "pin-sha256:AAAA");
    testing.assertEqual($sess.message, "Welcome");
    testing.assertEqual($sess.connectUrl, "https://vpn.example.com/saml");
}

func testParseAuthCompleteKeepsAConfiguredPin() {
    def p as types.Profile init fixtureProfile();
    $p.servercert = "pin-sha256:MINE";
    testing.assertEqual(parseAuthComplete($p, COMPLETE).fingerprint, "pin-sha256:MINE");
}

func testParseAuthCompleteAcceptsAHexHash() {
    def hex as string init strings.repeat("ab", 32);
    def body as string init strings.replace(COMPLETE, "pin-sha256:AAAA", $hex);
    testing.assertEqual(parseAuthComplete(fixtureProfile(), $body).fingerprint, $hex);
}

func testParseAuthCompleteLeavesAnEmptyHashUnpinned() {
    def body as string init strings.replace(COMPLETE, "pin-sha256:AAAA", "");
    testing.assertEqual(parseAuthComplete(fixtureProfile(), $body).fingerprint, "");
}

func throwsOnMalformedHash() {
    parseAuthComplete(
        fixtureProfile(),
        strings.replace(COMPLETE, "pin-sha256:AAAA", "pin-sha256:not a pin"));
}

func testParseAuthCompleteRefusesAMalformedHash() {
    # It would become an openconnect argument; fail where the cause is.
    testing.assertThrows("throwsOnMalformedHash", "gateway");
}

func testOnlyAGatewayRefusalFallsBackToThePlainProbe() {
    testing.assertTrue(fallsBackToPlain("gateway"));
    # A network or TLS failure would fail the plain probe the same way, after
    # another full timeout, and be reported as a refusal it was not.
    testing.assertFalse(fallsBackToPlain("runtime"));
    testing.assertFalse(fallsBackToPlain("timeout"));
    testing.assertFalse(fallsBackToPlain("http"));
}

func throwsOnRejectedToken() {
    parseAuthComplete(
        fixtureProfile(),
        '<config-auth type="auth-request"><auth id="main">' +
            '<error>bad token</error></auth></config-auth>');
}

func testParseAuthCompleteRejectsABadToken() {
    testing.assertThrows("throwsOnRejectedToken", "gateway");
}

func throwsOnInjectedSsoField() {
    # Such a name would otherwise be interpolated into the reply document.
    parseAuthRequest(strings.replace(
        AUTH_REQUEST,
        '<input type="sso" name="sso-token" />',
        '<input type="sso" name="a&gt;&lt;b" />'));
}

func testParseAuthRequestRefusesAnUnusableSsoField() {
    testing.assertThrows("throwsOnInjectedSsoField", "gateway");
}
