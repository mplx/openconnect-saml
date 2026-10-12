# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# saml_test.j - white-box tests for saml.j. Run with:
#
#     jennifer test src/saml_test.j
#
# Covers the pure surface: the <config-auth> protocol (building requests and
# parsing replies), the token-extraction rules, the browserless form walker's
# decisions, and the openconnect command line. Anything needing a socket, a
# browser or root is covered by tests/integration.sh instead.
use testing;
use lists; # not used by saml.j, so not inherited from the splice

# A profile with the fields the pure functions read, and nothing live.
func fixtureProfile() {
    def p as Profile init defaultProfile();
    $p.name = "work";
    $p.server = "https://vpn.example.com/saml";
    $p.version = "4.10.05111";
    return $p;
}

#
# ------------------------------------------------------------------ XML output
#

func testXmlEscape() {
    testing.assertEqual(xmlEscape("a&b"), "a&amp;b");
    testing.assertEqual(xmlEscape("<x>"), "&lt;x&gt;");
    testing.assertEqual(xmlEscape("say \"hi\""), "say &quot;hi&quot;");
    testing.assertEqual(xmlEscape("plain"), "plain");
}

func testStripXmlDecl() {
    testing.assertEqual(stripXmlDecl("<?xml version=\"1.0\"?><a/>"), "<a/>");
    testing.assertEqual(stripXmlDecl("  <a/>  "), "<a/>");
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
    def p as Profile init fixtureProfile();
    testing.assertFalse(strings.contains(initXml($p, false), "group-select"));
    $p.group = "SAML & Co";
    def body as string init initXml($p, false);
    testing.assertTrue(strings.contains($body, "<group-select>SAML &amp; Co</group-select>"));
}

func testReplyXmlEchoesOpaqueVerbatim() {
    def ar as AuthRequest init emptyAuthRequest();
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
    def ar as AuthRequest init emptyAuthRequest();
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
    def ar as AuthRequest init parseAuthRequest(AUTH_REQUEST);
    testing.assertEqual($ar.loginUrl, "https://idp.example.com/sso?ctx=1");
    testing.assertEqual($ar.loginFinalUrl, "https://vpn.example.com/final");
    testing.assertEqual($ar.tokenCookieName, "acSamlv2Token");
    testing.assertEqual($ar.ssoField, "sso-token");
    testing.assertEqual($ar.tunnelGroup, "cp_saml");
    testing.assertEqual($ar.browserMode, "");
    testing.assertFalse($ar.externalRefused);
    testing.assertContains($ar.opaqueXml, "<tunnel-group>cp_saml</tunnel-group>");
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
    def sess as Session init parseAuthComplete(fixtureProfile(), COMPLETE);
    testing.assertEqual($sess.cookie, "SESSION123");
    # The gateway reports its own certificate hash; it becomes --servercert.
    testing.assertEqual($sess.fingerprint, "pin-sha256:AAAA");
    testing.assertEqual($sess.message, "Welcome");
    testing.assertEqual($sess.connectUrl, "https://vpn.example.com/saml");
}

func testParseAuthCompleteKeepsAConfiguredPin() {
    def p as Profile init fixtureProfile();
    $p.servercert = "pin-sha256:MINE";
    testing.assertEqual(parseAuthComplete($p, COMPLETE).fingerprint, "pin-sha256:MINE");
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
# ----------------------------------------------------- browserless form walk
#

def const LOGIN_FORM as string init '<html><head><title>SSO</title></head><body>
<form action="/idp?execution=e1s2" method="post">
<input type="hidden" name="csrf_token" value="CSRF"/>
<input name="j_username" type="text" value=""/>
<input name="j_password" type="password" value=""/>
<input type="checkbox" name="donotcache" value="1"/>
<input type="checkbox" name="remember" value="1" checked/>
<button type="submit" name="_eventId_proceed" value="">Login</button>
</form></body></html>';

func creds() {
    return Credentials{user: "jdoe", password: "s3cr3t", factor: ""};
}

func credsFor(factor as string) {
    return Credentials{user: "jdoe", password: "s3cr3t", factor: $factor};
}

# A second-factor chooser: one form, several ways to be challenged.
def const FACTOR_FORM as string init '<html><body>' + '<form action="/idp/mfa" method="post">' +
    '<input type="hidden" name="csrf_token" value="CSRF"/>' +
    '<button type="submit" name="factor" value="Duo Push">Send a push</button>' +
    '<button type="submit" name="factor" value="Passcode">Enter a passcode</button>' +
    '<button type="submit" name="factor" value="WebAuthn">Security key</button>' +
    '</form></body></html>';

# The other shape: a radio group.
def const FACTOR_RADIO as string init '<html><body>' + '<form action="/idp/mfa" method="post">' +
    '<input type="radio" name="method" value="push" checked/>' +
    '<input type="radio" name="method" value="totp"/>' +
    '<input type="submit" name="go" value="Continue"/>' + '</form></body></html>';

func testFactorPicksTheNamedSubmitControl() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    testing.assertContains(encodeForm($form, credsFor("passcode")), "factor=Passcode");
    testing.assertContains(encodeForm($form, credsFor("webauthn")), "factor=WebAuthn");
}

func testFactorSendsOnlyTheChosenControl() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    def body as string init encodeForm($form, credsFor("passcode"));
    testing.assertFalse(strings.contains($body, "Duo+Push"));
    testing.assertFalse(strings.contains($body, "WebAuthn"));
    # hidden fields still ride along
    testing.assertContains($body, "csrf_token=CSRF");
}

func testWithoutAFactorTheFirstControlWins() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    testing.assertContains(encodeForm($form, creds()), "factor=Duo+Push");
}

func throwsOnUnknownFactor() {
    encodeForm(pickForm(html.parse(FACTOR_FORM))[0], credsFor("carrier-pigeon"));
}

func testAnUnmatchedFactorIsAnErrorNotAGuess() {
    # Pressing the wrong button here sends a push to someone's phone.
    testing.assertThrows("throwsOnUnknownFactor", "auth");
}

func testAFactorThatMatchesNothingOnAOneButtonFormIsIgnored() {
    # The credential form has a single submit control, so there is no choice to
    # make and the factor is simply not about this page.
    def form as html.Node init pickForm(html.parse(LOGIN_FORM))[0];
    testing.assertContains(encodeForm($form, credsFor("passcode")), "_eventId_proceed=");
}

func testFactorSelectsWithinARadioGroup() {
    def form as html.Node init pickForm(html.parse(FACTOR_RADIO))[0];
    testing.assertContains(encodeForm($form, credsFor("totp")), "method=totp");
    testing.assertFalse(strings.contains(encodeForm($form, credsFor("totp")), "method=push"));
    # with no factor asked for, the checked one is sent
    testing.assertContains(encodeForm($form, creds()), "method=push");
}

func testDescribeChoicesListsWhatIsOnOffer() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    def desc as string init describeChoices($form);
    # Quoted labels, not name=value pairs: a label is what --factor takes, and
    # the quotes show that a two-word one needs quoting on the command line.
    testing.assertContains($desc, quoted("Duo Push"));
    testing.assertContains($desc, quoted("Passcode"));
    testing.assertFalse(strings.contains($desc, "factor="));
}

func testAMultiWordFactorCanBePassedWhole() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    testing.assertContains(encodeForm($form, credsFor("Duo Push")), "factor=Duo+Push");
}

func testFactorLabelPrefersTheValue() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    testing.assertEqual(factorLabel(submitControls($form)[0]), "Duo Push");
}

func testMatchesFactorIsCaseInsensitiveAcrossAttributes() {
    def form as html.Node init pickForm(html.parse(FACTOR_FORM))[0];
    def controls as list of html.Node init submitControls($form);
    testing.assertEqual(len($controls), 3);
    testing.assertTrue(matchesFactor($controls[0], "PUSH"));
    testing.assertFalse(matchesFactor($controls[0], "passcode"));
    testing.assertFalse(matchesFactor($controls[0], ""));
}

func testEncodeFormFillsCredentialsAndEchoesHiddenFields() {
    def form as html.Node init pickForm(html.parse(LOGIN_FORM))[0];
    def body as string init encodeForm($form, creds());
    testing.assertContains($body, "j_username=jdoe");
    testing.assertContains($body, "j_password=s3cr3t");
    testing.assertContains($body, "csrf_token=CSRF");
    # The submit control tells the IdP which button was pressed.
    testing.assertContains($body, "_eventId_proceed=");
}

func testEncodeFormOmitsUncheckedBoxesButKeepsCheckedOnes() {
    def form as html.Node init pickForm(html.parse(LOGIN_FORM))[0];
    def body as string init encodeForm($form, creds());
    testing.assertFalse(strings.contains($body, "donotcache"));
    testing.assertContains($body, "remember=1");
}

func testPickFormPrefersTheOneWithAPassword() {
    def page as string init '<html><body>' +
        '<form action="/search"><input name="q" value=""/></form>' +
        '<form action="/login"><input name="j_password" type="password"/></form>' +
        '</body></html>';
    def form as html.Node init pickForm(html.parse($page))[0];
    testing.assertEqual(attrOrEmpty($form, "action"), "/login");
}

func testPickFormFindsNothingOnAFormlessPage() {
    testing.assertEqual(len(pickForm(html.parse("<html><body>hi</body></html>"))), 0);
}

func testFormHasPassword() {
    testing.assertTrue(formHasPassword(pickForm(html.parse(LOGIN_FORM))[0]));
    def plain as string init '<html><body><form><input name="q"/></form></body></html>';
    testing.assertFalse(formHasPassword(pickForm(html.parse($plain))[0]));
}

func testIsUserField() {
    testing.assertTrue(isUserField("j_username"));
    testing.assertTrue(isUserField("USERNAME"));
    testing.assertTrue(isUserField("loginfmt"));
    testing.assertFalse(isUserField("csrf_token"));
}

func testDescribeFormNamesFieldsWithoutValues() {
    def form as html.Node init pickForm(html.parse(LOGIN_FORM))[0];
    def desc as string init describeForm($form);
    testing.assertContains($desc, "j_password(password)");
    testing.assertContains($desc, "_eventId_proceed(button)");
    # Values can be CSRF tokens or whole assertions; they must not leak.
    testing.assertFalse(strings.contains($desc, "CSRF"));
}

func testPageTitle() {
    testing.assertEqual(pageTitle(html.parse(LOGIN_FORM)), "SSO");
    testing.assertEqual(pageTitle(html.parse("<html><body>x</body></html>")), "");
}

func throwsOnDuo() {
    guardSecondFactor("https://api-12345678.duosecurity.com/oauth/v1/authorize", []);
}

func testGuardSecondFactorStopsAtDuo() {
    testing.assertThrows("throwsOnDuo", "auth");
}

func testGuardSecondFactorPassesOrdinaryUrls() {
    guardSecondFactor("https://shibboleth.example.com/idp/profile", []);
}

func throwsOnLoop() {
    guardNoLoop(["GET /a", "GET /a"], "GET /a");
}

func testGuardNoLoopStopsOnTheThirdVisit() {
    testing.assertThrows("throwsOnLoop", "auth");
}

func testGuardNoLoopAllowsASecondVisit() {
    guardNoLoop(["GET /a"], "GET /a");
}

func testRenderTrailNumbersTheSteps() {
    def out as string init renderTrail(["GET /a", "POST /b"]);
    testing.assertContains($out, "1) GET /a");
    testing.assertContains($out, "2) POST /b");
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
    return BrowserOwner{name: "jdoe", uid: 1000, home: "/home/jdoe"};
}

func fixtureNobody() {
    return BrowserOwner{name: "", uid: -1, home: ""};
}

func testBrowserProfileDirFollowsTheOwner() {
    # An explicit setting wins, whoever the browser runs as.
    def p as Profile init fixtureProfile();
    $p.browserProfile = "/tmp/fixed";
    testing.assertEqual(browserProfileDir($p, fixtureNobody()), "/tmp/fixed");
    testing.assertEqual(browserProfileDir($p, fixtureOwner()), "/tmp/fixed");

    # A handoff moves the profile into that user's home, so root never owns the
    # session it reads a cookie out of.
    testing.assertEqual(
        browserProfileDir(fixtureProfile(), fixtureOwner()),
        "/home/jdoe/.cache/" + APP + "/browser");
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

#
# ------------------------------------------------ refusals around a credential
#

func testIsXmlName() {
    # What a real gateway asks for.
    testing.assertTrue(isXmlName("sso-token"));
    testing.assertTrue(isXmlName("sso-token-v2"));
    testing.assertTrue(isXmlName("_private"));
    testing.assertTrue(isXmlName("a.b-c9"));
    # The element name wraps the token and cannot be escaped, so anything that
    # breaks out of the tag is refused.
    testing.assertFalse(isXmlName(""));
    testing.assertFalse(isXmlName("a><b"));
    testing.assertFalse(isXmlName("a b"));
    testing.assertFalse(isXmlName("a/b"));
    testing.assertFalse(isXmlName("9lead"));
    testing.assertFalse(isXmlName("-lead"));
    testing.assertFalse(isXmlName("has\"quote"));
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

func testIsLoopbackHost() {
    testing.assertTrue(isLoopbackHost("localhost"));
    testing.assertTrue(isLoopbackHost("127.0.0.1"));
    testing.assertTrue(isLoopbackHost("127.1.2.3"));
    testing.assertTrue(isLoopbackHost("::1"));
    testing.assertTrue(isLoopbackHost("[::1]"));
    testing.assertTrue(isLoopbackHost("LOCALHOST"));
    # Not loopback, and not to be mistaken for it by a prefix test.
    testing.assertFalse(isLoopbackHost("vpn.example.com"));
    testing.assertFalse(isLoopbackHost("127.evil.com"));
    testing.assertFalse(isLoopbackHost("localhost.evil.com"));
    testing.assertFalse(isLoopbackHost("1270.0.0.1"));
    testing.assertFalse(isLoopbackHost(""));
    # Dotted quad only: neither a "127."-prefixed host name nor an out-of-range
    # octet may pose as a local address.
    testing.assertFalse(isLoopbackHost("127.0.0.1.evil.com"));
    testing.assertFalse(isLoopbackHost("127.999.0.1"));
    testing.assertFalse(isLoopbackHost("127.0.0"));
    testing.assertTrue(isLoopbackHost("127.255.255.254"));
}

func throwsOnPlainHttpHop() {
    guardHttps("http://idp.example.com/login", []);
}

func testGuardHttpsRefusesPlainHttp() {
    testing.assertThrows("throwsOnPlainHttpHop", "auth");
}

func testGuardHttpsAllowsTlsAndLoopback() {
    # No throw is the assertion: https anywhere, http only to ourselves.
    guardHttps("https://idp.example.com/login", []);
    guardHttps("http://127.0.0.1:8080/saml", []);
    testing.assertTrue(true);
}

func testPidIsOpenconnectRejectsAStranger() {
    # Alive but not openconnect: the stale-pid-file case `disconnect` must not
    # signal.
    testing.assertFalse(pidIsOpenconnect(1));
    testing.assertFalse(pidIsOpenconnect(0));
    testing.assertFalse(pidIsOpenconnect(-1));
}

func testBrowserLaunchPrefixOmitsAnUnknownRuntimeDir() {
    # uid -1 means the password database was unreadable; a made-up
    # /run/user/-1 is worse than no value.
    def owner as BrowserOwner init BrowserOwner{name: "jdoe", uid: -1, home: "/home/jdoe"};
    def argv as list of string init browserLaunchPrefix($owner);
    testing.assertTrue(lists.contains($argv, "HOME=/home/jdoe"));
    testing.assertFalse(lists.contains($argv, "XDG_RUNTIME_DIR=/run/user/-1"));
}

#
# ------------------------------------------------------- the openconnect side
#

func fixtureSession() {
    return Session{
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
    def p as Profile init fixtureProfile();
    $p.extra = ["--no-dtls"];
    testing.assertContains(openconnectArgv($p, fixtureSession(), false), "--no-dtls");
}

func testSudoPrefixIsNonInteractiveOnlyWhenAsked() {
    def p as Profile init fixtureProfile();
    testing.assertEqual(sudoPrefix($p, true), ["sudo", "-n"]);
    # A command we only print is typed by hand, where sudo may prompt.
    testing.assertEqual(sudoPrefix($p, false), ["sudo"]);
    $p.sudo = "";
    testing.assertEqual(len(sudoPrefix($p, true)), 0);
}

func testShellQuote() {
    testing.assertEqual(shellQuote("plain"), "'plain'");
    testing.assertEqual(shellQuote("it's"), "'it'\\''s'");
    testing.assertEqual(shellJoin(["a", "b c"]), "'a' 'b c'");
}

func testParseAuthenticateOutput() {
    def out as string init "COOKIE='abc'\nHOST='vpn.example.com'\n" +
        "CONNECT_URL='https://vpn.example.com/g'\nFINGERPRINT='pin-sha256:X'\n";
    def f as map of string to string init parseAuthenticateOutput($out);
    testing.assertEqual($f["COOKIE"], "abc");
    testing.assertEqual($f["CONNECT_URL"], "https://vpn.example.com/g");
    testing.assertEqual($f["FINGERPRINT"], "pin-sha256:X");
}

#
# ------------------------------------------------------------------- profiles
#

func testSlugMakesPathSafeNames() {
    testing.assertEqual(slug("work"), "work");
    testing.assertEqual(slug("vpn.example.com"), "vpn.example.com");
    testing.assertEqual(slug("a/b c"), "a-b-c");
    testing.assertEqual(slug(""), "default");
}

func testRunFilePaths() {
    def p as Profile init fixtureProfile();
    testing.assertEqual(pidFileFor($p), "/run/openconnect-saml-work.pid");
    testing.assertEqual(logFileFor($p), "/run/openconnect-saml-work.log");
}

func testRunFilePathFallsBackToTheHost() {
    def p as Profile init fixtureProfile();
    $p.name = "";
    testing.assertEqual(pidFileFor($p), "/run/openconnect-saml-vpn.example.com.pid");
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

func testDefaultProfileHasNoFactorPreference() {
    testing.assertEqual(defaultProfile().factor, "");
}

func testDefaultProfile() {
    def p as Profile init defaultProfile();
    testing.assertEqual($p.browser, "xdg-open");
    testing.assertEqual($p.sudo, "sudo");
    testing.assertEqual($p.capture, "auto");
    testing.assertEqual($p.cdpPort, 9333);
    testing.assertEqual($p.version, CLIENT_VERSION);
}

#
# ----------------------------------------------------------------------- misc
#

func testArgsMessageDropsThePrefix() {
    testing.assertEqual(argsMessage("args: unknown flag --x"), "unknown flag --x");
    testing.assertEqual(argsMessage("something else"), "something else");
}

func testVersionsAgree() {
    # The one string the packaging and the man page are checked against.
    testing.assertEqual(APP_VERSION, "0.3.0");
}
