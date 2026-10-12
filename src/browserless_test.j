# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# browserless_test.j - white-box overlay for browserless.j, spliced by `jennifer test`.
#
#     jennifer test src/browserless_test.j
use testing;
use strings;

func fixtureProfile() {
    def p as types.Profile init types.defaultProfile();
    $p.name = "work";
    $p.server = "https://vpn.example.com/saml";
    $p.version = "4.10.05111";
    return $p;
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
    return types.Credentials{user: "jdoe", password: "s3cr3t", factor: ""};
}

func credsFor(factor as string) {
    return types.Credentials{user: "jdoe", password: "s3cr3t", factor: $factor};
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
    testing.assertContains($desc, util.quoted("Duo Push"));
    testing.assertContains($desc, util.quoted("Passcode"));
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
