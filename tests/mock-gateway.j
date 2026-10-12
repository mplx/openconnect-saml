#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net

/**
 * A stand-in Cisco AnyConnect gateway with a Shibboleth-shaped identity
 * provider behind it, for the integration tests.
 *
 * Written in Jennifer so the suite needs nothing but the interpreter it is
 * already testing. One process serves both roles, because the flow crosses
 * between them and the tests care about that crossing.
 *
 * Usage: mock-gateway.j PORT [MODE]
 *   plain     the classic token flow (default)
 *   external  answers "external" when the client offers external-browser mode
 *   refuse    answers <error id="96"> to any client offering external-browser
 *   duo       redirects to Duo once the password is accepted
 *   factors   offers a choice of second factors as an HTML form
 *
 * @module mock-gateway
 * @version 0.4.0
 */

use io;
use os;
use httpd;
use strings;
use convert;

def const GOOD_USER as string init "jdoe";
def const GOOD_PASS as string init "hunter2";
def const SSO_TOKEN as string init "THE-SSO-TOKEN";
def const SESSION_TOKEN as string init "SESSION-abc123";
def const CERT_HASH as string init "pin-sha256:MOCKHASH";

def port as int init convert.toInt(os.ARGS[1]);
def mode as string init "plain";
if (len(os.ARGS) > 2) {
    $mode = os.ARGS[2];
}
def base as string init "http://127.0.0.1:" + convert.toString($port);

/**
 * The <config-auth type="auth-request"> the gateway opens a login with.
 * @param browserMode {string} value for <sso-v2-browser-mode>, or "" to omit it
 * @return {string} the XML document
 * @since 0.3
 */
func authRequest(browserMode as string) {
    def modeTag as string init "";
    if ($browserMode != "") {
        $modeTag = "<sso-v2-browser-mode>" + $browserMode + "</sso-v2-browser-mode>";
    }
    return '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">' +
        '<opaque is-for="sg"><tunnel-group>mock_saml</tunnel-group></opaque>' +
        '<auth id="main"><title>Login</title><message>Sign in</message>' + "<sso-v2-login>" +
        $base + "/sso/login</sso-v2-login>" + "<sso-v2-login-final>" + $base +
        "/sso/done</sso-v2-login-final>" +
        '<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>' + $modeTag +
        '<form><input type="sso" name="sso-token" /></form>' + '</auth></config-auth>';
}

/**
 * The <config-auth type="complete"> returned once the token is accepted.
 * @return {string} the XML document
 * @since 0.3
 */
func complete() {
    return '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="complete" aggregate-auth-version="2">' +
        "<session-token>" + SESSION_TOKEN + "</session-token>" +
        '<auth id="success"><banner>Welcome to the mock</banner></auth>' +
        "<config><vpn-base-config><server-cert-hash>" + CERT_HASH +
        "</server-cert-hash></vpn-base-config></config></config-auth>";
}

/**
 * A gateway refusal, as a real ASA phrases it.
 * @return {string} the XML document
 * @since 0.3
 */
func refusal() {
    return '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="complete" aggregate-auth-version="2">' +
        '<error id="96">VPN Server internal error.</error></config-auth>';
}

/**
 * The identity provider's browser-storage probe page, which a real browser
 * auto-submits with JavaScript.
 * @return {string} the HTML page
 * @since 0.3
 */
func probePage() {
    return '<html><head><title>Loading Session Information</title></head><body>' +
        '<form name="form1" action="/idp/sso?execution=e1s1" method="post">' +
        '<input type="hidden" name="csrf_token" value="CSRF1" />' +
        '<input name="shib_idp_ls_supported" type="hidden" />' +
        '<input name="_eventId_proceed" type="hidden" />' +
        '<input type="submit" value="Continue" /></form></body></html>';
}

/**
 * The identity provider's credential form.
 * @param note {string} an optional message shown above the form
 * @return {string} the HTML page
 * @since 0.3
 */
func loginPage(note as string) {
    return '<html><head><title>Sign in</title></head><body><p>' + $note + "</p>" +
        '<form action="/idp/sso?execution=e1s2" method="post">' +
        '<input type="hidden" name="csrf_token" value="CSRF2" />' +
        '<input name="j_username" type="text" value="" />' +
        '<input name="j_password" type="password" value="" />' +
        '<input type="checkbox" name="donotcache" value="1" />' +
        '<button type="submit" name="_eventId_proceed" value="">Login</button>' +
        "</form></body></html>";
}

/**
 * A second-factor chooser, the shape an identity provider uses when the choice
 * is HTML rather than a JavaScript prompt.
 * @return {string} the HTML page
 * @since 0.3
 */
func factorPage() {
    return '<html><head><title>Choose a second factor</title></head><body>' +
        '<form action="/idp/mfa" method="post">' +
        '<input type="hidden" name="csrf_token" value="CSRF3" />' +
        '<button type="submit" name="factor" value="Duo Push">Send me a push</button>' +
        '<button type="submit" name="factor" value="Passcode">Enter a passcode</button>' +
        '<button type="submit" name="factor" value="WebAuthn">Use a security key</button>' +
        "</form></body></html>";
}

/**
 * The auto-submitting assertion form the identity provider hands back.
 * @return {string} the HTML page
 * @since 0.3
 */
func assertionPage() {
    return '<html><body onload="document.forms[0].submit()">' + '<form action="' + $base +
        '/+CSCOE+/saml/sp/acs" method="post">' +
        '<input type="hidden" name="RelayState" value="ctx=1" />' +
        '<input type="hidden" name="SAMLResponse" value="PHNhbWw+PC9zYW1sPg==" />' +
        '<input type="submit" value="Continue" /></form></body></html>';
}

/**
 * Whether a form body carries the right credentials.
 * @param body {string} the urlencoded request body
 * @return {bool} true when both username and password match
 * @since 0.3
 */
func credentialsOk(body as string) {
    return strings.contains($body, "j_username=" + GOOD_USER) and
        strings.contains($body, "j_password=" + GOOD_PASS);
}

def srv as httpd.Server init httpd.listen("127.0.0.1:" + convert.toString($port));
io.eprintf("mock gateway (%s) on %s\n", $mode, $base);

while (true) { # lint-disable: L105
    def req as httpd.Request init httpd.accept($srv);
    # httpd.path drops the query, and the identity provider's steps are told
    # apart by it, so the step is read from the query directly.
    def target as string init httpd.path($req);
    def step as string init httpd.query($req, "execution");
    def body as string init convert.stringFromBytes(httpd.body($req), "utf-8");

    if ($target == "/" or strings.startsWith($target, "/saml")) {
        # The AnyConnect XML endpoint.
        if (strings.contains($body, 'type="init"')) {
            def offered as bool init strings.contains($body, "single-sign-on-external-browser");
            if ($mode == "refuse" and $offered) {
                httpd.setHeader($req, "Content-Type", "text/xml");
                httpd.respond($req, 200, refusal());
            } elseif ($mode == "external" and $offered) {
                httpd.setHeader($req, "Content-Type", "text/xml");
                httpd.respond($req, 200, authRequest("external"));
            } else {
                httpd.setHeader($req, "Content-Type", "text/xml");
                httpd.respond($req, 200, authRequest(""));
            }
        } elseif (strings.contains($body, 'type="auth-reply"')) {
            def hasToken as bool init strings.contains(
                $body,
                "<sso-token>" + SSO_TOKEN + "</sso-token>");
            def ok as bool init $hasToken and strings.contains($body, '<opaque is-for="sg">');
            httpd.setHeader($req, "Content-Type", "text/xml");
            if ($ok) {
                httpd.respond($req, 200, complete());
            } else {
                httpd.respond(
                    $req,
                    200,
                    '<config-auth type="auth-request"><auth id="main">' +
                        "<error>bad token</error></auth></config-auth>");
            }
        } else {
            httpd.setHeader($req, "Content-Type", "text/xml");
            httpd.respond($req, 200, '<config-auth type="unknown"/>');
        }
    } elseif (strings.startsWith($target, "/sso/login")) {
        # The service provider bounces the browser to the identity provider.
        httpd.setHeader($req, "Location", "/idp/sso?SAMLRequest=x");
        httpd.respond($req, 303, "");
    } elseif ($target == "/idp/sso" and httpd.query($req, "SAMLRequest") != "") {
        httpd.setHeader($req, "Location", "/idp/sso?execution=e1s1");
        httpd.setHeader($req, "Set-Cookie", "JSESSIONID=abc; path=/");
        httpd.respond($req, 302, "");
    } elseif ($target == "/idp/sso" and $step == "e1s1") {
        if ($body == "") {
            httpd.respond($req, 200, probePage());
        } else {
            httpd.respond($req, 200, loginPage("Enter your credentials"));
        }
    } elseif ($target == "/idp/sso" and $step == "e1s2") {
        if (not credentialsOk($body)) {
            httpd.respond($req, 200, loginPage("That was wrong"));
        } elseif ($mode == "factors") {
            httpd.respond($req, 200, factorPage());
        } elseif ($mode == "duo") {
            httpd.setHeader(
                $req,
                "Location",
                "https://api-12345678.duosecurity.com/oauth/v1/authorize?client_id=x");
            httpd.respond($req, 302, "");
        } else {
            httpd.respond($req, 200, assertionPage());
        }
    } elseif ($target == "/idp/mfa") {
        # Only the passcode route completes, so a test can tell which button
        # was actually pressed.
        if (strings.contains($body, "factor=Passcode")) {
            httpd.respond($req, 200, assertionPage());
        } else {
            httpd.respond(
                $req,
                200,
                "<html><head><title>Wrong factor</title></head><body>" +
                    "<p>that factor is not enrolled</p></body></html>");
        }
    } elseif (strings.startsWith($target, "/+CSCOE+/saml/sp/acs")) {
        if (strings.contains($body, "SAMLResponse=")) {
            httpd.setHeader(
                $req,
                "Set-Cookie",
                "acSamlv2Token=" + SSO_TOKEN + "; path=/; HttpOnly");
            httpd.setHeader($req, "Location", "/sso/done");
            httpd.respond($req, 302, "");
        } else {
            httpd.respond($req, 400, "no assertion");
        }
    } elseif (strings.startsWith($target, "/sso/done")) {
        httpd.respond($req, 200, "<html><body>You may close this window.</body></html>");
    } else {
        httpd.respond($req, 404, "not found");
    }
}
