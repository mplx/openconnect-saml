# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net

/**
 * Cisco's <config-auth> exchange: build the documents, post them, read the replies.
 *
 * @module protocol
 * @version 0.4.0
 */

use io;
use xml;
use strings;

import "http.j" as http;
import "./types.j" as types;
import "./util.j" as util;

#
# ---------------------------------------------- the AnyConnect <config-auth> XML
#

/**
 * The header set an AnyConnect client sends with a <config-auth> POST.
 * AnyConnect really does send that Content-Type for an XML body. Match it:
 * some gateways key off the whole header set to decide they are talking to a
 * real client.
 * @param version {string} the AnyConnect version to claim
 * @return {map of string to string} the request headers
 * @since 0.1
 */
func authHeaders(version as string) {
    def h as map of string to string init {};
    $h["User-Agent"] = "AnyConnect Linux_64 " + $version;
    $h["Accept"] = "*/*";
    $h["Accept-Encoding"] = "identity";
    $h["X-Transcend-Version"] = "1";
    $h["X-Aggregate-Auth"] = "1";
    $h["X-Support-HTTP-Auth"] = "true";
    $h["Content-Type"] = "application/x-www-form-urlencoded";
    return $h;
}

/**
 * POST one <config-auth> document to the gateway and return its reply.
 * The whole URL goes on the wire, path included, because on a Cisco gateway
 * that path is the group selector: https://vpn.example.com/saml picks the
 * tunnel group, where <group-select> is widely ignored.
 * @param prof {Profile} the active profile
 * @param body {string} the XML document to send
 * @return {string} the response body
 * @throws {Error} kind "gateway" on a non-2xx status
 * @since 0.1
 */
func postAuthXml(prof as types.Profile, body as string) {
    def noCa as bytes;
    def tls as http.TlsOptions init http.TlsOptions{skipVerify: $prof.insecure, caCert: $noCa};
    def resp as http.Response init http.requestWithTls(
        "POST",
        $prof.server,
        authHeaders($prof.version),
        $body,
        types.HTTP_TIMEOUT_MS,
        0,
        $tls);
    if ($resp.status < 200 or $resp.status >= 300) {
        util.fail(
            "gateway",
            io.sprintf("gateway answered HTTP %d %s", $resp.status, $resp.statusText));
    }
    return $resp.body;
}

/**
 * Build the <config-auth type="init"> document that opens a login.
 * @param prof {Profile} the active profile
 * @param offerExternal {bool} also advertise single-sign-on-external-browser
 * @return {string} the XML document
 * @since 0.1
 */
func initXml(prof as types.Profile, offerExternal as bool) {
    def caps as string init '<auth-method>single-sign-on-v2</auth-method>';
    if ($offerExternal) {
        $caps = $caps + '<auth-method>single-sign-on-external-browser</auth-method>';
    }
    def group as string init "";
    if ($prof.group != "") {
        $group = "<group-select>" + util.xmlEscape($prof.group) + "</group-select>";
    }
    def tpl as string init '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="init" aggregate-auth-version="2">' +
        '<version who="vpn">%s</version><device-id>%s</device-id>' +
        '%s<group-access>%s</group-access>' + '<capabilities>%s</capabilities></config-auth>';
    return io.sprintf(
        $tpl,
        util.xmlEscape($prof.version),
        types.DEVICE_ID,
        $group,
        util.xmlEscape($prof.server),
        $caps);
}

/**
 * Build the <config-auth type="auth-reply"> document that submits the SSO token.
 * The <opaque> block is echoed back byte for byte - it is the gateway's own
 * state, and it will reject a reply that alters it.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} what the gateway said when the login opened
 * @param token {string} the SSO token read out of the browser
 * @return {string} the XML document
 * @since 0.1
 */
func replyXml(prof as types.Profile, ar as types.AuthRequest, token as string) {
    def tpl as string init '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">' +
        '<version who="vpn">%s</version>' + '<device-id computer-name="%s">%s</device-id>' +
        '<session-token/><session-id/>%s' + '<auth><%s>%s</%s></auth></config-auth>';
    return io.sprintf(
        $tpl,
        util.xmlEscape($prof.version),
        util.xmlEscape(util.hostName()),
        types.DEVICE_ID,
        $ar.opaqueXml,
        $ar.ssoField,
        util.xmlEscape($token),
        $ar.ssoField);
}

/**
 * Trimmed text of a child element, tolerating its absence.
 * @param node {xml.Value} the parent element
 * @param name {string} the child's tag name, or a path to it
 * @param deflt {string} returned when there is no such child
 * @return {string} the child's text, or the default
 * @since 0.1
 */
func childText(node as xml.Value, name as string, deflt as string) {
    if (xml.has($node, $name)) {
        return strings.trim(xml.text(xml.get($node, $name)));
    }
    return $deflt;
}

/**
 * The `type` attribute of a <config-auth> document.
 * @param root {xml.Value} the document element
 * @return {string} the attribute value, or "" when it is missing
 * @since 0.1
 */
func rootType(root as xml.Value) {
    if (xml.hasAttr($root, "type")) {
        return xml.attr($root, "type");
    }
    return "";
}

/**
 * The element name the gateway wants the token under in the reply.
 * Named by the form's <input type="sso" name="...">.
 * @param auth {xml.Value} the <auth> element
 * @return {string} the field name, defaulting to "sso-token"
 * @since 0.1
 */
func ssoFieldName(auth as xml.Value) {
    if (xml.has($auth, "form")) {
        def form as xml.Value init xml.get($auth, "form");
        for (def input in xml.findAll($form, "input")) {
            if (xml.hasAttr($input, "type") and xml.attr($input, "type") == "sso" and
                xml.hasAttr($input, "name")) {
                return xml.attr($input, "name");
            }
        }
    }
    return "sso-token";
}

/**
 * A zeroed AuthRequest, for a variable that is filled in later.
 * @return {AuthRequest} every field empty or false
 * @since 0.1
 */
export func emptyAuthRequest() {
    return types.AuthRequest{
        loginUrl: "",
        loginFinalUrl: "",
        tokenCookieName: "",
        browserMode: "",
        ssoField: "",
        opaqueXml: "",
        tunnelGroup: "",
        externalRefused: false,
        title: "",
        message: ""
    };
}

/**
 * Parse the gateway's answer to an init request.
 * @param body {string} the response body
 * @return {AuthRequest} the login URL, token cookie name, opaque state and the rest
 * @throws {Error} kind "gateway" when the gateway refused, offered no SAML
 *     login, or named the token field something that is not an XML name
 * @since 0.1
 */
func parseAuthRequest(body as string) {
    def root as xml.Value init xml.decode($body);
    def kind as string init rootType($root);
    if ($kind != "auth-request") {
        # A refusal comes back as type="complete" carrying a top-level <error>.
        def why as string init childText($root, "error", "");
        if ($why == "") {
            $why = "got type='" + $kind + "' instead";
        }
        util.fail("gateway", "the gateway would not start a login: " + $why);
    }
    if (not xml.has($root, "auth")) {
        util.fail("gateway", "the gateway's auth-request carries no <auth> node");
    }

    def auth as xml.Value init xml.get($root, "auth");
    def err as string init childText($auth, "error", "");
    if ($err != "") {
        util.fail("gateway", "the gateway refused the request: " + $err);
    }

    def ar as types.AuthRequest init types.AuthRequest{
        loginUrl: childText($auth, "sso-v2-login", ""),
        loginFinalUrl: childText($auth, "sso-v2-login-final", ""),
        tokenCookieName: childText($auth, "sso-v2-token-cookie-name", "webvpn"),
        browserMode: childText($auth, "sso-v2-browser-mode", ""),
        ssoField: ssoFieldName($auth),
        opaqueXml: "",
        tunnelGroup: "",
        externalRefused: false,
        title: childText($auth, "title", ""),
        message: childText($auth, "message", "")
    };

    if ($ar.loginUrl == "") {
        util.fail(
            "gateway",
            "the gateway offered no <sso-v2-login> URL" +
                " - it does not look like it authenticates with SAML");
    }
    # The token is escaped; the element name around it cannot be. A gateway
    # naming a field `a><b` would inject into the reply.
    if (not util.isXmlName($ar.ssoField)) {
        util.fail(
            "gateway",
            "the gateway asked for the token under '" + $ar.ssoField +
                "', which is not a usable XML element name");
    }
    if ($ar.loginFinalUrl == "") {
        $ar.loginFinalUrl = $ar.loginUrl;
    }
    if (xml.has($root, "opaque")) {
        def opaque as xml.Value init xml.get($root, "opaque");
        $ar.opaqueXml = util.stripXmlDecl(xml.encode($opaque));
        $ar.tunnelGroup = childText($opaque, "tunnel-group", "");
    }
    return $ar;
}

/**
 * Parse the gateway's answer to an auth-reply, yielding a usable session.
 * @param prof {Profile} the active profile, for the connect URL and any configured pin
 * @param body {string} the response body
 * @return {Session} the VPN session cookie and the certificate pin to use
 * @throws {Error} kind "gateway" when the login did not complete
 * @since 0.1
 */
func parseAuthComplete(prof as types.Profile, body as string) {
    def root as xml.Value init xml.decode($body);
    def kind as string init rootType($root);
    if ($kind != "complete") {
        def why as string init "";
        if (xml.has($root, "auth")) {
            $why = childText(xml.get($root, "auth"), "error", "");
        }
        if ($why == "") {
            $why = "got type='" + $kind + "' instead";
        }
        util.fail("gateway", "the gateway did not complete the login: " + $why);
    }

    def sess as types.Session init types.Session{
        cookie: childText($root, "session-token", ""),
        connectUrl: $prof.server,
        fingerprint: $prof.servercert,
        message: ""
    };
    if ($sess.cookie == "") {
        util.fail("gateway", "the gateway completed the login but returned no <session-token>");
    }
    # The gateway hands us its own certificate hash; pin openconnect to it.
    if ($sess.fingerprint == "" and xml.has($root, "config/vpn-base-config/server-cert-hash")) {
        $sess.fingerprint = strings.trim(xml.text(xml.get(
            $root,
            "config/vpn-base-config/server-cert-hash")));
    }
    if (xml.has($root, "auth")) {
        def auth as xml.Value init xml.get($root, "auth");
        $sess.message = childText($auth, "banner", childText($auth, "message", ""));
    }
    return $sess;
}

/**
 * Probe the gateway, offering external-browser mode but not insisting on it.
 * Some gateways answer "VPN Server internal error" to any client that so much
 * as advertises single-sign-on-external-browser. Offering it is therefore only
 * ever an attempt: fall back to the plain sso-v2 probe, which every SAML
 * gateway answers.
 * @param prof {Profile} the active profile
 * @return {AuthRequest} the gateway's answer, with externalRefused set if the offer failed
 * @throws {Error} kind "gateway" when even the plain probe fails
 * @since 0.1
 */
export func probeOfferingExternal(prof as types.Profile) {
    try {
        return probeGateway($prof, true);
    } catch (e) {
        util.note($prof, "gateway refused the external-browser offer (" + $e.message + ")");
        def plain as types.AuthRequest init probeGateway($prof, false);
        $plain.externalRefused = true;
        return $plain;
    }
}

/**
 * Ask the gateway how it wants to authenticate.
 * @param prof {Profile} the active profile
 * @param offerExternal {bool} advertise single-sign-on-external-browser as well
 * @return {AuthRequest} the gateway's answer
 * @throws {Error} kind "gateway" when the gateway refuses or answers unexpectedly
 * @since 0.1
 */
export func probeGateway(prof as types.Profile, offerExternal as bool) {
    util.note($prof, "asking " + $prof.server + " how it wants to authenticate");
    return parseAuthRequest(postAuthXml($prof, initXml($prof, $offerExternal)));
}

/**
 * Submit an SSO token to the gateway and turn it into a VPN session.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} the gateway's answer to the init request
 * @param token {string} the SSO token, however it was obtained
 * @return {Session} the authenticated session
 * @throws {Error} kind "gateway" when the gateway rejects the token
 * @since 0.1
 */
export func submitToken(prof as types.Profile, ar as types.AuthRequest, token as string) {
    util.note($prof, "sending the token back to the gateway");
    return parseAuthComplete($prof, postAuthXml($prof, replyXml($prof, $ar, $token)));
}
