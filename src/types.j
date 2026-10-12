# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net

/**
 * The data every other module passes around, and the constants they share.
 *
 * @module types
 * @version 0.4.0
 */

import "http.j" as http;

/**
 * Program name, used in messages, the pid-file name and the config path.
 * @since 0.1
 */
export def const APP as string init "openconnect-saml";
/**
 * This program's own version, reported by --version.
 * @since 0.1
 */
export def const APP_VERSION as string init "0.4.0";

/**
 * The AnyConnect client version we claim to be.
 * The gateway matches on this, and openconnect must be told the same story
 * (--useragent / --version-string), so the two have to stay in step. A profile
 * may override it.
 * @since 0.1
 */
export def const CLIENT_VERSION as string init "4.10.05111";
/**
 * The <device-id> reported to the gateway, in AnyConnect's platform vocabulary.
 * @since 0.1
 */
export def const DEVICE_ID as string init "linux-64";
/**
 * Per-read idle timeout for the gateway conversation, in milliseconds.
 * @since 0.1
 */
export def const HTTP_TIMEOUT_MS as int init 30000;

/**
 * How many redirects and form submissions a browserless login may take before
 * it is declared stuck.
 * @since 0.2
 */
export def const MAX_SSO_STEPS as int init 12;

/**
 * Per-receive read timeout on the CDP socket, in milliseconds.
 * A reply to Storage.getCookies arrives in milliseconds, so this only bounds
 * the wait on a browser that has stopped answering.
 * @since 0.4
 */
export def const CDP_RECEIVE_MS as int init 5000;

/**
 * How many CDP frames one cookie poll will read before giving up on its reply.
 * The browser interleaves events with replies, so some skipping is normal; an
 * unbounded loop would sit inside one iteration of the caller's timeout.
 * @since 0.4
 */
export def const MAX_CDP_READS as int init 200;

/**
 * How many trailing lines of the browser's stderr an error message carries.
 * @since 0.4
 */
export def const BROWSER_LOG_LINES as int init 5;

/**
 * One VPN target: everything `connect` needs that is not discovered at runtime.
 * Built from the config file, then overlaid with command-line flags.
 * @field name {string} profile name from the config file ("" when none applies)
 * @field server {string} gateway URL including the group path, e.g. https://vpn.example.com/saml
 * @field group {string} tunnel group for <group-select>; most gateways ignore it, see `server`
 * @field browser {string} command that opens a URL ("-" to never launch one)
 * @field sudo {string} privilege helper for the tunnel ("" to run openconnect directly)
 * @field version {string} the AnyConnect version to claim
 * @field user {string} username for browserless mode
 * @field passwordCommand {string} command printing the password, for browserless mode
 * @field factor {string} which second factor to pick when the IdP offers a choice
 * @field debugDir {string} directory to save each browserless page into ("" = off)
 * @field capture {string} how token mode gets the cookie: "auto", "cdp" or "paste"
 * @field cdpPort {int} the browser's remote-debugging port for cdp capture
 * @field browserProfile {string} profile directory for the capture browser ("" = default)
 * @field captureTimeoutMs {int} how long to wait for the login to finish
 * @field servercert {string} certificate pin for openconnect ("" uses the one the gateway reports)
 * @field insecure {bool} skip TLS verification while authenticating
 * @field verbose {bool} narrate the exchange on stderr
 * @field extra {list of string} flags passed to openconnect verbatim
 * @since 0.1
 */
export def struct Profile {
    name as string,
    server as string,
    group as string,
    browser as string,
    sudo as string,
    version as string,
    user as string,
    passwordCommand as string,
    factor as string,
    debugDir as string,
    capture as string,
    cdpPort as int,
    browserProfile as string,
    captureTimeoutMs as int,
    servercert as string,
    insecure as bool,
    verbose as bool,
    extra as list of string
};

/**
 * What the gateway told us in its <config-auth type="auth-request">.
 * @field loginUrl {string} the SSO login URL to open in the browser
 * @field loginFinalUrl {string} the URL the browser lands on once the login succeeds
 * @field tokenCookieName {string} name of the cookie carrying the SSO token (usually acSamlv2Token)
 * @field browserMode {string} "external" for Cisco's external-browser flow, else ""
 * @field ssoField {string} element name for the token in the reply, from <input type="sso">
 * @field opaqueXml {string} the gateway's <opaque> block, to be echoed back verbatim
 * @field tunnelGroup {string} the tunnel group the gateway resolved us to, for diagnostics
 * @field externalRefused {bool} the gateway errored when offered external-browser mode
 * @field title {string} the login title to show the user
 * @field message {string} the login message to show the user
 * @since 0.1
 */
export def struct AuthRequest {
    loginUrl as string,
    loginFinalUrl as string,
    tokenCookieName as string,
    browserMode as string,
    ssoField as string,
    opaqueXml as string,
    tunnelGroup as string,
    externalRefused as bool,
    title as string,
    message as string
};

/**
 * Everything needed to hand the tunnel over to openconnect.
 * @field cookie {string} the VPN session cookie (openconnect's --cookie)
 * @field connectUrl {string} the URL openconnect should connect to
 * @field fingerprint {string} certificate pin for --servercert ("" to let openconnect decide)
 * @field message {string} the gateway's post-login banner, if any
 * @since 0.1
 */
export def struct Session {
    cookie as string,
    connectUrl as string,
    fingerprint as string,
    message as string
};

/**
 * The unprivileged user the capture browser has to run as.
 * A blank `name` is the normal case and means "run it as ourselves"; it is set
 * only when the program itself is root and the browser must be handed back.
 * @field name {string} login name, "" when we are already unprivileged
 * @field uid {int} that user's numeric uid, -1 when it could not be read
 * @field home {string} that user's home directory, "" when it could not be read
 * @since 0.4
 */
export def struct BrowserOwner {
    name as string,
    uid as int,
    home as string
};

/**
 * A Profile with the built-in defaults and no gateway set.
 * @return {Profile} the starting point for both config loading and the no-config case
 * @since 0.1
 */
export func defaultProfile() {
    return Profile{
        name: "",
        server: "",
        group: "",
        browser: "xdg-open",
        sudo: "sudo",
        version: CLIENT_VERSION,
        user: "",
        passwordCommand: "",
        factor: "",
        debugDir: "",
        capture: "auto",
        cdpPort: 9333,
        browserProfile: "",
        captureTimeoutMs: 300000,
        servercert: "",
        insecure: false,
        verbose: false,
        extra: []
    };
}

#
# ------------------------------------------------------ browserless SSO
#

/**
 * What a browserless login submits: the credentials, and which second factor to
 * choose if the identity provider offers a choice.
 * @field user {string} the username
 * @field password {string} the password
 * @field factor {string} the second factor to pick ("" = whatever comes first)
 * @since 0.2
 */
export def struct Credentials {
    user as string,
    password as string,
    factor as string
};

/**
 * One hop of the browserless login: the response, and the sessions it updated.
 * Jennifer has no tuples, so the per-origin session list rides along with the
 * response and the caller threads it forward.
 * @field sessions {list of http.Session} one live session per origin, updated
 * @field status {int} the HTTP status - but sessionFor overloads it as the
 *     index of the session it found or opened
 * @field location {string} the Location header, or "" when there was none
 * @field body {string} the response body
 * @since 0.2
 */
export def struct Hop {
    sessions as list of http.Session,
    status as int,
    location as string,
    body as string
};
