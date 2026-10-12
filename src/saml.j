# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net
# pragma-jennifer-capability: exec

/**
 * Everything openconnect-saml does, as a module: the AnyConnect <config-auth>
 * protocol, the three ways of obtaining an SSO token, and the command handlers.
 *
 * It lives here rather than in the executable so that `saml_test.j` can splice
 * it and test the private surface directly - a module top level is
 * declarations-only, which is exactly what a white-box overlay needs. The
 * executable is a five-line shell around `run`.
 *
 * See the README for the protocol, and openconnect-saml(1) for the interface.
 *
 * @module saml
 * @version 0.3.0
 * @see README.md
 */

use io;
use os;
use fs;
use path;
use xml;
use toml;
use strings;
use maps;
use lists;
use convert;
use binary;
use term;
use time;
use json;

import "http.j" as http;
import "uri.j" as uri;
import "args.j" as args;
import "html.j" as html;
import "websocket.j" as websocket;

/**
 * Program name, used in messages, the pid-file name and the config path.
 * @since 0.1
 */
def const APP as string init "openconnect-saml";
/**
 * This program's own version, reported by --version.
 * @since 0.1
 */
def const APP_VERSION as string init "0.3.0";

/**
 * The AnyConnect client version we claim to be.
 * The gateway matches on this, and openconnect must be told the same story
 * (--useragent / --version-string), so the two have to stay in step. A profile
 * may override it.
 * @since 0.1
 */
def const CLIENT_VERSION as string init "4.10.05111";
/**
 * The <device-id> reported to the gateway, in AnyConnect's platform vocabulary.
 * @since 0.1
 */
def const DEVICE_ID as string init "linux-64";
/**
 * Per-read idle timeout for the gateway conversation, in milliseconds.
 * @since 0.1
 */
def const HTTP_TIMEOUT_MS as int init 30000;

/**
 * How many redirects and form submissions a browserless login may take before
 * it is declared stuck.
 * @since 0.2
 */
def const MAX_SSO_STEPS as int init 12;

/**
 * Per-receive read timeout on the CDP socket, in milliseconds.
 * A reply to Storage.getCookies arrives in milliseconds, so this only bounds
 * the wait on a browser that has stopped answering.
 * @since 0.4
 */
def const CDP_RECEIVE_MS as int init 5000;

/**
 * How many CDP frames one cookie poll will read before giving up on its reply.
 * The browser interleaves events with replies, so some skipping is normal; an
 * unbounded loop would sit inside one iteration of the caller's timeout.
 * @since 0.4
 */
def const MAX_CDP_READS as int init 200;

/**
 * How many trailing lines of the browser's stderr an error message carries.
 * @since 0.4
 */
def const BROWSER_LOG_LINES as int init 5;

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
def struct Profile {
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
def struct AuthRequest {
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
def struct Session {
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
def struct BrowserOwner {
    name as string,
    uid as int,
    home as string
};

#
# ---------------------------------------------------------------- small helpers
#

/**
 * Raise a tagged Error, the one way this program reports a problem.
 * @param kind {string} short error class, e.g. "gateway" or "config"
 * @param message {string} the message shown to the user
 * @throws {Error} always, with the given kind and message
 * @since 0.1
 */
func fail(kind as string, message as string) {
    throw Error{kind: $kind, message: $message, file: "", line: 0, col: 0};
}

/**
 * Escape text for inclusion in an XML element or attribute.
 * @param s {string} the raw text
 * @return {string} the text with &, <, > and " replaced by entities
 * @since 0.1
 */
func xmlEscape(s as string) {
    def out as string init strings.replace($s, "&", "&amp;");
    $out = strings.replace($out, "<", "&lt;");
    $out = strings.replace($out, ">", "&gt;");
    $out = strings.replace($out, "\"", "&quot;");
    return $out;
}

/**
 * Whether a character may appear in an XML element name from gateway input.
 * Narrower than XML's NameChar: ASCII only. The names a Cisco gateway asks for
 * are `sso-token` and `sso-token-v2`.
 * @param c {string} one character
 * @param first {bool} true for the name's first position, where digits and
 *     `.`/`-` are not allowed
 * @return {bool} true when allowed in that position
 * @since 0.4
 */
func isXmlNameChar(c as string, first as bool) {
    def letters as string init "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    if (strings.contains($letters, $c)) {
        return true;
    }
    if ($first) {
        return false;
    }
    return strings.contains("0123456789.-", $c);
}

/**
 * Whether a string is safe to interpolate as an XML element name.
 * The reply names one element after whatever the gateway asked for, and a tag
 * name cannot be escaped the way text can.
 * @param s {string} the candidate name
 * @return {bool} true when usable as an element name
 * @since 0.4
 */
func isXmlName(s as string) {
    if ($s == "") {
        return false;
    }
    def first as bool init true;
    for (def c in strings.chars($s)) {
        if (not isXmlNameChar($c, $first)) {
            return false;
        }
        $first = false;
    }
    return true;
}

/**
 * Drop a leading <?xml ... ?> declaration.
 * xml.encode may prepend one, and an embedded fragment must not carry it.
 * @param s {string} serialized XML
 * @return {string} the same XML without its declaration
 * @since 0.1
 */
func stripXmlDecl(s as string) {
    def t as string init strings.trim($s);
    if (strings.startsWith($t, "<?xml")) {
        def i as int init strings.indexOf($t, "?>");
        if ($i >= 0) {
            $t = strings.trim(strings.substring($t, $i + 2));
        }
    }
    return $t;
}

/**
 * This machine's host name, for the gateway's <device-id computer-name>.
 * @return {string} the host name, or "linux" if it cannot be determined
 * @since 0.1
 */
func hostName() {
    def h as string init os.getEnv("HOSTNAME");
    if ($h != "") {
        return $h;
    }
    if (fs.exists("/etc/hostname")) {
        return strings.trim(fs.readString("/etc/hostname"));
    }
    return "linux";
}

/**
 * Reduce a string to characters safe in a file name.
 * @param s {string} the raw text
 * @return {string} the text with every unsafe character replaced by "-", never empty
 * @since 0.1
 */
func slug(s as string) {
    def out as string init "";
    for (def c in strings.chars($s)) {
        if (isSlugChar($c)) {
            $out = $out + $c;
        } else {
            $out = $out + "-";
        }
    }
    if ($out == "") {
        $out = "default";
    }
    return $out;
}

/**
 * Whether a character may appear in a file name built by `slug`.
 * @param c {string} a single character
 * @return {bool} true when the character is alphanumeric, "-", "_" or "."
 * @since 0.1
 */
func isSlugChar(c as string) {
    def ok as string init "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
    return strings.contains($ok, $c);
}

/**
 * Write a progress line to stderr, but only under --verbose.
 * @param prof {Profile} the active profile, consulted for its verbose flag
 * @param message {string} the line to write
 * @since 0.1
 */
func note(prof as Profile, message as string) {
    if ($prof.verbose) {
        io.eprintf("... %s\n", $message);
    }
}

#
# ------------------------------------------------------------------------ config
#

/**
 * Where the config file lives.
 * @return {string} $OPENCONNECT_SAML_CONFIG if set, else ~/.config/openconnect-saml/config.toml
 * @since 0.1
 */
func configPath() {
    def override as string init os.getEnv("OPENCONNECT_SAML_CONFIG");
    if ($override != "") {
        return $override;
    }
    return path.join(os.homeDir(), ".config", APP, "config.toml");
}

/**
 * Read a string from a TOML document, tolerating an absent key.
 * @param doc {toml.Value} the parsed config
 * @param ptr {string} JSON Pointer to the value
 * @param deflt {string} returned when the pointer resolves to nothing
 * @return {string} the value, or the default
 * @since 0.1
 */
func tomlString(doc as toml.Value, ptr as string, deflt as string) {
    if (toml.has($doc, $ptr)) {
        return toml.asString($doc, $ptr);
    }
    return $deflt;
}

/**
 * Read a boolean from a TOML document, tolerating an absent key.
 * @param doc {toml.Value} the parsed config
 * @param ptr {string} JSON Pointer to the value
 * @param deflt {bool} returned when the pointer resolves to nothing
 * @return {bool} the value, or the default
 * @since 0.1
 */
func tomlBool(doc as toml.Value, ptr as string, deflt as bool) {
    if (toml.has($doc, $ptr)) {
        return toml.asBool($doc, $ptr);
    }
    return $deflt;
}

/**
 * Read an integer from a TOML document, tolerating an absent key.
 * @param doc {toml.Value} the parsed config
 * @param ptr {string} JSON Pointer to the value
 * @param deflt {int} returned when the pointer resolves to nothing
 * @return {int} the value, or the default
 * @since 0.3
 */
func tomlInt(doc as toml.Value, ptr as string, deflt as int) {
    if (toml.has($doc, $ptr)) {
        return toml.asInt($doc, $ptr);
    }
    return $deflt;
}

/**
 * Read an array of strings from a TOML document, tolerating an absent key.
 * @param doc {toml.Value} the parsed config
 * @param ptr {string} JSON Pointer to the array
 * @return {list of string} the entries, empty when the pointer resolves to nothing
 * @since 0.1
 */
func tomlList(doc as toml.Value, ptr as string) {
    def out as list of string init [];
    if (not toml.has($doc, $ptr)) {
        return $out;
    }
    def n as int init toml.length($doc, $ptr);
    for (def i in 0..$n) {
        $out[] = toml.asString($doc, $ptr + "/" + convert.toString($i));
    }
    return $out;
}

/**
 * The profiles a config file defines.
 * Every top-level table is a profile; scalars such as `default` are not.
 * @param doc {toml.Value} the parsed config
 * @return {list of string} the profile names, in document order
 * @since 0.1
 */
func profileNames(doc as toml.Value) {
    def out as list of string init [];
    for (def k in toml.keys($doc)) {
        if (toml.typeOf($doc, "/" + $k) == "map") {
            $out[] = $k;
        }
    }
    return $out;
}

/**
 * A Profile with the built-in defaults and no gateway set.
 * @return {Profile} the starting point for both config loading and the no-config case
 * @since 0.1
 */
func defaultProfile() {
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

/**
 * Load one profile from the config file.
 * Falls back to the `default` key, and then to the only profile present if the
 * file defines exactly one.
 * @param name {string} the requested profile, or "" to let the file decide
 * @return {Profile} the profile, or the defaults when there is no config file
 * @throws {Error} kind "config" when the named profile does not exist
 * @since 0.1
 */
func loadProfile(name as string) {
    def prof as Profile init defaultProfile();
    def cfg as string init configPath();
    if (not fs.exists($cfg)) {
        if ($name != "") {
            fail(
                "config",
                "no config file at " + $cfg + ", so profile '" + $name + "' cannot be resolved");
        }
        return $prof;
    }

    def doc as toml.Value init toml.decode(fs.readString($cfg));
    def want as string init $name;
    if ($want == "") {
        $want = tomlString($doc, "/default", "");
    }
    if ($want == "") {
        def names as list of string init profileNames($doc);
        if (len($names) == 1) {
            $want = $names[0];
        }
    }
    if ($want == "") {
        return $prof;
    }

    def base as string init "/" + $want;
    if (not toml.has($doc, $base)) {
        fail(
            "config",
            "no profile named '" + $want + "' in " + $cfg + " (found: " +
                strings.join(profileNames($doc), ", ") + ")");
    }

    $prof.name = $want;
    $prof.server = tomlString($doc, $base + "/server", "");
    $prof.group = tomlString($doc, $base + "/group", "");
    $prof.browser = tomlString($doc, $base + "/browser", "xdg-open");
    $prof.sudo = tomlString($doc, $base + "/sudo", "sudo");
    $prof.version = tomlString($doc, $base + "/version", CLIENT_VERSION);
    $prof.user = tomlString($doc, $base + "/user", "");
    $prof.capture = tomlString($doc, $base + "/capture", "auto");
    $prof.cdpPort = tomlInt($doc, $base + "/cdpPort", 9333);
    $prof.browserProfile = tomlString($doc, $base + "/browserProfile", "");
    $prof.captureTimeoutMs = tomlInt($doc, $base + "/captureTimeout", 300) * 1000;
    $prof.passwordCommand = tomlString($doc, $base + "/passwordCommand", "");
    $prof.factor = tomlString($doc, $base + "/factor", "");
    $prof.servercert = tomlString($doc, $base + "/servercert", "");
    $prof.insecure = tomlBool($doc, $base + "/insecure", false);
    $prof.extra = tomlList($doc, $base + "/extra");
    return $prof;
}

/**
 * The profile to act on: the config file overlaid with command-line flags.
 * Also normalises the gateway URL, prepending https:// when no scheme is given.
 * @param r {args.Result} the parsed command line
 * @return {Profile} the effective profile
 * @throws {Error} kind "config" when no gateway URL is configured or passed
 * @since 0.1
 */
func resolveProfile(r as args.Result) {
    def prof as Profile init loadProfile(args.asString($r, "profile"));

    if (args.asString($r, "server") != "") {
        $prof.server = args.asString($r, "server");
    }
    if (args.asString($r, "group") != "") {
        $prof.group = args.asString($r, "group");
    }
    if (args.asString($r, "browser") != "") {
        $prof.browser = args.asString($r, "browser");
    }
    if (args.has($r, "sudo")) {
        $prof.sudo = args.asString($r, "sudo");
    }
    if (args.asString($r, "user") != "") {
        $prof.user = args.asString($r, "user");
    }
    if (args.asString($r, "password-command") != "") {
        $prof.passwordCommand = args.asString($r, "password-command");
    }
    if (args.asString($r, "factor") != "") {
        $prof.factor = args.asString($r, "factor");
    }
    if (args.asString($r, "debug-dir") != "") {
        $prof.debugDir = args.asString($r, "debug-dir");
    }
    # asString would report the flag's own default and silently outrank a
    # profile setting, so only an actually-supplied flag overrides.
    if (args.has($r, "capture")) {
        $prof.capture = args.asString($r, "capture");
    }
    if (args.asBool($r, "insecure")) {
        $prof.insecure = true;
    }
    if (args.asBool($r, "verbose")) {
        $prof.verbose = true;
    }

    if ($prof.server == "") {
        fail(
            "config",
            "no gateway URL - pass --server https://vpn.example.com," + " or put one in " +
                configPath());
    }
    if (not strings.startsWith($prof.server, "http://") and
        not strings.startsWith($prof.server, "https://")) {
        $prof.server = "https://" + $prof.server;
    }
    # Both directions carry a bearer credential: the SSO token in, the session
    # cookie out. --insecure already means "unauthenticated channel accepted",
    # so it is the only way through.
    if (strings.startsWith($prof.server, "http://") and not $prof.insecure and
        not isLoopbackHost(uri.parse($prof.server).host)) {
        fail(
            "config",
            "refusing to authenticate over plain http://: the SSO token and the VPN\n" +
                "  session cookie would cross the network in clear text.\n" +
                "  Use https://, or pass --insecure if you really mean it.");
    }
    return $prof;
}

/**
 * Where `connect` asks openconnect to write its pid, and `disconnect` reads it.
 * @param prof {Profile} the active profile
 * @return {string} an absolute path under /run, named after the profile
 * @since 0.1
 */
func pidFileFor(prof as Profile) {
    return runFileFor($prof, ".pid");
}

/**
 * Where the backgrounded openconnect's output is redirected.
 * @param prof {Profile} the active profile
 * @return {string} an absolute path under /run, named after the profile
 * @since 0.1
 */
func logFileFor(prof as Profile) {
    return runFileFor($prof, ".log");
}

/**
 * A per-profile path under /run, shared by the pid and log files.
 * @param prof {Profile} the active profile
 * @param suffix {string} the file extension, including the dot
 * @return {string} the absolute path
 * @since 0.1
 */
func runFileFor(prof as Profile, suffix as string) {
    def n as string init $prof.name;
    if ($n == "") {
        $n = uri.parse($prof.server).host;
    }
    return "/run/" + APP + "-" + slug($n) + $suffix;
}

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
func postAuthXml(prof as Profile, body as string) {
    def noCa as bytes;
    def tls as http.TlsOptions init http.TlsOptions{skipVerify: $prof.insecure, caCert: $noCa};
    def resp as http.Response init http.requestWithTls(
        "POST",
        $prof.server,
        authHeaders($prof.version),
        $body,
        HTTP_TIMEOUT_MS,
        0,
        $tls);
    if ($resp.status < 200 or $resp.status >= 300) {
        fail("gateway", io.sprintf("gateway answered HTTP %d %s", $resp.status, $resp.statusText));
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
func initXml(prof as Profile, offerExternal as bool) {
    def caps as string init '<auth-method>single-sign-on-v2</auth-method>';
    if ($offerExternal) {
        $caps = $caps + '<auth-method>single-sign-on-external-browser</auth-method>';
    }
    def group as string init "";
    if ($prof.group != "") {
        $group = "<group-select>" + xmlEscape($prof.group) + "</group-select>";
    }
    def tpl as string init '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="init" aggregate-auth-version="2">' +
        '<version who="vpn">%s</version><device-id>%s</device-id>' +
        '%s<group-access>%s</group-access>' + '<capabilities>%s</capabilities></config-auth>';
    return io.sprintf(
        $tpl,
        xmlEscape($prof.version),
        DEVICE_ID,
        $group,
        xmlEscape($prof.server),
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
func replyXml(prof as Profile, ar as AuthRequest, token as string) {
    def tpl as string init '<?xml version="1.0" encoding="UTF-8"?>' +
        '<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">' +
        '<version who="vpn">%s</version>' + '<device-id computer-name="%s">%s</device-id>' +
        '<session-token/><session-id/>%s' + '<auth><%s>%s</%s></auth></config-auth>';
    return io.sprintf(
        $tpl,
        xmlEscape($prof.version),
        xmlEscape(hostName()),
        DEVICE_ID,
        $ar.opaqueXml,
        $ar.ssoField,
        xmlEscape($token),
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
func emptyAuthRequest() {
    return AuthRequest{
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
 * @throws {Error} kind "gateway" when the gateway refused, or offered no SAML login
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
        fail("gateway", "the gateway would not start a login: " + $why);
    }
    if (not xml.has($root, "auth")) {
        fail("gateway", "the gateway's auth-request carries no <auth> node");
    }

    def auth as xml.Value init xml.get($root, "auth");
    def err as string init childText($auth, "error", "");
    if ($err != "") {
        fail("gateway", "the gateway refused the request: " + $err);
    }

    def ar as AuthRequest init AuthRequest{
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
        fail(
            "gateway",
            "the gateway offered no <sso-v2-login> URL" +
                " - it does not look like it authenticates with SAML");
    }
    # The token is escaped; the element name around it cannot be. A gateway
    # naming a field `a><b` would inject into the reply.
    if (not isXmlName($ar.ssoField)) {
        fail(
            "gateway",
            "the gateway asked for the token under '" + $ar.ssoField +
                "', which is not a usable XML element name");
    }
    if ($ar.loginFinalUrl == "") {
        $ar.loginFinalUrl = $ar.loginUrl;
    }
    if (xml.has($root, "opaque")) {
        def opaque as xml.Value init xml.get($root, "opaque");
        $ar.opaqueXml = stripXmlDecl(xml.encode($opaque));
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
func parseAuthComplete(prof as Profile, body as string) {
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
        fail("gateway", "the gateway did not complete the login: " + $why);
    }

    def sess as Session init Session{
        cookie: childText($root, "session-token", ""),
        connectUrl: $prof.server,
        fingerprint: $prof.servercert,
        message: ""
    };
    if ($sess.cookie == "") {
        fail("gateway", "the gateway completed the login but returned no <session-token>");
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
func probeOfferingExternal(prof as Profile) {
    try {
        return probeGateway($prof, true);
    } catch (e) {
        note($prof, "gateway refused the external-browser offer (" + $e.message + ")");
        def plain as AuthRequest init probeGateway($prof, false);
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
func probeGateway(prof as Profile, offerExternal as bool) {
    note($prof, "asking " + $prof.server + " how it wants to authenticate");
    return parseAuthRequest(postAuthXml($prof, initXml($prof, $offerExternal)));
}

#
# ------------------------------------------------------------ the browser round
#

/**
 * Open a URL in the user's browser, without waiting for it.
 * @param prof {Profile} the active profile, for the browser command
 * @param url {string} the URL to open
 * @return {bool} true if a browser was launched, false if disabled or it failed
 * @since 0.1
 */
func launchBrowser(prof as Profile, url as string) {
    if ($prof.browser == "" or $prof.browser == "-") {
        return false;
    }
    try {
        # Nothing waits on this one, and a captured stream with no reader is a
        # pipe waiting to fill.
        def child as os.Process init os.spawn(
            [$prof.browser, $url],
            {"stdout": "discard", "stderr": "discard"});
        note($prof, io.sprintf("launched %s (pid %d)", $prof.browser, $child.pid));
        return true;
    } catch (e) {
        io.eprintf("could not launch %s: %s\n", $prof.browser, $e.message);
        return false;
    }
}

/**
 * Pull the SSO token out of a pasted URL.
 * Prefers a query parameter named after the cookie, then any parameter that
 * looks token-ish, and falls back to the last path segment.
 * @param raw {string} the pasted URL
 * @param cookieName {string} the cookie name the gateway told us to expect
 * @return {string} the token
 * @since 0.1
 */
func tokenFromUrl(raw as string, cookieName as string) {
    def u as uri.Uri init uri.parse($raw);
    def q as map of string to string init {};
    if ($u.query != "") {
        $q = uri.parseQuery($u.query);
    }
    if (maps.has($q, $cookieName)) {
        return $q[$cookieName];
    }
    for (def k in $q) {
        if (strings.contains(strings.lower($k), "token")) {
            return $q[$k];
        }
    }
    def parts as list of string init strings.split($u.path, "/");
    return $parts[len($parts) - 1];
}

/**
 * Make sense of whatever the user pasted at the token prompt.
 * Accepts the bare cookie value, a "name=value" pair, a whole Cookie header, or
 * the final URL if the token happens to ride in its query string.
 * @param raw {string} the pasted text
 * @param cookieName {string} the cookie name the gateway told us to expect
 * @return {string} the token, or "" when nothing was pasted
 * @since 0.1
 */
func extractToken(raw as string, cookieName as string) {
    def s as string init strings.trim($raw);
    if ($s == "") {
        return "";
    }

    if (strings.contains($s, "://")) {
        return tokenFromUrl($s, $cookieName);
    }

    if (strings.contains($s, ";")) {
        for (def piece in strings.split($s, ";")) {
            def kv as string init strings.trim($piece);
            def i as int init strings.indexOf($kv, "=");
            if ($i > 0 and strings.substring($kv, 0, $i) == $cookieName) {
                return strings.trim(strings.substring($kv, $i + 1));
            }
        }
        # A Cookie header without the cookie we asked for. Returning the whole
        # header would send the gateway a token made of somebody else's cookies;
        # "" reaches the caller's "no token given" instead.
        return "";
    }

    def prefix as string init $cookieName + "=";
    if (strings.startsWith($s, $prefix)) {
        return strings.substring($s, len($prefix));
    }
    return $s;
}

/**
 * Whether a browser command can be driven over the Chrome DevTools Protocol.
 * Chromium and its relatives expose CDP behind --remote-debugging-port; Firefox
 * does not speak it, so it falls back to the paste prompt.
 * @param cmd {string} the configured browser command
 * @return {bool} true when the command looks Chromium-based
 * @since 0.3
 */
func browserSpeaksCdp(cmd as string) {
    def base as string init strings.lower(path.base($cmd));
    return strings.contains($base, "chromium") or strings.contains($base, "chrome") or
        strings.contains($base, "brave") or strings.contains($base, "vivaldi") or
        strings.contains($base, "edge");
}

/**
 * This process's effective uid.
 * No os.geteuid, so ask id(1). A failure reads as "not root", which costs only
 * the handoff below.
 * @return {int} the effective uid, or -1 when it could not be read
 * @since 0.4
 */
func effectiveUid() {
    try {
        def r as os.Result init os.run(["id", "-u"]);
        if ($r.exitCode != 0) {
            return -1;
        }
        return convert.toInt(strings.trim($r.stdout));
    } catch (e) {
        return -1;
    }
}

/**
 * Which user invoked us through a privilege helper, if any.
 * sudo and doas both record the original login name in the environment.
 * @return {string} the login name, "" when there is none or it was root itself
 * @since 0.4
 */
func invokingUser() {
    def who as string init os.getEnv("SUDO_USER");
    if ($who == "") {
        $who = os.getEnv("DOAS_USER");
    }
    if ($who == "root") {
        return "";
    }
    return $who;
}

/**
 * A user's uid and home directory, out of the password database.
 * @param name {string} the login name to look up
 * @return {BrowserOwner} the entry, with uid -1 and home "" when it is unknown
 * @since 0.4
 */
func passwdEntry(name as string) {
    def owner as BrowserOwner init BrowserOwner{name: $name, uid: -1, home: ""};
    try {
        def r as os.Result init os.run(["getent", "passwd", $name]);
        if ($r.exitCode != 0) {
            return $owner;
        }
        def fields as list of string init strings.split(strings.trim($r.stdout), ":");
        if (len($fields) < 6) {
            return $owner;
        }
        $owner.uid = convert.toInt($fields[2]);
        $owner.home = $fields[5];
    } catch (e) { # lint-disable: L103
        # An unparsable entry is the same as no entry.
    }
    return $owner;
}

/**
 * The advice that follows every "the capture browser cannot run as root".
 * @param prof {Profile} the active profile, so the hint names the real setting
 * @return {string} the indented advice lines
 * @since 0.4
 */
func unprivilegedAdvice(prof as Profile) {
    def how as string init "it escalates on its own";
    if ($prof.sudo == "") {
        $how = "set sudo = \"sudo\" so it can escalate on its own";
    }
    return "  Run " + APP + " as your normal desktop user: authentication never needs\n" +
        "  root, only the tunnel does, and " + $how + ".\n" +
        "  Or set capture = \"paste\" and read the cookie out of a browser you start.";
}

/**
 * Who the capture browser should run as.
 * A Chromium-based browser exits at once as root ("Running as root without
 * --no-sandbox is not supported"), so under sudo there is nothing to drive over
 * CDP. Hand it to the invoking user - where the IdP session and the X/Wayland
 * display already are - rather than adding --no-sandbox to the browser that
 * performs the real login.
 * @param prof {Profile} the active profile, for the advice in the error
 * @return {BrowserOwner} the user to drop to, name "" to stay as we are
 * @throws {Error} kind "privilege" when we are root with nobody to drop to
 * @since 0.4
 */
func browserOwner(prof as Profile) {
    if (effectiveUid() != 0) {
        return BrowserOwner{name: "", uid: -1, home: ""};
    }
    def who as string init invokingUser();
    if ($who == "") {
        fail(
            "privilege",
            "a Chromium-based browser refuses to start as root, and there is no\n" +
                "  SUDO_USER to hand it back to.\n" + unprivilegedAdvice($prof));
    }
    def owner as BrowserOwner init passwdEntry($who);
    if ($owner.home == "") {
        fail(
            "privilege",
            "a Chromium-based browser refuses to start as root, and " + $who +
                " has no\n  home directory in the password database to run it from.\n" +
                unprivilegedAdvice($prof));
    }
    def r as os.Result init os.run(["sudo", "-n", "-u", $who, "true"]);
    if ($r.exitCode != 0) {
        fail(
            "privilege",
            "a Chromium-based browser refuses to start as root, and `sudo -n -u " + $who +
                "`\n  does not work here, so it cannot be handed back to you.\n" +
                unprivilegedAdvice($prof));
    }
    return $owner;
}

/**
 * Where the capture browser keeps its profile.
 * Deliberately persistent and separate from your day-to-day profile: separate
 * so launching it never collides with a running browser, persistent so the
 * identity provider's session - and any "remember this device" the second
 * factor grants - survives to the next connect. When the browser is handed back
 * to an unprivileged user the profile follows it into that user's home, so root
 * never ends up owning the session it is about to read a cookie out of.
 * @param prof {Profile} the active profile
 * @param owner {BrowserOwner} who the browser will run as
 * @return {string} the profile directory
 * @since 0.3
 */
func browserProfileDir(prof as Profile, owner as BrowserOwner) {
    if ($prof.browserProfile != "") {
        return $prof.browserProfile;
    }
    def home as string init os.homeDir();
    if ($owner.home != "") {
        $home = $owner.home;
    }
    return path.join($home, ".cache", APP, "browser");
}

/**
 * Create the capture browser's profile directory, owned by its user.
 * Created as root inside someone else's home it would be unwritable by the
 * browser, so a handoff mkdirs through sudo too.
 * @param dir {string} the profile directory
 * @param owner {BrowserOwner} who the browser will run as
 * @throws {Error} kind "privilege" when the directory cannot be created
 * @since 0.4
 */
func makeBrowserProfileDir(dir as string, owner as BrowserOwner) {
    if ($owner.name == "") {
        fs.mkdirAll($dir);
        return;
    }
    def r as os.Result init os.run(["sudo", "-n", "-u", $owner.name, "mkdir", "-p", $dir]);
    if ($r.exitCode != 0) {
        fail(
            "privilege",
            "could not create " + $dir + " as " + $owner.name + ": " +
                strings.trim($r.stderr));
    }
}

/**
 * The words that put the capture browser in front of the right user.
 * sudo resets the environment, so the handoff carries it back by hand:
 * DISPLAY / WAYLAND_DISPLAY name the display; HOME and XDG_RUNTIME_DIR must
 * become the target user's, not root's. XAUTHORITY is left out so it defaults
 * to their ~/.Xauthority.
 * @param owner {BrowserOwner} who the browser must run as
 * @return {list of string} the prefix words, empty when running as ourselves
 * @since 0.4
 */
func browserLaunchPrefix(owner as BrowserOwner) {
    def argv as list of string init [];
    if ($owner.name == "") {
        return $argv;
    }
    $argv[] = "sudo";
    $argv[] = "-n";
    $argv[] = "-u";
    $argv[] = $owner.name;
    $argv[] = "env";
    $argv[] = "HOME=" + $owner.home;
    if ($owner.uid >= 0) {
        $argv[] = io.sprintf("XDG_RUNTIME_DIR=/run/user/%d", $owner.uid);
    }
    def display as string init os.getEnv("DISPLAY");
    if ($display != "") {
        $argv[] = "DISPLAY=" + $display;
    }
    def wayland as string init os.getEnv("WAYLAND_DISPLAY");
    if ($wayland != "") {
        $argv[] = "WAYLAND_DISPLAY=" + $wayland;
    }
    return $argv;
}

/**
 * The browser's CDP WebSocket endpoint, once it is listening.
 * @param port {int} the remote-debugging port
 * @param waitMs {int} how long to keep trying
 * @param child {os.Process} the browser, polled so an early exit is not waited out
 * @param logPath {string} file the browser's stderr went to, quoted on failure
 * @return {string} the browser-level WebSocket URL
 * @throws {Error} kind "auth" when the browser exits, or never opens the port
 * @since 0.3
 */
func cdpEndpoint(port as int, waitMs as int, child as os.Process, logPath as string) {
    def url as string init io.sprintf("http://127.0.0.1:%d/json/version", $port);
    def waited as int init 0;
    while ($waited < $waitMs) {
        try {
            def r as http.Response init http.requestWith("GET", $url, {}, "", 2000, 0);
            if ($r.status == 200) {
                return json.asString(json.decode($r.body), "/webSocketDebuggerUrl");
            }
        } catch (e) { # lint-disable: L103
            # Not listening yet; the browser is still starting.
        }
        # A browser that has already exited will never open the port, and its
        # stderr says why. Report that instead of waiting out the timeout and
        # then guessing at a stale profile.
        if (os.poll($child)) {
            fail(
                "auth",
                io.sprintf("the browser exited without opening its debug port %d.", $port) +
                    browserSaid($logPath));
        }
        time.sleep(time.fromMilliseconds(250));
        $waited = $waited + 250;
    }
    fail(
        "auth",
        io.sprintf(
            "the browser never opened its debug port %d." +
                " Is it already running with a different profile?",
            $port) + browserSaid($logPath));
}

/**
 * Whether a host is this machine talking to itself.
 * Over loopback a credential never leaves the kernel, so the plain-http refusal
 * has nothing to protect and would only rule out a local gateway. Syntactic on
 * purpose: a DNS answer must not be able to widen it.
 * @param host {string} the host part of a URL, brackets allowed for IPv6
 * @return {bool} true for localhost, ::1 and 127.0.0.0/8
 * @since 0.4
 */
func isLoopbackHost(host as string) {
    def h as string init strings.lower($host);
    if (strings.startsWith($h, "[") and strings.endsWith($h, "]")) {
        $h = strings.substring($h, 1, len($h) - 1);
    }
    if ($h == "localhost" or $h == "::1") {
        return true;
    }
    # Dotted quad only. A `127.` prefix test would accept `127.evil.com`, whose
    # owner can point it anywhere.
    def parts as list of string init strings.split($h, ".");
    if (len($parts) != 4 or $parts[0] != "127") {
        return false;
    }
    for (def p in $parts) {
        if (not isOctet($p)) {
            return false;
        }
    }
    return true;
}

/**
 * Whether a string is a decimal IPv4 octet.
 * @param s {string} the candidate, at most 3 digits
 * @return {bool} true for "0".."255"
 * @since 0.4
 */
func isOctet(s as string) {
    if ($s == "" or len($s) > 3) {
        return false;
    }
    for (def c in strings.chars($s)) {
        if (not strings.contains("0123456789", $c)) {
            return false;
        }
    }
    return convert.toInt($s) <= 255;
}

/**
 * Whether a cookie domain covers the gateway's host.
 * A cookie domain may be host-exact or dot-prefixed for a whole subtree.
 * @param domain {string} the cookie's domain
 * @param host {string} the gateway host
 * @return {bool} true when the cookie belongs to the gateway
 * @since 0.3
 */
func domainCovers(domain as string, host as string) {
    def d as string init strings.lower($domain);
    if (strings.startsWith($d, ".")) {
        $d = strings.substring($d, 1);
    }
    def h as string init strings.lower($host);
    return $d == $h or strings.endsWith($h, "." + $d);
}

/**
 * Ask the browser for one cookie, over CDP.
 * `Storage.getCookies` is a browser-level command, so it needs no page target
 * and it returns HttpOnly cookies - which is the whole point, since the SSO
 * token is HttpOnly and therefore invisible to document.cookie and to any
 * bookmarklet.
 * @param conn {websocket.Conn} the open CDP connection
 * @param id {int} the request id to use
 * @param cookieName {string} the cookie to look for
 * @param host {string} the gateway host the cookie must belong to
 * @return {string} the cookie value, or "" if it is not set yet
 * @since 0.3
 */
func cdpCookieOnce(conn as websocket.Conn, id as int, cookieName as string, host as string) {
    websocket.send($conn, io.sprintf('{"id":%d,"method":"Storage.getCookies"}', $id));
    # The browser interleaves events with replies; read until ours comes back,
    # but not forever - see MAX_CDP_READS.
    def reads as int init 0;
    while ($reads < MAX_CDP_READS) {
        $reads = $reads + 1;
        def m as websocket.Message init websocket.receive($conn);
        if ($m.kind != "text") {
            continue;
        }
        def reply as json.Value init json.decode($m.text);
        if (not json.has($reply, "/id") or json.asInt($reply, "/id") != $id) {
            continue;
        }
        if (not json.has($reply, "/result/cookies")) {
            return "";
        }
        def n as int init json.length($reply, "/result/cookies");
        for (def i in 0..$n) {
            def at as string init "/result/cookies/" + convert.toString($i);
            if (json.asString($reply, $at + "/name") == $cookieName and
                domainCovers(json.asString($reply, $at + "/domain"), $host)) {
                return json.asString($reply, $at + "/value");
            }
        }
        return "";
    }
    # Budget spent without our reply. Treat it as "not set yet" and let the
    # caller's deadline decide whether to ask again.
    return "";
}

/**
 * Delete a file, best effort.
 * @param path {string} the file to remove
 * @since 0.4
 */
func removeQuietly(path as string) {
    try {
        fs.remove($path);
    } catch (e) { # lint-disable: L103
        # Never existed, or someone else got there first.
    }
}

/**
 * The tail of the capture browser's stderr, for an error message.
 * The one line that matters is usually the browser's own refusal to start
 * ("Running as root without --no-sandbox is not supported"), and it is the last
 * thing it says; the lines before it are GPU and GCM noise.
 * @param logPath {string} file the browser's stderr was redirected to
 * @return {string} the lines, indented and prefixed, or "" when it said nothing
 * @since 0.4
 */
func browserSaid(logPath as string) {
    def raw as string init strings.trim(readLog($logPath));
    if ($raw == "") {
        return "";
    }
    def lines as list of string init strings.split($raw, "\n");
    def from as int init 0;
    if (len($lines) > BROWSER_LOG_LINES) {
        $from = len($lines) - BROWSER_LOG_LINES;
    }
    def out as string init "";
    for (def i in $from..len($lines)) {
        $out = $out + "\n    " + strings.trim($lines[$i]);
    }
    return "\n  the browser said:" + $out;
}

/**
 * Kill the capture browser, best effort.
 * The fallback behind closeCaptureBrowser, and the whole cleanup when the
 * failure predates the CDP connection.
 * @param child {os.Process} the browser process
 * @since 0.4
 */
func stopBrowser(child as os.Process) {
    try {
        os.kill($child);
    } catch (e) { # lint-disable: L103
        # Already gone, which is the wanted state.
    }
}

/**
 * Retire the capture browser and its connection.
 * `Browser.close` first: the profile is persistent, and the IdP session - any
 * "remember this device" included - only reaches disk on a clean shutdown. Kill
 * is the fallback. Called on every exit path, so no failed login leaves a live
 * SSO session behind an open debug port.
 * @param conn {websocket.Conn} the CDP connection
 * @param child {os.Process} the browser process
 * @since 0.4
 */
func closeCaptureBrowser(conn as websocket.Conn, child as os.Process) {
    try {
        websocket.send($conn, '{"id":999999,"method":"Browser.close"}');
    } catch (e) { # lint-disable: L103
        # Socket may be dead already; the kill below still applies.
    }
    try {
        websocket.close($conn);
    } catch (e) { # lint-disable: L103
        # Nothing to retire.
    }
    def waited as int init 0;
    while ($waited < 3000) {
        if (os.poll($child)) {
            return;
        }
        time.sleep(time.fromMilliseconds(100));
        $waited = $waited + 100;
    }
    stopBrowser($child);
}

/**
 * Launch the browser and wait for the gateway to hand it the SSO token.
 * You log in normally - password, second factor, whatever the identity provider
 * asks - and the cookie is read out of the browser rather than out of you.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} the gateway's answer, for the login URL and cookie name
 * @return {string} the SSO token
 * @throws {Error} kind "auth" when the browser cannot be driven, or you never finish
 * @since 0.3
 */
func captureTokenViaCdp(prof as Profile, ar as AuthRequest) {
    def owner as BrowserOwner init browserOwner($prof);
    def dir as string init browserProfileDir($prof, $owner);
    makeBrowserProfileDir($dir, $owner);
    if ($owner.name != "") {
        note(
            $prof,
            "we are root and a Chromium-based browser will not start as root;" +
                " handing the browser to " + $owner.name);
    }

    def argv as list of string init browserLaunchPrefix($owner);
    $argv[] = $prof.browser;
    $argv[] = io.sprintf("--remote-debugging-port=%d", $prof.cdpPort);
    # No --remote-allow-origins, deliberately: it disables the Origin check on
    # the debug socket, and `*` lets any page in any local browser drive this one
    # and read the HttpOnly cookie. Our client sends no Origin, so the check
    # never applies to it. Do not add it back.
    $argv[] = "--user-data-dir=" + $dir;
    $argv[] = "--no-first-run";
    $argv[] = "--no-default-browser-check";
    $argv[] = $ar.loginUrl;
    note($prof, "launching " + strings.join($argv, " "));

    # stdout discarded, stderr to a file: the default is "capture", which buffers
    # for an os.wait that never comes, and a browser is chatty enough to fill the
    # pipe and wedge. The file is what lets a failure say why the browser died
    # rather than only that the port never opened.
    def logPath as string init fs.makeTempFile();
    defer removeQuietly($logPath);
    def child as os.Process init os.spawn($argv, {"stdout": "discard", "stderr": $logPath});
    errdefer stopBrowser($child);
    note($prof, io.sprintf("browser pid %d", $child.pid));

    def wsUrl as string init cdpEndpoint($prof.cdpPort, 20000, $child, $logPath);
    def conn as websocket.Conn init websocket.connectWith($wsUrl, CDP_RECEIVE_MS);
    errdefer closeCaptureBrowser($conn, $child);

    def host as string init uri.parse($prof.server).host;
    io.printf("\nLog in in the browser window that just opened.\n");
    io.printf("Waiting for %s to be set on %s ...\n", $ar.tokenCookieName, $host);

    # A wall-clock deadline, not a tally of sleeps: the poll itself takes time,
    # so adding 1000 per turn made the real wait longer than captureTimeout and
    # the "gave up after N seconds" message wrong.
    def deadline as time.Time init time.add(
        time.now(),
        time.fromMilliseconds($prof.captureTimeoutMs));
    def id as int init 0;
    while (time.before(time.now(), $deadline)) {
        $id = $id + 1;
        if (os.poll($child)) {
            fail("auth", "the browser closed before the login finished." + browserSaid($logPath));
        }
        def token as string init "";
        try {
            $token = cdpCookieOnce($conn, $id, $ar.tokenCookieName, $host);
        } catch (e) {
            # The socket stopped answering. If the browser is gone, that is the
            # explanation worth printing; otherwise let the real error out.
            if (os.poll($child)) {
                fail(
                    "auth",
                    "the browser closed before the login finished." + browserSaid($logPath));
            }
            throw $e;
        }
        if ($token != "") {
            note($prof, "read " + $ar.tokenCookieName + " from the browser");
            closeCaptureBrowser($conn, $child);
            return $token;
        }
        time.sleep(time.fromMilliseconds(1000));
    }
    fail(
        "auth",
        io.sprintf(
            "gave up waiting %d seconds for %s." +
                " Finish the login sooner, or raise captureTimeout.",
            $prof.captureTimeoutMs // 1000,
            $ar.tokenCookieName));
}

/**
 * Get the SSO token out of a browser, by whichever route the browser allows.
 * A Chromium-based browser is driven over the DevTools protocol and the token
 * is read from it directly; anything else falls back to showing the login URL
 * and asking for the cookie by hand. `capture` decides, and defaults to
 * whichever of the two the configured browser supports.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} the login URL and cookie name
 * @return {string} the SSO token
 * @throws {Error} kind "auth" when nothing was captured or pasted
 * @since 0.1
 */
func askForToken(prof as Profile, ar as AuthRequest) {
    def useCdp as bool init $prof.capture == "cdp";
    if ($prof.capture == "auto") {
        $useCdp = browserSpeaksCdp($prof.browser);
    }
    if ($useCdp) {
        if (not browserSpeaksCdp($prof.browser)) {
            fail(
                "auth",
                $prof.browser + " does not speak the DevTools protocol;" +
                    " set capture = \"paste\", or point browser at a Chromium-based one");
        }
        return captureTokenViaCdp($prof, $ar);
    }

    def host as string init uri.parse($prof.server).host;
    io.printf("\n");
    if ($ar.title != "") {
        io.printf("%s\n", $ar.title);
    }
    if ($ar.message != "") {
        io.printf("%s\n", $ar.message);
    }
    io.printf("Log in here:\n\n  %s\n\n", $ar.loginUrl);

    if (launchBrowser($prof, $ar.loginUrl)) {
        io.printf("(opened in %s)\n\n", $prof.browser);
    } else {
        io.printf("(open that URL yourself)\n\n");
    }

    io.printf("When the login finishes the gateway sets a cookie named\n");
    io.printf("  %s\n", $ar.tokenCookieName);
    io.printf("on %s. Read it out of the browser:\n", $host);
    io.printf(
        "  F12 -> Application (Chrome) or Storage (Firefox) -> Cookies -> https://%s\n\n",
        $host);
    io.printf("Paste the value (the whole cookie or the final URL works too).\n");
    if ($prof.capture == "auto" and not browserSpeaksCdp($prof.browser)) {
        io.printf("\n(set browser = \"chromium\" in the profile and this step disappears:\n");
        io.printf(" the cookie is then read out of the browser for you.)\n");
    }

    def raw as string init io.readLine($ar.tokenCookieName + ": ");
    def token as string init extractToken($raw, $ar.tokenCookieName);
    if ($token == "") {
        fail("auth", "no token given, nothing to send to the gateway");
    }
    return $token;
}

#
# --------------------------------------------------------- driving openconnect
#

/**
 * Whether openconnect is installed and runnable.
 * @return {bool} true when `openconnect --version` succeeds
 * @since 0.1
 */
func haveOpenconnect() {
    try {
        def r as os.Result init os.run(["openconnect", "--version"]);
        return $r.exitCode == 0;
    } catch (e) {
        return false;
    }
}

/**
 * Whether the local openconnect can drive Cisco's external-browser SSO.
 * @return {bool} true when its help text mentions --external-browser
 * @since 0.1
 */
func supportsExternalBrowser() {
    try {
        def r as os.Result init os.run(["openconnect", "--help"]);
        return strings.contains($r.stdout + $r.stderr, "--external-browser");
    } catch (e) {
        return false;
    }
}

/**
 * The privilege-helper words a command line starts with, if any.
 * nonInteractive adds -n: os.run gives the child no terminal, so a password
 * prompt would hang. A command we only print is meant to be typed by hand, and
 * there sudo should be free to ask.
 * @param prof {Profile} the active profile, for the sudo command
 * @param nonInteractive {bool} forbid the helper from prompting
 * @return {list of string} the prefix words, empty when no helper is configured
 * @since 0.1
 */
func sudoPrefix(prof as Profile, nonInteractive as bool) {
    def argv as list of string init [];
    if ($prof.sudo != "") {
        $argv[] = $prof.sudo;
        if ($nonInteractive) {
            $argv[] = "-n";
        }
    }
    return $argv;
}

/**
 * Fail early, and with advice, if the privilege helper would need a password.
 * @param prof {Profile} the active profile
 * @throws {Error} kind "privilege" when credentials are not already cached
 * @since 0.1
 */
func checkPrivilege(prof as Profile) {
    if ($prof.sudo == "") {
        return;
    }
    def r as os.Result init os.run([$prof.sudo, "-n", "true"]);
    if ($r.exitCode != 0) {
        fail(
            "privilege",
            $prof.sudo + " needs a password and this script cannot prompt for one.\n" + "  Run `" +
                $prof.sudo + " -v` first (it caches for a few minutes), then try again,\n" +
                "  or use --print to get the command and run it yourself.");
    }
}

/**
 * The openconnect flags that make it introduce itself the way we did.
 * @param prof {Profile} the active profile
 * @return {list of string} the protocol, user agent and version flags
 * @since 0.1
 */
func clientArgs(prof as Profile) {
    def argv as list of string init [];
    $argv[] = "--protocol=anyconnect";
    $argv[] = "--useragent";
    $argv[] = "AnyConnect Linux_64 " + $prof.version;
    $argv[] = "--version-string";
    $argv[] = $prof.version;
    return $argv;
}

/**
 * The full command line that brings the tunnel up.
 * The cookie is not in it: it goes to openconnect over stdin, so it never
 * appears in the process list.
 * @param prof {Profile} the active profile
 * @param sess {Session} the authenticated session
 * @param background {bool} daemonise once connected and write a pid file
 * @param nonInteractive {bool} forbid the privilege helper from prompting
 * @return {list of string} the argv to run
 * @since 0.1
 */
func connectArgv(prof as Profile, sess as Session, background as bool, nonInteractive as bool) {
    def argv as list of string init sudoPrefix($prof, $nonInteractive);
    for (def a in openconnectArgv($prof, $sess, $background)) {
        $argv[] = $a;
    }
    return $argv;
}

/**
 * The openconnect command itself, without any privilege helper in front.
 * @param prof {Profile} the active profile
 * @param sess {Session} the authenticated session
 * @param background {bool} daemonise once connected and write a pid file
 * @return {list of string} the openconnect argv
 * @since 0.1
 */
func openconnectArgv(prof as Profile, sess as Session, background as bool) {
    def argv as list of string init [];
    $argv[] = "openconnect";
    for (def a in clientArgs($prof)) {
        $argv[] = $a;
    }
    $argv[] = "--cookie-on-stdin";
    if ($sess.fingerprint != "") {
        $argv[] = "--servercert";
        $argv[] = $sess.fingerprint;
    }
    if ($background) {
        $argv[] = "--background";
        $argv[] = "--pid-file";
        $argv[] = pidFileFor($prof);
    }
    for (def a in $prof.extra) {
        $argv[] = $a;
    }
    $argv[] = $sess.connectUrl;
    return $argv;
}

/**
 * Quote a word for a POSIX shell.
 * @param s {string} the word
 * @return {string} the word in single quotes, with embedded quotes escaped
 * @since 0.1
 */
func shellQuote(s as string) {
    return "'" + strings.replace($s, "'", "'\\''") + "'";
}

/**
 * Quote and join words into one shell command line.
 * @param argv {list of string} the words
 * @return {string} the words, each quoted, separated by spaces
 * @since 0.1
 */
func shellJoin(argv as list of string) {
    def parts as list of string init [];
    for (def a in $argv) {
        $parts[] = shellQuote($a);
    }
    return strings.join($parts, " ");
}

/**
 * Print the connect command for the user to run by hand.
 * Emitted as a printf pipeline so the cookie reaches openconnect over stdin
 * rather than through the process list.
 * @param prof {Profile} the active profile
 * @param sess {Session} the authenticated session
 * @since 0.1
 */
func printCommand(prof as Profile, sess as Session) {
    io.printf(
        "\nprintf '%%s\\n' %s \\\n  | %s\n\n",
        shellQuote($sess.cookie),
        shellJoin(connectArgv($prof, $sess, false, false)));
}

/**
 * Read a log a child process wrote, best effort.
 * Used for the backgrounded openconnect's output and the capture browser's
 * stderr. Either may be unreadable, which is not worth an error of its own: the
 * caller is already reporting a failure.
 * @param path {string} the log file
 * @return {string} its contents, or "" if it cannot be read
 * @since 0.1
 */
func readLog(path as string) {
    try {
        if (fs.exists($path)) {
            return fs.readString($path);
        }
    } catch (e) { # lint-disable: L103
        # Unreadable log: nothing to add to whatever the caller reports.
    }
    return "";
}

/**
 * Run openconnect and return once the tunnel is up.
 * openconnect daemonises only once the tunnel is fully up, so a zero exit here
 * really does mean connected.
 *
 * The command is wrapped in `sh -c 'exec ... >log 2>&1'` for a reason that is
 * easy to undo by accident: `--background` forks and lets the daemon keep the
 * stdout and stderr it inherited, and os.run waits for those to reach EOF, not
 * merely for the process to exit. Handed os.run's pipes, the daemon holds them
 * open for the life of the tunnel and os.run never returns. Redirecting to a
 * file leaves nothing holding the pipes, so os.run returns as soon as the
 * foreground half exits - and the output is still there to read back.
 * @param prof {Profile} the active profile
 * @param sess {Session} the authenticated session
 * @return {int} 0 on success
 * @throws {Error} kind "privilege" or "openconnect" when the tunnel does not come up
 * @since 0.1
 */
func startTunnel(prof as Profile, sess as Session) {
    checkPrivilege($prof);
    def logPath as string init logFileFor($prof);
    def inner as string init "exec " + shellJoin(openconnectArgv($prof, $sess, true)) + " >" +
        shellQuote($logPath) + " 2>&1";

    def argv as list of string init sudoPrefix($prof, true);
    $argv[] = "sh";
    $argv[] = "-c";
    $argv[] = $inner;
    note($prof, "starting " + $inner);

    def r as os.Result init os.run($argv, $sess.cookie + "\n");
    def logged as string init readLog($logPath);
    if ($r.exitCode != 0) {
        io.eprintf("%s", $r.stderr);
        io.eprintf("%s", $logged);
        fail("openconnect", io.sprintf("openconnect exited %d, see %s", $r.exitCode, $logPath));
    }
    io.printf("%s", $logged);
    return 0;
}

#
# ------------------------------------------------- external-browser handoff
#

/**
 * Parse the KEY='value' lines that openconnect --authenticate prints.
 * @param out {string} openconnect's standard output
 * @return {map of string to string} the fields, unquoted
 * @since 0.1
 */
func parseAuthenticateOutput(out as string) {
    def fields as map of string to string init {};
    for (def line in strings.split($out, "\n")) {
        def l as string init strings.trim($line);
        def i as int init strings.indexOf($l, "=");
        if ($i > 0) {
            def k as string init strings.substring($l, 0, $i);
            def v as string init strings.substring($l, $i + 1);
            if (strings.startsWith($v, "'") and strings.endsWith($v, "'") and len($v) >= 2) {
                $v = strings.substring($v, 1, len($v) - 1);
            }
            $fields[$k] = $v;
        }
    }
    return $fields;
}

/**
 * Let openconnect do the SSO, but only the SSO.
 * It runs as the invoking user, so the browser lands in their desktop session
 * instead of root's; only the tunnel itself is then started with privilege.
 * @param prof {Profile} the active profile
 * @return {Session} the cookie, connect URL and certificate pin openconnect obtained
 * @throws {Error} kind "openconnect" when authentication fails or yields no cookie
 * @since 0.1
 */
func authenticateExternally(prof as Profile) {
    def argv as list of string init ["openconnect"];
    for (def a in clientArgs($prof)) {
        $argv[] = $a;
    }
    $argv[] = "--external-browser";
    $argv[] = $prof.browser;
    $argv[] = "--authenticate";
    if ($prof.group != "") {
        $argv[] = "--authgroup";
        $argv[] = $prof.group;
    }
    if ($prof.servercert != "") {
        $argv[] = "--servercert";
        $argv[] = $prof.servercert;
    }
    $argv[] = $prof.server;

    io.printf("\nFinish the login in the browser window that opens.\n");
    io.printf("Waiting for openconnect to receive the SSO token ...\n");
    note($prof, strings.join($argv, " "));

    def r as os.Result init os.run($argv);
    if ($r.exitCode != 0) {
        io.eprintf("%s", $r.stderr);
        fail("openconnect", io.sprintf("openconnect --authenticate exited %d", $r.exitCode));
    }
    if ($prof.verbose) {
        io.eprintf("%s", $r.stderr);
    }

    def fields as map of string to string init parseAuthenticateOutput($r.stdout);
    if (not maps.has($fields, "COOKIE") or $fields["COOKIE"] == "") {
        fail("openconnect", "openconnect --authenticate returned no cookie");
    }

    def sess as Session init Session{
        cookie: $fields["COOKIE"],
        connectUrl: $prof.server,
        fingerprint: $prof.servercert,
        message: ""
    };
    if (maps.has($fields, "CONNECT_URL") and $fields["CONNECT_URL"] != "") {
        $sess.connectUrl = $fields["CONNECT_URL"];
    }
    if ($sess.fingerprint == "" and maps.has($fields, "FINGERPRINT")) {
        $sess.fingerprint = $fields["FINGERPRINT"];
    }
    return $sess;
}

/**
 * Complete a classic login: ask for the token, then submit it.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} the gateway's answer to the init request
 * @return {Session} the authenticated session
 * @throws {Error} kind "auth" or "gateway" when the token is missing or rejected
 * @since 0.1
 */
func finishTokenFlow(prof as Profile, ar as AuthRequest) {
    return submitToken($prof, $ar, askForToken($prof, $ar));
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
func submitToken(prof as Profile, ar as AuthRequest, token as string) {
    note($prof, "sending the token back to the gateway");
    return parseAuthComplete($prof, postAuthXml($prof, replyXml($prof, $ar, $token)));
}

/**
 * Authenticate by whichever route the gateway and the local openconnect support.
 * `auto` only offers external-browser when openconnect could actually use it,
 * and treats a refusal as a plain no. The gateway answers "external" only if we
 * advertised it, so `token` never has to deal with an encrypted token.
 * @param prof {Profile} the active profile
 * @param mode {string} "auto", "external" or "token"
 * @return {Session} the authenticated session
 * @throws {Error} when the gateway refuses or the token is rejected
 * @since 0.1
 */
func authenticate(prof as Profile, mode as string) {
    if ($mode == "external") {
        return authenticateExternally($prof);
    }
    if ($mode == "browserless") {
        return authenticateBrowserless($prof);
    }

    def tryExternal as bool init $mode == "auto" and supportsExternalBrowser();
    def ar as AuthRequest init emptyAuthRequest();
    if ($tryExternal) {
        $ar = probeOfferingExternal($prof);
    } else {
        $ar = probeGateway($prof, false);
    }

    if ($ar.browserMode == "external") {
        note($prof, "gateway offers external-browser mode; letting openconnect drive it");
        return authenticateExternally($prof);
    }
    return finishTokenFlow($prof, $ar);
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
def struct Credentials {
    user as string,
    password as string,
    factor as string
};

/**
 * One hop of the browserless login: the response, and the sessions it updated.
 * Jennifer has no tuples, so the per-origin session list rides along with the
 * response and the caller threads it forward.
 * @field sessions {list of http.Session} one live session per origin, updated
 * @field status {int} the HTTP status
 * @field location {string} the Location header, or "" when there was none
 * @field body {string} the response body
 * @since 0.2
 */
def struct Hop {
    sessions as list of http.Session,
    status as int,
    location as string,
    body as string
};

/**
 * Drop the last whole UTF-8 character from a byte accumulator.
 * Backspace removes a character, not a byte: a continuation byte (10xxxxxx) is
 * half of one, so it goes with its lead byte.
 * @param acc {list of int} the bytes typed so far
 * @return {list of int} the bytes without the last character
 * @since 0.4
 */
func dropLastRune(acc as list of int) {
    def out as list of int init $acc;
    while (len($out) > 0 and ($out[len($out) - 1] & 0xc0) == 0x80) {
        $out = lists.pop($out);
    }
    if (len($out) > 0) {
        $out = lists.pop($out);
    }
    return $out;
}

/**
 * Decode a byte accumulator as UTF-8.
 * @param acc {list of int} the bytes, each 0..255
 * @return {string} the decoded text
 * @since 0.4
 */
func bytesToString(acc as list of int) {
    if (len($acc) == 0) {
        return "";
    }
    def buf as bytes init binary.make(len($acc));
    for (def i in 0..len($acc)) {
        $buf[$i] = $acc[$i];
    }
    return convert.stringFromBytes($buf, "utf-8");
}

/**
 * Read a password without echoing it.
 * term.readByte yields bytes, not characters, so the line is accumulated as
 * bytes and decoded once at the end. Built with fromCodepoint per byte instead,
 * every non-ASCII character becomes mojibake - the two bytes of `é` turn into
 * `Ã©` - and the identity provider rejects a password nobody mistyped.
 * @param label {string} the prompt to show
 * @return {string} the line typed, without its newline
 * @throws {Error} when stdin is not a terminal
 * @since 0.2
 */
func promptHidden(label as string) {
    io.printf("%s", $label);
    def state as term.State init term.makeRaw("stdin");
    # Every path, exit 130 included, or the shell is left with echo off.
    defer term.restore($state);
    def acc as list of int init [];
    while (true) {
        def b as int init term.readByte();
        if ($b == -1 or $b == 10 or $b == 13) {
            break;
        }
        if ($b == 3) {
            io.printf("\n");
            exit 130;
        }
        if ($b == 127 or $b == 8) {
            $acc = dropLastRune($acc);
        } else {
            $acc[] = $b;
        }
    }
    io.printf("\n");
    return bytesToString($acc);
}

/**
 * Whether stdin can be switched to no-echo mode for a password prompt.
 * Asks by trying, rather than by os.isTerminal, which answers true for
 * /dev/null - a character device, but not a terminal.
 * @return {bool} true when a hidden prompt will work
 * @since 0.2
 */
func canPromptHidden() {
    try {
        def state as term.State init term.makeRaw("stdin");
        term.restore($state);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Work out the credentials for a browserless login.
 * The password comes from `passwordCommand` if set, else
 * $OPENCONNECT_SAML_PASSWORD, else a hidden prompt - so it need never be
 * written into the config file.
 * @param prof {Profile} the active profile
 * @return {Credentials} the username and password to submit
 * @throws {Error} kind "auth" when no username is configured or the command fails
 * @since 0.2
 */
func gatherCredentials(prof as Profile) {
    def user as string init $prof.user;
    if ($user == "") {
        if (io.eof()) {
            fail("auth", "no username - pass --user or set one in the profile");
        }
        $user = strings.trim(io.readLine("Username: "));
    }
    if ($user == "") {
        fail("auth", "no username given");
    }

    def password as string init "";
    if ($prof.passwordCommand != "") {
        note($prof, "running the password command");
        def r as os.Result init os.run(["sh", "-c", $prof.passwordCommand]);
        if ($r.exitCode != 0) {
            io.eprintf("%s", $r.stderr);
            fail("auth", io.sprintf("password command exited %d", $r.exitCode));
        }
        def lines as list of string init strings.split($r.stdout, "\n");
        $password = strings.trim($lines[0]);
    }
    if ($password == "") {
        $password = os.getEnv("OPENCONNECT_SAML_PASSWORD");
    }
    if ($password == "") {
        if (not canPromptHidden()) {
            fail(
                "auth",
                "no terminal to prompt for a password on - set passwordCommand" +
                    " in the profile, or $OPENCONNECT_SAML_PASSWORD");
        }
        $password = promptHidden("Password for " + $user + ": ");
    }
    if ($password == "") {
        fail("auth", "no password given");
    }
    return Credentials{user: $user, password: $password, factor: $prof.factor};
}

/**
 * What browserless mode calls itself to the identity provider.
 * An IdP login page is served to browsers, so ask for it as one; a login form
 * is one of the few places where a client's user agent still changes what it
 * is served.
 * @return {string} a current Firefox user-agent string
 * @since 0.2
 */
func browserAgent() {
    return "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
}

/**
 * Every element with the given tag, anywhere under a node.
 * html.findAll only steps through direct children, so a descendant search is
 * ours to do.
 * @param node {html.Node} the subtree root
 * @param tag {string} the tag name to collect
 * @return {list of html.Node} the matching elements, in document order
 * @since 0.2
 */
func collectTags(node as html.Node, tag as string) {
    def out as list of html.Node init [];
    if ($node.tag == $tag) {
        $out[] = $node;
    }
    for (def child in $node.children) {
        for (def found in collectTags($child, $tag)) {
            $out[] = $found;
        }
    }
    return $out;
}

/**
 * An attribute's value, or "" when the element does not carry it.
 * @param node {html.Node} the element
 * @param name {string} the attribute name
 * @return {string} the value, or ""
 * @since 0.2
 */
func attrOrEmpty(node as html.Node, name as string) {
    if (html.hasAttr($node, $name)) {
        return html.attrOf($node, $name);
    }
    return "";
}

/**
 * Whether a field name is asking for the username.
 * @param name {string} the form field's name
 * @return {bool} true for the usual username field names
 * @since 0.2
 */
func isUserField(name as string) {
    def n as string init strings.lower($name);
    return $n == "j_username" or $n == "username" or $n == "user" or $n == "loginfmt" or
        $n == "email";
}

/**
 * Pick the form to submit: one carrying a password field if there is one,
 * otherwise the first form with any named field.
 * Returns a list rather than a sentinel node: there is no empty html.Node,
 * because html.element rejects a blank tag name.
 * @param doc {html.Node} the parsed page
 * @return {list of html.Node} the chosen form, or empty when the page has none
 * @since 0.2
 */
func pickForm(doc as html.Node) {
    def fallback as list of html.Node init [];
    for (def form in collectTags($doc, "form")) {
        def named as bool init false;
        for (def input in collectTags($form, "input")) {
            if (attrOrEmpty($input, "name") != "") {
                $named = true;
            }
            if (strings.lower(attrOrEmpty($input, "type")) == "password") {
                return [$form];
            }
        }
        if ($named and len($fallback) == 0) {
            $fallback[] = $form;
        }
    }
    return $fallback;
}

/**
 * Stop with a straight answer when the walk reaches a second factor.
 * A second-factor prompt is a JavaScript application, not an HTML form, so the
 * form walker cannot go further and no amount of retrying will change that.
 * Saying which product it hit beats a generic "no form here".
 * @param url {string} the URL about to be fetched
 * @param trail {list of string} the walk so far, for the message
 * @throws {Error} kind "auth" when the URL belongs to a known second factor
 * @since 0.2
 */
func guardSecondFactor(url as string, trail as list of string) {
    def host as string init strings.lower(uri.parse($url).host);
    if (strings.contains($host, "duosecurity.com")) {
        fail(
            "auth",
            "the login reached Duo (" + $host + "), a second factor." +
                "\n  Browserless mode drives HTML forms; Duo's prompt is a JavaScript" +
                "\n  application, so this is as far as it goes. Use --mode token: the" +
                "\n  browser handles Duo, and you paste the cookie afterwards." +
                renderTrail($trail));
    }
}

/**
 * Refuse to take the browserless walk anywhere but over TLS.
 * The walk carries the password, and before it the CSRF tokens and SAML
 * assertions that stand in for it, to whatever URL the previous page named -
 * a `Location:` or a form `action`, neither of them ours. Checked on every hop,
 * not just the first: an IdP that redirects to http, or serves a form whose
 * action is http, would otherwise get the password in clear.
 * @param url {string} the URL about to be fetched
 * @param trail {list of string} the walk so far, for the message
 * @throws {Error} kind "auth" when the URL is neither https nor loopback
 * @since 0.4
 */
func guardHttps(url as string, trail as list of string) {
    def u as uri.Uri init uri.parse($url);
    def scheme as string init strings.lower($u.scheme);
    if ($scheme == "https" or isLoopbackHost($u.host)) {
        return;
    }
    fail(
        "auth",
        "the login tried to continue over " + $scheme + "://, not https:\n  " + $url +
            "\n  Browserless mode submits your password to the form it reaches, so it will" +
            "\n  not send anything over an unencrypted connection." +
            "\n  Use --mode token, where the browser drives the login." + renderTrail($trail));
}

/**
 * Stop if the walk has come back to the same place twice.
 * Three visits to one URL is a cycle, not progress - end it while the trail is
 * still short enough to read.
 * @param trail {list of string} the walk so far, one "METHOD URL" per step
 * @param where {string} the step about to be taken
 * @throws {Error} kind "auth" when this is the third visit
 * @since 0.2
 */
func guardNoLoop(trail as list of string, where as string) {
    def seen as int init 0;
    for (def past in $trail) {
        if ($past == $where) {
            $seen = $seen + 1;
        }
    }
    if ($seen >= 2) {
        fail(
            "auth",
            "the identity provider keeps serving the same page:" + renderTrail($trail) +
                "\n  This login needs a browser - use --mode token.");
    }
}

/**
 * Announce a page dump directory, once, before anything is written to it.
 * @param prof {Profile} the active profile
 * @since 0.2
 */
func announceDebugDir(prof as Profile) {
    if ($prof.debugDir == "") {
        return;
    }
    fs.mkdirAll($prof.debugDir);
    # 0700 before the first write: these pages carry replayable CSRF tokens and
    # SAML assertions, and the default mode is world-readable.
    fs.chmod($prof.debugDir, 0o700);
    io.eprintf("saving each page to %s - they contain CSRF tokens and SAML\n", $prof.debugDir);
    io.eprintf("assertions, so read before sharing and delete when done.\n");
}

/**
 * A page's <title>, for diagnostics.
 * @param doc {html.Node} the parsed page
 * @return {string} the title text, or "" when the page has none
 * @since 0.2
 */
func pageTitle(doc as html.Node) {
    for (def t in collectTags($doc, "title")) {
        for (def child in $t.children) {
            if (strings.trim($child.text) != "") {
                return strings.trim($child.text);
            }
        }
    }
    return "";
}

/**
 * A form's fields as "name(type)", for diagnostics.
 * Names and types only - a value can be a CSRF token or a whole SAML assertion,
 * and this ends up on a terminal and in bug reports.
 * @param form {html.Node} the form element
 * @return {string} a comma-separated inventory, or "(none)"
 * @since 0.2
 */
func describeForm(form as html.Node) {
    def parts as list of string init [];
    for (def input in collectTags($form, "input")) {
        def name as string init attrOrEmpty($input, "name");
        if ($name != "") {
            def kind as string init strings.lower(attrOrEmpty($input, "type"));
            if ($kind == "") {
                $kind = "text";
            }
            $parts[] = $name + "(" + $kind + ")";
        }
    }
    for (def button in collectTags($form, "button")) {
        def name as string init attrOrEmpty($button, "name");
        if ($name != "") {
            $parts[] = $name + "(button)";
        }
    }
    if (len($parts) == 0) {
        return "(none)";
    }
    return strings.join($parts, ", ");
}

/**
 * Render the walk so far, so a failure says where it went, not just that it
 * failed. This is the difference between "use a browser" and a bug report
 * somebody can act on.
 * @param trail {list of string} one "METHOD URL" per step
 * @return {string} the trail, one indented step per line
 * @since 0.2
 */
func renderTrail(trail as list of string) {
    def out as string init "";
    for (def i in 0..len($trail)) {
        $out = $out + io.sprintf("\n  %d) %s", $i + 1, $trail[$i]);
    }
    return $out;
}

/**
 * Save one page of the walk for inspection.
 * Opt-in (--debug-dir) because these pages carry CSRF tokens and SAML
 * assertions; the caller is told as much before anything is written.
 * @param dir {string} the directory to write into
 * @param step {int} the 1-based step number
 * @param url {string} the URL that produced the page
 * @param body {string} the page source
 * @since 0.2
 */
func dumpPage(dir as string, step as int, url as string, body as string) {
    def name as string init path.join($dir, io.sprintf("%d.html", $step));
    fs.writeString($name, "<!-- " + $url + " -->\n" + $body);
    # The 0700 directory is the real barrier; this keeps the mode if the file is
    # copied out.
    fs.chmod($name, 0o600);
}

/**
 * Whether a form asks for a password.
 * @param form {html.Node} the form element
 * @return {bool} true when it carries a password field
 * @since 0.2
 */
func formHasPassword(form as html.Node) {
    for (def input in collectTags($form, "input")) {
        if (strings.lower(attrOrEmpty($input, "type")) == "password") {
            return true;
        }
    }
    return false;
}

/**
 * Whether a control answers to a factor name.
 * Matched against the control's name, value and id, case-insensitively and by
 * substring, because an identity provider labels the same choice differently in
 * each: name="factor" value="Duo Push", or id="push-button", or name="push".
 * @param node {html.Node} the control
 * @param factor {string} the factor asked for, e.g. "push" or "passcode"
 * @return {bool} true when the control looks like that factor
 * @since 0.3
 */
func matchesFactor(node as html.Node, factor as string) {
    def want as string init strings.lower($factor);
    if ($want == "") {
        return false;
    }
    for (def attr in ["name", "value", "id"]) {
        if (strings.contains(strings.lower(attrOrEmpty($node, $attr)), $want)) {
            return true;
        }
    }
    return false;
}

/**
 * Every control that submits a form: a submit-ish <input> or a named <button>.
 * @param form {html.Node} the form element
 * @return {list of html.Node} the submit controls, in document order
 * @since 0.3
 */
func submitControls(form as html.Node) {
    def out as list of html.Node init [];
    for (def input in collectTags($form, "input")) {
        def kind as string init strings.lower(attrOrEmpty($input, "type"));
        def isSubmit as bool init $kind == "submit" or $kind == "button" or $kind == "image";
        if ($isSubmit and attrOrEmpty($input, "name") != "") {
            $out[] = $input;
        }
    }
    for (def button in collectTags($form, "button")) {
        if (attrOrEmpty($button, "name") != "") {
            $out[] = $button;
        }
    }
    return $out;
}

/**
 * The label a control answers to, for --factor.
 * Its value if it has one, else its name, else its id - the same attributes
 * matchesFactor searches, so what is shown is what can be passed.
 * @param node {html.Node} the control
 * @return {string} the label
 * @since 0.3
 */
func factorLabel(node as html.Node) {
    for (def attr in ["value", "name", "id"]) {
        if (attrOrEmpty($node, $attr) != "") {
            return attrOrEmpty($node, $attr);
        }
    }
    return "";
}

/**
 * Wrap a string in double quotes.
 * @param s {string} the text
 * @return {string} the text, quoted
 * @since 0.3
 */
func quoted(s as string) {
    return "\"" + $s + "\"";
}

/**
 * How a form describes the choices it offers, for an error message.
 * Quoted, because a label like `Duo Push` contains a space and has to be quoted
 * on the command line; and listed as labels rather than name=value pairs,
 * because a label is what --factor takes. Printing the pair would invite
 * somebody to copy `factor=Duo Push` and be refused a second time.
 * @param form {html.Node} the form element
 * @return {string} the choices, quoted and comma separated
 * @since 0.3
 */
func describeChoices(form as html.Node) {
    def parts as list of string init [];
    for (def control in submitControls($form)) {
        def label as string init factorLabel($control);
        if ($label != "" and not lists.contains($parts, quoted($label))) {
            $parts[] = quoted($label);
        }
    }
    for (def input in collectTags($form, "input")) {
        if (strings.lower(attrOrEmpty($input, "type")) == "radio") {
            def label as string init factorLabel($input);
            if ($label != "" and not lists.contains($parts, quoted($label))) {
                $parts[] = quoted($label);
            }
        }
    }
    if (len($parts) == 0) {
        return "(none)";
    }
    return strings.join($parts, ", ");
}

/**
 * Which submit control to press.
 * With no factor asked for, the first - which is what a browser does when you
 * press Enter. With one asked for, the control that answers to it. A form
 * offering a real choice and no control matching the request is an error rather
 * than a guess: pressing the wrong button here sends a push to someone's phone.
 * @param form {html.Node} the form element
 * @param factor {string} the factor asked for, or "" for no preference
 * @return {list of html.Node} the chosen control, or empty when there is none
 * @throws {Error} kind "auth" when a choice is offered but nothing matches
 * @since 0.3
 */
func chooseSubmit(form as html.Node, factor as string) {
    def controls as list of html.Node init submitControls($form);
    if (len($controls) == 0) {
        return [];
    }
    if ($factor == "") {
        return [$controls[0]];
    }
    for (def control in $controls) {
        if (matchesFactor($control, $factor)) {
            return [$control];
        }
    }
    # One button is not a choice, so a factor that does not match it is simply
    # not about this page - the login form itself, say. Press it and move on.
    if (len($controls) == 1) {
        return [$controls[0]];
    }
    fail(
        "auth",
        "no way to pick " + quoted($factor) + " on this form." + "\n  It offers: " +
            describeChoices($form) + "\n  --factor matches any part of one, ignoring case:" +
            " --factor push, or --factor " + quoted("Duo Push") + ".");
}

/**
 * The value to send for each radio group in a form.
 * Decided in one pass before anything is encoded, because the answer depends on
 * the whole group: an explicit --factor beats the pre-checked default, and the
 * pre-checked option can appear before the one that was asked for.
 * @param form {html.Node} the form element
 * @param factor {string} the factor asked for, or "" for no preference
 * @return {map of string to string} group name to chosen value
 * @since 0.3
 */
func radioChoices(form as html.Node, factor as string) {
    def chosen as map of string to string init {};
    for (def input in collectTags($form, "input")) {
        def name as string init attrOrEmpty($input, "name");
        def isRadio as bool init strings.lower(attrOrEmpty($input, "type")) == "radio";
        if ($isRadio and $name != "" and matchesFactor($input, $factor)) {
            $chosen[$name] = attrOrEmpty($input, "value");
        }
    }
    for (def input in collectTags($form, "input")) {
        def name as string init attrOrEmpty($input, "name");
        def isRadio as bool init strings.lower(attrOrEmpty($input, "type")) == "radio";
        if ($isRadio and $name != "" and not maps.has($chosen, $name)) {
            if (html.hasAttr($input, "checked")) {
                $chosen[$name] = attrOrEmpty($input, "value");
            }
        }
    }
    return $chosen;
}

/**
 * Encode a form's fields as an application/x-www-form-urlencoded body.
 * Hidden fields (CSRF tokens, SAMLResponse, RelayState) are echoed back as
 * they came; a password field takes the password, a username-ish field the
 * username; an unchecked checkbox or radio is left out, as a browser leaves it
 * out; and the first submit control is included so the IdP sees which button
 * was pressed - Shibboleth's `_eventId_proceed` is exactly that.
 * @param form {html.Node} the form element
 * @param creds {Credentials} the credentials to fill in
 * @return {string} the encoded body
 * @since 0.2
 */
func encodeForm(form as html.Node, creds as Credentials) {
    def parts as list of string init [];
    def chosen as list of html.Node init chooseSubmit($form, $creds.factor);
    def radios as map of string to string init radioChoices($form, $creds.factor);
    def radioSent as list of string init [];

    for (def input in collectTags($form, "input")) {
        def name as string init attrOrEmpty($input, "name");
        if ($name == "") {
            continue;
        }
        def kind as string init strings.lower(attrOrEmpty($input, "type"));
        def value as string init attrOrEmpty($input, "value");

        if ($kind == "password") {
            $value = $creds.password;
        } elseif (isUserField($name)) {
            $value = $creds.user;
        } elseif ($kind == "radio") {
            # A radio group is the other way an identity provider offers a
            # choice of factors, so --factor selects within it; otherwise the
            # pre-checked option is sent, as a browser would. Exactly one value
            # per group reaches the wire.
            def wanted as bool init maps.has($radios, $name) and $radios[$name] == $value;
            if (not $wanted or lists.contains($radioSent, $name)) {
                continue;
            }
            $radioSent[] = $name;
        } elseif ($kind == "checkbox") {
            if (not html.hasAttr($input, "checked")) {
                continue;
            }
        } elseif ($kind == "submit" or $kind == "button" or $kind == "image") {
            if (len($chosen) == 0 or not sameNode($input, $chosen[0])) {
                continue;
            }
        }
        $parts[] = uri.encodeForm($name) + "=" + uri.encodeForm($value);
    }

    for (def button in collectTags($form, "button")) {
        def name as string init attrOrEmpty($button, "name");
        if ($name == "" or len($chosen) == 0 or not sameNode($button, $chosen[0])) {
            continue;
        }
        $parts[] = uri.encodeForm($name) + "=" + uri.encodeForm(attrOrEmpty($button, "value"));
    }

    return strings.join($parts, "&");
}

/**
 * Whether two controls are the same one.
 * Nodes are value-semantic, so identity is by content: for a form control the
 * tag plus name, value and type settle it.
 * @param a {html.Node} one control
 * @param b {html.Node} the other
 * @return {bool} true when they are the same control
 * @since 0.3
 */
func sameNode(a as html.Node, b as html.Node) {
    return $a.tag == $b.tag and attrOrEmpty($a, "name") == attrOrEmpty($b, "name") and
        attrOrEmpty($a, "value") == attrOrEmpty($b, "value") and
        attrOrEmpty($a, "type") == attrOrEmpty($b, "type");
}

/**
 * The index of the session for a URL's origin, adding one if none exists yet.
 * A SAML login crosses hosts (gateway to IdP and back), and cookies are
 * per-host, so each origin gets its own session and its own jar.
 * @param sessions {list of http.Session} the sessions so far
 * @param url {string} the URL whose origin is wanted
 * @param opts {http.Options} options for a session that has to be opened
 * @return {Hop} the (possibly extended) session list; status carries the index
 * @since 0.2
 */
func sessionFor(sessions as list of http.Session, url as string, opts as http.Options) {
    def u as uri.Uri init uri.parse($url);
    def port as int init 443;
    if ($u.scheme == "http") {
        $port = 80;
    }
    if ($u.port != "") {
        $port = convert.toInt($u.port);
    }
    def out as list of http.Session init $sessions;
    for (def i in 0..len($out)) {
        if ($out[$i].scheme == $u.scheme and $out[$i].host == $u.host and $out[$i].port == $port) {
            return Hop{sessions: $out, status: $i, location: "", body: ""};
        }
    }
    $out[] = http.connect(originOfUrl($url), $opts);
    return Hop{sessions: $out, status: len($out) - 1, location: "", body: ""};
}

/**
 * The origin of a URL, in the form http.connect wants.
 * @param url {string} any absolute URL
 * @return {string} scheme://host[:port]/
 * @since 0.2
 */
func originOfUrl(url as string) {
    def u as uri.Uri init uri.parse($url);
    def origin as string init $u.scheme + "://" + $u.host;
    if ($u.port != "") {
        $origin = $origin + ":" + $u.port;
    }
    return $origin + "/";
}

/**
 * Perform one request as part of the browserless login.
 * @param sessions {list of http.Session} the per-origin sessions
 * @param url {string} the absolute URL to fetch
 * @param method {string} "GET" or "POST"
 * @param body {string} the form body for a POST, "" otherwise
 * @param opts {http.Options} options for a session that has to be opened
 * @return {Hop} the response and the updated sessions
 * @since 0.2
 */
func hop(
    sessions as list of http.Session,
    url as string,
    method as string,
    body as string,
    opts as http.Options) {
    def found as Hop init sessionFor($sessions, $url, $opts);
    def live as list of http.Session init $found.sessions;
    def idx as int init $found.status;

    def u as uri.Uri init uri.parse($url);
    def target as string init $u.path;
    if ($target == "") {
        $target = "/";
    }
    if ($u.query != "") {
        $target = $target + "?" + $u.query;
    }

    def headers as map of string to string init {};
    $headers["User-Agent"] = browserAgent();
    $headers["Accept"] = "text/html,application/xhtml+xml,*/*";
    $headers["Accept-Encoding"] = "identity";
    if ($method == "POST") {
        $headers["Content-Type"] = "application/x-www-form-urlencoded";
    }

    # A keep-alive socket can be closed by the peer between requests (an HTTP/1.0
    # server, or one that caps requests per connection) without saying so in the
    # previous response, and the failure only shows on the next write.
    #
    # A GET may simply be sent again. A POST may not: http.exchange writes the
    # request and then reads the response, and from out here a throw does not say
    # which half failed - so a retry can resend a form the server already acted
    # on. In this walk that means a second password attempt against a lockout
    # counter, or a second push to somebody's phone. So the condition is avoided
    # instead of recovered from: a POST onto an already-used session gets a fresh
    # connection first, and is then sent exactly once.
    def blank as http.Response init http.Response{status: 0, statusText: "", headers: {}, body: ""};
    def ex as http.Exchange init http.Exchange{response: $blank, session: $live[$idx]};
    def reused as bool init len($found.sessions) == len($sessions);
    if ($method == "POST" and $reused) {
        $live[$idx] = http.connect(originOfUrl($url), $opts);
        $ex = http.exchange($live[$idx], $method, $target, $headers, $body);
    } else {
        def sent as bool init false;
        try {
            $ex = http.exchange($live[$idx], $method, $target, $headers, $body);
            $sent = true;
        } catch (e) { # lint-disable: L103
            # Retried below; if the retry fails too, that error propagates.
        }
        if (not $sent) {
            $live[$idx] = http.connect(originOfUrl($url), $opts);
            $ex = http.exchange($live[$idx], $method, $target, $headers, $body);
        }
    }
    $live[$idx] = $ex.session;

    def location as string init "";
    if (maps.has($ex.response.headers, "location")) {
        $location = $ex.response.headers["location"];
    }
    return Hop{
        sessions: $live,
        status: $ex.response.status,
        location: $location,
        body: $ex.response.body
    };
}

/**
 * The SSO token from a session jar belonging to the gateway's own host.
 * The gateway sets it once the IdP's assertion has been accepted, so its
 * appearance is what tells us the login is done.
 * @param sessions {list of http.Session} the per-origin sessions
 * @param gatewayHost {string} the gateway's host name
 * @param cookieName {string} the cookie the gateway said it would set
 * @return {string} the token, or "" if it has not been set yet
 * @since 0.2
 */
func tokenFromJars(sessions as list of http.Session, gatewayHost as string, cookieName as string) {
    for (def s in $sessions) {
        if ($s.host == $gatewayHost and maps.has($s.jar, $cookieName)) {
            return $s.jar[$cookieName];
        }
    }
    return "";
}

/**
 * Retire every session opened during a browserless login.
 * The gateway is about to be asked for a VPN session over a fresh connection,
 * and there is no reason to still be holding the login's sockets open.
 * @param sessions {list of http.Session} the sessions to close
 * @since 0.2
 */
func closeSessions(sessions as list of http.Session) {
    for (def s in $sessions) {
        try {
            http.close($s);
        } catch (e) { # lint-disable: L103
            # Already closed by the peer: nothing to retire.
        }
    }
}

/**
 * Log in without a browser, by walking the IdP's HTML forms.
 * Follows redirects and submits each form in turn - the storage probe, the
 * credential form, and the auto-submitting SAMLResponse form an IdP would
 * normally have JavaScript post - until the gateway sets its token cookie.
 * Anything it cannot drive (an interactive second factor, a JavaScript-only
 * page) ends as an error naming the fields it did not understand, because
 * guessing at a login form is how accounts get locked.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} the gateway's answer, for the login URL and cookie name
 * @param creds {Credentials} the credentials to submit
 * @return {string} the SSO token
 * @throws {Error} kind "auth" when the flow stalls, or the login is refused
 * @since 0.2
 */
func browserlessToken(prof as Profile, ar as AuthRequest, creds as Credentials) {
    def noCa as bytes;
    def opts as http.Options init http.defaultOptions();
    $opts.timeoutMs = HTTP_TIMEOUT_MS;
    $opts.tls = http.TlsOptions{skipVerify: $prof.insecure, caCert: $noCa};

    def gatewayHost as string init uri.parse($prof.server).host;
    def sessions as list of http.Session init [];
    def url as string init $ar.loginUrl;
    def method as string init "GET";
    def body as string init "";
    def sentPassword as bool init false;
    def trail as list of string init [];

    announceDebugDir($prof);

    for (def step in 0..MAX_SSO_STEPS) {
        def where as string init $method + " " + $url;
        note($prof, io.sprintf("sso step %d: %s", $step + 1, $where));
        # Before anything is sent: this is the hop that would carry it.
        guardHttps($url, $trail);
        guardSecondFactor($url, $trail);
        guardNoLoop($trail, $where);
        $trail[] = $where;

        def h as Hop init hop($sessions, $url, $method, $body, $opts);
        $sessions = $h.sessions;
        if ($prof.debugDir != "") {
            dumpPage($prof.debugDir, $step + 1, $where, $h.body);
        }

        def token as string init tokenFromJars($sessions, $gatewayHost, $ar.tokenCookieName);
        if ($token != "") {
            note($prof, "gateway set " + $ar.tokenCookieName);
            closeSessions($sessions);
            return $token;
        }

        if ($h.status >= 300 and $h.status < 400 and $h.location != "") {
            $url = uri.resolve($url, $h.location);
            $method = "GET";
            $body = "";
            continue;
        }
        if ($h.status != 200) {
            fail(
                "auth",
                io.sprintf("the identity provider answered HTTP %d at %s", $h.status, $url) +
                    renderTrail($trail));
        }

        def doc as html.Node init html.parse($h.body);
        def title as string init pageTitle($doc);
        note($prof, "  page: " + $title);
        def forms as list of html.Node init pickForm($doc);
        if (len($forms) == 0) {
            fail(
                "auth",
                "nothing to submit at " + $url + "\n  page: " + $title +
                    "\n  This is where the browserless walk ends - the page has no HTML form" +
                    " to fill in, so it is JavaScript or a second factor." +
                    "\n  Use --mode token." + renderTrail($trail));
        }
        def form as html.Node init $forms[0];
        note($prof, "  form: " + describeForm($form));
        # Being shown the credential form again means the last submission was
        # refused. Stop: resubmitting the same wrong password until the step
        # budget runs out is how an account gets locked.
        def wantsPassword as bool init formHasPassword($form);
        if ($wantsPassword and $sentPassword) {
            fail(
                "auth",
                "the identity provider rejected the credentials for " + $creds.user +
                    " (it asked for the password a second time)" + renderTrail($trail));
        }
        $sentPassword = $sentPassword or $wantsPassword;
        def action as string init attrOrEmpty($form, "action");
        if ($action == "") {
            $action = $url;
        }
        $body = encodeForm($form, $creds);
        if ($body == "") {
            fail(
                "auth",
                "the form at " + $url + " has no fields this can fill" + "\n  page: " + $title +
                    "\n  fields: " + describeForm($form) + "\n  Use --mode token." +
                    renderTrail($trail));
        }
        $url = uri.resolve($url, $action);
        # Unconditional, not under --verbose: the form's action decides where the
        # password goes, and the walk got here on someone else's redirects.
        if ($wantsPassword) {
            io.printf("Submitting the password for %s to %s\n", $creds.user, uri.parse($url).host);
        }
        $method = "POST";
        if (strings.lower(attrOrEmpty($form, "method")) == "get") {
            $method = "GET";
        }
    }
    fail(
        "auth",
        io.sprintf("gave up after %d steps without a token.", MAX_SSO_STEPS) +
            " The walk kept moving but never reached one, so the login wants" +
            "\n  something this cannot give it. Use --mode token, and if the trail below" +
            "\n  looks like it should have worked, --debug-dir will save every page." +
            renderTrail($trail));
}

/**
 * Authenticate with no browser at all, submitting the credentials ourselves.
 * @param prof {Profile} the active profile
 * @return {Session} the authenticated session
 * @throws {Error} kind "auth" or "gateway" when the login fails
 * @since 0.2
 */
func authenticateBrowserless(prof as Profile) {
    # Other modes risk a token; this one submits the password. Skipping
    # verification would hand it to whatever answers the connection.
    if ($prof.insecure) {
        fail(
            "config",
            "--insecure and --mode browserless are not allowed together: browserless\n" +
                "  mode submits your password, and skipping certificate verification would\n" +
                "  hand it to whatever answers the connection.\n" +
                "  Drop --insecure, or use --mode token and let the browser do the login.");
    }
    def ar as AuthRequest init probeGateway($prof, false);
    def creds as Credentials init gatherCredentials($prof);
    def token as string init browserlessToken($prof, $ar, $creds);
    return submitToken($prof, $ar, $token);
}

#
# -------------------------------------------------------------------- commands
#

/**
 * The `connect` command: authenticate, then bring the tunnel up.
 * @param r {args.Result} the parsed command line
 * @return {int} the process exit code
 * @throws {Error} when openconnect is missing, or authentication or the tunnel fails
 * @since 0.1
 */
func cmdConnect(r as args.Result) {
    def prof as Profile init resolveProfile($r);
    if (not haveOpenconnect()) {
        fail(
            "openconnect",
            "openconnect is not on PATH - install it first (pacman -S openconnect)");
    }
    def sess as Session init authenticate($prof, args.asString($r, "mode"));
    if ($sess.message != "") {
        io.printf("\n%s\n", $sess.message);
    }

    if (args.asBool($r, "print")) {
        io.printf("\nAuthenticated. Run this to bring the tunnel up:\n");
        printCommand($prof, $sess);
        return 0;
    }
    io.printf("\nAuthenticated. Starting the tunnel ...\n");
    startTunnel($prof, $sess);
    def teardown as string init APP + " disconnect";
    if ($prof.name != "") {
        $teardown = $teardown + " " + $prof.name;
    }
    io.printf("Connected. Tear it down with: %s\n", $teardown);
    return 0;
}

/**
 * The `cookie` command: authenticate and print the session, shell-eval friendly.
 * @param r {args.Result} the parsed command line
 * @return {int} the process exit code
 * @throws {Error} when authentication fails
 * @since 0.1
 */
func cmdCookie(r as args.Result) {
    def prof as Profile init resolveProfile($r);
    def sess as Session init authenticate($prof, args.asString($r, "mode"));
    io.printf("COOKIE=%s\n", shellQuote($sess.cookie));
    io.printf("CONNECT_URL=%s\n", shellQuote($sess.connectUrl));
    io.printf("FINGERPRINT=%s\n", shellQuote($sess.fingerprint));
    return 0;
}

/**
 * The `probe` command: report how the gateway authenticates, and what we can do.
 * @param r {args.Result} the parsed command line
 * @return {int} the process exit code
 * @throws {Error} kind "gateway" when the gateway cannot be reached or refuses
 * @since 0.1
 */
func cmdProbe(r as args.Result) {
    def prof as Profile init resolveProfile($r);
    def ar as AuthRequest init probeOfferingExternal($prof);

    io.printf("gateway            %s\n", $prof.server);
    if ($ar.tunnelGroup != "") {
        io.printf("tunnel group       %s\n", $ar.tunnelGroup);
    }
    if ($prof.group != "") {
        io.printf("group-select       %s (sent; many gateways ignore it)\n", $prof.group);
    }
    if ($ar.title != "") {
        io.printf("title              %s\n", $ar.title);
    }
    if ($ar.message != "") {
        io.printf("message            %s\n", $ar.message);
    }
    io.printf("login url          %s\n", $ar.loginUrl);
    io.printf("final url          %s\n", $ar.loginFinalUrl);
    io.printf("token cookie       %s\n", $ar.tokenCookieName);
    io.printf("reply field        %s\n", $ar.ssoField);

    def mode as string init $ar.browserMode;
    if ($mode == "") {
        $mode = "webview / classic - the paste-the-cookie flow";
    }
    io.printf("browser mode       %s\n", $mode);
    if ($ar.externalRefused) {
        io.printf("external browser   refused by this gateway (it errors if offered)\n");
    }
    io.printf("openconnect        ");
    if (not haveOpenconnect()) {
        io.printf("not installed\n");
    } elseif (supportsExternalBrowser()) {
        io.printf("present, has --external-browser\n");
    } else {
        io.printf("present, no --external-browser\n");
    }

    io.printf("\n");
    if ($ar.browserMode == "external" and supportsExternalBrowser()) {
        io.printf("`%s connect` will let openconnect do the SSO - no pasting needed.\n", APP);
    } else {
        io.printf("`%s connect` will send you to the browser and ask you to paste the\n", APP);
        io.printf("%s cookie back.\n", $ar.tokenCookieName);
    }
    return 0;
}

/**
 * The pid `connect` recorded for this profile.
 * @param prof {Profile} the active profile
 * @return {int} the pid, or 0 when there is no usable pid file
 * @since 0.1
 */
func readPid(prof as Profile) {
    def f as string init pidFileFor($prof);
    if (not fs.exists($f)) {
        return 0;
    }
    try {
        def raw as string init strings.trim(fs.readString($f));
        if ($raw == "") {
            return 0;
        }
        return convert.toInt($raw);
    } catch (e) {
        # A truncated or clobbered pid file is "no tunnel", not a crash in
        # `status`; the caller's own message is the useful one.
        return 0;
    }
}

/**
 * Whether a process is still running.
 * @param pid {int} the process id
 * @return {bool} true when /proc has an entry for it
 * @since 0.1
 */
func pidAlive(pid as int) {
    if ($pid <= 0) {
        return false;
    }
    return fs.exists("/proc/" + convert.toString($pid));
}

/**
 * Whether a pid is a live openconnect, not merely a live process.
 * The pid file outlives the tunnel and Linux reuses pids, so "something runs
 * under that number" is not "the tunnel is up". `disconnect` signals it as
 * root, so the alternative is killing whatever inherited the number.
 * @param pid {int} the process id from the pid file
 * @return {bool} true when that process is still openconnect
 * @since 0.4
 */
func pidIsOpenconnect(pid as int) {
    if (not pidAlive($pid)) {
        return false;
    }
    try {
        # NUL-separated argv; a substring test suffices.
        return strings.contains(
            fs.readString("/proc/" + convert.toString($pid) + "/cmdline"),
            "openconnect");
    } catch (e) {
        # Exited between the two reads, or /proc is unreadable.
        return false;
    }
}

/**
 * The `status` command: report whether the tunnel is up.
 * @param r {args.Result} the parsed command line
 * @return {int} 0 when the tunnel is up, 1 when it is not
 * @since 0.1
 */
func cmdStatus(r as args.Result) {
    def prof as Profile init resolveProfile($r);
    def pid as int init readPid($prof);
    if (pidIsOpenconnect($pid)) {
        io.printf("up - openconnect pid %d (%s)\n", $pid, pidFileFor($prof));
        return 0;
    }
    io.printf("down\n");
    return 1;
}

/**
 * The `disconnect` command: stop a tunnel started by `connect`.
 * @param r {args.Result} the parsed command line
 * @return {int} 0 when a tunnel was stopped, 1 when there was none
 * @throws {Error} kind "privilege" or "openconnect" when the process cannot be signalled
 * @since 0.1
 */
func cmdDisconnect(r as args.Result) {
    def prof as Profile init resolveProfile($r);
    def pid as int init readPid($prof);
    if (not pidIsOpenconnect($pid)) {
        if (pidAlive($pid)) {
            # Refusing on purpose: the tunnel is already gone and something else
            # has inherited the number. Signalling it would kill a stranger.
            io.printf(
                "not disconnecting: pid %d in %s is no longer openconnect\n",
                $pid,
                pidFileFor($prof));
            io.printf("  the tunnel is already down and the pid has been reused\n");
            return 1;
        }
        io.printf("nothing to disconnect (no live pid in %s)\n", pidFileFor($prof));
        return 1;
    }
    checkPrivilege($prof);
    def argv as list of string init sudoPrefix($prof, true);
    $argv[] = "kill";
    $argv[] = convert.toString($pid);
    def res as os.Result init os.run($argv);
    if ($res.exitCode != 0) {
        io.eprintf("%s", $res.stderr);
        fail("openconnect", io.sprintf("could not signal pid %d", $pid));
    }
    io.printf("disconnected (pid %d)\n", $pid);
    return 0;
}

#
# ------------------------------------------------------------------------- main
#

/**
 * An empty parse result, for a variable filled in by a fallible parse.
 * @return {args.Result} a result with no command and nothing done
 * @since 0.3
 */
func emptyResult() {
    return args.Result{
        command: "",
        values: {},
        lists: {},
        counts: {},
        present: {},
        helpText: "",
        done: false
    };
}

/**
 * Strip the args module's own prefix from a parse error.
 * The module tags its messages "args: "; the reader wants the mistake, not the
 * name of the parser that caught it.
 * @param message {string} the raw error message
 * @return {string} the message without its prefix
 * @since 0.3
 */
func argsMessage(message as string) {
    if (strings.startsWith($message, "args: ")) {
        return strings.substring($message, 6);
    }
    return $message;
}

/**
 * A parser carrying the options every subcommand accepts.
 * @param prog {string} the subcommand name
 * @param help {string} its one-line description
 * @return {args.Parser} the parser, ready for subcommand-specific additions
 * @since 0.1
 */
func commonFlags(prog as string, help as string) {
    def p as args.Parser init args.parser($prog, $help);
    $p = args.positionalOpt($p, "profile", "", "profile from the config file");
    $p = args.flag($p, "server", "s", "", "gateway URL, e.g. https://vpn.example.com");
    $p = args.flag($p, "group", "g", "", "tunnel group / authgroup");
    $p = args.flag($p, "browser", "b", "", "command that opens a URL (default xdg-open)");
    $p = args.flag($p, "sudo", "", "sudo", "privilege helper for the tunnel (empty to skip)");
    $p = args.flag($p, "user", "u", "", "username for browserless mode");
    $p = args.flag($p, "password-command", "", "", "command printing the password on stdout");
    $p = args.flag($p, "factor", "", "", "second factor to pick when the IdP offers a choice");
    $p = args.flag($p, "debug-dir", "", "", "save each browserless page here (contains secrets)");
    $p = args.choices(
        args.flag($p, "capture", "", "auto", "how token mode reads the cookie"),
        ["auto", "cdp", "paste"]);
    $p = args.boolFlag($p, "insecure", "k", "skip TLS verification while authenticating");
    $p = args.boolFlag($p, "verbose", "v", "show what is going on");
    return $p;
}

/**
 * Add the --mode flag to a parser.
 * @param p {args.Parser} the parser to extend
 * @return {args.Parser} the parser with --mode added
 * @since 0.1
 */
func modeFlag(p as args.Parser) {
    return args.choices(
        args.flag($p, "mode", "m", "auto", "auto, external, token or browserless"),
        ["auto", "external", "token", "browserless"]);
}

/**
 * Parse the command line and run the requested command.
 * Kept here rather than in the executable so the whole program is one module,
 * testable as one unit; the executable only supplies the exit status.
 * @return {int} the process exit status
 * @since 0.3
 */
export func run() {
    def topParser as args.Parser init args.parser(
        APP,
        "Connect to a Cisco AnyConnect gateway that authenticates with SAML/SSO.");
    $topParser = args.version($topParser, APP_VERSION);

    def connectParser as args.Parser init modeFlag(commonFlags(
        "connect",
        "authenticate, then bring the tunnel up"));
    $connectParser = args.boolFlag(
        $connectParser,
        "print",
        "p",
        "print the openconnect command instead of running it");

    $topParser = args.command($topParser, "connect", "authenticate and connect", $connectParser);
    $topParser = args.command(
        $topParser,
        "cookie",
        "authenticate and print the session cookie",
        modeFlag(commonFlags("cookie", "authenticate and print the session cookie")));
    $topParser = args.command(
        $topParser,
        "probe",
        "ask the gateway how it authenticates",
        commonFlags("probe", "ask the gateway how it authenticates"));
    $topParser = args.command(
        $topParser,
        "disconnect",
        "tear down a tunnel started by connect",
        commonFlags("disconnect", "tear down a tunnel started by connect"));
    $topParser = args.command(
        $topParser,
        "status",
        "is the tunnel up?",
        commonFlags("status", "is the tunnel up?"));

    # A misspelled flag is a usage mistake, not a crash: report it like one, point
    # at --help, and exit 2 the way a CLI is expected to. args throws rather than
    # exiting so that the program - not the parser - decides this.
    def cli as args.Result init emptyResult();
    try {
        $cli = args.parse($topParser, os.ARGS);
    } catch (e) {
        io.eprintf("%s: %s\n", APP, argsMessage($e.message));
        io.eprintf("Try `%s --help`, or `%s <command> --help`.\n", APP, APP);
        exit 2;
    }

    if ($cli.done) {
        io.printf("%s\n", $cli.helpText);
        exit 0;
    }
    if ($cli.command == "") {
        io.printf("%s\n", args.usage($topParser));
        exit 2;
    }

    try {
        def code as int init 0;
        match ($cli.command) {
            when "connect" { $code = cmdConnect($cli); }
            when "cookie" { $code = cmdCookie($cli); }
            when "probe" { $code = cmdProbe($cli); }
            when "disconnect" { $code = cmdDisconnect($cli); }
            when "status" { $code = cmdStatus($cli); }
        }
        exit $code;
    } catch (e) {
        io.eprintf("%s: %s\n", APP, $e.message);
        exit 1;
    }
}
