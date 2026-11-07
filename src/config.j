# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0

/**
 * The config file and the command line, resolved into one Profile.
 *
 * @module config
 * @version 0.6.0
 */

use os;
use fs;
use path;
use toml;
use strings;
use convert;

import "args.j" as args;
import "uri.j" as uri;
import "./types.j" as types;
import "./util.j" as util;

#
# ------------------------------------------------------------------------ config
#

/**
 * Where the config file lives.
 * @return {string} $OCSAML_CONFIG if set, else ~/.config/ocsaml/config.toml
 * @since 0.1
 */
func configPath() {
    def override as string init os.getEnv("OCSAML_CONFIG");
    if ($override != "") {
        return $override;
    }
    return path.join(os.homeDir(), ".config", types.APP, "config.toml");
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
 * Load one profile from the config file.
 * Falls back to the `default` key, and then to the only profile present if the
 * file defines exactly one.
 * @param name {string} the requested profile, or "" to let the file decide
 * @return {Profile} the profile, or the defaults when there is no config file
 * @throws {Error} kind "config" when the named profile does not exist
 * @since 0.1
 */
func loadProfile(name as string) {
    def prof as types.Profile init types.defaultProfile();
    def cfg as string init configPath();
    if (not fs.exists($cfg)) {
        if ($name != "") {
            util.fail(
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

    return readProfile($doc, $want, $cfg);
}

/**
 * Fill a Profile from one table of a parsed config file.
 * @param doc {toml.Value} the parsed config
 * @param want {string} the profile name, a top-level table
 * @param cfg {string} the config file's path, for messages
 * @return {Profile} the defaults overlaid with the table's keys
 * @throws {Error} kind "config" when the table does not exist, `cdpPort` is not
 *     a TCP port, or `captureTimeout` is under a second
 * @since 0.4
 */
func readProfile(doc as toml.Value, want as string, cfg as string) {
    def prof as types.Profile init types.defaultProfile();
    def base as string init "/" + $want;
    if (not toml.has($doc, $base)) {
        util.fail(
            "config",
            "no profile named '" + $want + "' in " + $cfg + " (found: " +
                strings.join(profileNames($doc), ", ") + ")");
    }

    $prof.name = $want;
    $prof.server = tomlString($doc, $base + "/server", "");
    $prof.group = tomlString($doc, $base + "/group", "");
    $prof.browser = tomlString($doc, $base + "/browser", "xdg-open");
    $prof.sudo = tomlString($doc, $base + "/sudo", "sudo");
    $prof.version = tomlString($doc, $base + "/version", types.CLIENT_VERSION);
    $prof.user = tomlString($doc, $base + "/user", "");
    $prof.capture = tomlString($doc, $base + "/capture", "auto");
    $prof.cdpPort = tomlInt($doc, $base + "/cdpPort", 9333);
    # Out of range it would reach --remote-debugging-port and fail in the
    # browser's words, not ours.
    if ($prof.cdpPort < 1 or $prof.cdpPort > 65535) {
        util.fail(
            "config",
            "cdpPort = " + convert.toString($prof.cdpPort) + " in " + $cfg +
                " is not a TCP port (1..65535)");
    }
    $prof.browserProfile = tomlString($doc, $base + "/browserProfile", "");
    def captureTimeout as int init tomlInt($doc, $base + "/captureTimeout", 300);
    # Zero or less puts the capture deadline in the past before the browser
    # has opened.
    if ($captureTimeout < 1) {
        util.fail(
            "config",
            "captureTimeout = " + convert.toString($captureTimeout) + " in " + $cfg +
                " must be at least 1 (seconds)");
    }
    $prof.captureTimeoutMs = $captureTimeout * 1000;
    $prof.passwordCommand = tomlString($doc, $base + "/passwordCommand", "");
    $prof.factor = tomlString($doc, $base + "/factor", "");
    $prof.servercert = tomlString($doc, $base + "/servercert", "");
    $prof.insecure = tomlBool($doc, $base + "/insecure", false);
    $prof.extra = tomlList($doc, $base + "/extra");
    return $prof;
}

/**
 * A gateway URL with a scheme, in lower case.
 * No scheme means https. The scheme is case-insensitive by RFC 3986, but what
 * follows compares it as text and the wire gets whatever is stored, so it is
 * folded once here.
 * @param server {string} the URL as configured or passed
 * @return {string} the URL with a lower-case `http://` or `https://` prefix
 * @since 0.4
 */
func normaliseServer(server as string) {
    def lowered as string init strings.lower($server);
    def out as string init $server;
    if (not strings.startsWith($lowered, "http://") and
        not strings.startsWith($lowered, "https://")) {
        $out = "https://" + $server;
    }
    def scheme as string init strings.lower(uri.parse($out).scheme);
    return $scheme + strings.substring($out, len($scheme));
}

/**
 * Whether a gateway URL is a plain-http one that must be refused.
 * Both directions carry a bearer credential - the SSO token in, the session
 * cookie out - so clear text is refused unless the host is this machine (the
 * credential never leaves the kernel) or --insecure already said
 * "unauthenticated channel accepted".
 * @param server {string} the normalised gateway URL
 * @param insecure {bool} the profile's --insecure
 * @return {bool} true when the URL is remote http:// and --insecure is off
 * @since 0.4
 */
func refusesPlainHttp(server as string, insecure as bool) {
    def u as uri.Uri init uri.parse($server);
    return strings.lower($u.scheme) == "http" and not $insecure and
        not util.isLoopbackHost($u.host);
}

/**
 * The profile to act on: the config file overlaid with command-line flags.
 * Also normalises the gateway URL, prepending https:// when no scheme is given.
 * @param r {args.Result} the parsed command line
 * @return {Profile} the effective profile
 * @throws {Error} kind "config" when no gateway URL is configured or passed, or
 *     when it is a remote http:// URL and --insecure was not given
 * @since 0.1
 */
export func resolveProfile(r as args.Result) {
    def prof as types.Profile init loadProfile(args.asString($r, "profile"));

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
        util.fail(
            "config",
            "no gateway URL - pass --server https://vpn.example.com," + " or put one in " +
                configPath());
    }
    $prof.server = normaliseServer($prof.server);
    if (refusesPlainHttp($prof.server, $prof.insecure)) {
        util.fail(
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
export func pidFileFor(prof as types.Profile) {
    return runFileFor($prof, ".pid");
}

/**
 * Where the backgrounded openconnect's output is redirected.
 * @param prof {Profile} the active profile
 * @return {string} an absolute path under /run, named after the profile
 * @since 0.1
 */
export func logFileFor(prof as types.Profile) {
    return runFileFor($prof, ".log");
}

/**
 * A per-profile path under /run, shared by the pid and log files.
 * @param prof {Profile} the active profile
 * @param suffix {string} the file extension, including the dot
 * @return {string} the absolute path
 * @since 0.1
 */
func runFileFor(prof as types.Profile, suffix as string) {
    def n as string init $prof.name;
    if ($n == "") {
        $n = uri.parse($prof.server).host;
    }
    return "/run/" + types.APP + "-" + util.slug($n) + $suffix;
}
