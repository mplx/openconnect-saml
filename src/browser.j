# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net
# pragma-jennifer-capability: exec

/**
 * Getting an SSO token out of a browser - over the DevTools protocol where that
 * works, by asking you to paste it where it does not.
 *
 * @module browser
 * @version 0.4.0
 */

use io;
use os;
use fs;
use path;
use strings;
use maps;
use convert;
use time;
use json;

import "http.j" as http;
import "uri.j" as uri;
import "websocket.j" as websocket;
import "./types.j" as types;
import "./util.j" as util;

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
func launchBrowser(prof as types.Profile, url as string) {
    if ($prof.browser == "" or $prof.browser == "-") {
        return false;
    }
    try {
        # Nothing waits on this one, and a captured stream with no reader is a
        # pipe waiting to fill.
        def child as os.Process init os.spawn(
            [$prof.browser, $url],
            {"stdout": "discard", "stderr": "discard"});
        util.note($prof, io.sprintf("launched %s (pid %d)", $prof.browser, $child.pid));
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
 * the final URL if the token rides in its query string.
 * @param raw {string} the pasted text
 * @param cookieName {string} the cookie name the gateway told us to expect
 * @return {string} the token, or "" when nothing was pasted - or when a Cookie
 *     header was pasted that does not carry cookieName
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
    def owner as types.BrowserOwner init types.BrowserOwner{name: $name, uid: -1, home: ""};
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
func unprivilegedAdvice(prof as types.Profile) {
    def how as string init "it escalates on its own";
    if ($prof.sudo == "") {
        $how = "set sudo = \"sudo\" so it can escalate on its own";
    }
    return "  Run " + types.APP + " as your normal desktop user: authentication never needs\n" +
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
func browserOwner(prof as types.Profile) {
    if (effectiveUid() != 0) {
        return types.BrowserOwner{name: "", uid: -1, home: ""};
    }
    def who as string init invokingUser();
    if ($who == "") {
        util.fail(
            "privilege",
            "a Chromium-based browser refuses to start as root, and there is no\n" +
                "  SUDO_USER to hand it back to.\n" + unprivilegedAdvice($prof));
    }
    def owner as types.BrowserOwner init passwdEntry($who);
    if ($owner.home == "") {
        util.fail(
            "privilege",
            "a Chromium-based browser refuses to start as root, and " + $who +
                " has no\n  home directory in the password database to run it from.\n" +
                unprivilegedAdvice($prof));
    }
    def r as os.Result init os.run(["sudo", "-n", "-u", $who, "true"]);
    if ($r.exitCode != 0) {
        util.fail(
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
func browserProfileDir(prof as types.Profile, owner as types.BrowserOwner) {
    if ($prof.browserProfile != "") {
        return $prof.browserProfile;
    }
    def home as string init os.homeDir();
    if ($owner.home != "") {
        $home = $owner.home;
    }
    return path.join($home, ".cache", types.APP, "browser");
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
func makeBrowserProfileDir(dir as string, owner as types.BrowserOwner) {
    if ($owner.name == "") {
        fs.mkdirAll($dir);
        return;
    }
    def r as os.Result init os.run(["sudo", "-n", "-u", $owner.name, "mkdir", "-p", $dir]);
    if ($r.exitCode != 0) {
        util.fail(
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
func browserLaunchPrefix(owner as types.BrowserOwner) {
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
            util.fail(
                "auth",
                io.sprintf("the browser exited without opening its debug port %d.", $port) +
                    browserSaid($logPath));
        }
        time.sleep(time.fromMilliseconds(250));
        $waited = $waited + 250;
    }
    util.fail(
        "auth",
        io.sprintf(
            "the browser never opened its debug port %d." +
                " Is it already running with a different profile?",
            $port) + browserSaid($logPath));
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
 * @return {string} the cookie value, or "" if it is not set yet - also when
 *     MAX_CDP_READS frames passed without our reply, which the caller's
 *     deadline, not this function, decides what to do about
 * @since 0.3
 */
func cdpCookieOnce(conn as websocket.Conn, id as int, cookieName as string, host as string) {
    websocket.send($conn, io.sprintf('{"id":%d,"method":"Storage.getCookies"}', $id));
    # The browser interleaves events with replies; read until ours comes back,
    # but not forever - see MAX_CDP_READS.
    def reads as int init 0;
    while ($reads < types.MAX_CDP_READS) {
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
 * The tail of the capture browser's stderr, for an error message.
 * The one line that matters is usually the browser's own refusal to start
 * ("Running as root without --no-sandbox is not supported"), and it is the last
 * thing it says; the lines before it are GPU and GCM noise.
 * @param logPath {string} file the browser's stderr was redirected to
 * @return {string} the lines, indented and prefixed, or "" when it said nothing
 * @since 0.4
 */
func browserSaid(logPath as string) {
    def raw as string init strings.trim(util.readLog($logPath));
    if ($raw == "") {
        return "";
    }
    def lines as list of string init strings.split($raw, "\n");
    def from as int init 0;
    if (len($lines) > types.BROWSER_LOG_LINES) {
        $from = len($lines) - types.BROWSER_LOG_LINES;
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
 * @throws {Error} kind "auth" when the browser exits, cannot be driven, or you
 *     never finish; kind "privilege" when it cannot be run as the right user
 * @since 0.3
 */
func captureTokenViaCdp(prof as types.Profile, ar as types.AuthRequest) {
    def owner as types.BrowserOwner init browserOwner($prof);
    def dir as string init browserProfileDir($prof, $owner);
    makeBrowserProfileDir($dir, $owner);
    if ($owner.name != "") {
        util.note(
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
    # never applies to it. Do not add it.
    $argv[] = "--user-data-dir=" + $dir;
    $argv[] = "--no-first-run";
    $argv[] = "--no-default-browser-check";
    $argv[] = $ar.loginUrl;
    util.note($prof, "launching " + strings.join($argv, " "));

    # stdout discarded, stderr to a file: the default is "capture", which buffers
    # for an os.wait that never comes, and a browser is chatty enough to fill the
    # pipe and wedge. The file is what lets a failure say why the browser died
    # rather than only that the port never opened.
    def logPath as string init fs.makeTempFile();
    defer util.removeQuietly($logPath);
    def child as os.Process init os.spawn($argv, {"stdout": "discard", "stderr": $logPath});
    errdefer stopBrowser($child);
    util.note($prof, io.sprintf("browser pid %d", $child.pid));

    def wsUrl as string init cdpEndpoint($prof.cdpPort, 20000, $child, $logPath);
    def conn as websocket.Conn init websocket.connectWith($wsUrl, types.CDP_RECEIVE_MS);
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
            util.fail(
                "auth",
                "the browser closed before the login finished." + browserSaid($logPath));
        }
        def token as string init "";
        try {
            $token = cdpCookieOnce($conn, $id, $ar.tokenCookieName, $host);
        } catch (e) {
            # The socket stopped answering. If the browser is gone, that is the
            # explanation worth printing; otherwise let the real error out.
            if (os.poll($child)) {
                util.fail(
                    "auth",
                    "the browser closed before the login finished." + browserSaid($logPath));
            }
            throw $e;
        }
        if ($token != "") {
            util.note($prof, "read " + $ar.tokenCookieName + " from the browser");
            closeCaptureBrowser($conn, $child);
            return $token;
        }
        time.sleep(time.fromMilliseconds(1000));
    }
    util.fail(
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
export func askForToken(prof as types.Profile, ar as types.AuthRequest) {
    def useCdp as bool init $prof.capture == "cdp";
    if ($prof.capture == "auto") {
        $useCdp = browserSpeaksCdp($prof.browser);
    }
    if ($useCdp) {
        if (not browserSpeaksCdp($prof.browser)) {
            util.fail(
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
        util.fail("auth", "no token given, nothing to send to the gateway");
    }
    return $token;
}
