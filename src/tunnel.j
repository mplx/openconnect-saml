# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: exec

/**
 * Everything that drives openconnect(8): its command line, the privilege helper,
 * the background tunnel and its pid file.
 *
 * @module tunnel
 * @version 0.4.0
 */

use io;
use os;
use fs;
use strings;
use maps;
use convert;

import "./config.j" as config;
import "./types.j" as types;
import "./util.j" as util;

#
# --------------------------------------------------------- driving openconnect
#

/**
 * Whether openconnect is installed and runnable.
 * Costs a process spawn, so callers that need the answer twice should keep it
 * in a local: a module holds no mutable state, so this cannot memoise itself.
 * @return {bool} true when `openconnect --version` succeeds
 * @since 0.1
 */
export func haveOpenconnect() {
    try {
        def r as os.Result init os.run(["openconnect", "--version"]);
        return $r.exitCode == 0;
    } catch (e) {
        return false;
    }
}

/**
 * Whether the local openconnect can drive Cisco's external-browser SSO.
 * Spawns openconnect, like haveOpenconnect; the same advice about a local
 * applies.
 * @return {bool} true when its help text mentions --external-browser
 * @since 0.1
 */
export func supportsExternalBrowser() {
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
export func sudoPrefix(prof as types.Profile, nonInteractive as bool) {
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
export func checkPrivilege(prof as types.Profile) {
    if ($prof.sudo == "") {
        return;
    }
    def r as os.Result init os.run([$prof.sudo, "-n", "true"]);
    if ($r.exitCode != 0) {
        util.fail(
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
func clientArgs(prof as types.Profile) {
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
func connectArgv(
    prof as types.Profile,
    sess as types.Session,
    background as bool,
    nonInteractive as bool) {
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
func openconnectArgv(prof as types.Profile, sess as types.Session, background as bool) {
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
        $argv[] = config.pidFileFor($prof);
    }
    for (def a in $prof.extra) {
        $argv[] = $a;
    }
    $argv[] = $sess.connectUrl;
    return $argv;
}

/**
 * Print the connect command for the user to run by hand.
 * Emitted as a printf pipeline so the cookie reaches openconnect over stdin
 * rather than through the process list.
 * @param prof {Profile} the active profile
 * @param sess {Session} the authenticated session
 * @since 0.1
 */
export func printCommand(prof as types.Profile, sess as types.Session) {
    io.printf(
        "\nprintf '%%s\\n' %s \\\n  | %s\n\n",
        util.shellQuote($sess.cookie),
        util.shellJoin(connectArgv($prof, $sess, false, false)));
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
export func startTunnel(prof as types.Profile, sess as types.Session) {
    checkPrivilege($prof);
    def logPath as string init config.logFileFor($prof);
    def inner as string init "exec " + util.shellJoin(openconnectArgv($prof, $sess, true)) + " >" +
        util.shellQuote($logPath) + " 2>&1";

    def argv as list of string init sudoPrefix($prof, true);
    $argv[] = "sh";
    $argv[] = "-c";
    $argv[] = $inner;
    util.note($prof, "starting " + $inner);

    def r as os.Result init os.run($argv, $sess.cookie + "\n");
    def logged as string init util.readLog($logPath);
    if ($r.exitCode != 0) {
        io.eprintf("%s", $r.stderr);
        io.eprintf("%s", $logged);
        util.fail(
            "openconnect",
            io.sprintf("openconnect exited %d, see %s", $r.exitCode, $logPath));
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
export func authenticateExternally(prof as types.Profile) {
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
    util.note($prof, strings.join($argv, " "));

    def r as os.Result init os.run($argv);
    if ($r.exitCode != 0) {
        io.eprintf("%s", $r.stderr);
        util.fail("openconnect", io.sprintf("openconnect --authenticate exited %d", $r.exitCode));
    }
    if ($prof.verbose) {
        io.eprintf("%s", $r.stderr);
    }

    def fields as map of string to string init parseAuthenticateOutput($r.stdout);
    if (not maps.has($fields, "COOKIE") or $fields["COOKIE"] == "") {
        util.fail("openconnect", "openconnect --authenticate returned no cookie");
    }

    def sess as types.Session init types.Session{
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
 * The pid `connect` recorded for this profile.
 * @param prof {Profile} the active profile
 * @return {int} the pid, or 0 when there is no usable pid file
 * @since 0.1
 */
export func readPid(prof as types.Profile) {
    def f as string init config.pidFileFor($prof);
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
export func pidAlive(pid as int) {
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
export func pidIsOpenconnect(pid as int) {
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
