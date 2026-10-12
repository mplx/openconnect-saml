# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: exec

/**
 * The subcommands, the flag parser, and run() - the program as the user meets it.
 *
 * @module commands
 * @version 0.4.0
 */

use io;
use os;
use strings;
use convert;

import "args.j" as args;
import "./browser.j" as browser;
import "./browserless.j" as browserless;
import "./config.j" as config;
import "./protocol.j" as protocol;
import "./tunnel.j" as tunnel;
import "./types.j" as types;
import "./util.j" as util;

/**
 * Complete a classic login: ask for the token, then submit it.
 * @param prof {Profile} the active profile
 * @param ar {AuthRequest} the gateway's answer to the init request
 * @return {Session} the authenticated session
 * @throws {Error} kind "auth" or "gateway" when the token is missing or rejected
 * @since 0.1
 */
func finishTokenFlow(prof as types.Profile, ar as types.AuthRequest) {
    return protocol.submitToken($prof, $ar, browser.askForToken($prof, $ar));
}

/**
 * Authenticate by whichever route the gateway and the local openconnect support.
 * `auto` only offers external-browser when openconnect could actually use it,
 * and treats a refusal as a plain no. The gateway answers "external" only if we
 * advertised it, so `token` never has to deal with an encrypted token.
 * @param prof {Profile} the active profile
 * @param mode {string} "auto", "external", "token" or "browserless"
 * @return {Session} the authenticated session
 * @throws {Error} when the gateway refuses or the token is rejected
 * @since 0.1
 */
func authenticate(prof as types.Profile, mode as string) {
    if ($mode == "external") {
        return tunnel.authenticateExternally($prof);
    }
    if ($mode == "browserless") {
        return browserless.authenticateBrowserless($prof);
    }

    def tryExternal as bool init $mode == "auto" and tunnel.supportsExternalBrowser();
    def ar as types.AuthRequest init protocol.emptyAuthRequest();
    if ($tryExternal) {
        $ar = protocol.probeOfferingExternal($prof);
    } else {
        $ar = protocol.probeGateway($prof, false);
    }

    if ($ar.browserMode == "external") {
        util.note($prof, "gateway offers external-browser mode; letting openconnect drive it");
        return tunnel.authenticateExternally($prof);
    }
    return finishTokenFlow($prof, $ar);
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
    def prof as types.Profile init config.resolveProfile($r);
    if (not tunnel.haveOpenconnect()) {
        util.fail(
            "openconnect",
            "openconnect is not on PATH - install it first (pacman -S openconnect)");
    }
    def sess as types.Session init authenticate($prof, args.asString($r, "mode"));
    if ($sess.message != "") {
        io.printf("\n%s\n", $sess.message);
    }

    if (args.asBool($r, "print")) {
        io.printf("\nAuthenticated. Run this to bring the tunnel up:\n");
        tunnel.printCommand($prof, $sess);
        return 0;
    }
    io.printf("\nAuthenticated. Starting the tunnel ...\n");
    tunnel.startTunnel($prof, $sess);
    def teardown as string init types.APP + " disconnect";
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
    def prof as types.Profile init config.resolveProfile($r);
    def sess as types.Session init authenticate($prof, args.asString($r, "mode"));
    io.printf("COOKIE=%s\n", util.shellQuote($sess.cookie));
    io.printf("CONNECT_URL=%s\n", util.shellQuote($sess.connectUrl));
    io.printf("FINGERPRINT=%s\n", util.shellQuote($sess.fingerprint));
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
    def prof as types.Profile init config.resolveProfile($r);
    def ar as types.AuthRequest init protocol.probeOfferingExternal($prof);

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
    # Each of these spawns openconnect, and the report needs the second answer
    # twice, so both are taken once and kept.
    def haveOc as bool init tunnel.haveOpenconnect();
    def hasExternal as bool init $haveOc and tunnel.supportsExternalBrowser();
    io.printf("openconnect        ");
    if (not $haveOc) {
        io.printf("not installed\n");
    } elseif ($hasExternal) {
        io.printf("present, has --external-browser\n");
    } else {
        io.printf("present, no --external-browser\n");
    }

    io.printf("\n");
    if ($ar.browserMode == "external" and $hasExternal) {
        io.printf("`%s connect` will let openconnect do the SSO - no pasting needed.\n", types.APP);
    } else {
        io.printf(
            "`%s connect` will send you to the browser and ask you to paste the\n",
            types.APP);
        io.printf("%s cookie back.\n", $ar.tokenCookieName);
    }
    return 0;
}

/**
 * The `status` command: report whether the tunnel is up.
 * @param r {args.Result} the parsed command line
 * @return {int} 0 when the tunnel is up, 1 when it is not
 * @since 0.1
 */
func cmdStatus(r as args.Result) {
    def prof as types.Profile init config.resolveProfile($r);
    def pid as int init tunnel.readPid($prof);
    if (tunnel.pidIsOpenconnect($pid)) {
        io.printf("up - openconnect pid %d (%s)\n", $pid, config.pidFileFor($prof));
        return 0;
    }
    io.printf("down\n");
    return 1;
}

/**
 * The `disconnect` command: stop a tunnel started by `connect`.
 * @param r {args.Result} the parsed command line
 * @return {int} 0 when a tunnel was stopped, 1 when there was none - or when
 *     the recorded pid is alive but is no longer openconnect
 * @throws {Error} kind "privilege" or "openconnect" when the process cannot be signalled
 * @since 0.1
 */
func cmdDisconnect(r as args.Result) {
    def prof as types.Profile init config.resolveProfile($r);
    def pid as int init tunnel.readPid($prof);
    if (not tunnel.pidIsOpenconnect($pid)) {
        if (tunnel.pidAlive($pid)) {
            # Refusing on purpose: the tunnel is already gone and something else
            # has inherited the number. Signalling it would kill a stranger.
            io.printf(
                "not disconnecting: pid %d in %s is no longer openconnect\n",
                $pid,
                config.pidFileFor($prof));
            io.printf("  the tunnel is already down and the pid has been reused\n");
            return 1;
        }
        io.printf("nothing to disconnect (no live pid in %s)\n", config.pidFileFor($prof));
        return 1;
    }
    tunnel.checkPrivilege($prof);
    def argv as list of string init tunnel.sudoPrefix($prof, true);
    $argv[] = "kill";
    $argv[] = convert.toString($pid);
    def res as os.Result init os.run($argv);
    if ($res.exitCode != 0) {
        io.eprintf("%s", $res.stderr);
        util.fail("openconnect", io.sprintf("could not signal pid %d", $pid));
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
        types.APP,
        "Connect to a Cisco AnyConnect gateway that authenticates with SAML/SSO.");
    $topParser = args.version($topParser, types.APP_VERSION);

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
        io.eprintf("%s: %s\n", types.APP, argsMessage($e.message));
        io.eprintf("Try `%s --help`, or `%s <command> --help`.\n", types.APP, types.APP);
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
        io.eprintf("%s: %s\n", types.APP, $e.message);
        exit 1;
    }
}
