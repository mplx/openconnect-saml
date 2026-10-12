# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net
# pragma-jennifer-capability: exec

/**
 * Logging in with no browser at all, by walking the identity provider's HTML forms.
 *
 * @module browserless
 * @version 0.4.0
 */

use io;
use os;
use fs;
use path;
use strings;
use maps;
use lists;
use convert;
use term;

import "html.j" as html;
import "http.j" as http;
import "uri.j" as uri;
import "./protocol.j" as protocol;
import "./types.j" as types;
import "./util.j" as util;

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
            $acc = util.dropLastRune($acc);
        } else {
            $acc[] = $b;
        }
    }
    io.printf("\n");
    return util.bytesToString($acc);
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
func gatherCredentials(prof as types.Profile) {
    def user as string init $prof.user;
    if ($user == "") {
        if (io.eof()) {
            util.fail("auth", "no username - pass --user or set one in the profile");
        }
        $user = strings.trim(io.readLine("Username: "));
    }
    if ($user == "") {
        util.fail("auth", "no username given");
    }

    def password as string init "";
    if ($prof.passwordCommand != "") {
        util.note($prof, "running the password command");
        def r as os.Result init os.run(["sh", "-c", $prof.passwordCommand]);
        if ($r.exitCode != 0) {
            io.eprintf("%s", $r.stderr);
            util.fail("auth", io.sprintf("password command exited %d", $r.exitCode));
        }
        def lines as list of string init strings.split($r.stdout, "\n");
        $password = strings.trim($lines[0]);
    }
    if ($password == "") {
        $password = os.getEnv("OPENCONNECT_SAML_PASSWORD");
    }
    if ($password == "") {
        if (not canPromptHidden()) {
            util.fail(
                "auth",
                "no terminal to prompt for a password on - set passwordCommand" +
                    " in the profile, or $OPENCONNECT_SAML_PASSWORD");
        }
        $password = promptHidden("Password for " + $user + ": ");
    }
    if ($password == "") {
        util.fail("auth", "no password given");
    }
    return types.Credentials{user: $user, password: $password, factor: $prof.factor};
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
        util.fail(
            "auth",
            "the login reached Duo (" + $host + "), a second factor." +
                "\n  Browserless mode drives HTML forms; Duo's prompt is a JavaScript" +
                "\n  application, so this is as far as it goes. Use --mode token: the" +
                "\n  browser handles Duo, and you paste the cookie afterwards." +
                util.renderTrail($trail));
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
    if ($scheme == "https" or util.isLoopbackHost($u.host)) {
        return;
    }
    util.fail(
        "auth",
        "the login tried to continue over " + $scheme + "://, not https:\n  " + $url +
            "\n  Browserless mode submits your password to the form it reaches, so it will" +
            "\n  not send anything over an unencrypted connection." +
            "\n  Use --mode token, where the browser drives the login." + util.renderTrail($trail));
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
        util.fail(
            "auth",
            "the identity provider keeps serving the same page:" + util.renderTrail($trail) +
                "\n  This login needs a browser - use --mode token.");
    }
}

/**
 * Announce a page dump directory, once, before anything is written to it.
 * @param prof {Profile} the active profile
 * @since 0.2
 */
func announceDebugDir(prof as types.Profile) {
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
        if ($label != "" and not lists.contains($parts, util.quoted($label))) {
            $parts[] = util.quoted($label);
        }
    }
    for (def input in collectTags($form, "input")) {
        if (strings.lower(attrOrEmpty($input, "type")) == "radio") {
            def label as string init factorLabel($input);
            if ($label != "" and not lists.contains($parts, util.quoted($label))) {
                $parts[] = util.quoted($label);
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
    util.fail(
        "auth",
        "no way to pick " + util.quoted($factor) + " on this form." + "\n  It offers: " +
            describeChoices($form) + "\n  --factor matches any part of one, ignoring case:" +
            " --factor push, or --factor " + util.quoted("Duo Push") + ".");
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
 * out; and one submit control is included so the IdP sees which button was
 * pressed - Shibboleth's `_eventId_proceed` is exactly that. Which one is
 * chooseSubmit's answer: the --factor match, else the first.
 * @param form {html.Node} the form element
 * @param creds {Credentials} the credentials to fill in
 * @return {string} the encoded body
 * @since 0.2
 */
func encodeForm(form as html.Node, creds as types.Credentials) {
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
            return types.Hop{sessions: $out, status: $i, location: "", body: ""};
        }
    }
    $out[] = http.connect(originOfUrl($url), $opts);
    return types.Hop{sessions: $out, status: len($out) - 1, location: "", body: ""};
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
    def found as types.Hop init sessionFor($sessions, $url, $opts);
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
    # Load-bearing under value semantics: http.exchange returns the session it
    # advanced - cookie jar, open socket and all - and the copy we passed in is
    # now stale. Dropping this line loses every Set-Cookie of this hop.
    $live[$idx] = $ex.session;

    def location as string init "";
    if (maps.has($ex.response.headers, "location")) {
        $location = $ex.response.headers["location"];
    }
    return types.Hop{
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
func browserlessToken(prof as types.Profile, ar as types.AuthRequest, creds as types.Credentials) {
    def noCa as bytes;
    def opts as http.Options init http.defaultOptions();
    $opts.timeoutMs = types.HTTP_TIMEOUT_MS;
    $opts.tls = http.TlsOptions{skipVerify: $prof.insecure, caCert: $noCa};

    def gatewayHost as string init uri.parse($prof.server).host;
    def sessions as list of http.Session init [];
    def url as string init $ar.loginUrl;
    def method as string init "GET";
    def body as string init "";
    def sentPassword as bool init false;
    def trail as list of string init [];

    announceDebugDir($prof);

    for (def step in 0..types.MAX_SSO_STEPS) {
        def where as string init $method + " " + $url;
        util.note($prof, io.sprintf("sso step %d: %s", $step + 1, $where));
        # Before anything is sent: this is the hop that would carry it.
        guardHttps($url, $trail);
        guardSecondFactor($url, $trail);
        guardNoLoop($trail, $where);
        $trail[] = $where;

        def h as types.Hop init hop($sessions, $url, $method, $body, $opts);
        $sessions = $h.sessions;
        if ($prof.debugDir != "") {
            dumpPage($prof.debugDir, $step + 1, $where, $h.body);
        }

        def token as string init tokenFromJars($sessions, $gatewayHost, $ar.tokenCookieName);
        if ($token != "") {
            util.note($prof, "gateway set " + $ar.tokenCookieName);
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
            util.fail(
                "auth",
                io.sprintf("the identity provider answered HTTP %d at %s", $h.status, $url) +
                    util.renderTrail($trail));
        }

        def doc as html.Node init html.parse($h.body);
        def title as string init pageTitle($doc);
        util.note($prof, "  page: " + $title);
        def forms as list of html.Node init pickForm($doc);
        if (len($forms) == 0) {
            util.fail(
                "auth",
                "nothing to submit at " + $url + "\n  page: " + $title +
                    "\n  This is where the browserless walk ends - the page has no HTML form" +
                    " to fill in, so it is JavaScript or a second factor." +
                    "\n  Use --mode token." + util.renderTrail($trail));
        }
        def form as html.Node init $forms[0];
        util.note($prof, "  form: " + describeForm($form));
        # Being shown the credential form again means the last submission was
        # refused. Stop: resubmitting the same wrong password until the step
        # budget runs out is how an account gets locked.
        def wantsPassword as bool init formHasPassword($form);
        if ($wantsPassword and $sentPassword) {
            util.fail(
                "auth",
                "the identity provider rejected the credentials for " + $creds.user +
                    " (it asked for the password a second time)" + util.renderTrail($trail));
        }
        $sentPassword = $sentPassword or $wantsPassword;
        def action as string init attrOrEmpty($form, "action");
        if ($action == "") {
            $action = $url;
        }
        $body = encodeForm($form, $creds);
        if ($body == "") {
            util.fail(
                "auth",
                "the form at " + $url + " has no fields this can fill" + "\n  page: " + $title +
                    "\n  fields: " + describeForm($form) + "\n  Use --mode token." +
                    util.renderTrail($trail));
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
    util.fail(
        "auth",
        io.sprintf("gave up after %d steps without a token.", types.MAX_SSO_STEPS) +
            " The walk kept moving but never reached one, so the login wants" +
            "\n  something this cannot give it. Use --mode token, and if the trail below" +
            "\n  looks like it should have worked, --debug-dir will save every page." +
            util.renderTrail($trail));
}

/**
 * Authenticate with no browser at all, submitting the credentials ourselves.
 * @param prof {Profile} the active profile
 * @return {Session} the authenticated session
 * @throws {Error} kind "config" with --insecure, else "auth" or "gateway" when
 *     the login fails
 * @since 0.2
 */
export func authenticateBrowserless(prof as types.Profile) {
    # Other modes risk a token; this one submits the password. Skipping
    # verification would hand it to whatever answers the connection.
    if ($prof.insecure) {
        util.fail(
            "config",
            "--insecure and --mode browserless are not allowed together: browserless\n" +
                "  mode submits your password, and skipping certificate verification would\n" +
                "  hand it to whatever answers the connection.\n" +
                "  Drop --insecure, or use --mode token and let the browser do the login.");
    }
    def ar as types.AuthRequest init protocol.probeGateway($prof, false);
    def creds as types.Credentials init gatherCredentials($prof);
    def token as string init browserlessToken($prof, $ar, $creds);
    return protocol.submitToken($prof, $ar, $token);
}
