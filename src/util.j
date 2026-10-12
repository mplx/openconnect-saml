# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0

/**
 * Small helpers with no topic of their own: errors, escaping, shell quoting, byte and
 * string shaping.
 *
 * @module util
 * @version 0.4.0
 */

use io;
use os;
use fs;
use strings;
use lists;
use convert;
use binary;

import "./types.j" as types;

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
export func fail(kind as string, message as string) {
    throw Error{kind: $kind, message: $message, file: "", line: 0, col: 0};
}

/**
 * Escape text for inclusion in an XML element or attribute.
 * @param s {string} the raw text
 * @return {string} the text with &, <, > and " replaced by entities
 * @since 0.1
 */
export func xmlEscape(s as string) {
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
export func isXmlName(s as string) {
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
export func stripXmlDecl(s as string) {
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
export func hostName() {
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
export func slug(s as string) {
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
export func note(prof as types.Profile, message as string) {
    if ($prof.verbose) {
        io.eprintf("... %s\n", $message);
    }
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
export func isLoopbackHost(host as string) {
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
 * Delete a file, best effort.
 * @param path {string} the file to remove
 * @since 0.4
 */
export func removeQuietly(path as string) {
    try {
        fs.remove($path);
    } catch (e) { # lint-disable: L103
        # Never existed, or someone else got there first.
    }
}

/**
 * Quote a word for a POSIX shell.
 * @param s {string} the word
 * @return {string} the word in single quotes, with embedded quotes escaped
 * @since 0.1
 */
export func shellQuote(s as string) {
    return "'" + strings.replace($s, "'", "'\\''") + "'";
}

/**
 * Quote and join words into one shell command line.
 * @param argv {list of string} the words
 * @return {string} the words, each quoted, separated by spaces
 * @since 0.1
 */
export func shellJoin(argv as list of string) {
    def parts as list of string init [];
    for (def a in $argv) {
        $parts[] = shellQuote($a);
    }
    return strings.join($parts, " ");
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
export func readLog(path as string) {
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
 * Drop the last whole UTF-8 character from a byte accumulator.
 * Backspace removes a character, not a byte: a continuation byte (10xxxxxx) is
 * half of one, so it goes with its lead byte.
 * @param acc {list of int} the bytes typed so far
 * @return {list of int} the bytes without the last character
 * @since 0.4
 */
export func dropLastRune(acc as list of int) {
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
export func bytesToString(acc as list of int) {
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
 * Render the walk so far, so a failure says where it went, not just that it
 * failed. This is the difference between "use a browser" and a bug report
 * somebody can act on.
 * @param trail {list of string} one "METHOD URL" per step
 * @return {string} the trail, one indented step per line
 * @since 0.2
 */
export func renderTrail(trail as list of string) {
    def out as string init "";
    for (def i in 0..len($trail)) {
        $out = $out + io.sprintf("\n  %d) %s", $i + 1, $trail[$i]);
    }
    return $out;
}

/**
 * Wrap a string in double quotes.
 * @param s {string} the text
 * @return {string} the text, quoted
 * @since 0.3
 */
export func quoted(s as string) {
    return "\"" + $s + "\"";
}
