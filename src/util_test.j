# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# util_test.j - white-box overlay for util.j, spliced by `jennifer test`.
#
#     jennifer test src/util_test.j
use testing;
use convert;

#
# ------------------------------------------------------------------ XML output
#

func testXmlEscape() {
    testing.assertEqual(xmlEscape("a&b"), "a&amp;b");
    testing.assertEqual(xmlEscape("<x>"), "&lt;x&gt;");
    testing.assertEqual(xmlEscape("say \"hi\""), "say &quot;hi&quot;");
    testing.assertEqual(xmlEscape("plain"), "plain");
}

func testStripXmlDecl() {
    testing.assertEqual(stripXmlDecl("<?xml version=\"1.0\"?><a/>"), "<a/>");
    testing.assertEqual(stripXmlDecl("  <a/>  "), "<a/>");
}

func testRenderTrailNumbersTheSteps() {
    def out as string init renderTrail(["GET /a", "POST /b"]);
    testing.assertContains($out, "1) GET /a");
    testing.assertContains($out, "2) POST /b");
}

#
# ---------------------------------------------------- the hidden password line
#

# term.readByte hands back bytes, so the prompt accumulates bytes and decodes
# once. Decoding per byte turns the two bytes of a non-ASCII character into two
# characters, and the identity provider then rejects a password nobody mistyped.

func testBytesToStringDecodesUtf8() {
    # "é" is C3 A9; one character out, not two.
    def acc as list of int init [195, 169];
    testing.assertEqual(bytesToString($acc), "é");
    testing.assertEqual(len(bytesToString($acc)), 1);
    # Decoding per byte would yield "Ã©"; that is the bug this guards.
    testing.assertFalse(bytesToString($acc) ==
        convert.fromCodepoint(195) + convert.fromCodepoint(169));
    testing.assertEqual(bytesToString([]), "");
    testing.assertEqual(bytesToString([104, 105]), "hi");
    # A 3-byte character (€ = E2 82 AC) and a 4-byte one (😀 = F0 9F 98 80).
    testing.assertEqual(bytesToString([226, 130, 172]), "€");
    testing.assertEqual(bytesToString([240, 159, 152, 128]), "😀");
}

func testBytesToStringRoundTripsAPassword() {
    def pw as string init "Sömmer-2026€";
    def raw as bytes init convert.bytesFromString($pw, "utf-8");
    def acc as list of int init [];
    for (def i in 0..len($raw)) {
        $acc[] = $raw[$i];
    }
    testing.assertEqual(bytesToString($acc), $pw);
}

func testDropLastRuneRemovesWholeCharacters() {
    # Backspace after "é" must clear both its bytes, not leave half a character.
    testing.assertEqual(bytesToString(dropLastRune([104, 195, 169])), "h");
    testing.assertEqual(bytesToString(dropLastRune([226, 130, 172])), "");
    testing.assertEqual(bytesToString(dropLastRune([240, 159, 152, 128])), "");
    testing.assertEqual(bytesToString(dropLastRune([104, 105])), "h");
    # Backspace on an empty line is not an error.
    testing.assertEqual(len(dropLastRune([])), 0);
}

#
# ------------------------------------------------ refusals around a credential
#

func testIsXmlName() {
    # What a real gateway asks for.
    testing.assertTrue(isXmlName("sso-token"));
    testing.assertTrue(isXmlName("sso-token-v2"));
    testing.assertTrue(isXmlName("_private"));
    testing.assertTrue(isXmlName("a.b-c9"));
    # The element name wraps the token and cannot be escaped, so anything that
    # breaks out of the tag is refused.
    testing.assertFalse(isXmlName(""));
    testing.assertFalse(isXmlName("a><b"));
    testing.assertFalse(isXmlName("a b"));
    testing.assertFalse(isXmlName("a/b"));
    testing.assertFalse(isXmlName("9lead"));
    testing.assertFalse(isXmlName("-lead"));
    testing.assertFalse(isXmlName("has\"quote"));
}

func testIsLoopbackHost() {
    testing.assertTrue(isLoopbackHost("localhost"));
    testing.assertTrue(isLoopbackHost("127.0.0.1"));
    testing.assertTrue(isLoopbackHost("127.1.2.3"));
    testing.assertTrue(isLoopbackHost("::1"));
    testing.assertTrue(isLoopbackHost("[::1]"));
    testing.assertTrue(isLoopbackHost("LOCALHOST"));
    # Not loopback, and not to be mistaken for it by a prefix test.
    testing.assertFalse(isLoopbackHost("vpn.example.com"));
    testing.assertFalse(isLoopbackHost("127.evil.com"));
    testing.assertFalse(isLoopbackHost("localhost.evil.com"));
    testing.assertFalse(isLoopbackHost("1270.0.0.1"));
    testing.assertFalse(isLoopbackHost(""));
    # Dotted quad only: neither a "127."-prefixed host name nor an out-of-range
    # octet may pose as a local address.
    testing.assertFalse(isLoopbackHost("127.0.0.1.evil.com"));
    testing.assertFalse(isLoopbackHost("127.999.0.1"));
    testing.assertFalse(isLoopbackHost("127.0.0"));
    testing.assertTrue(isLoopbackHost("127.255.255.254"));
}

func testShellQuote() {
    testing.assertEqual(shellQuote("plain"), "'plain'");
    testing.assertEqual(shellQuote("it's"), "'it'\\''s'");
    testing.assertEqual(shellJoin(["a", "b c"]), "'a' 'b c'");
}

#
# ------------------------------------------------------------------- profiles
#

func testSlugMakesPathSafeNames() {
    testing.assertEqual(slug("work"), "work");
    testing.assertEqual(slug("vpn.example.com"), "vpn.example.com");
    testing.assertEqual(slug("a/b c"), "a-b-c");
    testing.assertEqual(slug(""), "default");
}
