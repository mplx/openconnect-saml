# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# commands_test.j - white-box overlay for commands.j, spliced by `jennifer test`.
#
#     jennifer test src/commands_test.j
use testing;

#
# ----------------------------------------------------------------------- misc
#

func testArgsMessageDropsThePrefix() {
    testing.assertEqual(argsMessage("args: unknown flag --x"), "unknown flag --x");
    testing.assertEqual(argsMessage("something else"), "something else");
}

# The privilege check runs before the browser: a helper that would prompt
# (`false` stands in for a sudo with no cached credentials) fails the connect
# up front, unless the command is only printed.
func testPreflightRefusesAHelperThatWouldPrompt() {
    def p as types.Profile init types.defaultProfile();
    $p.sudo = "false";
    try {
        preflight($p, false);
        throw Error{kind: "test", message: "preflight did not fail"};
    } catch (e) {
        testing.assertEqual($e.kind, "privilege");
        testing.assertContains($e.message, "false -v");
    }
    # --print starts nothing, so it needs no rights.
    preflight($p, true);
}

func testPreflightPassesCachedOrNoHelper() {
    def p as types.Profile init types.defaultProfile();
    $p.sudo = "true";
    preflight($p, false);
    $p.sudo = "";
    preflight($p, false);
}
