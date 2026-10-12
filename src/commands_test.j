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
