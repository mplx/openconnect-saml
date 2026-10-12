# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
#
# types_test.j - white-box overlay for types.j, spliced by `jennifer test`.
#
#     jennifer test src/types_test.j
use testing;

func testDefaultProfileHasNoFactorPreference() {
    testing.assertEqual(defaultProfile().factor, "");
}

func testDefaultProfile() {
    def p as Profile init defaultProfile();
    testing.assertEqual($p.browser, "xdg-open");
    testing.assertEqual($p.sudo, "sudo");
    testing.assertEqual($p.capture, "auto");
    testing.assertEqual($p.cdpPort, 9333);
    testing.assertEqual($p.version, CLIENT_VERSION);
}

func testVersionsAgree() {
    # The one string the packaging and the man page are checked against.
    testing.assertEqual(APP_VERSION, "0.4.0");
}
