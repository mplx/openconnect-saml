# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>
# pragma-jennifer-version: >=0.25.0
# pragma-jennifer-capability: net
# pragma-jennifer-capability: exec

/**
 * openconnect-saml as a module: a facade over the topic modules.
 *
 * `bin/openconnect-saml` and the installed layout both name this path, so it is
 * the entry point; everything real lives in commands.j and what that imports.
 *
 * @module saml
 * @version 0.4.0
 * @see README.md
 */

import "./commands.j" as commands;

/**
 * Parse the command line and run the requested command.
 * @return {int} the process exit status
 * @since 0.3
 */
export func run() {
    return commands.run();
}
