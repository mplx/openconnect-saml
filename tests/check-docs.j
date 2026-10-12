#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <developer@mplx.eu>

/**
 * Check one .j file's doc comments: every func, struct and const documented,
 * and no drift between an @param / @field and the thing it names.
 *
 * docblock reports drift but not absence, and absence is the commoner mistake,
 * so coverage is counted here as well. Exits non-zero on either.
 *
 * @module check-docs
 * @version 0.4.0
 */

use io;
use os;
use fs;
use strings;
import "docblock.j" as docblock;

def target as string init os.ARGS[1];
def src as string init fs.readString($target);
def doc as docblock.FileDoc init docblock.parse($src);

def problems as int init 0;

for (def d in $doc.diagnostics) {
    io.eprintf("  %s line %d: %s\n", $d.severity, $d.line, $d.message);
    $problems = $problems + 1;
}

# Coverage: a documented construct is one whose declaration is preceded by the
# end of a doc comment. Cheap, and exactly what the eye checks for.
def lines as list of string init strings.split($src, "\n");
def undocumented as int init 0;
def total as int init 0;
for (def i in 0..len($lines)) {
    def line as string init $lines[$i];
    # `export` prefixes any of them, and a missed prefix silently drops the
    # construct from coverage rather than failing - so the list is the gate.
    def isDecl as bool init strings.startsWith($line, "func ") or
        strings.startsWith($line, "export func ") or
        strings.startsWith($line, "def struct ") or
        strings.startsWith($line, "export def struct ") or
        strings.startsWith($line, "def const ") or
        strings.startsWith($line, "export def const ");
    if ($isDecl) {
        $total = $total + 1;
        if ($i == 0 or strings.trim($lines[$i - 1]) != "*/") {
            io.eprintf("  undocumented: %s\n", $line);
            $undocumented = $undocumented + 1;
        }
    }
}
$problems = $problems + $undocumented;

io.printf(
    "  %s: %d constructs, %d undocumented, %d diagnostics\n",
    $target,
    $total,
    $undocumented,
    len($doc.diagnostics));
if ($problems > 0) {
    exit 1;
}
