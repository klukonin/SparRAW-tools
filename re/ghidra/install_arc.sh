#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the ARCompact processor module into a Ghidra 12.x tree and compile
# its Sleigh spec, so fw_code/uc_code of wil6210/Talyn can be disassembled.
#
#   ./install_arc.sh /path/to/ghidra_12.1.3_PUBLIC
#
# Source: niooss-ledger/ghidra, branch arcompact_on_12.1.2 (Ledger Donjon,
# SSTIC 2021).  Only the Sleigh data files are installed -- the Java emulation
# library is not needed for disassembly/decompilation, and dropping it avoids
# a Gradle build.  Little-endian; language id ARCompact:LE:32:default.
set -eu
G="${1:?usage: install_arc.sh <ghidra install dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DST="$G/Ghidra/Processors/ARC"

[ -x "$G/support/sleigh" ] || { echo "no $G/support/sleigh -- not a Ghidra dir"; exit 1; }
mkdir -p "$DST/data/languages"
cp "$HERE/ARC-module/Module.manifest" "$DST/"
cp "$HERE"/ARC-module/data/languages/ARCompact.* "$DST/data/languages/"

# recompile the .sla against this Ghidra (the shipped one is fine, but be safe)
"$G/support/sleigh" "$DST/data/languages/ARCompact.slaspec"
echo "installed ARCompact into $DST"
echo "language id: ARCompact:LE:32:default"
