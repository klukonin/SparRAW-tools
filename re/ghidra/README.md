# Ghidra helpers for wil6210 / Talyn

Everything needed to disassemble, retype and **patch** the firmware in Ghidra
12.x, plus the loop back into a flashable `.fw`.

## 1. ARCompact processor module

The firmware code (`fw_code` @ 0x900000) and microcode (`uc_code` @ 0xa38000)
are **ARC** (Synopsys, ARCompact ISA). Ghidra ships no ARC processor, so
install the Ledger Donjon module (SSTIC 2021):

```
./install_arc.sh ../ghidra_12.1.3_PUBLIC
```

It copies the Sleigh files into `Ghidra/Processors/ARC` and compiles
`ARCompact.sla`. Language id: **`ARCompact:LE:32:default`** (little-endian).
Only the disassembler/decompiler spec is installed; the Java p-code emulation
library from the upstream module is left out (not needed, and it would want a
Gradle build). Source of the module is kept in `ARC-module/`.

## 2. Disassemble the code

```
G=../ghidra_12.1.3_PUBLIC
# extract the code segment as a raw blob
python3 - <<'PY'
import sys; sys.path.insert(0,'..'); import wil_syms as w
m=w.Memory.from_fw('wil6436.fw')
for base,data in m.segments:
    if base==0x900000: open('fw_code.bin','wb').write(data)
PY
python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py $G --headless \
    PROJ wil -import fw_code.bin -loader BinaryLoader -loader-baseAddr 0x900000 \
    -processor "ARCompact:LE:32:default"
```

`wil_syms.py segments wil6436.fw` lists every loadable segment with its AHB
and linker address; feed the base to `-loader-baseAddr`.

## 3. Patch the code and get a flashable image back

Two ways, both fix the container CRC:

**By hand**, when you know the address and the bytes:

```
python3 ../wil_syms.py patch wil6436.fw --addr 0x900204 --bytes e078e078 -o out.fw
```

**From Ghidra**, when you edited instructions in the tool: run
`arc_export_patch.py` against the original blob to dump exactly the changed
runs, then replay them:

```
# inside Ghidra, headless or via the Script Manager:
#   arc_export_patch.py  fw_code.bin  0x900000  patch.overlay
python3 ../wil_syms.py patch wil6436.fw --overlay patch.overlay -o out.fw
```

The overlay is plain `0xADDR: hexbytes` lines. `patch` refuses a run that
crosses a segment boundary, and recomputes the `.fw` crc so `wil_brd.py info`
reports `crc OK`.

Verified end to end: two `mov_s` at 0x900204 turned into `nop_s nop_s`, the
repackaged `.fw` disassembles back to `nop_s nop_s`, and the overlay route
produces a byte-identical image to the direct `--bytes` patch.

## 4. Полнообразный проект для исследования

`wil_syms.py project` собирает набор для Ghidra, где в одной программе лежит
**весь образ** — код и данные — с наложенными типами:

```
python3 ../wil_syms.py project wil6436.fw -o kit
# затем однократно собрать и проанализировать (ARC-код, пара минут):
G=../ghidra_12.1.3_PUBLIC
python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py $G --headless \
    PROJ wil6436 -import kit/seg_00900000.bin -loader BinaryLoader \
    -loader-baseAddr 0x900000 -processor "ARCompact:LE:32:default" \
    -noanalysis -scriptPath kit -preScript wil_build_project.py kit
```

`wil_build_project.py` создаёт блок памяти на каждый сегмент (fw_code, fw_data,
uc_code, uc_data и второй кодовый блок 0x9a0000), грузит байты, накладывает
типы FW и ucode из `layout_*.json`, ставит метку `reset` на 0x900000 и гоняет
автоанализ. На wil6436.fw выходит **348 функций, 1492 символа**, 455 типов FW и
315 ucode. Готовый проект уже собран — `wil6436-project/wil6436.gpr`, открывать
в Ghidra GUI.

**Замечание про xref.** ARC грузит глобалы через gp/регистр, и плоский
анализатор почти не восстанавливает статические ссылки на data-символы. Поэтому
исследование идёт от функций в декомпиляторе, а типизированные данные
(`g_station_table`, `g_fw_dedicated_registers`, менеджеры) — карта, по которой
опознаёшь, что функция трогает.
