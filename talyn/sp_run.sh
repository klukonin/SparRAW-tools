#!/bin/bash
# Ghidra headless по образам Sparrow (seg/sp_*): fw — код 0x0 (вектора прыгают на 0x120…; хост 0x8c0000), данные 0x800000; uc — код 0x0, данные 0x800000.
# инструменты — рядом со скриптом, данные — в TALYN_DATA (seg/sp_*, выгрузка out_sp/)
H=$(cd "$(dirname "$0")" && pwd)
T=${TALYN_DATA:?каталог данных Talyn}; cd "$T"
G=${GHIDRA:?путь к ghidra_12.1.3_PUBLIC с модулем ARCompact (SparRAW-tools/re/ghidra)}
mkdir -p out_sp
for n in "$@"; do for kind in fw uc; do
  [ $kind = fw ] && { f=8c0000; b=0x0; } || { f=920000; b=0x0; }
  echo "### $n $kind $(date +%T)"
  python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py $G --headless $T/proj ${n}_$kind -overwrite \
    -import seg/$n/$f.bin -loader BinaryLoader -loader-baseAddr $b -processor ARCompact:LE:32:default \
    -scriptPath $H/scripts -preScript addblocks.py seg/$n $kind -preScript sp_entry.py $b -postScript export.py out_sp/${n}_$kind \
    -analysisTimeoutPerFile 3600 < /dev/null > out_sp/${n}_$kind.log 2>&1
  grep -E "EXPORT DONE|ERROR" out_sp/${n}_$kind.log | head -3
  wc -l < out_sp/${n}_$kind/funcs.txt 2>/dev/null
done; done
echo SP_DONE
