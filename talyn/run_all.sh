#!/bin/bash
# инструменты — рядом со скриптом, данные — в TALYN_DATA (каталог talyn/ закрытого SparRAW-pro)
H=$(cd "$(dirname "$0")" && pwd)
T=${TALYN_DATA:?каталог данных Talyn}; cd "$T"
G=${GHIDRA:?путь к ghidra_12.1.3_PUBLIC с модулем ARCompact (SparRAW-tools/re/ghidra)}
while read n f; do for kind in fw uc; do
  base=$( [ $kind = fw ] && echo 900000 || echo a38000 )
  echo "### $n $kind $(date +%T)"
  python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py $G --headless $T/proj ${n}_$kind \
    -import seg/$n/$base.bin -loader BinaryLoader -loader-baseAddr 0x0 -processor ARCompact:LE:32:default \
    -scriptPath $H/scripts -preScript addblocks.py seg/$n $kind -postScript export.py out/${n}_$kind \
    -analysisTimeoutPerFile 3600 < /dev/null > out/${n}_$kind.log 2>&1
  grep -E "EXPORT DONE|ERROR" out/${n}_$kind.log | head -3
  wc -l out/${n}_$kind/funcs.txt 2>/dev/null
done; done < images.txt
echo ALL_DONE
