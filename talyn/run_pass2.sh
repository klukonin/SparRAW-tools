#!/bin/bash
G=${GHIDRA:?путь к ghidra_12.1.3_PUBLIC с модулем ARCompact (SparRAW-tools/re/ghidra)}
# инструменты — рядом со скриптом, данные — в TALYN_DATA (каталог talyn/ закрытого SparRAW-pro)
H=$(cd "$(dirname "$0")" && pwd)
T=${TALYN_DATA:?каталог данных Talyn}; cd "$T"
L="python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py $G --headless $T/proj"
while read n f; do for k in fw uc; do
  echo "### $n $k $(date +%T)"
  if [ -s seed/${n}_$k.txt ]; then
    $L ${n}_$k -process -noanalysis -scriptPath $H/scripts -postScript seed.py seed/${n}_$k.txt -postScript export.py out2/${n}_$k < /dev/null > out2_${n}_$k.seed.log 2>&1
  else mkdir -p out2/${n}_$k; cp out/${n}_$k/* out2/${n}_$k/; fi
  grep -hE "SEED|EXPORT DONE" out2_${n}_$k.seed.log 2>/dev/null
  python3 -I $H/names/fwlog_names.py plain/$f.fw out2/${n}_$k/listing.dis $k names/${n}_$k.txt 2>&1 | tr '\n' ' '; echo
  if grep -q . names/${n}_$k.txt 2>/dev/null && [ $(wc -l < names/${n}_$k.txt) -gt 1 ]; then
    $L ${n}_$k -process -noanalysis -scriptPath $H/scripts -postScript applynames.py names/${n}_$k.txt -postScript export.py out3/${n}_$k < /dev/null > out3_${n}_$k.log 2>&1
    grep -hE "NAMES APPLIED|EXPORT DONE" out3_${n}_$k.log
  fi
done; done < images.txt
echo PASS2_DONE
