#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Снимок СТОКОВОГО состояния прошивки wil6210 на устройстве (OpenWrt/BusyBox).
# Запускать НА УСТРОЙСТВЕ и ДО любой подмены прошивки.
#
#   ./wil_stock_snapshot.sh            # снять снимок (не перезапишет уже снятый)
#   ./wil_stock_snapshot.sh --force    # пересоздать (ОПАСНО: затрёт эталон)
#
# Кладёт нетронутые копии в /root/wil-stock/ + MANIFEST с контрольными суммами
# и собирает /root/wil-stock.tar.gz — его нужно скопировать С УСТРОЙСТВА
# (scp root@<устройство>:/root/wil-stock.tar.gz recovery/).

FWDIR=${FWDIR:-/lib/firmware}
STOCK=${STOCK:-/root/wil-stock}
FILES="wil6210.fw wil6210.brd wil6210_sparrow_plus.fw wil6436.fw wil6436.brd"

sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else md5sum "$1"; fi; }

SDIR=$(dirname "$STOCK"); SBASE=$(basename "$STOCK")

if [ -d "$STOCK" ] && [ "$1" != "--force" ]; then
    echo "снимок уже существует: $STOCK"
    echo "это ЗАЩИТА: повторный запуск затёр бы эталон уже пропатченным файлом."
    echo "если точно нужно пересоздать — ./wil_stock_snapshot.sh --force"
    exit 1
fi

[ -d "$STOCK" ] && chmod -R u+w "$STOCK" 2>/dev/null
mkdir -p "$STOCK" || exit 1
M="$STOCK/MANIFEST"
: > "$M"
{
    echo "# снимок стоковой прошивки wil6210"
    echo "date:      $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "host:      $(cat /proc/sys/kernel/hostname 2>/dev/null)"
    echo "kernel:    $(uname -r)"
    [ -f /etc/openwrt_release ] && sed -n 's/^DISTRIB_DESCRIPTION=//p' /etc/openwrt_release | tr -d "'" | sed 's/^/openwrt:   /'
    echo "fw_dir:    $FWDIR"
} >> "$M"

echo "--- файлы ---" >> "$M"
n=0
for f in $FILES; do
    [ -f "$FWDIR/$f" ] || continue
    cp -p "$FWDIR/$f" "$STOCK/$f" || { echo "не удалось скопировать $f"; exit 1; }
    printf '%-28s %10d  %s\n' "$f" "$(wc -c < "$FWDIR/$f")" "$(sum "$FWDIR/$f" | cut -d' ' -f1)" >> "$M"
    n=$((n+1))
done
[ "$n" = 0 ] && { echo "ВНИМАНИЕ: в $FWDIR не найдено ни одного файла wil6210/wil6436"; }

echo "--- версия прошивки из журнала ядра ---" >> "$M"
dmesg 2>/dev/null | grep -i "wil6210" | grep -iE "fw version|firmware|board" | tail -10 >> "$M"

echo "--- параметры модуля ---" >> "$M"
if [ -d /sys/module/wil6210/parameters ]; then
    for p in /sys/module/wil6210/parameters/*; do
        printf '%-24s %s\n' "$(basename "$p")" "$(cat "$p" 2>/dev/null)" >> "$M"
    done
fi

chmod -R a-w "$STOCK" 2>/dev/null
tar czf "$SDIR/$SBASE.tar.gz" -C "$SDIR" "$SBASE" 2>/dev/null

echo "снимок готов: $STOCK  (файлов: $n)"
echo
cat "$M"
echo
echo "СКОПИРУЙ С УСТРОЙСТВА:  scp root@<устройство>:$SDIR/$SBASE.tar.gz recovery/"
echo "без этой копии откат возможен только с самого устройства."
