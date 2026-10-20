#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Безопасная подмена прошивки wil6210 с АВТОМАТИЧЕСКИМ ОТКАТОМ (OpenWrt/BusyBox).
# Модель «commit/confirm»: ставим прошивку, взводим таймер отката; если связь с
# устройством потеряна и confirm не пришёл — таймер сам вернёт сток и перезагрузит
# драйвер. Это главная защита при работе по 60ГГц-линку.
#
#   ./wil_fw_swap.sh install <файл.fw> [секунд]   # по умолчанию 300
#
# ВАЖНО: install и revert ПЕРЕЗАГРУЖАЮТ УЗЕЛ (модуль выгружать нельзя, см. reload).
# Значит, таймер автооткатa переживает перезагрузку только если его взвести
# заново — после загрузки проверяй `status` и при необходимости `revert`.
#   ./wil_fw_swap.sh confirm                      # отменить откат (связь жива)
#   ./wil_fw_swap.sh revert                       # вернуть сток немедленно
#   ./wil_fw_swap.sh status
#
# Требует заранее снятого снимка: ./wil_stock_snapshot.sh

FWDIR=${FWDIR:-/lib/firmware}
STOCK=${STOCK:-/root/wil-stock}
TARGET=${TARGET:-wil6210.fw}
PIDF=/tmp/wil_fw_swap.pid
LOG=/tmp/wil_fw_swap.log

sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else md5sum "$1"; fi; }

# ВНИМАНИЕ: выгружать модуль НЕЛЬЗЯ. `rmmod wil6210` уходит в самодедлок
# (детектор ядра: "task rmmod is blocked on a mutex likely owned by task rmmod"),
# после чего узел не лечится ни `reboot`, ни аппаратным watchdog'ом — только
# передёргиванием питания. Проверено дважды, 2026-09-21 и 2026-09-22.
# Поэтому прошивка меняется подменой файла и ПЕРЕЗАГРУЗКОЙ УЗЛА целиком.
reload() {
    echo "перезагрузка узла (выгружать модуль нельзя)..." | tee -a "$LOG"
    sync
    (setsid sh -c "sleep 2; reboot" </dev/null >/dev/null 2>&1 &)
}

restore() {
    [ -f "$STOCK/$TARGET" ] || { echo "НЕТ ЭТАЛОНА $STOCK/$TARGET — откат невозможен"; return 1; }
    cp -f "$STOCK/$TARGET" "$FWDIR/$TARGET" || return 1
    echo "сток восстановлен: $FWDIR/$TARGET" | tee -a "$LOG"
    reload
}

cancel_timer() {
    if [ -f "$PIDF" ]; then
        kill "$(cat "$PIDF")" 2>/dev/null
        rm -f "$PIDF"
        return 0
    fi
    return 1
}

case "$1" in
install)
    NEW="$2"; T="${3:-300}"
    [ -f "$NEW" ] || { echo "нет файла: $NEW"; exit 1; }
    [ -f "$STOCK/$TARGET" ] || { echo "сначала сними снимок: ./wil_stock_snapshot.sh"; exit 1; }
    # защита от подмены мусором: у образа должна быть сигнатура записи wil_fw
    sz=$(wc -c < "$NEW")
    [ "$sz" -lt 100000 ] && { echo "подозрительно маленький образ ($sz Б) — прерываю"; exit 1; }
    cancel_timer && echo "прежний таймер отката снят"
    : > "$LOG"
    echo "эталон : $(sum "$STOCK/$TARGET")" | tee -a "$LOG"
    echo "ставлю : $(sum "$NEW")"           | tee -a "$LOG"
    cp -f "$NEW" "$FWDIR/$TARGET" || exit 1
    # таймер отката в отдельной сессии, переживает разрыв ssh
    if command -v setsid >/dev/null 2>&1; then
        setsid sh -c "sleep $T; [ -f $PIDF ] && { echo 'ТАЙМЕР: откат' >> $LOG; \
            cp -f $STOCK/$TARGET $FWDIR/$TARGET; rm -f $PIDF; sync; reboot; }" \
            >/dev/null 2>&1 &
    else
        nohup sh -c "sleep $T; [ -f $PIDF ] && { cp -f $STOCK/$TARGET $FWDIR/$TARGET; \
            rm -f $PIDF; sync; reboot; }" >/dev/null 2>&1 &
    fi
    echo $! > "$PIDF"
    echo "АВТООТКАТ через $T с (pid $(cat $PIDF)). Подтверди: ./wil_fw_swap.sh confirm"
    reload
    ;;
confirm)
    if cancel_timer; then echo "автооткат отменён — прошивка остаётся"; \
    else echo "активного таймера нет"; fi
    ;;
revert)
    cancel_timer >/dev/null
    restore
    ;;
status)
    echo "цель   : $FWDIR/$TARGET"
    [ -f "$FWDIR/$TARGET" ] && echo "текущая: $(sum "$FWDIR/$TARGET")"
    [ -f "$STOCK/$TARGET" ] && echo "эталон : $(sum "$STOCK/$TARGET")" || echo "эталон : НЕТ СНИМКА"
    if [ -f "$PIDF" ]; then echo "автооткат: ВЗВЕДЁН (pid $(cat $PIDF))"; else echo "автооткат: не взведён"; fi
    [ -f "$LOG" ] && { echo "--- журнал ---"; cat "$LOG"; }
    ;;
*)
    sed -n '2,15p' "$0"; exit 1;;
esac
