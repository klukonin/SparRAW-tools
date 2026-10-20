#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Восстановление MikroTik через RouterBOOT Etherboot (BOOTP + TFTP).
# Запускать от root:  sudo tools/netboot.sh <образ-initramfs-kernel.bin>
#
# Процедура на устройстве:
#   1) выдернуть питание;
#   2) зажать кнопку reset и НЕ отпуская подать питание;
#   3) держать, пока индикатор не начнёт мигать, дождаться, пока мигание
#      прекратится/сменится — только тогда отпустить: плата уходит в Etherboot
#      и начинает слать BOOTP-запросы;
#   4) в логе dnsmasq появится BOOTP(eno1) с MAC устройства, затем отдача файла.
# После загрузки устройство поднимется на 192.168.1.1 (initramfs, ssh без пароля).
# Дальше: scp -O sysupgrade-образ в /tmp и sysupgrade -n (initramfs во флеш не пишет).
#
# ВАЖНО: соседний живой узел не должен раздавать DHCP и занимать 192.168.1.1
#        (`/etc/init.d/dnsmasq stop` на нём, адрес увести в сторону).
set -e
IFACE=${IFACE:-eno1}
SRV=${SRV:-192.168.1.5}
RANGE_FROM=${RANGE_FROM:-192.168.1.100}
RANGE_TO=${RANGE_TO:-192.168.1.250}
ELF=${1:?укажи ELF-образ (…-initramfs-kernel.bin)}

[ -r "$ELF" ] || { echo "нет файла $ELF"; exit 1; }
file "$ELF" | grep -q ELF || { echo "$ELF не ELF — RouterBOOT его не загрузит"; exit 1; }

# server-ID в ответе = адрес интерфейса, с которого отвечает dnsmasq. Плата
# помнит, КТО выдал ей адрес в прошлый раз, и её DHCPREQUEST несёт тот самый
# server-ID; ответ с другого адреса она отвергает («wrong server-ID»).
# Поэтому на время восстановления забираем нужный адрес себе, а конкурирующие
# адреса той же /24 временно снимаем — иначе dnsmasq возьмёт чужой.
ADDED=""; REMOVED=""
NET=$(echo "$SRV" | cut -d. -f1-3)
# ПОРЯДОК ВАЖЕН: сначала снять чужие адреса этой /24, потом вешать свой.
# При promote_secondaries=0 удаление ОСНОВНОГО адреса подсети сносит и все
# вторичные в ней — то есть добавленный первым $SRV исчезнет вместе с ним.
for a in $(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | grep "^$NET\." | grep -vx "$SRV/24"); do
    echo "-- временно снимаю $a с $IFACE (иначе server-ID будет чужим)"
    ip addr del "$a" dev "$IFACE"
    REMOVED="$REMOVED $a"
done
if ! ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | grep -qx "$SRV/24"; then
    echo "-- временно вешаю $SRV/24 на $IFACE"
    ip addr add "$SRV/24" dev "$IFACE"
    ADDED="$SRV/24"
fi
ip -4 -o addr show dev "$IFACE" | awk '{print "   адреса " $2 ": " $4}' 

DIR=$(mktemp -d /tmp/netboot.XXXXXX)
cp "$ELF" "$DIR/rb.bin"
chmod 755 "$DIR"; chmod 644 "$DIR/rb.bin"
restore() {
    rm -rf "$DIR"
    for a in $REMOVED; do ip addr add "$a" dev "$IFACE" 2>/dev/null; done
    [ -n "$ADDED" ] && ip addr del "$ADDED" dev "$IFACE" 2>/dev/null
    echo "-- адреса $IFACE восстановлены"
}
trap restore EXIT

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
    echo "-- открываю ufw на $IFACE: 67/udp (BOOTP), 69/udp (TFTP)"
    ufw allow in on "$IFACE" to any port 67 proto udp >/dev/null
    ufw allow in on "$IFACE" to any port 69 proto udp >/dev/null
fi

echo "-- отдаю $(basename "$ELF") как rb.bin с $SRV ($IFACE), Ctrl-C для выхода"
# Диапазон намеренно широкий: плата помнит прежний адрес и шлёт DHCPREQUEST
# именно на него; если он вне диапазона, dnsmasq отвечает NAK и цикл не сходится.
# --dhcp-authoritative НЕ ставить: с ним чужой server-ID в REQUEST превращается
# в NAK, и плата зацикливается. Без него dnsmasq молчит, клиент по таймауту
# возвращается в DISCOVER и принимает наш OFFER.
# RouterBOOT в Etherboot не принимает ЮНИКАСТОВЫЙ ответ (адреса у него ещё нет)
# и хочет имя файла явно, опциями 66/67, а не только в поле file.
exec dnsmasq -d --port=0 \
    -i "$IFACE" --bind-interfaces \
    --dhcp-range="$RANGE_FROM,$RANGE_TO,255.255.255.0,5m" \
    --dhcp-broadcast --bootp-dynamic \
    --dhcp-boot=rb.bin,,"$SRV" \
    --dhcp-option=66,"$SRV" --dhcp-option=67,rb.bin \
    --enable-tftp --tftp-root="$DIR" --tftp-no-blocksize \
    --log-dhcp
