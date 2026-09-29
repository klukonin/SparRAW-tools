#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Управление розетками TP-Link Tapo (протокол KLAP) по локальному API.

Нужен включённый в приложении Tapo раздел «Tapo Lab» -> «Third-Party
Compatibility», иначе /app/handshake1 отвечает 403.

Учётные данные: ~/.tapo_creds (две строки - почта и пароль) либо переменные
TAPO_USER / TAPO_PASS. Протокол позволяет проверить их локально: устройство
присылает хэш, который должен совпасть с посчитанным у нас.

Использование:
    tapo_plug.py <ip> state|on|off|cycle [пауза_сек]|power
    tapo_plug.py <ip> probe            - перебрать варианты учётных данных
"""
import sys, os, json, base64, hashlib, time, struct
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def sha256(b):
    return hashlib.sha256(b).digest()


def sha1(b):
    return hashlib.sha1(b).digest()


def auth_hash_v2(user, pw):
    return sha256(sha1(user.encode()) + sha1(pw.encode()))


def auth_hash_v1(user, pw):
    return hashlib.md5(hashlib.md5(user.encode()).digest()
                       + hashlib.md5(pw.encode()).digest()).digest()


class Klap:
    def __init__(self, ip):
        self.ip = ip
        self.s = requests.Session()
        self.key = self.iv = self.sig = None
        self.seq = 0

    def handshake1(self, local_seed):
        r = self.s.post("http://%s/app/handshake1" % self.ip,
                        data=local_seed, timeout=10)
        r.raise_for_status()
        if len(r.content) != 48:
            sys.exit("handshake1: неожиданный ответ %d байт" % len(r.content))
        return r.content[:16], r.content[16:]

    def try_auth(self, local_seed, remote_seed, server_hash, ah):
        return sha256(local_seed + remote_seed + ah) == server_hash

    def handshake(self, ah):
        local_seed = os.urandom(16)
        remote_seed, server_hash = self.handshake1(local_seed)
        if not self.try_auth(local_seed, remote_seed, server_hash, ah):
            return False
        r = self.s.post("http://%s/app/handshake2" % self.ip,
                        data=sha256(remote_seed + local_seed + ah), timeout=10)
        if r.status_code != 200:
            sys.exit("handshake2: HTTP %d" % r.status_code)
        base = local_seed + remote_seed + ah
        self.key = sha256(b"lsk" + base)[:16]
        ivs = sha256(b"iv" + base)
        self.iv12, self.seq = ivs[:12], struct.unpack(">i", ivs[-4:])[0]
        self.sig = sha256(b"ldk" + base)[:28]
        return True

    def _iv(self):
        return self.iv12 + struct.pack(">i", self.seq)

    def request(self, payload):
        self.seq += 1
        data = json.dumps(payload).encode()
        pad = 16 - len(data) % 16
        data += bytes([pad]) * pad
        c = Cipher(algorithms.AES(self.key), modes.CBC(self._iv())).encryptor()
        ct = c.update(data) + c.finalize()
        body = sha256(self.sig + struct.pack(">i", self.seq) + ct) + ct
        r = self.s.post("http://%s/app/request" % self.ip, data=body,
                        params={"seq": self.seq}, timeout=10)
        r.raise_for_status()
        d = Cipher(algorithms.AES(self.key), modes.CBC(self._iv())).decryptor()
        raw = d.update(r.content[32:]) + d.finalize()
        return json.loads(raw[:-raw[-1]])


def candidates():
    """Варианты учётных данных: из файла/окружения и известные пустые."""
    out = []
    u, p = os.environ.get('TAPO_USER'), os.environ.get('TAPO_PASS')
    if u and p:
        out.append((u, p, "из окружения"))
    path = os.path.expanduser('~/.tapo_creds')
    if os.path.exists(path):
        lines = [l.strip() for l in open(path) if l.strip()]
        if len(lines) >= 2:
            out.append((lines[0], lines[1], "из ~/.tapo_creds"))
    out += [("", "", "пустые"),
            ("kasa@tp-link.net", "kasaSetup", "заводские kasa")]
    return out


def connect(ip, verbose=False):
    for user, pw, label in candidates():
        for fn, ver in ((auth_hash_v2, "v2"), (auth_hash_v1, "v1")):
            k = Klap(ip)
            try:
                if k.handshake(fn(user, pw)):
                    if verbose:
                        print("  подошли: %s (KLAP %s)" % (label, ver))
                    return k
            except Exception:
                pass
    return None


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    ip, cmd = sys.argv[1], sys.argv[2]
    if cmd == 'probe':
        print("перебираю варианты для %s:" % ip)
        k = connect(ip, verbose=True)
        if not k:
            print("  ни один не подошёл — нужны почта и пароль аккаунта TP-Link")
        return
    k = connect(ip)
    if not k:
        sys.exit("не удалось войти: положи почту и пароль от аккаунта TP-Link "
                 "в ~/.tapo_creds (две строки)")
    if cmd == 'state':
        r = k.request({"method": "get_device_info"})
        print("включена" if r["result"]["device_on"] else "выключена")
    elif cmd in ('on', 'off'):
        k.request({"method": "set_device_info",
                   "params": {"device_on": cmd == 'on'}})
        print("включена" if cmd == 'on' else "выключена")
    elif cmd == 'power':
        # P110 отдаёт current_power В ВАТТАХ (проверено: работающий wAP 60G
        # даёт 3 Вт, недогруженный — 2 Вт). Ноль = узел не питается.
        r = k.request({"method": "get_current_power"})
        w = r.get("result", {}).get("current_power")
        if w is None:
            print("розетка не отдаёт мощность:", r)
        else:
            print("%d Вт" % w)
        r2 = k.request({"method": "get_energy_usage"})
        d = r2.get("result", {})
        if 'today_runtime' in d:
            print("работает сегодня: %d мин, за месяц: %d мин"
                  % (d.get('today_runtime', 0), d.get('month_runtime', 0)))
    elif cmd == 'cycle':
        pause = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0
        k.request({"method": "set_device_info", "params": {"device_on": False}})
        print("выключена, пауза %.0f с" % pause)
        time.sleep(pause)
        k.request({"method": "set_device_info", "params": {"device_on": True}})
        print("включена")
    else:
        sys.exit("неизвестная команда: %s" % cmd)


if __name__ == '__main__':
    main()
