# SparRAW-tools

Инструменты проекта SparRAW (wil6210 / Sparrow, 60 ГГц 802.11ad): работа
с образами и board-файлами, чтение лога прошивки и трассы ucode со стенда,
управление стендом, скрипты опытов.

Репозитории SparRAW рассчитаны на соседнюю раскладку:

```
SparRAW/
  SparRAW-firmware/   SparRAW-driver/   SparRAW-tools/   SparRAW-docs/
```

Скрипты стенда находят корень сами (`$SPARRAW`, по умолчанию — на два
уровня выше `bench/NN`).

## host/ — хост и стенд

| скрипт | что |
|---|---|
| `wil_fw_log.py` | чтение и декодирование кольца лога прошивки (строки из `fwlog-strings`) |
| `wil_ucode_log.py`, `wil_uc_collect.py`, `wil_uc_stream.py` | лог и трасса ucode (debugfs `uc_trace`, патч драйвера 910) |
| `wil_mac_ring.py` | снятие кольца команд MAC по `blob_uc_data` |
| `wil_memscan.py` | серия дампов памяти + фильтры (метод «ArtMoney») |
| `wil_tsf_probe.py`, `wil_beacon_stats.sh` | TSF и статистика маяков |
| `wil_direct_link.sh` | безролевой линк PBSS записями с хоста (4.1) |
| `wil_fw_swap.sh`, `wil_stock_snapshot.sh` | замена образа на узле, снимок стока для отката |
| `netboot.sh` | восстановление узла через Etherboot RouterBOOT |
| `tapo_plug.py` | питание узлов через розетки Tapo (`TAPO_USER`/`TAPO_PASS` из окружения, адрес — аргументом) |
| `mac_cmd_fieldlink.py` | поиск связей между полями разных команд MAC в трассе |

## re/ — образы и board-файлы

| скрипт | что |
|---|---|
| `wil_brd.py` | разбор/сборка/починка `.brd` и `.fw` (контейнер записей драйвера) — см. `re/README.md` |
| `wil_brd_regs.py` | board-файл как набор записей регистров |
| `fw_strip_for_openwrt.py` | удаление вендорских записей 100/101/102 — образ для драйвера OpenWrt |
| `npk_unpack.py`, `npk_decrypt.py` | распаковка и расшифровка npk (XOR-ключевой поток) |
| `wil_syms.py`, `gen_symbols_ld.py`, `asm_gate.py` | символы и гейт ассемблера |
| `wmi.py`, `wiburn.py`, `sm_name_resolver.py` | WMI, ini-файлы wiburn, имена автоматов |
| `ghidra/` | скрипты Ghidra ранней фазы разбора и их выходные таблицы; `ARC-module/` — процессорный модуль ARCompact (Ledger Donjon, SSTIC 2021), `install_arc.sh` ставит его в Ghidra 12.x |

## bench/ — опыты на стенде

`bench/41/` — ночные серии 4.1 (2026-09-27), `bench/62/` — серии 6.2
(регистры, NAV, BF, флапы; 2026-09-28/29). Журналы пишутся в
`SparRAW-firmware/6.2/build/bench-62-mix/` (создать перед запуском), итоги —
в `SparRAW-firmware/6.2/ref/BENCH-62.md`. Перед каждым опытом оба узла
перезапускаются питанием.

## Окружение стенда

Учётные данные и адреса в скрипты не зашиты — только переменные окружения:

| переменная | что |
|---|---|
| `TAPO_USER`, `TAPO_PASS` | учётная запись Tapo для `tapo_plug.py` |
| `TAPO_AP`, `TAPO_STA` | адреса розеток узлов AP и STA (обязательны для `bench/`; `ab_test.sh`/`boot_series.sh` в SparRAW-firmware берут `PLUG`, по умолчанию `TAPO_AP`) |
| `NODE_AP`, `NODE_STA` | адреса узлов AP и STA (в скриптах узлы по-прежнему помечены как 11 и 12, `node 11` → `$NODE_AP`); обязательны для `bench/`, `host/wil_direct_link.sh` и стендовых скриптов SparRAW-firmware |
| `SPARRAW` | корень с соседними репозиториями (по умолчанию вычисляется) |

## Лицензия

Инструменты — GNU AGPL v3 или новее ([LICENSE](LICENSE)); документация —
CC BY 4.0. `re/ghidra/ARC-module` — под Apache 2.0; данные, извлечённые из
вендорских прошивок и пакетов, лицензией проекта не покрываются. Подробно —
[COPYING.md](COPYING.md).
