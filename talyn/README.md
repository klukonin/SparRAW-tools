# talyn — разбор прошивки Talyn (QCA6436, 802.11ay)

Talyn по начинке почти Sparrow: fw и uc на том же ARC600, общий драйвер wil6210. Его поддержка ведётся
в рамках SparRAW; здесь — инструменты разбора. Данные (образы, сегменты, выгрузки, карты) в репозиторий не входят:
скрипты работают с каталогом, который задаёт `TALYN_DATA` (`plain/`, `seg/`, `out*/`, `names/`, `seed/`,
`regmap/*.tsv`, `sparrow_rgf/`, `images.txt` — список «имя образ»).

| файл | что |
|---|---|
| `run_all.sh` | Ghidra headless (ARCompact:LE:32): проекты `proj/<образ>_{fw,uc}`, выгрузка `out/` |
| `run_pass2.sh` | дозапуск дизассемблера от ссылок на строки журнала (`seed/`), имена по строкам журнала, выгрузка `out3/` |
| `scripts/` | скрипты Ghidra: сегменты (`addblocks.py`), затравки, имена, экспорт funcs/listing/decomp |
| `names/fwlog_names.py`, `names/seedfilter.py` | имена функций по записям журнала fw/uc (limm 0x01000000\|смещение) |
| `regmap/regmap.py` | карта обращений к регистрам (база mov/add + смещение ld/st) |
| `regmap/wilseg.py` | разбор образа wil6210 на сегменты по AHB-адресу |
| `regmap/union.py` | сводная карта периферии 0x880000…0x8bffff по всем образам, нашей fw и драйверу |
| `regmap/sparrow_applic.py` | какие регистры Talyn 7.5 есть в железе Sparrow (по снимкам RGF) |
| `regmap/tdm/tdm_regs.py` | регистры TDMA Terragraph и их наличие у Sparrow |
| `wmi/wmi_switch.py` | восстановление диспетчера команд WMI (switch по id, таблицы переходов) |

Переменные: `TALYN_DATA` — данные; `GHIDRA` — ghidra_12.1.3_PUBLIC с модулем ARCompact (`re/ghidra`, install_arc.sh);
`SPARRAW` — каталог с SparRAW-firmware и SparRAW-driver (для `union.py`); `REGAUDIT` — каталог со списком
регистров нашей прошивки (`inventory2.tsv`, `talyn-regs.tsv`).

Пример: `GHIDRA=… TALYN_DATA=… ./run_all.sh && GHIDRA=… TALYN_DATA=… ./run_pass2.sh` (около 30 мин на все образы).
Описание результатов — SparRAW-docs `talyn/`.
