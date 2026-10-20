# wil_brd.py — разбор, сборка и починка wil6210 .brd/.fw

Python 3, без зависимостей. Формат взят из драйвера (`fw.h`, `fw_inc.c`):
общий контейнер записей для board-файлов и прошивок.

```
struct wil_fw_record_head { __le16 type; __le16 flags; __le32 size; }
```

Первая запись — всегда `file_header` (type 6) с сигнатурой `'0126'`
(0x36323130), crc32 по всему образу и полем `data_len`.
CRC считается как `zlib.crc32(image[:data_len])` с обнулённым полем crc.

## Команды

```
wil_brd.py info FILE [--fw FW.fw]         разобрать и показать записи
wil_brd.py unpack FILE -o DIR [--fw ...]  разложить записи по файлам + manifest.json
wil_brd.py pack DIR -o FILE               собрать обратно (crc и data_len пересчитываются)
wil_brd.py brdinfo FW.fw                  таблица brd_info из прошивки
wil_brd.py fixcrc FILE... [-i|-o OUT]     пересчитать crc
```

## Про адреса в .brd

Драйвер **игнорирует** поле `addr` внутри data-записей board-файла: реальные
адреса назначения берутся из таблицы `brd_info`, лежащей в comment-записи
соответствующей прошивки (magic `0xabcddcbb`). Поэтому `--fw` у `info`/`unpack`
подставляет настоящие адреса и максимальные размеры:

```
$ wil_brd.py brdinfo wil6436.fw
[0] base_addr=0x0006bdd4 max_size_bytes=20480
[1] base_addr=0x00070dd4 max_size_bytes=12288
```

## fixcrc

По умолчанию чинится **только crc**, и только у структурно целых файлов:
записи должны укладываться ровно в `data_len`. Если структура сломана
(обрезанный файл, мусор в хвосте, битый `data_len`) — команда отказывается
работать с кодом возврата 2 и говорит, что именно не так.

```
$ wil_brd.py fixcrc -i *.brd
data_len : 3588 (unchanged)
crc      : 0xd414aa93 -> 0xeb5c4046
backup   : ./wil6210-wap60g-60deg.brd.bak
```

- `-i/--in-place` — править на месте, рядом кладётся `.bak` (`--no-backup` отключает)
- `-o OUT` — записать в другой файл (только для одного входного)
- `-n/--dry-run` — только показать, что изменится
- `--fix-data-len` — **отдельно** разрешить пересчёт `data_len` по фактической
  раскладке записей; нужно для спасения файлов после неудачной расшифровки,
  хвост за пределами `data_len` при этом сохраняется как есть

---

# wmi.py — кодек WMI

Собирает и разбирает команды и события wil6210/Talyn по `wmi.xml` из релиза
WIGIG.TLN. Ничего не переписано руками: 174 команды, 152 события, 276 структур,
1165 полей, 97 enum'ов читаются прямо из вендорского файла, поэтому раскладка
следует за прошивкой, а не за заголовком драйвера, который может отставать.

## Команды

```
wmi.py list [ШАБЛОН]              структуры, их вид, id и размер
wmi.py show ИМЯ [--kind cmd]      раскладка полей со смещениями
wmi.py build ИМЯ поле=знач -o f   готовый блоб для wmi_send
wmi.py decode файл [--name ИМЯ]   разбор блоба; без --name читает wmi-заголовок
wmi.py enum [ШАБЛОН]              значения enum'ов
```

```
$ wmi.py build SET_RF_SECTOR_ON sector_idx=12 sector_type=1 rf_modules_vec=0x0f -o s.bin
SET_RF_SECTOR_ON -> s.bin (12 bytes: 8 header + 4 payload)
send with:  cat s.bin > $(find /sys/kernel/debug/ieee80211 -name wil6210)/wmi_send
```

Блоб это `struct wmi_cmd_hdr {u8 mid; u8 reserved; __le16 command_id; __le32 ts}`
плюс payload — ровно то, что ждёт `debugfs/wmi_send`.

## Описания и расшифровка значений

Всё, что вендор написал в `wmi.xml`, вытаскивается наружу: 249 структур из 276
имеют описание, 517 полей из 1132 — свой комментарий, а у 132 полей комментарий
называет конкретный enum, и тогда число превращается в имя константы.

```
$ wmi.py show SET_SELECTED_RF_SECTOR_INDEX
purpose   : Force RF sector index for communication with specified CID.
            Assumes that TXSS/BRP is disabled by other command

  off   size  field                        type                 count
  0     1     cid                          U08                  1
        Connection/Station ID in [0:7] range
  1     1     sector_type                  U08                  1
        enum wmi_rf_sector_type: WMI_RF_SECTOR_TYPE_RX=0, WMI_RF_SECTOR_TYPE_TX=1
        type of requested RF sector (enum wmi_rf_sector_type)
```

При разборе возвращается не только число, но и что оно значит:

```
$ wmi.py decode event.bin
event     : WMI_SET_RF_SECTOR_ON_DONE_EVENTID (0x19a4)
purpose   : Success/Fail status for WMI_SET_RF_SECTOR_ON_CMD

  status                     1  = WMI_RF_SECTOR_STATUS_BAD_PARAMETERS_ERROR
                             result status of WMI_SET_RF_SECTOR_ON_CMD
```

В обратную сторону это тоже работает — константу можно писать именем:

```
wmi.py build SET_SELECTED_RF_SECTOR_INDEX cid=3 sector_type=WMI_RF_SECTOR_TYPE_TX sector_idx=42
```

Программно: `doc(name)` — описание структуры, `layout(name)` — поля со
смещениями, комментариями и привязкой к enum, `describe(name, data)` — разбор,
где каждое поле это `{'value', 'symbol', 'enum', 'doc'}`. `decode()` остался
«сырым» и возвращает голые числа.

## Два нюанса, без которых кодек врёт

**Представления.** У каждого поля в `wmi.xml` есть флаги `publishFW`,
`publishLinux`, `publishWin`, и одна и та же структура выглядит по-разному для
прошивки и для хоста. У `PMC`, например, для FW это `mem_base_l` + `mem_base_h`,
а для Linux — один 64-битный `mem_base`. По умолчанию берётся вид **fw** —
именно его ждёт устройство; `--view linux` нужен для сверки с заголовком.

**Совпадающие имена.** 49 имён существуют и как `cmd`, и как `event`
(`CONNECT`, `RADAR_GENERAL_CONFIG`, …), причём размеры разные: у
`RADAR_GENERAL_CONFIG` команда 28 байт, событие 4. Структуры ключуются парой
(вид, имя); при неоднозначности берётся `cmd`, выбрать явно — `--kind`.

## Проверено

Сверка **всех 266** структур с `wmi.h` драйвера (linux-4.4, вид `--view linux`):
размеры совпали у 266, расхождений 0. Круговое преобразование
encode → decode возвращает исходные значения. Из 115 командных структур 112
собираются в блоб автоматически; у `PROBED_SSID`, `RCP_ADDBA_REQ` и анонимного
`START_SCAN::$_9` id не выводится из имени — раскладка работает, номер команды
задаётся ключом `--id`. Событий с распознанной структурой 126 из 152;
у остальных в XML просто нет отдельной структуры.

---

# wiburn.py — формат ini и board-образы

Питоновское покрытие offline-части C++ `wiburn`.

## Что внутри board-файла

Payload data-записи `.brd` — это **плоская последовательность пар dword
(address, value)** в little-endian, ровно в порядке строк секции
`[PRODUCTION]` из ini. Первая пара — `0xBDF0BDF0 = 0x50000000`
(«Talyn multi-array format»), дальше указательная таблица (47 пар = 376 байт),
дальше секции данных.

Псевдоадрес `0xFEDCBA98` — не адрес, а метка версии FW
(`FW_VERSION_LABEL_ADDR` в `gen_ini_output.py`): значение равно версии,
записанной подряд цифрами, например 7.5.0.77 → `75077` → `0x00012545`.
Подставляется ключом `-v version.h` с токенами `MAJOR/MINOR/SUB_MINOR/FW_REV_BUILD`.

В конце образа бывает пара-терминатор `0xffffffff / 0xffffffff` и ещё один
dword. Его происхождение установить не удалось: это **не** CRC payload'а
(перебраны crc32/crc32c/crc32k/crc32q во всех сочетаниях init/xorout/reflect
по трём диапазонам), а в части файлов там просто нули. Драйвер его не
проверяет — `wil_brd_process` копирует payload как есть. Поэтому он
сохраняется verbatim: `brd2ini` выносит его строкой `;;trailer=0x...`,
`ini2brd`/`ini2bin` умеют вернуть через `--trailer`, а пару-терминатор
добавляет `--terminator`.

## Команды

```
wiburn.py iniinfo FILE.ini                 разбор ini: секции, размер образа
wiburn.py ini2bin FILE.ini -o OUT.bin      ini -> сырой образ
wiburn.py bin2ini OUT.bin -o FILE.ini      сырой образ -> ini
wiburn.py ini2brd FILE.ini... -o OUT.brd   ini -> контейнер .brd
wiburn.py brd2ini FILE.brd [-o BASE]       .brd -> ini (по одному на data-запись)

wiburn.py imageinfo IMG.bin                разбор flash-образа: указатели, секции, CRC
wiburn.py imagefixcrc IMG.bin [-o|-n]      пересчёт CRC32 всех секций образа
wiburn.py imageextract IMG.bin -o DIR      выгрузка секций образа по файлам
```

## Flash-образ

Раскладка по `flash_sections.h` / `flash_image.cpp`: в начале образа таблица
указателей `pointers_t` (26 dword, `signature = 0x40`), каждый указатель ведёт
**на данные секции**, то есть на `ptr - sizeof(section_header_t)` лежит заголовок
`{BYTE reserved; BYTE section_id; u_int16_t section_size}`. В конце секции —
её CRC32: `CCRC32::CalcCRC` по `section_size - 4` байтам от начала секции.
`CCRC32` строит отражённую таблицу с `CRC_MASK` на входе и выходе, то есть
совпадает с `zlib.crc32`.

`imageinfo` дополнительно разбирает секцию `ids` (`ids_section`: mac, ssid,
ppm, board_type, bl_ver и 16 production-полей). Коды возврата: 0 — все CRC
сошлись, 1 — есть расхождения.

**Оговорка:** реального дампа flash wigig на дисках нет, поэтому эта часть
проверена на синтетическом образе, собранном по той же раскладке (4 секции,
включая `ids`), — чтение, обнаружение битых CRC и починка возвращают образ
байт-в-байт к исходному. На настоящем дампе стоит перепроверить.

`brd2ini` печатает готовую команду для обратной сборки с нужными
`--addr`/`--flags`. Лексер ini повторяет `ini_parser.cpp::get_clean_line`:
нижний регистр, `[`/`]` и `=` → пробел, `;` и `#` — комментарий до конца
строки; правила на 1/2/3/4 токена — как в `ini_parser.cpp::init`.

## Метаданные образа: теги

Секции `image_info` и `usb_info` — это TLV-список: после заголовка секции идут
пары `{tag_header_t (reserved, tag_id, tag_size), тело}`, завершает список тег
`0xff`, за ним CRC32. `imageinfo` разбирает все семь известных тегов:

```
  @0x001000 image_info  id=10  size=84  crc=0x2997187e OK
        tag format_version  (0x01) format_version=1
        tag version         (0x02) major=7, minor=5, build=77, text=7.5.0.77
        tag timestamp       (0x03) text=2026-09-18 14:30:15
        tag configuration_id(0x04) ascii=TALYN-LAB-01
        tag device_id       (0x05) device_id=0x1234, revision_id=2
        tag hw_id           (0x06) digital_soc_id=3, board_id=7, antenna_id=4,
                                   rf_id=1, serial_id=4242
```

`version` — упакованное битовое поле `minor:8 major:8 build:13 sub_minor:3`,
`timestamp` хранит минуты/часы/секунды/месяц/день/год отдельными байтами.

## Секция ids: чтение, запись, точечная правка

```
wiburn.py ids2ini IMG.bin [-o ids.ini]        выгрузить в [IDS] ini
wiburn.py ini2ids IMG.bin ids.ini [-o OUT]    записать ini обратно
wiburn.py setid IMG.bin --name ssid --value talyn-node-7
```

Ключи ini те же, что у оригинала: `version, mac_address, ssid, local, ppm,
board, lo_power_xif_gc, lo_power_stg2_bias, vga_bias, vga_stg1_fine_bias,
ats_ver, mlt_ver, bl_ver, lo_power_gc_ctrl, production1…16`. Ловушка вендора:
в ini поле называется `board`, а в структуре — `board_type`.

`setid` меняет одно поле и пересчитывает CRC секции: правка ssid и board_type
затронула 17 байт образа, остальное не тронуто.

## Сборка образа

```
wiburn.py imagebuild ids=ids.bin image_info=info.bin production=prod.bin \
          -o img.bin [--size 0x40000] [--reduced]
```

Раскладка повторяет `flash_image.cpp`: каждая секция выравнивается вверх до
границы под-сектора **4 КБ** (`SUB_SECTOR`, `NEXT_PTR`), а секция `ids` кладётся
по фиксированному адресу **44 КБ** — или **4 КБ** с ключом `--reduced`.
Заголовки секций, таблица указателей и CRC проставляются автоматически.

## Символы: reg_tree, fw_symbols, ucode_symbols

```
wiburn.py symbols ФАЙЛ.ini [ШАБЛОН]
```

Секции таблиц трансляции содержат по четыре токена в строке — имя, адрес,
начальный и конечный бит:

```
[fw_symbols] 3 entries
  fw.rf.rx_gain      0x00880100 [15:8] 8 bits
  fw.rf.tx_gain      0x00880100  [7:0] 8 bits
```

Программно: `load_translation_maps(path)` даёт `{карта: {имя: (адрес, start,
end)}}`, а `apply_bits(word, value, start, end)` укладывает значение в нужные
биты, не трогая остальные — два символа по одному адресу складываются в одно
слово.

## Чего нет

Работы с железом: `-burn`, `-read`, `-erase`, `-query` через PCI/USB —
для этого нужен `libwigig_pciaccess` и само устройство. И применения
таблиц трансляции символов `[reg_tree]`, `[fw_symbols]`, `[ucode_symbols]`
из ini: такие секции парсятся и сохраняются, но имена в адреса не
разрешаются. (Большие карты символов прошивки и микрокода — это другое, ими
занимается `wil_syms.py` ниже.)

## Проверено

- round-trip `unpack` → `pack` байт-в-байт на 21 файле Talyn (`WIGIG_TLN_7.5_full`)
  и на 314 файлах из остального корпуса;
- crc сходится на эталонных файлах (`Mainline/wil6210.fw` 5.2.0.18,
  UBNT 6.2.0.225, `Mainline/wil6210.brd`);
- зашифрованные микротиковские brd/fw отвергаются на проверке сигнатуры;
- `brd2ini` → `ini2brd` байт-в-байт на 19 board-файлах Talyn;
- `fixcrc` починил 14 реальных `.fw` с битой CRC (микротиковские и расшифрованные),
  после чего все 14 проходят проверку;
- `imagefixcrc` на синтетическом образе с двумя испорченными секциями
  восстановил его побайтово (`cmp` с оригиналом — 0 различий);
- сквозная цепочка воспроизводит штатный файл Qualcomm **побайтово**:

```
python2 board_file_gen.py -s input/FreeSpace_TalynA2_SingleRF_Single_chain_sectors.xml \
                          -c input/classification.xml -v version.h -o out.ini
python3 wiburn.py ini2brd out.ini -o gen.brd --addr 0x00a2f800 --flags 0x0900 \
                          --terminator --trailer 0xCD35E1BD
cmp gen.brd FreeSpace_TalynA2_SingleRF_Single_chain_sectors.brd   # совпадает
```

---

# wil_syms.py — карты символов FW и ucode

Рядом с образами в релизе WIGIG.TLN лежат две карты символов:

```
globals/TALYN_M_B0/fw_image_globals.xml      455 глобалов, 42432 узла
globals/TALYN_M_B0/ucode_image_globals.xml   481 глобал,  34376 узлов
```

Это полная раскладка памяти прошивки: имя, адрес, битовый диапазон и
вложенность — структуры, объединения, массивы, битовые поля и enum'ы.
`wil_syms.py` читает их, разрешает имена в адреса, вытаскивает значения из
образа и выгружает всё это в Ghidra.

## Команды

```
wil_syms.py info                        счётчики и регионы, где живут глобалы
wil_syms.py regions                     таблица трансляции линкер <-> AHB
wil_syms.py list [ШАБЛОН] [--all]       список символов
wil_syms.py show ИМЯ [--values ОБРАЗ]   раскладка одного символа, можно со значениями
wil_syms.py resolve ПУТЬ...             адрес, биты, маска, готовая команда peek
wil_syms.py at АДРЕС [--bit N]          что лежит по адресу
wil_syms.py read ОБРАЗ ПУТЬ...          значения по именам
wil_syms.py dump ОБРАЗ [ШАБЛОН]         значения всех глобалов
wil_syms.py poke ОБРАЗ ИМЯ=ЗНАЧ -o OUT  правка образа по имени, crc пересчитывается
wil_syms.py segments ОБРАЗ              загружаемые записи с адресами и смещениями
wil_syms.py patch ОБРАЗ --addr A --bytes HEX -o OUT   правка байтами по адресу (для кода)
wil_syms.py ghidra -o КАТАЛОГ           выгрузка символов, раскладки и карты памяти
```

Ключ `--image ucode` переключает на карту микрокода, `--dir` — на другой
каталог с XML (по умолчанию берётся `WIGIG_TLN_7.5_11ad_pack/globals/TALYN_M_B0`).

### Чип: Talyn и Sparrow

`--chip` выбирает карту памяти: **`talyn-mb`** (по умолчанию, это `TALYN_M_B0`),
`talyn` (старая узкая таблица) и **`sparrow`** — предшественник Talyn (wil6210
FW 6.x, напр. UBNT airFiber на Sparrow+). Карта Sparrow взята из драйвера
(`sparrow_fw_mapping`, `wmi.c`) и сверена с реальными сегментами: fw_code
@0x8c0000, fw_data @0x900000, uc_code @0x920000, uc_data @0x940000.

Символьных карт (globals XML) для Sparrow нет — поэтому команды по именам
(`show`/`resolve`/`read`/`dump`/`ghidra`) на нём недоступны, а **структурные
работают полностью**: `segments`, `patch` (правка кода/данных с crc),
`project` (грузит весь образ в Ghidra и дизассемблирует ARC — на
`wil6210_sparrow_plus.fw` 6.2.0.225 выходит ~2950 функций). `wil_brd.py` и
board-файлы (`wiburn.py`) на Sparrow работали и раньше — формат контейнера
общий.

```
python3 wil_syms.py --chip sparrow segments wil6210_sparrow_plus.fw
python3 wil_syms.py --chip sparrow project  wil6210_sparrow_plus.fw -o kit
python3 wil_syms.py --chip sparrow patch    wil6210_sparrow_plus.fw --addr 0x8c0100 --bytes e078 -o out.fw
```

## Что в узле

```
<node address="0xa202c4" name="error_level_enable" type="field" start="0" end="0"/>
```

`start`/`end` — биты, считанные **от собственного адреса узла**, младший
первым; узел занимает `[address*8 + start .. address*8 + end]`. `field` —
битовое поле, `table` — всё остальное. Две формы имени особые: `<7>` — это
элемент массива 7, а `<286331153>HW_BOOT_DONE` — константа enum со значением
286331153 (у таких узлов `end = -1`, то есть нулевая ширина).

Вендор заводит по три-четыре уровня-обёртки на каждый тип
(`log_api_log_table_header_s` → `..._le` → поля). Обёртка, которая
единственная у родителя и повторяет его адрес и биты, в путях пропускается,
поэтому путь читается так, как написан в прошивке:

```
$ wil_syms.py resolve g_log_table_header.module_level_enable[3].error_level_enable
symbol    : g_log_table_header.module_level_enable[3].u_module_level_enable.error_level_enable
AHB       : 0xa202c7   linker: 0x8402c7   region: fw_peri
bits      :    [0]    width 1  size 1 B
dword     : 0xa202c4  shift 24  mask 0x01000000
peek      : echo 0xa202c4 > $D/mem_addr && cat $D/mem_val
```

Запрос сопоставляется как **подпоследовательность** сегментов пути, так что
уровни-обёртки и виды объединений можно не писать. Если одно и то же поле
достижимо через несколько видов объединения — это не конфликт, биты те же,
возвращается кратчайший путь.

## Адреса: AHB, а не линкерные

Оба файла пишут **AHB-адреса** — то же пространство, в которое грузятся
data-записи `.brd`/`.fw` (0x900000 fw_code, 0xa00000 fw_data, 0xa20000
fw_peri, 0xa38000 uc_code, 0xa78000 uc_data). Линкерные адреса — другие, и
именно они лежат в значениях указателей **внутри** данных прошивки.
Таблица трансляции взята у самого вендора
(`host_manager_11ad/access_layer_11ad/AddressTranslator.cpp`, который, как
там и написано, копирует её из драйвера) и сверена с `wmi.c` драйвера.

**Ловушка вендора:** в `AddressTranslator.cpp` лежит только
`talyn_fw_mapping` и написано «Address translator only supports TALYN map», а
`TALYN_M_B0` — это Talyn-**MB**, у которого 768 КБ кода вместо 1 МБ и ещё
шесть регионов (`sec_pka`, `sec_kdf_rgf`, `sec_main`, `dum_user_rgf`,
`dma_ofu`, `ucode_debug`). По умолчанию берётся `talyn-mb`, старая таблица —
`--chip talyn`.

**Ловушка драйвера:** `debugfs/mem_addr` проходит через `wmi_addr_remap`,
который ищет адрес в **линкерных** диапазонах. AHB-адреса из диапазона
0x900000…0xa80000 при этом тоже работают — их ловит тождественный регион
`upper`, — и только благодаря этому по AHB-адресу доступен и микрокод, у
которого `fw = false`. Команда `peek` печатает выровненный по dword адрес,
потому что `wmi_buffer` отвергает невыровненные.

## Чтение и правка по именам

```
$ wil_syms.py read wil6436.fw g_version_major g_version_minor g_version_build \
                              g_boot_state g_bcon_interval_msec
g_version_major        0x00000007  7
g_version_minor        0x00000005  5
g_version_build        0x0000004d  77
g_boot_state           0x11111111  286331153     HW_BOOT_DONE
g_bcon_interval_msec   0x00000064  100
```

Источником может быть `.fw` или сырой дамп региона с живого железа
(`--dump blob_fw_data --base 0xa00000`; файлы `blob_*` в debugfs отдают
регион целиком и только на чтение).

`poke` правит **образ**, а не устройство: находит нужную data-запись,
укладывает значение в биты, не трогая соседние, и пересчитывает crc
контейнера. Константы enum принимаются по имени.

```
$ wil_syms.py poke test.fw g_bcon_interval_msec=200 g_led_enabled=0 \
                           g_boot_state=FW_BOOT_DONE -o patched.fw
g_bcon_interval_msec   0xa0058c  0x64 -> 0xc8
g_led_enabled          0xa00474  0x1 -> 0x0
g_boot_state           0xa00360  0x11111111 -> 0x33333333
6 byte(s) changed
written patched.fw, crc -> 0x0cb61fb2
```

Правки на живом устройстве штатными средствами нет: `mem_val` открыт только
на чтение (у `fops_memread` нет `.write`), `blob_*` — 0444, а команды записи
в память в `wmi.xml` не нашлось.

## Выгрузка в Ghidra

```
wil_syms.py ghidra -o out --fw wil6436.fw
```

кладёт четыре файла:

| файл | что это |
|---|---|
| `wil_fw_symbols.txt` | `имя адрес` — формат, который ждёт `ImportSymbolsScript.java` |
| `wil_fw_layout.json` | полная раскладка: структуры, объединения, массивы, биты, enum'ы |
| `wil_fw_memory.csv` | регионы с AHB- и линкерными адресами и сколько байт каждого занимает образ |
| `wil_apply_globals.py` | скрипт для Ghidra (Jython): метки + типы |

Скрипт строит из раскладки настоящие типы (`StructureDataType`,
`UnionDataType`, `ArrayDataType`, `EnumDataType`, битовые поля через
`insertBitFieldAt`), кладёт их в категорию `/wil6210` и применяет по адресам.
Хедлесс, Ghidra 12.x (Jython выкинут, скрипты на Python 3 идут через
PyGhidra, поэтому запускать надо её launcher'ом, а не `analyzeHeadless`):

```
G=../ghidra_12.1.3_PUBLIC
python3 $G/Ghidra/Features/PyGhidra/support/pyghidra_launcher.py $G --headless \
    PROJ wil -import fw_data.bin -loader BinaryLoader -loader-baseAddr 0xa00000 \
    -processor "ARM:LE:32:v7" -noanalysis \
    -scriptPath out -postScript wil_apply_globals.py out/wil_fw_layout.json
```

Первый запуск спросит разрешение поставить PyGhidra в venv
(`~/.config/ghidra/<версия>/venv`) — ставится офлайн из колёс, лежащих в самой
Ghidra. На Ghidra ≤ 11 тот же скрипт запускается обычным `analyzeHeadless` и
идёт через Jython; заголовок скрипта совместим с обоими.

**Про процессор.** Прошивка и микрокод — **ARC** (Synopsys). Процессора ARC в
штатной Ghidra нет ни в 10.1.4, ни в 12.1.3 (в 12.1.3 добавились BPF, Hexagon,
Loongarch, M16C, NDS32, Xtensa — ARC среди них нет), нужен сторонний модуль
ARCompact. Но метки и типы от выбора языка не зависят: данные (`fw_data`,
`uc_data`) размечаются любым 32-битным little-endian языком, дизассемблер
нужен только для `fw_code`/`uc_code`.

Сама Ghidra 12.1.3 лежит рядом с инструментами —
`60_GHZ/ghidra_12.1.3_PUBLIC/` (и архив `ghidra_12.1.3_PUBLIC_20260817.zip`).

**Модуль ARCompact поставлен.** Чтобы дизассемблировать сам код прошивки
(`fw_code` @ 0x900000, `uc_code` @ 0xa38000), нужен процессор ARC, которого в
Ghidra нет. Модуль от Ledger Donjon (SSTIC 2021, `niooss-ledger/ghidra`, ветка
`arcompact_on_12.1.2`) установлен в `ghidra_12.1.3_PUBLIC/Ghidra/Processors/ARC`,
`ARCompact.sla` скомпилирован. Язык — **`ARCompact:LE:32:default`**. Исходник
модуля и установщик лежат в `ghidra/` (`./install_arc.sh <ghidra>`
ставит заново после переустановки Ghidra). Ставится только Sleigh-спецификация
— Java-библиотека эмуляции из апстрима не нужна для дизассемблера и потребовала
бы сборки Gradle.

```
$ python3 wil_syms.py segments wil6436.fw
AHB        linker     file-off      bytes  region
0x00900000 0x00000000 0x00000048   441812  fw_code
0x00a00000 0x00800000 0x0006be28    79156  fw_data
0x00a38000 0x00000000 0x0007f368   259156  uc_code
0x00a78000 0x00800000 0x000be7c8    14112  uc_data
0x009a0000 0x000a0000 0x000c1fb0   131072  fw_code
```

### Правка кода: цикл замкнут

`segments` показывает загружаемые записи и их адреса, `patch` пишет байты по
AHB-адресу обратно в образ и пересчитывает crc контейнера. Два входа:

```
# по адресу и байтам напрямую
wil_syms.py patch wil6436.fw --addr 0x900204 --bytes e078e078 -o out.fw

# или диффом из Ghidra: скрипт ghidra/arc_export_patch.py снимает
# ровно изменённые прогоны в overlay-файл (строки "0xADDR: hexbytes"),
wil_syms.py patch wil6436.fw --overlay patch.overlay -o out.fw
```

`patch` отказывается писать прогон, пересекающий границу сегмента.
Поверено насквозь: два `mov_s` по 0x900204 заменены на `nop_s nop_s` (`e078
e078`), пересобранный `.fw` дизассемблируется обратно в `nop_s nop_s`,
`wil_brd.py info` даёт `crc OK`, а overlay-маршрут из Ghidra даёт образ,
байт-в-байт совпадающий с прямым `--bytes`. Подробности — `ghidra/README.md`.

**Указатели в карте.** 37 узлов (32 в FW, 5 в ucode) лежат **вне** своего
родителя: вендор разворачивает указатель на месте, но по адресу того
объекта, на который он указывает (`state_names`, `event_names`, пулы
памяти). Они выгружаются отдельными объектами с именем вида
`g_linear_power__m_lp_sm__state_names`. Длина у них **номинальная** — соседние
такие объекты перекрываются, — поэтому скрипт кладёт их только туда, где
адрес ещё свободен, и печатает, сколько пропустил.

## Проверено

- **версия и дата сборки читаются из образа по именам.** `g_version_*` в
  `wil6436.fw` дают 7.5.0.77 — ровно то, что написано в комментарии
  контейнера; `g_compilation_*` дают 2019-09-18 13:42:38;
- **раскладка битовых полей сверена с чужим кодом.** `g_log_table_header` —
  это `write_ptr` (u32) плюс массив из 16 байт, в каждом
  `error/warn/info/verbose_level_enable` по биту и `reserved0:4`. Бит в бит
  совпадает со `struct log_table_header` и `struct module_level_enable` из
  LogCollector. Число модулей 16 совпадает с `NUM_MODULES` в debug-tools
  2020 года и **не** совпадает с 17 в публичном LogCollector 2017-го
  (там `SECURITY` и `PSM` ещё раздельные): заголовок сместился на байт,
  старый сборщик логов на Talyn разъедется;
- **адреса совпали с драйвером.** `g_fw_dedicated_registers` лежит по
  0x880a3c — это `RGF_USER_BL` из `wil6210.h`, а его поле `rev_id` по
  0x880a8c — это `RGF_USER_FW_REV_ID`. Драйвер знает из этого блока четыре
  регистра, карта расписывает все 128 байт (`fw_main_state`, `fw_sub_state`,
  `tx_goodput`, `rx_goodput`, `bf_mcs`, `rf_status` с enum'ом, `per`, …);
- **все адреса попали в известные регионы.** 455 глобалов FW:
  434 в `fw_data`, 18 в `fw_peri`, 3 в `rgf`; 481 глобал ucode: 470 в
  `uc_data`, 10 в `fw_peri` (общая с прошивкой периферия), 1 в `uc_code`.
  Ни одного вне таблицы Talyn-MB;
- **чтение образа.** Из `wil6436.fw` читаются 434 глобала из 455; остальные
  21 живут в `fw_peri` и `rgf`, которых в образе нет — это RAM, которую
  прошивка инициализирует сама;
- **правка образа.** `poke` трёх символов изменил ровно 6 байт полезной
  нагрузки (плюс 4 байта crc), `wil_brd.py info` на результате говорит
  `crc OK`, обратное чтение возвращает записанные значения;
- **Ghidra, не на словах.** Выгрузка прогнана хедлессом на **двух** версиях:
  10.1.4 (Jython) и 12.1.3 (PyGhidra, Python 3) — результат совпал до числа.
  На образе `fw_data` применено 455 типов, **434 из 434** настоящих глобала
  получили тип ровно той длины, что стоит в карте, 11 объектов-мишеней
  пропущены как перекрывающиеся; на `uc_data` — 314 типов. Ошибок при
  построении типов нет.
