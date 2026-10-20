# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Восстановление имён функций 4.1.0.1000 из лог-строк.
#   fw_code  -> строки в блоке fw_strings @0x01000000 (запись 101)
#   uc_code  -> отдельный пул (запись 100), таблица в uc4100_strmap.json
# Конвенция ссылки одна и та же: в инструкции лежит 0x01000000 | offset.
# Аргумент: путь к uc4100_strmap.json.  Только чтение, ничего не меняет.
import json, re, sys
from collections import defaultdict

sp = currentProgram.getAddressFactory().getDefaultAddressSpace()
fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

UC_STR = {int(k): v for k, v in json.load(open(getScriptArgs()[0])).items()}
FW_LO, FW_HI = 0x01000000, 0x0101b354
UC_LO, UC_HI = 0x920000, 0x9380c4

def fw_string(addr):
    out = bytearray()
    for i in range(200):
        try: v = mem.getByte(sp.getAddress(addr + i)) & 0xff
        except Exception: return None
        if v == 0: break
        out.append(v)
    if not out: return None
    s = out.decode('latin1')
    return s if all(32 <= ord(c) < 127 or c in '\t' for c in s) else None

# имя = идентификатор (возможно class::method) в НАЧАЛЕ строки, после
# необязательного тега [XXX]. Терминатор обязателен и определяет ВЕС кандидата:
#   "()" 4 (явная запись вызова) | "(" 3 | ":" 2 | ". " 1
# Голого пробела как терминатора НЕТ: иначе любое английское слово в начале
# строки становится "именем" (ловушка: "Update TX Beacon ..." -> Update).
NAME_RE = re.compile(
    r'^(?:\[[A-Za-z0-9_ /-]{1,14}\]\s*)?'
    r'([A-Za-z_][A-Za-z0-9_]{2,}(?:::[A-Za-z_][A-Za-z0-9_]*)*)'
    r'\s*(\(\)|\(|:(?!:)|\.\s|\s)')
WEIGHT = {'()': 4, '(': 3, ':': 2}
# отсекаем явно не-имена
STOP = {'the','for','and','not','error','failed','warning','info','debug','got',
        'received','send','sent','start','started','stop','stopped','set','get',
        'new','old','bad','max','min','num','len','size','val','value','cur',
        'was','has','can','all','out','req','rsp','msg','cmd','evt','TSF','MID',
        'Illegal','Invalid','Unknown','No','Not','Can','Cannot','Wrong','Missing'}

def candidate(s):
    """-> (имя, вес) или None"""
    m = NAME_RE.match(s)
    if not m: return None
    n, term = m.group(1), m.group(2)
    if n in STOP or n.lower() in STOP: return None
    if n.endswith(('.c', '.cpp', '.h')): return None
    t = term.strip()
    w = WEIGHT.get(t, 1)
    if t == '':
        # терминатор — голый пробел. Принимаем ТОЛЬКО очевидно «именные»
        # токены, иначе первое английское слово строки станет именем
        # ("Update TX Beacon ..." -> Update).
        if '::' not in n and not ('_' in n and len(n) >= 12):
            return None
    if '::' in n:
        return (n, w + 3)                       # class::method — сильнейший признак
    if len(n) < 5: return None
    # голый идентификатор принимаем, только если он ПОХОЖ на имя функции:
    # есть подчёркивание, либо он не выглядит английским словом с заглавной
    if '_' not in n and (n[0].isupper() or len(n) < 8): return None
    return (n, w)

rows = []
for f in fm.getFunctions(True):
    ep = f.getEntryPoint().getOffset()
    is_uc = ep >= UC_LO
    strs = []
    ins = listing.getInstructionAt(f.getEntryPoint())
    end = f.getBody().getMaxAddress().getOffset()
    while ins is not None and ins.getAddress().getOffset() <= end:
        for i in range(ins.getNumOperands()):
            for o in ins.getOpObjects(i):
                try: v = o.getValue()
                except Exception: continue
                if not isinstance(v, int): continue
                if is_uc:
                    if (v >> 24) == 0x01:
                        s = UC_STR.get(v & 0xfffff)
                        if s: strs.append(s)
                else:
                    if FW_LO <= v < FW_HI:
                        s = fw_string(v)
                        if s: strs.append(s)
        ins = ins.getNext()
    if not strs: continue
    score = defaultdict(int); hits = defaultdict(int)
    for s in strs:
        c = candidate(s)
        if c:
            score[c[0]] += c[1]; hits[c[0]] += 1
    if not score:
        rows.append((ep, None, f.getBody().getNumAddresses(), len(strs), 0, strs[0][:60]))
        continue
    best = sorted(score.items(), key=lambda kv: (-kv[1], -hits[kv[0]], kv[0]))[0]
    rows.append((ep, best[0], f.getBody().getNumAddresses(), len(strs), best[1],
                 strs[0][:60]))

rows.sort()
named = [r for r in rows if r[1]]
print('FUNCS_WITH_STRINGS %d  NAMED %d' % (len(rows), len(named)))
for ep, nm, sz, ns, votes, sample in rows:
    print('ROW 0x%08x %-52s %5d %3d %2d | %s'
          % (ep, nm or '?', sz, ns, votes, sample.replace('\n', ' ')))
