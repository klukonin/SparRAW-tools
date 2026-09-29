# SPDX-License-Identifier: AGPL-3.0-or-later
# @category wil6210
# @runtime PyGhidra
# Поиск адреса функции как ДАННЫХ (таблицы указателей) по всему образу.
import struct, sys
sp=currentProgram.getAddressFactory().getDefaultAddressSpace()
mem=currentProgram.getMemory(); fm=currentProgram.getFunctionManager()
listing=currentProgram.getListing()
# ВАЖНО: таблицы указателей хранят адреса в пространстве ПРОЦЕССОРА
# (код виден CPU с нуля, хосту — с 0x8c0000). Ищем обе формы.
_t=[int(x,16) for x in getScriptArgs()[0].split(',')]
targets=[]
for t in _t:
    targets.append(t)
    if t>=0x8c0000: targets.append(t-0x8c0000)
    else: targets.append(t+0x8c0000)
BLOCKS=[('fw_code',0x8c0000,0x8f3b58),('fw_data',0x900000,0x906880),
        ('uc_code',0x920000,0x9380c4),('uc_data',0x940000,0x940ef4)]
raw={}
for nm,lo,hi in BLOCKS:
    b=bytearray(hi-lo)
    try:
        mem.getBytes(sp.getAddress(lo), b)
    except Exception as e:
        print('не прочитан %s: %s'%(nm,e)); continue
    raw[nm]=(lo,bytes((x+256)%256 for x in b))
for t in targets:
    pat=struct.pack('<I',t)
    print('\n=== 0x%08x как данные ==='%t)
    found=0
    for nm,(lo,data) in raw.items():
        i=data.find(pat)
        while i>=0:
            a=lo+i
            ctx=[]
            for k in range(-3,4):
                o=i+k*4
                if 0<=o<len(data)-4:
                    v=struct.unpack_from('<I',data,o)[0]
                    f=fm.getFunctionContaining(sp.getAddress(v)) if 0x8c0000<=v<0x940000 else None
                    ctx.append('%s%s'%('*' if k==0 else '', f.getName() if f and f.getEntryPoint().getOffset()==v else '0x%08x'%v))
            print('  %s @0x%06x : %s'%(nm,a,' | '.join(ctx)))
            found+=1
            i=data.find(pat,i+1)
    if not found: print('  не найден как данные')
