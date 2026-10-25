import sys,struct,re
fw,dis,kind,out=sys.argv[1:5]
b=open(fw,'rb').read();o=0;recs={}
while o+8<=len(b):
    t,fl,sz=struct.unpack_from('<HHI',b,o)
    if o+8+sz>len(b):break
    recs.setdefault(t,b[o+8:o+8+sz]);o=(o+8+sz+3)&~3
tab=recs.get(0x65 if kind=='fw' else 0x64)
if tab is None: open(out,'w').close(); print(0); sys.exit()
st=set();i=0
while i<len(tab):
    j=tab.find(b'\0',i)
    if j<0:break
    if j-i>=4: st.add(i)
    i=j+1
n=0
with open(out,'w') as f:
    for line in open(dis):
        p=line.rstrip('\n').split('\t')
        if len(p)<4: continue
        m=re.search(r'0x(1[0-9a-f]{6})\b',p[3])
        if m and (int(m.group(1),16)&0xffffff) in st:
            f.write(p[0].strip().rstrip(':')+'\n'); n+=1
print(n)
