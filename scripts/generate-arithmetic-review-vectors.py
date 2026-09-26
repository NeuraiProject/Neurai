#!/usr/bin/env python3
"""Independent integer oracle: ScriptNum sign/magnitude and 64-bit boundaries.
No node imports. Emits literal C++ scripts/results for VerifyScript tests.
"""
LIMIT = 2**63-1

def number(n):
    if not n:return b''
    raw=abs(n).to_bytes((abs(n).bit_length()+7)//8,'little')
    if raw[-1]&128:raw+=bytes([128 if n<0 else 0])
    elif n<0:raw=raw[:-1]+bytes([raw[-1]|128])
    return raw

def push(raw):
    if not raw:return b'\0'
    if len(raw)==1 and 1<=raw[0]<=16:return bytes([80+raw[0]])
    if raw==b'\x81':return b'\x4f'
    return bytes([len(raw)])+raw

def emit(values, opcode, result, error='OK'):
    wire=b''.join(push(number(v)) for v in values)+bytes([opcode])
    expected=number(result).hex() if error=='OK' else ''
    print(f'        {{"{wire.hex()}", "{expected}", SCRIPT_ERR_{error}}},')

pairs=[(0,0),(7,3),(-7,3),(7,-3),(-7,-3),(2**31-1,1),(2**31,2),
       (LIMIT,1),(-LIMIT,-1),(LIMIT,LIMIT),(-LIMIT,LIMIT),(2**32,2**31),
       (-2**32,2**31),(3037000499,3037000499),(3037000500,3037000500)]
for a,b in pairs:
    operations={0x93:('ADD',a+b),0x94:('SUB',a-b),0x95:('MUL',a*b),
                0x9a:('',int(bool(a) and bool(b))),0x9b:('',int(bool(a) or bool(b))),
                0x9c:('',int(a==b)),0x9e:('',int(a!=b)),0x9f:('',int(a<b)),
                0xa0:('',int(a>b)),0xa1:('',int(a<=b)),0xa2:('',int(a>=b)),
                0xa3:('',min(a,b)),0xa4:('',max(a,b))}
    for opcode,(name,result) in operations.items():
        emit([a,b],opcode,result,name+'_OVERFLOW' if abs(result)>LIMIT else 'OK')
    for opcode,name in [(0x96,'DIV'),(0x97,'MOD')]:
        q=(abs(a)//abs(b))*(-1 if (a<0)!=(b<0) else 1) if b else 0
        emit([a,b],opcode,q if opcode==0x96 else a-q*b,'OK' if b else name+'_BY_ZERO')
for a in [0,1,-1,2**31-1,-(2**31-1),LIMIT,-LIMIT]:
    for opcode,result,name in [(0x8b,a+1,'ADD'),(0x8c,a-1,'SUB'),(0x8f,-a,''),
                               (0x90,abs(a),''),(0x91,int(a==0),''),(0x92,int(a!=0),'')]:
        emit([a],opcode,result,name+'_OVERFLOW' if abs(result)>LIMIT else 'OK')
for x,lo,hi in [(0,0,1),(1,0,1),(-LIMIT,-LIMIT,LIMIT),(LIMIT,-LIMIT,LIMIT),
                (2**32,0,2**32+1),(2,3,1)]:emit([x,lo,hi],0xa5,int(lo<=x<hi))
