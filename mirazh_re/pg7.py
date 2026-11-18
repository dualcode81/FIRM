import struct, sys, re
import keystone
sys.path.insert(0, r"C:\Users\Andrey\mirazh_re")
from sbin_dec import keystream, crc16_xmodem, KEY_HEADER

_KS = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)

CAVE = 0x36800
CVA = 0x100000 + CAVE
BUF = 0x20A778
REC0 = 0x20EDF4
HOOK = 0x12E604
BOFF = 0x15  # MSRV body offset inside packet buffer

LBL = [
    (0x09, "POZAR"), (0x0A, "TRVOGA"), (0x0B, "VZLYATO"), (0x0C, "NYATO"),
    (0x0D, "NEVZLYAT"), (0x0E, "POZAR1"), (0x0F, "POZAR2"),
    (0x12, "TR MEM"), (0x13, "TR PAN"), (0x15, "TR OG NEIZV"),
    (0x23, "GOTOVO"), (0x28, "NAPR PRIM"), (0x29, "NAPR OTKL"),
    (0x2A, "NAPR OSNOV"), (0x2B, "NAPR REZ"),
    (0x38, "SAB ZAMYLK"), (0x3B, "OBNAZHEN"), (0x3C, "UBRAN"),
    (0x45, "SAB OTKR"), (0x56, "NET SVYAZI"), (0x59, "SVYAZ VOSST"),
    (0x89, "BLOKIROVKA"), (0x91, "POISK SETI"), (0xBF, "SABOTAZH"),
]
lbltab = bytearray()
for _c, _s in LBL:
    lbltab += struct.pack("<H", _c) + _s.encode("ascii").ljust(14, b"\0")
lbltab += struct.pack("<H", 0xFFFF) + b"\0" * 14

SRC = r"""
b stub
stub:
push {r4, r5, r6, r7}
sub sp, sp, #0x1c
str r0, [sp]
str r1, [sp, #4]
str r2, [sp, #8]
str r3, [sp, #0xc]
str r4, [sp, #0x10]
str r5, [sp, #0x14]
str r6, [sp, #0x18]
bl 0x1258dc
ldr r0, [sp]
ldr r1, [sp, #4]
ldr r2, [sp, #8]
ldr r3, [sp, #0xc]
ldr r4, [sp, #0x10]
ldr r5, [sp, #0x14]
ldr r6, [sp, #0x18]
pop {r4, r5, r6, r7}
b post
post:
push {r4, r5, r6, r7, r8}
mov r7, r1
ldr r8, [pc, #P_BUF]
mov r4, #8
mov r2, #0
ldr r5, [pc, #P_REC0]
savlp:
ldrb r3, [r7, r2]
strb r3, [r5, r2]
add r2, r2, #1
subs r4, r4, #1
bne savlp
mov r7, r5
ldrb r4, [r7]
ldr r3, [pc, #P_0FFFF]
ldr r6, [pc, #P_LBLTAB]
scanlp:
ldrh r2, [r6]
cmp r2, r3
beq nolbl
cmp r2, r4
beq foundlbl
add r6, r6, #16
b scanlp
foundlbl:
add r6, r6, #2
b lblpad
nolbl:
mov r6, #0
lblpad:
add r3, r8, #BOFF
mov r4, #12
lbl1:
cmp r6, #0
beq lblspc
ldrb r12, [r6]
cmp r12, #0
bne lblstore
mov r6, #0
lblspc:
mov r12, #' '
lblstore:
strb r12, [r3]
add r3, r3, #1
cmp r6, #0
addne r6, r6, #1
subs r4, r4, #1
bne lbl1
add r3, r8, #BOFF12
mov r4, #8
mov r2, #0
hexlp:
ldrb r0, [r7, r2]
mov r1, r0, lsr #4
cmp r1, #10
addhs r1, r1, #7
add r1, r1, #'0'
strb r1, [r3]
add r3, r3, #1
and r1, r0, #0xf
cmp r1, #10
addhs r1, r1, #7
add r1, r1, #'0'
strb r1, [r3]
add r3, r3, #1
mov r1, #' '
strb r1, [r3]
add r3, r3, #1
add r2, r2, #1
subs r4, r4, #1
bne hexlp
ldrb r2, [r7, #2]
ldrb r1, [r7, #3]
orr r2, r2, r1, lsl #8
mov r12, #' '
strb r12, [r3]
add r3, r3, #1
mov r0, #0x2700
add r0, r0, #0x10
mov r4, #5
diglp:
mov r12, #0
dsub:
cmp r2, r0
blo drem
sub r2, r2, r0
add r12, r12, #1
b dsub
drem:
add r12, r12, #'0'
strb r12, [r3]
add r3, r3, #1
mov r1, #0
ddiv:
cmp r0, #10
blo dnext
sub r0, r0, #10
add r1, r1, #1
b ddiv
dnext:
subs r4, r4, #1
beq done
cmp r1, #0
beq spcdig
mov r0, r1
b diglp
spcdig:
mov r12, #' '
strb r12, [r3]
add r3, r3, #1
subs r4, r4, #1
bne spcdig
done:
pop {r4, r5, r6, r7, r8}
mov r0, r8
bx lr
"""

def encode_ldr_lit(reg, off, addr):
    u = 1 if off >= 0 else 0
    return 0xE51F0000 | (reg << 12) | (u << 23) | (abs(off) & 0xFFF)

lines = [l.strip() for l in SRC.splitlines() if l.strip() and not l.startswith("#")]
lines = [l.replace("#BOFF12", "#0x%x" % (BOFF + 12)).replace("#BOFF", "#0x%x" % BOFF) for l in lines]

labels = {}
addr = CVA
for l in lines:
    if l.endswith(":") and l[:-1].isidentifier():
        labels[l[:-1]] = addr
    else:
        addr += 4
code_end = addr
POOLADDR = (code_end + 3) & ~3
POOLVALS = [BUF, REC0, 0xFFFF, 0]
POOLVALS[3] = POOLADDR + 4 * 4
POOLIDX = {"P_BUF": 0, "P_REC0": 1, "P_0FFFF": 2, "P_LBLTAB": 3}

words = []
addr = CVA
for l in lines:
    if l.endswith(":") and l[:-1].isidentifier():
        continue
    ml = re.match(r"ldr r(\d+), \[pc, #(P_\w+)\]", l)
    if ml:
        w = encode_ldr_lit(int(ml.group(1)),
                           POOLADDR + 4 * POOLIDX[ml.group(2)] - (addr + 8), addr)
    elif l.split() and l.split()[0] in ("b", "bl", "bne", "beq", "blo", "bhs") and \
            l.split()[1] in labels:
        parts = l.split()
        diff = labels[parts[1]] - (addr + 8)
        cond = {"b": None, "bl": "B", "bne": 0x1, "beq": 0x0, "blo": 0x3, "bhs": 0x2}[parts[0]]
        if cond is None:
            w = 0xEA000000 | ((diff >> 2) & 0xFFFFFF)
        elif cond == "B":
            w = 0xEB000000 | ((diff >> 2) & 0xFFFFFF)
        else:
            w = 0x0A000000 | (cond << 28) | ((diff >> 2) & 0xFFFFFF)
    else:
        enc, cnt = _KS.asm(l, addr)
        assert cnt == 1, l
        w = int.from_bytes(bytes(enc), "little")
    words.append(w)
    addr += 4

code = b"".join(struct.pack("<I", w) for w in words)
pool = b"".join(struct.pack("<I", v) for v in POOLVALS)
blob = code + b"\0" * (POOLADDR - code_end) + pool + bytes(lbltab)
assert len(blob) <= 0xC00, hex(len(blob))
print("cave:", hex(len(blob)), "code:", hex(len(code)), "POST VA:", hex(labels["post"]))

# ---------- patch image ----------
BIN = r"E:\Hermess\cache\scratch\mirazh\m8-03_1.14.bin"
img = bytearray(open(BIN, "rb").read())
assert int.from_bytes(img[HOOK - 0x100000:HOOK - 0x100000 + 4], "little") == 0xEBFFDCB4
imm = (CVA + 4 - (HOOK + 8)) >> 2
img[HOOK - 0x100000:HOOK - 0x100000 + 4] = struct.pack("<I", 0xEA000000 | (imm & 0xFFFFFF))
img[CAVE:CAVE + len(blob)] = blob
open(r"E:\Hermess\cache\scratch\mirazh\m8-03_1.14_patched.bin", "wb").write(img)

# ---------- rebuild .sbin ----------
d = open(r"E:\Hermess\cache\scratch\mirazh\m8sw\m8-03_1_14.sbin", "rb").read()
hbuf = bytes(a ^ b for a, b in zip(d[:128], keystream(KEY_HEADER, 128)))
key = struct.unpack_from("<H", hbuf, 6)[0]
newdata = bytes(img)
h2 = bytearray(hbuf)
h2[8:10] = struct.pack("<H", crc16_xmodem(newdata))
enc = bytes(a ^ b for a, b in zip(h2, keystream(KEY_HEADER, 128))) + \
      bytes(a ^ b for a, b in zip(newdata, keystream(key, len(newdata))))
OUT = r"C:\Users\Andrey\mirazh_re\m8-03_1.14_textsms.sbin"
open(OUT, "wb").write(enc)
print("wrote", OUT, len(enc))
