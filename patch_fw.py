#!/usr/bin/env python3
"""Build the patched M8 firmware: SMS events become readable UCS2 text.
Patch site: 0x12E5A8 (SMS event sender, proven chain to user's garbled SMS)."""
import struct, sys
sys.path.insert(0, '/home/z/my-project/scripts')
sys.path.insert(0, '/home/z/my-project/download')
from sbin_tool import crypt, crc16_xmodem, parse_header, HEADER_SIZE, HDR_KEY_PLAIN, KEY_TABLE

SRC = '/home/z/my-project/upload/m8-03_1_14.sbin'
OUT = '/home/z/my-project/download/m8-03_1_14_SMS_TEXT.sbin'
BIN = '/home/z/my-project/download/m8-03_1_14_patched.bin'

BASE = 0x00100000
PATCH_ADDR = 0x0012E5A8
END_OLD    = 0x0012E668          # old function ends here (b 0x131BF4)

raw = open(SRC, 'rb').read()
hdr = crypt(raw[:HEADER_SIZE], HDR_KEY_PLAIN)
h = parse_header(hdr)
body = bytearray(crypt(raw[HEADER_SIZE:], h['key']))

off = PATCH_ADDR - BASE
orig = struct.unpack_from('<I', body, off)[0]
print(f"original @0x{PATCH_ADDR:08X}: {orig:08X} (expect E92D41FF)")
assert orig == 0xE92D41FF

POOL_BASE = PATCH_ADDR + 0x90    # literals at +0x90..+0x9B
L_TAB, L_BUF, L_NUM = POOL_BASE, POOL_BASE + 4, POOL_BASE + 8

code = []
def emit(*words):
    for w in words:
        code.append(w & 0xFFFFFFFF)

def ldr_lit(rd, lit_addr):
    pc = PATCH_ADDR + len(code) * 4
    base = (pc + 8) & ~3
    delta = lit_addr - base
    assert 0 <= delta <= 0xFFF, f"literal too far: {delta:#x}"
    emit(0xE59F0000 | (rd << 12) | delta)

def bl_addr(addr):
    pc = PATCH_ADDR + len(code) * 4
    offb = addr - (pc + 8)
    emit(0xEB000000 | ((offb >> 2) & 0x00FFFFFF))

def bcc(dest_idx, cond):
    idx = len(code)
    offw = dest_idx - idx - 2
    emit((cond << 28) | 0x0A000000 | (offw & 0x00FFFFFF))

emit(0xE92D40F0)   # push {r4-r7, lr}
emit(0xE1A04000)   # mov r4, r0  (obj)
emit(0xE1A07001)   # mov r7, r1  (payload ptr)
emit(0xE1A06002)   # mov r6, r2  (payload len)
emit(0xE5D70000)   # ldrb r0, [r7]
emit(0xE3500020)   # cmp r0, #0x20
bhs_idx = len(code)
emit(0x2A000000)   # bhs Ldirect
emit(0xE3500013)   # cmp r0, #19
blo_idx = len(code)
emit(0xBA000000)   # blo Lid
emit(0xE3A00013)   # mov r0, #19 ; fallback "Неизвестно"
lid_idx = len(code)
ldr_lit(1, L_TAB)
emit(0xE3A0200C)   # mov r2, #12
emit(0xE0030290)   # mul r3, r0, r2
emit(0xE0811003)   # add r1, r1, r3
ldr_lit(0, L_BUF)
emit(0xE3A0200C)   # mov r2, #12
bl_addr(0x1FFB68)  # mempcpy(dst, text, 12)
ldr_lit(0, L_BUF)
bl_addr(0x1FFBF8)  # strlen
emit(0xE1A06000)   # mov r6, r0
ldr_lit(7, L_BUF)  # ldr r7, =0x20A778
ldirect_idx = len(code)
# ---- Ldirect ----
ldr_lit(0, L_NUM)  # ldr r0, =0x20E990
bl_addr(0x11D9C8)  # number
emit(0xE1A05000)   # mov r5, r0
emit(0xE24DD004)   # sub sp, sp, #4
emit(0xE58D6000)   # str r6, [sp]
emit(0xE594004C)   # ldr r0, [r4, #0x4C]
emit(0xE1A03007)   # mov r3, r7
emit(0xE3A02010)   # mov r2, #0x10 (UCS2)
emit(0xE1A01005)   # mov r1, r5
bl_addr(0x121714)  # QueueSMS
emit(0xE28DD004)   # add sp, sp, #4
emit(0xE3A0100A)   # mov r1, #0xA
emit(0xE1A00004)   # mov r0, r4
emit(0xE8BD40F0)   # pop {r4-r7, lr}
pc = PATCH_ADDR + len(code) * 4
offb = 0x131BF4 - (pc + 8)
emit(0xEA000000 | ((offb >> 2) & 0x00FFFFFF))

# fix conditional branches
code[bhs_idx] = (0x2A000000 | ((ldirect_idx - bhs_idx - 2) & 0x00FFFFFF))
code[blo_idx] = (0xBA000000 | ((lid_idx - blo_idx - 2) & 0x00FFFFFF))

# pad with NOPs so the pool lands exactly at POOL_BASE
while PATCH_ADDR + len(code) * 4 < POOL_BASE:
    emit(0xE1A00000)   # nop (mov r0, r0)

emit(0x0013AE00)   # short event text table
emit(0x0020A778)   # packet buffer
emit(0x0020E990)   # SMS recipient config pointer

# disassemble the patch back for the log
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
print("---- patch disassembly ----")
codebytes = b''.join(struct.pack('<I', w) for w in code)
for ins in md.disasm(codebytes, PATCH_ADDR):
    print(f"0x{ins.address:08X}: {ins.mnemonic:<7} {ins.op_str}")
print(f"code size: {len(code)} words = {len(code)*4} bytes (limit {END_OLD-PATCH_ADDR})")
assert len(code) * 4 <= END_OLD - PATCH_ADDR, "patch overflows!"

# ---- apply ----
for i, w in enumerate(code):
    struct.pack_into('<I', body, off + 4 * i, w)
for i in range(off + len(code) * 4, END_OLD - BASE):
    body[i] = 0

body_bytes = bytes(body)
open(BIN, 'wb').write(body_bytes)
print(f"patched binary -> {BIN}")

# ---- rebuild sbin ----
flash_crc = crc16_xmodem(body_bytes)
buf = bytearray(HEADER_SIZE)
buf[0:6] = bytes([h['typ'], h['v1'], h['v2'], h['v3'], h['key_index'], h['vbase']])
struct.pack_into('<H', buf, 6, KEY_TABLE.get(h['key_index'], 0))
struct.pack_into('<H', buf, 8, flash_crc)
struct.pack_into('<H', buf, 10, h['eeprom_crc'])
struct.pack_into('<I', buf, 12, h['soft_size'])
struct.pack_into('<I', buf, 16, h['time_create'])
buf[20] = h['typ_addr']
struct.pack_into('<I', buf, 21, h['addr'])
buf[25] = h['boot_rev']
hdr_enc = crypt(bytes(buf), HDR_KEY_PLAIN)
body_enc = crypt(body_bytes, h['key'])
open(OUT, 'wb').write(hdr_enc + body_enc)
print(f"patched sbin -> {OUT} (crc=0x{flash_crc:04X})")

# ---- verify ----
raw2 = open(OUT, 'rb').read()
h2 = parse_header(crypt(raw2[:HEADER_SIZE], HDR_KEY_PLAIN))
body2 = crypt(raw2[HEADER_SIZE:], h2['key'])
print("verify crc:", crc16_xmodem(body2) == h2['flash_crc'])
print("verify body:", body2 == body_bytes)
chk = struct.unpack_from('<I', body2, off)[0]
print("verify patch entry:", f"0x{chk:08X}", chk == 0xE92D40F0)
