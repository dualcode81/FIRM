#!/usr/bin/env python3
"""sbin_tool.py - decoder/encoder for Stels (Miraj-GSM) .sbin firmware files.

Format (recovered from SharpLib.Sbin / HeaderSbin / Sbin.EncodeFile / DecodeFileSbin in SLibX.dll):

  FILE = HEADER(128) + BODY(SoftSize)
  HEADER (encrypted with fixed key, plain-key = 43998 for normal files, 47836 for xmodem variant):
    off 0  : Typ        device type (u8)
    off 1  : V1         version hi (u8)
    off 2  : V2         version lo (u8)
    off 3  : V3         version lit (u8)
    off 4  : KeyIndex   index into KEY_TABLE (u8)
    off 5  : VBase      base version (u8)
    off 6  : Key        u16 initial data key (== KEY_TABLE[KeyIndex])
    off 8  : FlashCrc   u16 CRC16/XMODEM of decoded body
    off 10 : EepromCrc  u16
    off 12 : SoftSize   u32 body size
    off 16 : TimeCreate u32 (NTP seconds since 1900)
    off 20 : TypAddr    u8
    off 21 : Addr       u32
    off 25 : BootRev    u8
    off 26..127 zero padding
  BODY: firmware binary XOR-encrypted with LFSR keystream seeded by header.Key.

  Crypto: 16-bit Galois-style LFSR, taps bits 0,2,6,11, feedback into bit15.
  Per output byte: 8 LFSR steps; the 8 shifted-out key bits (bit0), in order,
  form the XOR byte (first step -> LSB of output byte).

KEY_TABLE (from SLibX Sbin::.cctor):
  0 -> 43998 (0xABDE), 5 -> 21608 (0x5468), 7 -> 12938 (0x328A),
  17 -> 63672 (0xF8B8), 19 -> 50748 (0xC63C), 23 -> 8078 (0x1F8E), 255 -> 0
"""
import struct, sys, os

KEY_TABLE = {0: 43998, 5: 21608, 7: 12938, 17: 63672, 19: 50748, 23: 8078, 255: 0}
HDR_KEY_PLAIN = 43998      # header encryption key (normal .sbin)
HDR_KEY_XMODEM = 47836     # header encryption key (xmodem/.sbinx variant)
HEADER_SIZE = 128
TYP_M8 = 51                # Miraj-GSM-M8 platform


def shift_key(key):
    """Advance LFSR by 8 steps; return (new_key, output_byte)."""
    out = 0
    for _ in range(8):
        fb = ((key & 1) != 0) ^ ((key & 4) != 0) ^ ((key & 0x40) != 0) ^ ((key & 0x800) != 0)
        out = (out >> 1) & 0xFF
        if key & 1:
            out |= 0x80
        key = (key >> 1) & 0xFFFF
        if fb:
            key |= 0x8000
    return key & 0xFFFF, out & 0xFF


def crypt(buf, key):
    """XOR buf with LFSR keystream seeded by key (in-place semantics of Sbin.Encrypt)."""
    res = bytearray(buf)
    k = key & 0xFFFF
    for i in range(len(res)):
        k, b = shift_key(k)
        res[i] ^= b
    return bytes(res)


def crc16_xmodem(data, init=0):
    crc = init
    for b in data:
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def parse_header(buf):
    typ, v1, v2, v3, key_index, vbase = buf[0:6]
    key = struct.unpack_from('<H', buf, 6)[0]
    flash_crc = struct.unpack_from('<H', buf, 8)[0]
    eeprom_crc = struct.unpack_from('<H', buf, 10)[0]
    soft_size = struct.unpack_from('<I', buf, 12)[0]
    time_create = struct.unpack_from('<I', buf, 16)[0]
    typ_addr = buf[20]
    addr = struct.unpack_from('<I', buf, 21)[0]
    boot_rev = buf[25]
    return dict(typ=typ, v1=v1, v2=v2, v3=v3, key_index=key_index, vbase=vbase,
                key=key, flash_crc=flash_crc, eeprom_crc=eeprom_crc,
                soft_size=soft_size, time_create=time_create,
                typ_addr=typ_addr, addr=addr, boot_rev=boot_rev)


def decode(sbin_path, out_path=None, hdr_key=HDR_KEY_PLAIN):
    raw = open(sbin_path, 'rb').read()
    hdr_enc = raw[:HEADER_SIZE]
    body_enc = raw[HEADER_SIZE:]
    hdr_dec = crypt(hdr_enc, hdr_key)
    h = parse_header(hdr_dec)
    pad = hdr_dec[26:HEADER_SIZE]
    pad_ok = (set(pad) <= {0})
    if h['soft_size'] != len(body_enc):
        print(f"WARNING: SoftSize={h['soft_size']} != body size {len(body_enc)}")
    body = crypt(body_enc, h['key'])
    calc = crc16_xmodem(body)
    ok = (calc == h['flash_crc'])
    print(f"Typ={h['typ']} V={h['v1']}.{h['v2']}.{h['v3']} KeyIndex={h['key_index']} "
          f"VBase={h['vbase']} Key=0x{h['key']:04X}")
    print(f"SoftSize={h['soft_size']} TimeCreate=0x{h['time_create']:08X} "
          f"Addr=0x{h['addr']:08X} BootRev={h['boot_rev']}")
    print(f"padding zeros: {pad_ok}  CRC16: calc=0x{calc:04X} hdr=0x{h['flash_crc']:04X} "
          f"-> {'OK' if ok else 'FAIL'}")
    if out_path is None:
        out_path = os.path.splitext(sbin_path)[0] + '.decoded.bin'
    open(out_path, 'wb').write(body)
    print("decoded ->", out_path)
    return h, body


def build_header(typ, v1, v2, v3, key_index, vbase, flash_crc, eeprom_crc,
                 soft_size, time_create, typ_addr=0, addr=0, boot_rev=0):
    buf = bytearray(HEADER_SIZE)
    buf[0:6] = bytes([typ, v1, v2, v3, key_index, vbase])
    struct.pack_into('<H', buf, 6, KEY_TABLE.get(key_index, 0))
    struct.pack_into('<H', buf, 8, flash_crc)
    struct.pack_into('<H', buf, 10, eeprom_crc)
    struct.pack_into('<I', buf, 12, soft_size)
    struct.pack_into('<I', buf, 16, time_create)
    buf[20] = typ_addr
    struct.pack_into('<I', buf, 21, addr)
    buf[25] = boot_rev
    return bytes(buf)


def encode(bin_path, sbin_path, typ=TYP_M8, v1=1, v2=14, v3=32, key_index=5,
           vbase=1, eeprom_crc=0, time_create=0, typ_addr=0, addr=0, boot_rev=0):
    data = open(bin_path, 'rb').read()
    key = KEY_TABLE.get(key_index, 0)
    flash_crc = crc16_xmodem(data)
    hdr = build_header(typ, v1, v2, v3, key_index, vbase, flash_crc, eeprom_crc,
                       len(data), time_create, typ_addr, addr, boot_rev)
    hdr_enc = crypt(hdr, HDR_KEY_PLAIN)
    body_enc = crypt(data, key)
    open(sbin_path, 'wb').write(hdr_enc + body_enc)
    print(f"encoded -> {sbin_path}  (crc=0x{flash_crc:04X}, key=0x{key:04X})")


def selftest(src):
    """Roundtrip: decode src, re-encode with same params, compare bytes."""
    h, body = decode(src, '/tmp/_rt.bin')
    hdr = build_header(h['typ'], h['v1'], h['v2'], h['v3'], h['key_index'],
                       h['vbase'], h['flash_crc'], h['eeprom_crc'], h['soft_size'],
                       h['time_create'], h['typ_addr'], h['addr'], h['boot_rev'])
    re_enc = crypt(hdr, HDR_KEY_PLAIN) + crypt(body, h['key'])
    orig = open(src, 'rb').read()
    print("roundtrip:", "IDENTICAL" if re_enc == orig else "MISMATCH")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'decode':
        decode(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == 'encode':
        encode(sys.argv[2], sys.argv[3])
    elif cmd == 'test':
        selftest(sys.argv[2])
