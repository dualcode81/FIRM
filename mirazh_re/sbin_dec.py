import struct, sys, datetime

def keystream(key16, n):
    out = bytearray(n)
    k = key16
    for i in range(n):
        b = 0
        for _ in range(8):
            fb = ((k & 1) ^ ((k >> 2) & 1) ^ ((k >> 6) & 1) ^ ((k >> 11) & 1))
            b >>= 1
            if k & 1:
                b |= 0x80
            k >>= 1
            if fb:
                k |= 0x8000
        out[i] = b
    return out

def crc16_xmodem(d):
    crc = 0
    for byte in d:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

KEY_HEADER = 43998   # 0xAC5E  .sbin
KEY_HEADER_X = 47836 # .sbinx

def decode(path, is_x=False):
    d = open(path, 'rb').read()
    hk = KEY_HEADER_X if is_x else KEY_HEADER
    hbuf = bytes(a ^ b for a, b in zip(d[:128], keystream(hk, 128)))
    typ, v1, v2, v3, keyidx, vbase = hbuf[0], hbuf[1], hbuf[2], hbuf[3], hbuf[4], hbuf[5]
    key, flashcrc, eepromcrc = struct.unpack_from('<HHH', hbuf, 6)
    softsize, timecreate = struct.unpack_from('<II', hbuf, 12)
    typaddr = hbuf[20]
    addr = struct.unpack_from('<I', hbuf, 21)[0]
    bootrev = hbuf[25]
    print(f"typ={typ} ver={v1}.{v2}.{v3} base={vbase} keyIdx={keyidx} key=0x{key:04X}")
    print(f"flashCrc=0x{flashcrc:04X} eepromCrc=0x{eepromcrc:04X} softSize={softsize}")
    print(f"timeCreate={datetime.datetime.utcfromtimestamp(timecreate)} typAddr={typaddr} addr=0x{addr:08X} bootRev={bootrev}")
    data = bytes(a ^ b for a, b in zip(d[128:], keystream(key, len(d) - 128)))
    crc = crc16_xmodem(data)
    print(f"dataLen={len(data)} crcCheck={'OK' if crc == flashcrc and softsize == len(data) else f'MISMATCH crc=0x{crc:04X}'}")
    return hbuf, data

if __name__ == '__main__':
    h, data = decode(sys.argv[1])
    open(sys.argv[2], 'wb').write(data)
    open(sys.argv[2] + '.hdr', 'wb').write(h)
