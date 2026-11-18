# SAM-BA restore tool for AT91SAM7S256 (Mirazh M8-03) via USART0 TTL serial.
# Protocol: ROM SAM-BA monitor ASCII terminal mode (W/w/G/V commands), plus
# SAM7S MC flash page programming (FMR=FFFFFF40 FCR=FFFFFF44 FSR=FFFFFF48).
# Usage: python sam_flash.py COM5 [image.bin] [--verify] [--unlock-only]
import sys, time, struct

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM3"
IMG  = sys.argv[2] if len(sys.argv) > 2 else r"C:\Users\Andrey\mirazh_re\m8-03_1_14.bin"
DO_VERIFY = "--verify" in sys.argv
BAUDS = [115200, 9600, 19200, 57600, 38400, 19200]

import serial  # pyserial

FLASH_BASE = 0x100000
NPAGES = 1024
PAGE = 256
IMG_LEN_LIMIT = 0x3C000          # app region only; config region 0x3C000+ NEVER touched
MC_FMR, MC_FCR, MC_FSR = 0xFFFFFF40, 0xFFFFFF44, 0xFFFFFF48
KEY = 0x5A
CMD_WP = 1                        # program page (auto-erase, SAM7S)
CMD_SLB = 2                       # set lock bit
CMD_CLB = 4                       # clear lock bit
LOCK_PAGES = list(range(0, 512, 32))   # SAM7S256: 16 lock regions: pages 0..1023, but 256K chip: region = 64 pages → 0,64,..,960
LOCK_PAGES = list(range(0, 1024, 64))

class Mon:
    def __init__(self, s):
        self.s = s
    def cmd(self, c, wait=1.0, read=False):
        self.s.reset_input_buffer()
        self.s.write(c.encode())
        time.sleep(0.02)
        if not read:
            return None
        self.s.timeout = wait
        r = b""
        while not r.endswith(b"#"):
            ch = self.s.read(1)
            if not ch:
                break
            r += ch
        return r.decode(errors="replace")
    def read32(self, addr):
        r = self.cmd("w%06X#" % addr, wait=2.0, read=True)
        if r is None:
            return None
        h = "".join(ch for ch in r if ch in "0123456789abcdefABCDEF")
        return int(h[:8], 16) if len(h) >= 8 else None
    def write32(self, addr, val):
        self.cmd("W%06X,%08X#" % (addr, val & 0xFFFFFFFF))

def hello_mon(s):
    for attempt in range(3):
        s.write(b"\x7F" + b"\x8B" * 129)
        s.flush()
        time.sleep(0.35)
        r = s.read(64)
        if b"S" in r or b">" in r:
            return True
        # also try plain terminal mode
        s.reset_input_buffer()
        s.write(b"V#\r\n")
        time.sleep(0.2)
        r = s.read(64)
        if r and any(c >= 32 for c in r):
            return True
    return False

def fsr(mon):
    return mon.read32(MC_FSR)

def wait_fsr(mon, tmo=10.0):
    t0 = time.time()
    while time.time() - t0 < tmo:
        f = fsr(mon)
        if f is None:
            return None
        if f & 1:
            return f
        time.sleep(0.05)
    return None

def program_image(mon, data):
    nimg = (len(data) + PAGE - 1) // PAGE
    print("pages to write: %d" % nimg)
    f = wait_fsr(mon)
    if f is None:
        print("FATAL: FSR not ready/not readable"); return False
    # 1) unlock everything
    print("unlocking lock regions...")
    for pg in LOCK_PAGES:
        wait_fsr(mon)
        mon.write32(MC_FCR, (KEY << 24) | (pg << 8) | CMD_CLB)
        f = wait_fsr(mon, 5)
        if f is None or (f and (f >> 2) & 1):
            print("unlock err at page %d FSR=%s" % (pg, None if f is None else hex(f)))
    # check locks cleared
    f = fsr(mon)
    if f is None:
        return False
    locked = (f >> 16) & 0xFFFF
    print("lock status after unlock: %04X" % locked)
    # 2) write + program each page
    t0 = time.time()
    for pg in range(nimg):
        base = FLASH_BASE + pg * PAGE
        chunk = data[pg*PAGE:(pg+1)*PAGE].ljust(PAGE, b"\xff")
        wait_fsr(mon)
        for w in range(0, PAGE, 4):
            v = struct.unpack_from("<I", chunk, w)[0]
            mon.write32(base + w, v)
        mon.write32(MC_FCR, (KEY << 24) | (pg << 8) | CMD_WP)
        f = wait_fsr(mon, 5)
        if f is None:
            print("FATAL: monitor lost at page %d" % pg); return False
        if f & 0x0E:   # FPER(bit1) LOCKE(bit2) FGA(bit3) per AT91C SAM7S MC_FSR
            print("ERR prog page %d FSR=%08X" % (pg, f))
            return False
        if pg % 64 == 0:
            el = time.time() - t0
            print("page %d/%d  %5.1f%%  %5.1fs" % (pg, nimg, 100.0*pg/nimg, el))
    print("programmed in %.1f s" % (time.time() - t0))
    # 3) relock all regions
    print("relocking...")
    for pg in LOCK_PAGES:
        wait_fsr(mon)
        mon.write32(MC_FCR, (KEY << 24) | (pg << 8) | CMD_SLB)
        wait_fsr(mon, 5)
    return True

def verify_image(mon, data):
    nimg = (len(data) + PAGE - 1) // PAGE
    bad = 0
    for pg in range(0, nimg, 8):   # spot-check every 8th page for speed
        base = FLASH_BASE + pg * PAGE
        for w in range(0, PAGE, 4):
            v = mon.read32(base + w)
            e = struct.unpack_from("<I", data[pg*PAGE + w:][:4].ljust(4, b"\xff"))[0]
            if v != e:
                bad += 1
                if bad < 20:
                    print("MISMATCH %06X got %08X exp %08X" % (base + w, v or -1, e))
    print("verify done, mismatches=%d" % bad)
    return bad == 0

def main():
    data = open(IMG, "rb").read(IMG_LEN_LIMIT)
    for baud in BAUDS:
        print("== trying %s @ %d" % (PORT, baud))
        try:
            s = serial.Serial(PORT, baud, timeout=1)
        except Exception as e:
            print("open fail:", e); continue
        mon = Mon(s)
        if not hello_mon(s):
            print("no SAM-BA answer at %d" % baud)
            s.close(); continue
        print("SAM-BA alive at %d" % baud)
        v = mon.cmd("V#", wait=2.0, read=True)
        print("monitor id:", (v or "").strip())
        ok = program_image(mon, data)
        if ok and DO_VERIFY:
            verify_image(mon, data)
        s.close()
        if ok:
            print("DONE")
            return
        print("retrying once with fresh handshake...")
    print("FAILED")

if __name__ == "__main__":
    main()
