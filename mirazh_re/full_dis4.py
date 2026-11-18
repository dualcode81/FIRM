# v4: strings = printable runs ANYWHERE; pool annotate by containment
import capstone, struct, re, sys, bisect

BIN = sys.argv[1]
OUT = sys.argv[2]
FUNCOUT = sys.argv[3]
CODE_END = int(sys.argv[4], 16)
BASE = 0x100000
d = open(BIN, 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

runs = []  # (start_off, s)
pat = re.compile(rb"[\x20-\x7e]{4,}|[\x80-\xff]{4,}|[\x20-\x7e\x80-\xff]{6,}")
for m in pat.finditer(d):
    runs.append((m.start(), m.group().decode('cp1251', errors='replace')))
starts = [r[0] for r in runs]
strmap = {BASE + s: txt for s, txt in runs}

def str_for_va(v):
    """string whose region contains VA v (v may point mid-run)."""
    i = bisect.bisect_right(starts, v - BASE) - 1
    if i >= 0:
        s, txt = runs[i]
        if s <= v - BASE < s + len(txt):
            off = v - BASE - s
            return txt[off:]
    return None

# function starts
fset = set()
for off in range(0, CODE_END - 4, 4):
    w = struct.unpack_from("<I", d, off)[0]
    if (w & 0x0F000000) == 0x0B000000:
        imm = w & 0xFFFFFF
        if imm & 0x800000:
            imm -= 0x1000000
        t = BASE + off + 8 + imm * 4
        if BASE <= t < BASE + CODE_END:
            fset.add(t - BASE)
    if (w >> 16) == 0xE92D and (w & 0x4000):
        fset.add(off)
fset.discard(0)

def annot(off, ops):
    m = re.search(r"\[pc,\s*#(-?)0x([0-9a-f]+)\]", ops)
    if m:
        imm = int(m.group(2), 16) * (-1 if m.group(1) else 1)
        pool = ((BASE + off + 8) & ~3) + imm
        p = pool - BASE
        if 0 <= p < len(d) - 3:
            v = struct.unpack_from("<I", d, p)[0]
            txt = str_for_va(v)
            if txt:
                return f"  ; '{txt[:60]}'"
            return f"  ; pool {pool:06X} = {v:08X}" + (f" f{v:06X}" if (v - BASE) in fset else "")
    if ops[:2] in ("bl", "bx"):
        m = re.search(r"#0x([0-9a-fA-F]+)", ops)
        if m:
            txt = str_for_va(int(m.group(1), 16))
            if txt:
                return f"  ; '{txt[:60]}'"
    return ""

recs = []
off = 0
nbad = 0
while off < CODE_END:
    got = None
    for insn in md.disasm(d[off:off + 4], BASE + off):
        got = insn
        break
    if got:
        recs.append((off, got.mnemonic, got.op_str))
    else:
        nbad += 1
        recs.append((off, None, None))
    off += 4

func_info = []
cur = None
nstr = 0
with open(OUT, "w", encoding="utf-8") as f:
    for off, mn, ops in recs:
        if off in fset:
            if cur:
                func_info.append(cur)
            cur = [off, 0]
            f.write(f"\n===== FUNC {BASE+off:06X} =====\n")
        w = struct.unpack_from("<I", d, off)[0]
        if mn is None:
            txt = str_for_va(BASE + off)
            extra = f"  ; '{txt[:60]}'" if txt else ""
            if txt:
                nstr += 1
            f.write(f"{off:05X}  .word      {w:08X}{extra}\n")
        else:
            f.write(f"{off:05X}  {mn:<10} {ops:<40} {w:08X}{annot(off, ops)}\n")
        if cur:
            cur[1] += 4
if cur:
    func_info.append(cur)

with open(FUNCOUT, "w", encoding="utf-8") as f:
    for s, ln in func_info:
        f.write(f"{BASE+s:06X} size={ln}\n")
print(f"recs={len(recs)} data={nbad} funcs={len(func_info)} runs={len(runs)} inline_str_words={nstr}")
