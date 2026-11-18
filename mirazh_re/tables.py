# Scan image for u32 function-pointer tables (runs of code-range VAs)
import struct, sys, json

BIN = sys.argv[1]
FW = sys.argv[2]
CODE_END = int(sys.argv[3], 16)
BASE = 0x100000
d = open(BIN, 'rb').read()

runs = []
cur = []
prev = None
for off in range(0x100, len(d) - 4, 4):
    v = struct.unpack_from("<I", d, off)[0]
    is_ptr = BASE <= v < BASE + CODE_END and (v & 3) == 0
    if is_ptr:
        if cur and off == prev + 4:
            cur.append((off, v))
        else:
            if len(cur) >= 4:
                runs.append(cur)
            cur = [(off, v)]
        prev = off
    else:
        if len(cur) >= 4:
            runs.append(cur)
        cur = []
if len(cur) >= 4:
    runs.append(cur)

out = []
for r in runs:
    off0 = r[0][0]
    ptrs = [v for _, v in r]
    uniq = len(set(ptrs))
    out.append({"addr": hex(BASE + off0), "n": len(r), "uniq": uniq,
                "targets": [hex(v) for v in ptrs]})
out.sort(key=lambda t: -t["n"])
json.dump(out, open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_tables.json", "w"), indent=1)
big = [t for t in out if t["n"] >= 8]
print("tables>=8:", len(big), "total:", len(out))
for t in big[:25]:
    print(t["addr"], "n=", t["n"], "uniq=", t["uniq"], "t0..t3:", t["targets"][:4])
