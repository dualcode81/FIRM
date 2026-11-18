# Functional report: subsystems, entry points, call chains, patch sites
import json, re, collections, sys

FW = sys.argv[1] if len(sys.argv) > 1 else "m8"
BASE = 0x100000
fm = json.load(open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_fmap.json", encoding="utf-8"))
dis = open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_full_dis.txt", encoding="utf-8").read()
funcs = {}
cur = None
for line in dis.splitlines():
    m = re.match(r"===== FUNC (\w+) =====", line)
    if m:
        cur = int(m.group(1), 16)
        funcs[cur] = []
        continue
    if cur is not None:
        funcs[cur].append(line)

def a2i(s):
    return int(s, 16)

# name functions by their string refs
names = {}
for f, d in fm.items():
    fi = a2i(f)
    tag = None
    for s in d["strings"]:
        if re.match(r"^(AT\+|[A-Z]{3,}=?|PL-|CH-)", s):
            tag = s; break
    names[fi] = tag

def chain(target, depth=4):
    """who calls target, transitively (upward chain)."""
    lvl = {target}
    seen = {target}
    out = []
    for _ in range(depth):
        nxt = set()
        for f in lvl:
            for c in fm.get(hex(f), {}).get("called_by", []):
                ci = a2i(c)
                if ci not in seen:
                    nxt.add(ci)
                    out.append((_, ci))
        seen |= nxt
        lvl = nxt
        if not lvl:
            break
    return out

def subsys(f):
    d = fm.get(hex(f), {})
    blob = " ".join(d["strings"])
    tags = []
    if re.search(r"CMG|SMS|MSRV|PDU", blob): tags.append("SMS")
    if re.search(r"CRING|CLIP|VOICE|DTMF|ATD|ATA|ATH|S0=", blob): tags.append("CALL")
    if re.search(r"COPS|CSQ|GPRS|TCP|CIP|Socket|PPP", blob): tags.append("NET")
    if re.search(r"Пожар|Тревог|охран|Охран|Шлейф|Шлеиф|Раздел|Снят|Взят|Сабот", blob): tags.append("ALARM")
    if re.search(r"220|АКБ|Питан|Батар", blob): tags.append("POWER")
    if re.search(r"Журнал|обыт|Восстанов", blob): tags.append("JOURNAL")
    if re.search(r"Flash|AT45|Boot|бнов", blob): tags.append("FLASH")
    return tags

report = []
W = report.append
W(f"# {FW.upper()} firmware functional map (auto)\n")

# 1. functions with >=1 string ref, grouped by tag
W("\n## 1. Functions that reference known protocol/AT strings\n")
scored = []
for f, d in fm.items():
    if d["strings"]:
        scored.append((a2i(f), d))
scored.sort()
for fi, d in scored:
    W(f"\n### f{fi:06X}  refs={len(d['strings'])} calls={len(d['calls'])} callers={[hex(a2i(c)) for c in d['called_by']]}")
    W("  strings: " + " | ".join(dict.fromkeys(d["strings"]))[:400])

# 2. SMS send chain upward
W("\n\n## 2. Upward call chains to key routines\n")
KEYS = []
if FW == "m8":
    KEYS = [0x12E5A8, 0x1258DC, 0x1256B8, 0x11442C, 0x114224, 0x104BF4, 0x104C84]
else:
    # find A8 sms send: funcs referencing CMGS
    KEYS = [a2i(f) for f, d in fm.items() if any("CMGS" in s for s in d["strings"])]
for k in KEYS:
    W(f"\nup-chain from f{k:06X}:")
    for lvl, c in chain(k):
        d = fm.get(hex(c), {})
        W(f"  L{lvl+1} f{c:06X} {'['+','.join(subsys(c))+']' if subsys(c) else ''} {' '.join(d.get('strings',[])[:3])[:120]}")

# 3. big functions likely subsystem cores
W("\n\n## 3. Largest functions (subsystem cores)\n")
sizes = []
for f, body in funcs.items():
    sizes.append((len(body), f))
sizes.sort(reverse=True)
for ln, fi in sizes[:25]:
    d = fm.get(hex(fi), {})
    s = (d["strings"][0] if d["strings"] else "")[:60]
    W(f"  f{fi:06X} insns={ln:<5} callers={len(d['called_by'])} refs={len(d['strings'])} {s}")

open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_func_report.md", "w", encoding="utf-8").write("\n".join(report))
print("wrote", FW + "_func_report.md", "sections:", len(report))
