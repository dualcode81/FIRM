# Build function map from annotated listing (uppercase hex safe)
import re, sys, json, collections

LST, FUNCS, OUT = sys.argv[1], sys.argv[2], sys.argv[3]

LINE = re.compile(r"^([0-9a-fA-F]{5})\s+(\.word|[a-z]+)\s\s(.*?)\s\s([0-9A-Fa-f]{8})(.*)$")

funcs = {}
callers = collections.defaultdict(set)
cur = None
for line in open(LST, encoding="utf-8"):
    m = re.match(r"===== FUNC (\w+) =====", line)
    if m:
        cur = int(m.group(1), 16)
        funcs[cur] = {"strings": [], "calls": set(), "words": []}
        continue
    if cur is None:
        continue
    line = line.rstrip("\n")
    m = LINE.match(line)
    if not m:
        continue
    mn, ops, w, note = m.group(2), m.group(3), m.group(4), m.group(5).strip()
    if mn == ".word":
        wv = int(w, 16)
        sm = re.search(r"; (.*)", note)
        if sm:
            funcs[cur]["strings"].append(sm.group(1))
        continue
    bm = re.search(r"#(0x[0-9A-Fa-f]+)", ops)
    if mn in ("bl", "blx") and bm:
        t = int(bm.group(1), 16)
        funcs[cur]["calls"].add(t)
        callers[t].add(cur)
    sm = re.search(r"'(.*)'", note)
    if sm:
        funcs[cur]["strings"].append(sm.group(1))
    else:
        pm = re.search(r"= (\w+)$", note)
        if pm:
            funcs[cur]["words"].append(pm.group(1))

out = {hex(f): {"strings": d["strings"],
                "calls": sorted(hex(c) for c in d["calls"]),
                "called_by": sorted(hex(c) for c in callers.get(f, ())),
                "words": d["words"]}
       for f, d in funcs.items()}
json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("funcs:", len(out), "with strings:", sum(1 for v in out.values() if v["strings"]),
      "refs:", sum(len(v["strings"]) for v in out.values()))

kw = {
 "sms": ["SMS", "CMGS", "CMGF", "CMGR", "CMGL", "CMGD", "MSRV", "PDU", "+CMT"],
 "call": ["CRING", "CLIP", "ATD", "ATH", "ATA", "RING", "VOICE", "DTMF", "VGT", "S0="],
 "gprs_net": ["GPRS", "TCP", "PPP", "PING", "COPS", "CSQ", "CGREG", "CIREG", "SOCKET"],
 "journal": ["Журнал", "обыт", "Восстановлен", "восстанов"],
 "alarm": ["Пожар", "Тревог", "тревог", "Охран", "охран", "Взят", "Снят", "взят", "снят", "Сабот", "Невзят", "Шлеиф", "Шлейф", "аздел"],
 "power": ["220", "АКБ", "Батаре", "батар", "Питан", "питан"],
 "config_cmd": ["READ_", "WRITE_", "SET_", "конфиг", "настрой", "арол", "Serial"],
 "fw_flash": ["Boot", "Flash", "бнов", "AT45DB", "DataFlash", "擦"],
 "tone_siren": ["Сирен", "сирен", "Звук", "звук", "tone", "Tone", "Alton", "audio"],
}
groups = collections.defaultdict(list)
for f, d in out.items():
    blob = " ".join(d["strings"])
    for g, keys in kw.items():
        if any(k in blob for k in keys):
            groups[g].append(f)
for g in sorted(groups):
    print(g, len(groups[g]))
json.dump({g: v for g, v in groups.items()}, open(OUT + ".groups.json", "w"), indent=1)
