# Master functional doc: subsystems w/ function addresses + evidence strings
import json, re, sys, collections

FW = sys.argv[1]  # m8 | a8
fm = json.load(open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_fmap.json", encoding="utf-8"))
tables = json.load(open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_tables.json", encoding="utf-8"))

def strs(addr_hex, k=4):
    v = fm.get(addr_hex) or fm.get(addr_hex.lower()) or {}
    return v.get("strings", [])[:k], v.get("calls", [])[:6], v.get("called_by", [])[:6]

out = []
W = out.append
W(f"# {FW.upper()} — функциональная карта (автоген)\n")
W("\n## Диспетчерские таблицы (указатели функций в данных)\n")
for t in tables:
    if t["n"] < 8:
        continue
    W(f"\nTABLE {t['addr']} ({t['n']} энтов):")
    for tgt in t["targets"]:
        s, c, b = strs(tgt, 3)
        W(f"   -> {tgt}  {' | '.join(x[:40] for x in s) if s else ''}")

W("\n\n## Функции с протокольными/модемными строками\n")
proto = []
for f, d in fm.items():
    for s in d["strings"]:
        if re.match(r"^(AT\+|AT[SDH]|\+C|PL-|CH-|MSRV|Msrv|MGS=)", s):
            proto.append((int(f, 16), f, d))
            break
proto.sort()
for _, f, d in proto:
    W(f"{f}: {' | '.join(x[:48] for x in d['strings'][:5])}")

W("\n\n## Функции с русскими строками (пользовательский функционал)\n")
ru = []
for f, d in fm.items():
    rus = [s for s in d["strings"] if re.search(r"[а-яА-ЯёЁ]", s)]
    if rus:
        ru.append((int(f, 16), f, rus))
ru.sort()
for _, f, rus in ru[:80]:
    W(f"{f}: {' | '.join(x[:44] for x in rus[:4])}")

open(rf"E:\Hermess\cache\scratch\mirazh\{FW}_master.md", "w", encoding="utf-8").write("\n".join(out))
print("sections:", len(out), "->", FW + "_master.md")
