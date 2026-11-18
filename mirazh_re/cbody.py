import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
name = sys.argv[2]
maxlen = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
# find definition (has '{')
m = re.search(rf"(?:int32_t|void|int|uint32_t) {re.escape(name)}\([^;]*?\)\s*{{.*?(?=\n(?:int32_t|void|int|uint32_t) (?:f[nN]c|function_)|\Z)", src, re.S)
print(m.group(0)[:maxlen] if m else f"definition of {name} not found")
