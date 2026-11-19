#!/usr/bin/env python3
"""(Re)generate `api.methods` from the dispatch arms in rpc.rs.

The inventory is a static list because Rust gives no runtime reflection over match arms, which makes
drift certain unless something checks. Two things check it: this script regenerates the list from the
source, and gates_web.sh diffs what a running node reports against the arms it can grep out of the
same file. Either alone would rot.

Idempotent: run it again after adding a handler.
"""
import io
import re
import sys

R = 'crates/rsnext-node/src/rpc.rs'
raw = io.open(R, encoding='utf-8', newline='').read()
crlf = '\r\n' in raw
t = raw.replace('\r\n', '\n')

START = '        "api.methods" => {'
END = '            ]}))\n        }\n'


def discover(text):
    out = set()
    for line in text.split('\n'):
        s = line.strip()
        if s.startswith('"') and s.endswith('=> {') or ('" =>' in s and s.startswith('"')):
            name = s[1:s.index('"', 1)]
            if '.' in name and name != 'api.methods':
                out.add(name)
    return out


methods = discover(t) | {'api.methods'}
if len(methods) < 20:
    raise SystemExit(f'refusing: only {len(methods)} methods discovered - extraction is broken')

arm = (START + '\n'
       '            // The control plane\'s own surface, so a UI or script can check before calling.\n'
       '            // This array is generated from the dispatch arms in this file (see\n'
       '            // tools/publish docs), and gates_web.sh diffs the running node\'s answer against\n'
       '            // those same arms - an inventory nobody verifies is worse than none.\n'
       '            Ok(json!({"methods": [\n'
       + ',\n'.join('                "%s"' % m for m in sorted(methods)) + '\n'
       + END)

if START in t:
    i = t.index(START)
    j = t.index(END, i) + len(END)
    t = t[:i] + arm + t[j:]
    verb = 'regenerated'
else:
    anchor = '        "peers.ban" => {'
    if t.count(anchor) != 1:
        raise SystemExit('ANCHOR peers.ban not unique')
    t = t.replace(anchor, arm + anchor, 1)
    verb = 'inserted'

io.open(R, 'w', encoding='utf-8', newline='').write(t.replace('\n', '\r\n') if crlf else t)
print(f'{verb} api.methods with {len(methods)} entries')
if '--check' in sys.argv:
    # used by the gate: report any arm missing from the list
    now = discover(io.open(R, encoding='utf-8', newline='').read().replace('\r\n', '\n'))
    listed = set(re.findall(r'"([a-z]+\.[a-z_]+)"', t[t.index(START):t.index(END) + 4]))
    missing = sorted(now - listed)
    print('arms not listed:', missing or 'none')
    sys.exit(1 if missing else 0)
