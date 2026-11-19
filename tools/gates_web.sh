#!/usr/bin/env bash
# WebUI bridge gate. The bridge is the only network-facing door of a node, so it is tested as one:
# auth before data, least privilege on the token file, loopback-only by default, and live events
# that actually reach a subscriber. Assertions are on persisted state, not on request echoes.
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node; U=1000:1000
A=rs-alice; B=rs-bob
FAIL=0
pass(){ echo "PASS  $1"; }
fail(){ echo "FAIL  $1"; FAIL=$((FAIL+1)); }

# pick an available HTTP client inside the image
client() { docker exec $1 sh -c 'command -v curl >/dev/null && echo curl || (command -v python3 >/dev/null && echo py) || echo none'; }
CLI=$(client $A)
[ "$CLI" = none ] && { echo "no http client in image (need curl or python3)"; exit 3; }
echo "http client: $CLI"

httpget(){ # container url [token]
  local c=$1 url=$2 tok=${3:-}
  if [ "$CLI" = curl ]; then
    docker exec "$c" curl -sS -o - -w '\n%{http_code}' ${tok:+-H "authorization: Bearer $tok"} "$url" 2>&1
  else
    docker exec -e U_="$url" -e T_="$tok" "$c" python3 -c '
import os,urllib.request
req=urllib.request.Request(os.environ["U_"])
if os.environ.get("T_"): req.add_header("authorization","Bearer "+os.environ["T_"])
try:
    r=urllib.request.urlopen(req,timeout=8); print(r.read().decode()); print(r.status)
except urllib.error.HTTPError as e: print(e.read().decode()); print(e.code)'
  fi
}
httppost(){ # container url json [token]
  local c=$1 url=$2 body=$3 tok=${4:-}
  if [ "$CLI" = curl ]; then
    docker exec "$c" curl -sS -X POST -H 'content-type: application/json' ${tok:+-H "authorization: Bearer $tok"} -d "$body" "$url" 2>&1
  else
    docker exec -e U_="$url" -e B_="$body" -e T_="$tok" "$c" python3 -c '
import os,urllib.request
req=urllib.request.Request(os.environ["U_"],data=os.environ["B_"].encode(),method="POST")
req.add_header("content-type","application/json")
if os.environ.get("T_"): req.add_header("authorization","Bearer "+os.environ["T_"])
try: print(urllib.request.urlopen(req,timeout=15).read().decode())
except urllib.error.HTTPError as e: print(e.read().decode())'
  fi
}

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done; sleep 1
rm -f web_a.log web_b.log sse_a.log
rm -rf a_dir/web.token b_dir/web.token
docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/web_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/web_b.log 2>&1"
sleep 10
AE=$(awk '/endpoint_id\(hex\)/{print $3}' web_a.log); AA=$(awk '/local_addr/{print $3}' web_a.log)
BE=$(awk '/endpoint_id\(hex\)/{print $3}' web_b.log); BA=$(awk '/local_addr/{print $3}' web_b.log)
AFP=$(docker exec -u $U -w /src $A $BIN id a_dir | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}')
BFP=$(docker exec -u $U -w /src $B $BIN id b_dir | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}')

docker exec -d -u $U -w /src $A sh -c "$BIN web a_dir 127.0.0.1:8780 > /src/web_http.log 2>&1"; sleep 3
TOK=$(docker exec $A cat a_dir/web.token 2>/dev/null | tr -d '\r\n')
[ -n "$TOK" ] && pass "H1 token 已生成并落在数据目录" || fail "H1 没有生成 token"
MODE=$(docker exec $A sh -c 'stat -c %a /src/a_dir/web.token' 2>/dev/null | tr -d '\r')
[ "$MODE" = "600" ] && pass "H2 token 文件权限 0600" || fail "H2 token 权限是 $MODE"

OUT=$(httpget $A http://127.0.0.1:8780/health | tail -1)
[ "$OUT" = "200" ] && pass "H3 /health 免鉴权可探活" || fail "H3 /health -> $OUT"

PAGE=$(httpget $A http://127.0.0.1:8780/)
CODE=$(printf '%s\n' "$PAGE" | tail -1)
{ [ "$CODE" = "200" ] && printf '%s' "$PAGE" | grep -qi 'RetroShare-Next'; } && pass "H4 UI 外壳可获取（含应用标题）" || fail "H4 UI -> code=$CODE"

NOAUTH=$(httppost $A http://127.0.0.1:8780/rpc '{"method":"node.info"}' | tr -d '\r')
echo "$NOAUTH" | grep -q 'bearer token' && pass "H5 无 token 的 /rpc 被拒（401，不返回任何数据）" || fail "H5 无鉴权竟然通过: $NOAUTH"
BAD=$(httppost $A http://127.0.0.1:8780/rpc '{"method":"node.info"}' wrongtoken | tr -d '\r')
echo "$BAD" | grep -q 'bearer token' && pass "H6 错误 token 被拒" || fail "H6 错误 token 却通过: $BAD"

OK=$(httppost $A http://127.0.0.1:8780/rpc '{"method":"node.info"}' "$TOK" | tr -d '\r')
echo "$OK" | grep -q '"ok": *true' && pass "H7 带 token 的 /rpc 正常返回 node.info" || fail "H7: $OK"

httppost $A http://127.0.0.1:8780/rpc "{\"method\":\"forum.post\",\"params\":{\"body\":\"via web bridge\"}}" "$TOK" >/dev/null
python3 -c "
import sqlite3
rows=[r[0] for r in sqlite3.connect('a_dir/rsnext.db').execute('SELECT body FROM posts')]
assert 'via web bridge' in rows, rows" && pass "H8 通过 HTTP 发的帖子落进节点数据库（收方状态为准）" || fail "H8 未落库"

# live events: subscribe over SSE, then have bob send alice a DM through the normal path
docker exec -d -u $U -w /src -e TK="$TOK" $A python3 -u -c '
import os, urllib.request
r = urllib.request.Request("http://127.0.0.1:8780/events")
r.add_header("authorization", "Bearer " + os.environ["TK"])
with urllib.request.urlopen(r, timeout=90) as resp, open("/src/sse_a.log", "ab", buffering=0) as f:
    for line in resp:
        f.write(line)
'
sleep 2
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "sse over bridge" >/dev/null 2>&1
sleep 3
SSE_HITS=$(docker exec $A sh -c 'grep -c "chat" /src/sse_a.log 2>/dev/null || true' | tr -d '\r')
[ "${SSE_HITS:-0}" -ge 1 ] && pass "H9 私信事件经 SSE 实时送达订阅者" || fail "H9 SSE 未收到事件: $(docker exec $A head -c 200 /src/sse_a.log 2>/dev/null | tr -d '\r')"

# loopback-only by default: a neighbouring container must not be able to reach the bridge
echo "=== H11 控制面自报的方法表与源码一致 ==="
# The inventory is generated from the dispatch arms, so it can drift the moment someone adds a
# handler and forgets to regenerate. Diffing the live node against the source makes that a red gate
# instead of a UI that silently calls a method that answers "unknown method".
docker exec -u $U -w /src $A $BIN rpc a_dir api.methods > api_methods.out 2>&1
if python3 - <<'PY'
import json, re, sys
live = json.load(open('api_methods.out'))['result']['methods']
src = open('crates/rsnext-node/src/rpc.rs', encoding='utf-8').read().replace('\r\n', '\n')
arms = set()
for line in src.split('\n'):
    s = line.strip()
    if s.startswith('"') and '" =>' in s:
        n = s[1:s.index('"', 1)]
        if '.' in n and n != 'api.methods':
            arms.add(n)
arms.add('api.methods')
missing = sorted(arms - set(live))
extra   = sorted(set(live) - arms)
print(f'   source arms={len(arms)} reported={len(live)}')
if missing: print('   not reported:', missing)
if extra:   print('   reported but no arm:', extra)
sys.exit(1 if (missing or extra) else 0)
PY
then pass "H11 api.methods 与 rpc.rs 的 dispatch 分支完全一致（共 $(python3 -c "import json;print(len(json.load(open('api_methods.out'))['result']['methods']))" 2>/dev/null) 个方法）"
else fail "H11 方法表与源码不一致（跑 python3 tools/gen_api_methods.py 重新生成）"; fi

AIP=$(awk '/local_addr/{print $3}' web_a.log | cut -d: -f1)
REACH=$(docker exec $B sh -c "timeout 4 sh -c 'echo > /dev/tcp/$AIP/8780' 2>/dev/null && echo yes || echo no" | tr -d '\r')
[ "$REACH" = no ] && pass "H10 桥仅绑回环：跨容器不可达（默认安全）" || fail "H10 桥在 $AIP:8780 对外暴露"

docker exec $B sh -c 'pkill -x rsnext-node; exit 0'
docker exec $A sh -c 'for p in $(pgrep -x rsnext-node); do tr "\0" " " < /proc/$p/cmdline | grep -q "web a_dir" && kill $p; done; pkill -x rsnext-node; exit 0' 2>/dev/null
echo; echo "FAILURES=$FAIL"; exit $FAIL
