#!/usr/bin/env bash
# M3 RSS gate: subscribe -> poll -> guid dedupe -> feed-level error isolation -> replication.
# A feed item becomes a post in a channel named after the subscription, so RSS inherits the
# per-channel merkle roots: R5 asserts BOTH nodes agree on the root of a feed-derived channel,
# which is the proof the integration is real and not a private side-store.
# The feed is served from inside the bob container (127.0.0.1:8899): no external network needed.
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node; U=1000:1000
A=rs-alice; B=rs-bob
FAIL=0
pass(){ echo "PASS  $1"; }
fail(){ echo "FAIL  $1"; FAIL=$((FAIL+1)); }
rpc(){ if [ $# -ge 4 ]; then docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" "$4" 2>&1
     else docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" 2>&1; fi; }
# grep-style assertion, mirroring gates_m2.sh: defined here because each suite is standalone
ok(){ if grep -q "$1" "$2"; then pass "$3"; else fail "$3 (missing /$1/ in $(tail -2 "$2" | tr -d '\r' | tr '\n' ' '))"; fi; }
jget(){ python3 -c "import json,sys;d=json.load(sys.stdin);print(eval('d'+sys.argv[1]))" "$1" 2>/dev/null; }

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
docker exec $B sh -c 'pkill -f "http.server 8899"; exit 0'
sleep 1
rm -f rss_a.log rss_b.log rss_*.out
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/peers.json b_dir/peers.json a_dir/pairing.json b_dir/pairing.json
rm -rf rss_fixture

fpof(){ docker exec -u $U -w /src $1 $BIN id $2 2>/dev/null | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}' | head -1; }
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
[ -n "$AFP" ] && [ -n "$BFP" ] || { echo "ABORT: no node identity"; exit 1; }

mkdir -p rss_fixture
feed_item(){ printf '  <item><guid>%s</guid><title>%s</title><link>https://example.test/%s</link><pubDate>Tue, 02 Jan 2024 0%d:00:00 GMT</pubDate></item>\n' "$1" "$2" "$1" "$3"; }
{ echo '<?xml version="1.0"?><rss version="2.0"><channel><title>Project log</title>'; feed_item g1 'first entry' 1; feed_item g2 'second &amp; entity' 2; echo '</channel></rss>'; } > rss_fixture/feed.xml

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/rss_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/rss_b.log 2>&1"
docker exec -d -u $U -w /src $B sh -c 'cd /src/rss_fixture && python3 -m http.server 8899 >/dev/null 2>&1'
sleep 9
AE=$(awk '/endpoint_id\(hex\)/{print $3}' rss_a.log); AA=$(awk '/local_addr/{print $3}' rss_a.log)
[ -n "$AE" ] && [ -n "$AA" ] && pass "gateR0 两端 daemon 就绪，feed server 已起" || { echo "ABORT: daemon 未就绪"; exit 1; }
docker exec -u $U -w /src $A $BIN invite2 a_dir P1 "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" >/dev/null 2>&1

URL='http://127.0.0.1:8899/feed.xml'
echo "=== R1 订阅与首次抓取 ==="
docker exec -u $U -w /src $B $BIN rss-add b_dir "$URL" log > rss_add.out 2>&1
ok "$URL" rss_add.out "gateR1a rss-add 记录了 URL"
docker exec -u $U -w /src $B $BIN rss-fetch b_dir > rss_f1.out 2>&1
grep -q '"posted": 2' rss_f1.out && pass "gateR1b 首次抓取投递 2 条" || fail "gateR1b 未投递 2 条: $(tail -3 rss_f1.out | tr -d '\r')"
docker exec -u $U -w /src $B $BIN channel-list b_dir > rss_ch.out 2>&1
grep -q 'log' rss_ch.out && pass "gateR1c 订阅生成了同名频道" || fail "gateR1c 频道未出现: $(tail -3 rss_ch.out | tr -d '\r')"

posts(){ rpc "$1" "$2" forum.list "{\"channel\":\"$3\"}" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["result"]["posts"]))' 2>/dev/null; }

echo "=== R2 重抓必须一条不增（guid 去重）==="
docker exec -u $U -w /src $B $BIN rss-fetch b_dir > rss_f2.out 2>&1
grep -q '"posted": 0' rss_f2.out && pass "gateR2a 第二次 posted=0" || fail "gateR2a 重复投递: $(tail -3 rss_f2.out | tr -d '\r')"
[ "$(posts $B b_dir log)" = "2" ] && pass "gateR2b 频道内仍是 2 帖（没有重复条目）" || fail "gateR2b 帖子数=$(posts $B b_dir log) 期望 2"

echo "=== R3 上游新增一条，只补新条目 ==="
{ echo '<?xml version="1.0"?><rss version="2.0"><channel><title>Project log</title>'; feed_item g1 'first entry' 1; feed_item g2 'second &amp; entity' 2; feed_item g3 'third arrived' 3; echo '</channel></rss>'; } > rss_fixture/feed.xml
docker exec -u $U -w /src $B $BIN rss-fetch b_dir > rss_f3.out 2>&1
grep -q '"posted": 1' rss_f3.out && pass "gateR3a 增量 posted=1" || fail "gateR3a 增量异常: $(tail -3 rss_f3.out | tr -d '\r')"
[ "$(posts $B b_dir log)" = "3" ] && pass "gateR3b 频道累计 3 帖" || fail "gateR3b 帖子数=$(posts $B b_dir log) 期望 3"

echo "=== R4 一个坏订阅不能拖垮整轮抓取 ==="
docker exec -u $U -w /src $B $BIN rss-add b_dir 'http://127.0.0.1:9/dead.xml' dead >/dev/null 2>&1
docker exec -u $U -w /src $B timeout 60 $BIN rss-fetch b_dir > rss_f4.out 2>&1
grep -q '"error"' rss_f4.out && pass "gateR4a 坏 feed 以 error 字段报告" || fail "gateR4a 未报告错误"
grep -q '"feed": "log"' rss_f4.out && pass "gateR4b 好 feed 仍然被抓取" || fail "gateR4b 好 feed 被跳过"

echo "=== R5 feed 频道参与 merkle 复制（这是复用频道机制的全部意义）==="
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > rss_sync.out 2>&1
RA=$(rpc $A a_dir node.info | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)["result"]["channel_roots"],sort_keys=True))')
RB=$(rpc $B b_dir node.info | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)["result"]["channel_roots"],sort_keys=True))')
echo "     alice roots: $RA"
echo "     bob   roots: $RB"
[ "$RA" = "$RB" ] && pass "gateR5a 两端 per-channel roots 一致" || fail "gateR5a roots 不一致"
echo "$RA" | grep -q '"log"' && pass "gateR5b feed 频道已复制到 alice" || fail "gateR5b alice 上没有 log 频道"
[ "$(posts $A a_dir log)" = "3" ] && pass "gateR5c alice 收到 3 条 feed 帖子" || fail "gateR5c alice 帖子数=$(posts $A a_dir log) 期望 3"

docker exec $B sh -c 'pkill -f "http.server 8899"; exit 0'
echo
echo "FAILURES=$FAIL"
exit $FAIL
