#!/usr/bin/env bash
# Forget (local erasure) acceptance. The property that matters is not "rows disappear" - it is that
# they stay gone when a peer who still holds them offers them back on the next sync. G3 is that
# assertion. G4 asserts the limitation as well, so the gate cannot be read as "deletion propagates".
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node; U=1000:1000
A=rs-alice; B=rs-bob
FAIL=0
pass(){ echo "PASS  $1"; }
fail(){ echo "FAIL  $1"; FAIL=$((FAIL+1)); }
rpc(){ if [ $# -ge 4 ]; then docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" "$4" 2>&1
     else docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" 2>&1; fi; }
fpof(){ docker exec -u $U -w /src $1 $BIN id $2 2>/dev/null | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}' | head -1; }
posts(){ rpc "$1" "$2" forum.list "{\"channel\":\"$3\"}" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["result"]["posts"]) if d.get("ok") else -1)' 2>/dev/null; }
docs(){ rpc "$1" "$2" search.status | python3 -c 'import json,sys;d=json.load(sys.stdin)["result"];print(d["docs"],d["posts"],d["files"])' 2>/dev/null; }

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 1
rm -f fg_a.log fg_b.log fg_*.out
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/peers.json b_dir/peers.json a_dir/pairing.json b_dir/pairing.json \
       a_dir/rsnext.sock b_dir/rsnext.sock inv.txt
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
[ -n "$AFP" ] && [ -n "$BFP" ] || { echo "ABORT: no identities"; exit 1; }

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/fg_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/fg_b.log 2>&1"
sleep 10
AE=$(awk '/endpoint_id\(hex\)/{print $3}' fg_a.log); AA=$(awk '/local_addr/{print $3}' fg_a.log)
BE=$(awk '/endpoint_id\(hex\)/{print $3}' fg_b.log); BA=$(awk '/local_addr/{print $3}' fg_b.log)
[ -n "$AE" ] && [ -n "$BE" ] || { echo "ABORT: daemons not up"; exit 1; }
docker exec -u $U -w /src $A $BIN invite2 a_dir FG1 "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" >/dev/null 2>&1
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "handshake" >/dev/null 2>&1

echo "=== G1 基线：两人都有 2 帖 ==="
docker exec -u $U -w /src $A $BIN channel-create a_dir notes x >/dev/null 2>&1
rpc $A a_dir forum.post '{"body":"first note","channel":"notes"}' >/dev/null
rpc $A a_dir forum.post '{"body":"second note","channel":"notes"}' >/dev/null
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > fg1.out 2>&1
[ "$(posts $A a_dir notes)" = "2" ] && [ "$(posts $B b_dir notes)" = "2" ] \
  && pass "G1 alice 与 bob 各有 2 帖" || fail "G1 基线不符 alice=$(posts $A a_dir notes) bob=$(posts $B b_dir notes)"

echo "=== G2 alice 本地擦除，索引同步干净 ==="
docker exec -u $U -w /src $A $BIN forget a_dir channel notes > fg2.out 2>&1
grep -q 'erased 2 local row' fg2.out && pass "G2a 擦除 2 行并说明只影响本节点" || fail "G2a $(tail -2 fg2.out | tr -d '\r')"
[ "$(posts $A a_dir notes)" = "0" ] && pass "G2b alice 该频道已空" || fail "G2b 仍有 $(posts $A a_dir notes) 帖"
read -r DOCS POSTS FILES <<<"$(docs $A a_dir)"
if [ "${DOCS:-x}" = "$(( ${POSTS:-0} + ${FILES:-0} ))" ]; then pass "G2c 擦除后索引不变量仍成立（docs=$DOCS posts=$POSTS files=$FILES）"
else fail "G2c 索引残留: docs=$DOCS 但 posts+files=$(( ${POSTS:-0} + ${FILES:-0} ))"; fi
rpc $A a_dir search.query '{"query":"note"}' | grep -q '"hits": \[\]' && pass "G2d 搜索也搜不到被擦除的内容" || fail "G2d 索引仍可搜到已擦除内容"

echo "=== G3 关键：对端把同一批帖子再推回来，不得复活 ==="
docker exec -u $U -w /src $A timeout 90 $BIN p2p-sync a_dir $BE $BA $BFP > fg3.out 2>&1
R3=$?
[ "$R3" = "0" ] || fail "G3a alice 主动同步失败 rc=$R3: $(tail -2 fg3.out | tr -d '\r')"
N=$(posts $A a_dir notes)
[ "$N" = "0" ] && pass "G3 已擦除的内容没有被同步回来（墓碑生效）" || fail "G3 复活了 $N 帖 —— 没有墓碑的话这正是必然结果"

echo "=== G4 边界如实记录：对端仍持有副本 ==="
[ "$(posts $B b_dir notes)" = "2" ] && pass "G4 bob 仍持有 2 帖（本地擦除不扩散，门禁不会把它写成隐私删除）" || fail "G4 bob 的副本数=$(posts $B b_dir notes) 期望 2"

echo "=== G5 墓碑不影响该频道后续内容 ==="
rpc $A a_dir forum.post '{"body":"third note after erase","channel":"notes"}' >/dev/null
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > fg5.out 2>&1
N5=$(rpc $B b_dir forum.list '{"channel":"notes"}' | python3 -c '
import json,sys
rows=json.load(sys.stdin)["result"]["posts"]
print(sum(1 for r in rows if "after erase" in r["body"]))' 2>/dev/null)
[ "${N5:-0}" = "1" ] && pass "G5 擦除后新帖照常复制到 bob（墓碑只挡被删的那几行）" || fail "G5 新帖未抵达 bob: $N5"

echo "=== G6 墓碑可审计 ==="
TB=$(rpc $A a_dir history.forgotten | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["result"]["tombstones"]))' 2>/dev/null)
[ "${TB:-0}" = "2" ] && pass "G6 history.forgotten 列出 2 条墓碑" || fail "G6 墓碑数=${TB:-空} 期望 2"

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
echo
echo "FAILURES=$FAIL"
exit $FAIL
