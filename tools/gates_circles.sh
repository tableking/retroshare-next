#!/usr/bin/env bash
# Circles acceptance, three nodes. alice is friends with bob (initially in the circle) and carol
# (outside it).
#
# Every negative assertion is paired with a positive control in the same round: carol must receive
# the public channel while being refused the private one, otherwise "no private posts" would be
# indistinguishable from "sync is broken" - and a privacy gate that can be satisfied by a broken
# product is worse than no gate.
#
# Deliberately linear: no mid-suite database wipes or re-bonding. An earlier revision reset the
# peers' state half-way through to "guarantee a clean measurement" and produced failures that had
# nothing to do with the feature.
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node; U=1000:1000
A=rs-alice; B=rs-bob; C=rs-carol
FAIL=0
pass(){ echo "PASS  $1"; }
fail(){ echo "FAIL  $1"; FAIL=$((FAIL+1)); }
rpc(){ if [ $# -ge 4 ]; then docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" "$4" 2>&1
     else docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" 2>&1; fi; }
fpof(){ docker exec -u $U -w /src $1 $BIN id $2 2>/dev/null | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}' | head -1; }
posts(){ rpc "$1" "$2" forum.list "{\"channel\":\"$3\"}" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["result"]["posts"]) if d.get("ok") else -1)' 2>/dev/null; }
total(){ rpc "$1" "$2" node.info | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["result"]["posts"] if d.get("ok") else -1)' 2>/dev/null; }
has_root(){ rpc "$1" "$2" node.info | python3 -c "import json,sys;print('yes' if '$3' in json.load(sys.stdin)['result']['channel_roots'] else 'no')" 2>/dev/null; }
has_chan(){ rpc "$1" "$2" channels.list | python3 -c "import json,sys;d=json.load(sys.stdin);print('yes' if any(c['name']=='$3' for c in d['result']['channels']) else 'no')" 2>/dev/null; }

for n in $A $B $C; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 1
rm -f ci_a.log ci_b.log ci_c.log ci_*.out
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* c_dir a_dir/peers.json b_dir/peers.json c_dir/peers.json \
       a_dir/pairing.json b_dir/pairing.json c_dir/pairing.json a_dir/rsnext.sock b_dir/rsnext.sock c_dir/rsnext.sock inv.txt
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
docker exec -u $U -w /src $C sh -c "$BIN init carol c_dir" >/dev/null 2>&1
CFP=$(fpof $C c_dir)
[ -n "$AFP" ] && [ -n "$BFP" ] && [ -n "$CFP" ] || { echo "ABORT: missing identities"; exit 1; }
echo "alice=$AFP bob=$BFP carol=$CFP"

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/ci_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/ci_b.log 2>&1"
docker exec -d -u $U -w /src $C sh -c "$BIN net c_dir 7803 > /src/ci_c.log 2>&1"
sleep 10
AE=$(awk '/endpoint_id\(hex\)/{print $3}' ci_a.log); AA=$(awk '/local_addr/{print $3}' ci_a.log)
[ -n "$AE" ] && [ -n "$AA" ] || { echo "ABORT: alice daemon not up"; exit 1; }

echo "=== K1 两位好友分别绑定（两个一次性码按序消耗）==="
docker exec -u $U -w /src $A $BIN invite2 a_dir CODE_BOB "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" > ci_ab.out 2>&1
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "bob hello" > ci_sb.out 2>&1
RB=$?
[ "$RB" = "0" ] && pass "K1a bob 绑定后首次联系成功" || fail "K1a bob 首次联系失败 rc=$RB: $(tail -2 ci_sb.out | tr -d '\r')"
docker exec -u $U -w /src $A $BIN invite2 a_dir CODE_CAROL "$AA" > inv.txt
docker exec -u $U -w /src $C sh -c "cd /src && $BIN accept c_dir \"\$(cat inv.txt)\"" > ci_ac.out 2>&1
docker exec -u $U -w /src $C timeout 60 $BIN p2p-send c_dir $AE $AA $AFP "carol hello" > ci_sc.out 2>&1
RC=$?
[ "$RC" = "0" ] && pass "K1b carol 绑定后首次联系成功" || fail "K1b carol 首次联系失败 rc=$RC: $(tail -2 ci_sc.out | tr -d '\r')"
PEERS=$(rpc $A a_dir peers.list | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["result"]["peers"]) if d.get("ok") else "ERR")' 2>/dev/null)
[ "${PEERS:-}" = "2" ] && pass "K1c alice 侧记录了两位好友" || fail "K1c alice 好友数=${PEERS:-空} 期望 2（ERR=RPC 失败，0=未绑定）"

echo "=== K2 一条私密内容 + 一条公开内容 ==="
docker exec -u $U -w /src $A $BIN channel-create a_dir secret "private plans" >/dev/null 2>&1
docker exec -u $U -w /src $A $BIN channel-create a_dir public "open talk" >/dev/null 2>&1
rpc $A a_dir forum.post '{"body":"classified: only for family","channel":"secret"}' >/dev/null
rpc $A a_dir forum.post '{"body":"hello everyone","channel":"public"}' >/dev/null
[ "$(posts $A a_dir secret)" = "1" ] && [ "$(posts $A a_dir public)" = "1" ] \
  && pass "K2 alice 两个频道各 1 帖（前提成立）" || fail "K2 前提不成立 secret=$(posts $A a_dir secret) public=$(posts $A a_dir public)"

echo "=== K3 基线：限制之前 bob 能收到私密帖 ==="
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > ci_b1.out 2>&1
[ "$(posts $B b_dir secret)" = "1" ] && pass "K3 bob 同步到私密帖（限制前的基线）" || fail "K3 bob 未收到: total=$(total $B b_dir) secret=$(posts $B b_dir secret)"

echo "=== K4 建立圈子并限制频道 ==="
docker exec -u $U -w /src $A $BIN circle-create a_dir family > ci_c1.out 2>&1
docker exec -u $U -w /src $A $BIN circle-add a_dir family "$BFP" > ci_c2.out 2>&1
docker exec -u $U -w /src $A $BIN restrict a_dir secret family > ci_c3.out 2>&1
grep -q 'only be sent to members' ci_c3.out && pass "K4a secret 已限制到 family" || fail "K4a $(tail -1 ci_c3.out | tr -d '\r')"
rpc $A a_dir circles.list | grep -q "\"$BFP\"" && pass "K4b 控制面能读到圈子成员" || fail "K4b circles.list 缺成员"

echo "=== K5 圈外人 carol：正文、根、定义都拿不到，公开频道照收 ==="
docker exec -u $U -w /src $C timeout 90 $BIN p2p-sync c_dir $AE $AA $AFP > ci_c4.out 2>&1
TT=$(total $C c_dir)
if [ "${TT:-0}" = "0" ]; then
  fail "K5a0 carol 整轮同步颗粒无收（total=0），隐私断言无从判断: $(tail -3 ci_c4.out | tr -d '\r')"
else
  pass "K5a0 carol 正常同步到内容（total=$TT），后续否定断言才有意义"
  [ "$(posts $C c_dir secret)" = "0" ] && pass "K5b 圈外人拿不到私密正文" || fail "K5b 私密正文泄露: $(posts $C c_dir secret) 帖"
  [ "$(has_root $C c_dir secret)" = "no" ] && pass "K5c 圈外人看不到 secret 的 merkle 根（频道存在性未泄露）" || fail "K5c 根泄露"
  [ "$(has_chan $C c_dir secret)" = "no" ] && pass "K5d 圈外人的频道列表里没有 secret（定义未随帖泄露）" || fail "K5d 定义泄露"
  [ "$(posts $C c_dir public)" = "1" ] && pass "K5e 同一轮里公开频道正常抵达（拦截是选择性的）" || fail "K5e 公开频道也没到，选择性无法证明"
fi

echo "=== K6 移出圈子立即生效 ==="
docker exec -u $U -w /src $A $BIN circle-remove a_dir family "$BFP" > ci_c5.out 2>&1
rpc $A a_dir forum.post '{"body":"second private note","channel":"secret"}' >/dev/null
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > ci_b2.out 2>&1
N=$(posts $B b_dir secret)
[ "$N" = "1" ] && pass "K6 移出后 bob 不再收到该频道新帖（仍为 1 帖）" || fail "K6 移出后 bob 有 $N 帖 期望仍为 1"

echo "=== K7 解除限制后恢复复制 ==="
docker exec -u $U -w /src $A $BIN unrestrict a_dir secret > ci_c6.out 2>&1
grep -qi 'public to friends again' ci_c6.out && pass "K7a 解除限制" || fail "K7a $(tail -1 ci_c6.out | tr -d '\r')"
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > ci_b3.out 2>&1
N2=$(posts $B b_dir secret)
[ "$N2" = "2" ] && pass "K7b 解除后 bob 补齐缺失那帖（2 帖）" || fail "K7b 解除后 $N2 帖 期望 2"

for n in $A $B $C; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
echo
echo "FAILURES=$FAIL"
exit $FAIL
