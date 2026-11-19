#!/usr/bin/env bash
# Ban list acceptance. The point of a ban is that it outranks an authenticated friend, so the gate
# binds first and only then bans - testing a ban against a stranger would pass even if the check
# were placed after the identity proof, which is exactly the ordering that cannot work.
#   B1 banned peer cannot deliver; B2 nothing lands in the inbox; B3 the refusal is explained;
#   B4 the ban list is inspectable with its reason; B5 unban restores delivery; B6 the ban survives
#   a daemon restart (a memory-only list would be a lie).
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node; U=1000:1000
A=rs-alice; B=rs-bob
FAIL=0
pass(){ echo "PASS  $1"; }
fail(){ echo "FAIL  $1"; FAIL=$((FAIL+1)); }
rpc(){ if [ $# -ge 4 ]; then docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" "$4" 2>&1
     else docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" 2>&1; fi; }
inbox_n(){ rpc $A a_dir chat.inbox '{"limit":99}' | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["result"]["messages"]) if d.get("ok") else -1)' 2>/dev/null; }
fpof(){ docker exec -u $U -w /src $1 $BIN id $2 2>/dev/null | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}' | head -1; }

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 1
rm -f bn_a.log bn_b.log bn_*.out
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/peers.json b_dir/peers.json a_dir/pairing.json b_dir/pairing.json \
       a_dir/inbox.json a_dir/rsnext.sock b_dir/rsnext.sock inv.txt
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
[ -n "$AFP" ] && [ -n "$BFP" ] || { echo "ABORT: no node identity"; exit 1; }

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/bn_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/bn_b.log 2>&1"
sleep 9
AE=$(awk '/endpoint_id\(hex\)/{print $3}' bn_a.log); AA=$(awk '/local_addr/{print $3}' bn_a.log)
[ -n "$AE" ] && [ -n "$AA" ] || { echo "ABORT: daemons not up"; exit 1; }

echo "=== 先正常建立友谊（封禁必须能压过已绑定关系）==="
docker exec -u $U -w /src $A $BIN invite2 a_dir BC1 "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" >/dev/null 2>&1
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "hello before ban" > bn0.out 2>&1
R0=$?
[ "$R0" = "0" ] && pass "B0 绑定后通信正常（封禁测试的前提成立）" || { fail "B0 基线通信就失败，后续无法判定"; echo "FAILURES=$FAIL"; exit $FAIL; }
[ "$(inbox_n)" = "1" ] && pass "B0b 消息确实送达 alice" || fail "B0b 收件数=$(inbox_n) 期望 1"

echo "=== B1/B2/B3 封断后不再投递 ==="
docker exec -u $U -w /src $A $BIN ban a_dir "$BFP" "spam" > bn1.out 2>&1
grep -q "banned $BFP" bn1.out && pass "B1a alice 把 bob 列入封禁（含原因）" || fail "B1a $(tail -1 bn1.out | tr -d '\r')"
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "should never arrive" > bn2.out 2>&1
R2=$?
[ "$R2" != "0" ] && pass "B1b 被封禁方发送失败（非零退出 $R2，而不是静默成功）" || fail "B1b 封禁后发送仍返回 0"
[ "$(inbox_n)" = "1" ] && pass "B2 被封禁的消息没有落进收件箱（仍为 1 条）" || fail "B2 收件数=$(inbox_n)，封禁期间竟写入了消息"
grep -qi 'banned' bn_a.log && pass "B3 alice 日志说明了拒绝原因（banned）" || fail "B3 日志缺少可读原因: $(tail -2 bn_a.log | tr -d '\r')"

echo "=== B4 名单可查 ==="
docker exec -u $U -w /src $A $BIN bans a_dir > bn4.out 2>&1
grep -q "$BFP" bn4.out && grep -q 'spam' bn4.out && pass "B4 bans 列出指纹与原因" || fail "B4 名单不完整: $(tail -2 bn4.out | tr -d '\r')"
rpc $A a_dir peers.bans | grep -q '"reason": "spam"' && pass "B4b 控制面同样能读名单" || fail "B4b peers.bans 无该条目"

echo "=== B6 重启后封禁依然生效（名单必须持久，不是在内存里）==="
docker exec $A sh -c 'pkill -x rsnext-node; exit 0'; sleep 2
docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/bn_a2.log 2>&1"
sleep 9
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "after restart" > bn6.out 2>&1
R6=$?
[ "$R6" != "0" ] && [ "$(inbox_n)" = "1" ] && pass "B6 daemon 重启后封禁仍然拦截（非零退出且未写入）" || fail "B6 重启后封禁失效 rc=$R6 收件=$(inbox_n)"

echo "=== B5 解封恢复通信（不破坏既有绑定）==="
docker exec -u $U -w /src $A $BIN unban a_dir "$BFP" > bn5.out 2>&1
grep -qi 'unbanned' bn5.out && pass "B5a 解封成功" || fail "B5a $(tail -1 bn5.out | tr -d '\r')"
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "back again" > bn5b.out 2>&1
R5=$?
[ "$R5" = "0" ] && [ "$(inbox_n)" = "2" ] && pass "B5b 解封后消息恢复投递（收件 2 条，无需重新加好友）" || fail "B5b 解封后仍不通 rc=$R5 收件=$(inbox_n)"

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
echo
echo "FAILURES=$FAIL"
exit $FAIL
