#!/usr/bin/env bash
# Presence acceptance. The property that matters is not "online shows up" - it is that presence
# records AUTHENTICATED contact only, so a refused stranger must never appear in the list. That is
# what the placement of the peer_seen hook after peer_gate buys, and P3 is the gate that proves it.
# Aging is exercised by rewriting last_seen rather than sleeping, so the thresholds are tested
# exactly rather than approximately.
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
state_of(){ rpc $A a_dir peers.presence | python3 -c "
import json,sys
d=json.load(sys.stdin)
rows=(d.get('result') or {}).get('peers') or []
print(next((r['state'] for r in rows if r['fingerprint']=='$1'), 'ABSENT'))" 2>/dev/null; }

for n in $A $B $C; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 1
rm -f pr_a.log pr_b.log pr_*.out
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/peers.json b_dir/peers.json a_dir/pairing.json b_dir/pairing.json \
       a_dir/rsnext.sock b_dir/rsnext.sock inv.txt
rm -rf c_dir
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
docker exec -u $U -w /src $C sh -c "$BIN init carol c_dir" >/dev/null 2>&1
CFP=$(docker exec -u $U -w /src $C $BIN id c_dir 2>/dev/null | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}' | head -1)
[ -n "$AFP" ] && [ -n "$BFP" ] && [ -n "$CFP" ] || { echo "ABORT: missing identities (alice=$AFP bob=$BFP carol=$CFP)"; exit 1; }

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/pr_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/pr_b.log 2>&1"
sleep 9
AE=$(awk '/endpoint_id\(hex\)/{print $3}' pr_a.log); AA=$(awk '/local_addr/{print $3}' pr_a.log)
[ -n "$AE" ] || { echo "ABORT: alice daemon not up"; exit 1; }

echo "=== P1 尚无任何已认证联系 ==="
docker exec -u $U -w /src $A $BIN presence a_dir > pr1.out 2>&1
grep -qi 'no authenticated contact' pr1.out && pass "P1 空状态如实报告，不虚构好友" || fail "P1 $(tail -2 pr1.out | tr -d '\r')"

echo "=== P2 已认证联系记为 online ==="
docker exec -u $U -w /src $A $BIN invite2 a_dir PC1 "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" >/dev/null 2>&1
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "presence hello" > pr2.out 2>&1
[ "$?" = "0" ] || fail "P2a 基线发送失败，后续无法判定"
[ "$(state_of "$BFP")" = "online" ] && pass "P2 好友的已认证联系显示 online" || fail "P2 状态=$(state_of "$BFP") 期望 online"

echo "=== P3 被拒绝的陌生人不得进入名单（这是钩子放在门禁之后的全部理由）==="
docker exec -u $U -w /src $C timeout 60 $BIN p2p-send c_dir $AE $AA "$AFP" "stranger noise" > pr3.out 2>&1
[ "$(state_of "$CFP")" = "ABSENT" ] && pass "P3 被拒联系人未记入 presence" || fail "P3 陌生人出现在名单里: $(state_of "$CFP")"

echo "=== P4 老化按阈值计算（改写时间戳，不靠 sleep）==="
python3 - <<'PY'
import sqlite3, subprocess, time
old = int(time.time()) - 10_000          # > AWAY_SECS(900) -> offline
db = sqlite3.connect('a_dir/rsnext.db')
db.execute("UPDATE peer_presence SET last_seen=? WHERE 1=1", (old,)); db.commit()
print('   last_seen rewritten to', old)
PY
[ "$(state_of "$BFP")" = "offline" ] && pass "P4 超过阈值后如实降级为 offline" || fail "P4 状态=$(state_of "$BFP") 期望 offline"

echo "=== P5 数据形状可被上层使用 ==="
rpc $A a_dir peers.presence | python3 -c '
import json,sys
d=json.load(sys.stdin)["result"]
assert "now" in d and d["peers"], d
p=d["peers"][0]
assert set(("fingerprint","state","last_seen")) <= set(p), p
assert isinstance(p["last_seen"], int) and p["last_seen"] > 0, p' \
  && pass "P5 peers.presence 返回 now + 每条含指纹/状态/最后联系时间" || fail "P5 结构不完整: $(rpc $A a_dir peers.presence | head -c 160)"

echo "=== P6/P7 心跳（RSNEXT_STATUS_TICK 显式开启）==="
for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 2
rm -f pr_a2.log pr_b2.log
docker exec -d -u $U -w /src $A sh -c "RSNEXT_STATUS_TICK=4 $BIN net a_dir 7801 > /src/pr_a2.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "RSNEXT_STATUS_TICK=4 $BIN net b_dir 7802 > /src/pr_b2.log 2>&1"
sleep 10
grep -q 'status tick every 4s' pr_a2.log pr_b2.log && pass "P6a 开关生效时 daemon 明确宣告心跳周期" || fail "P6a 未见心跳宣告"

# bob declares himself away; the declaration only reaches alice on the next hi, i.e. via heartbeat
docker exec -u $U -w /src $B $BIN status b_dir away 90 > pr6.out 2>&1
grep -qi 'declared state = away' pr6.out && pass "P6b bob 写入自报状态" || fail "P6b $(tail -1 pr6.out | tr -d '\r')"
SEEN_BEFORE=$(rpc $A a_dir peers.presence | python3 -c "
import json,sys
p=[r for r in json.load(sys.stdin)['result']['peers'] if r['fingerprint']=='$BFP']
print(p[0]['last_seen'] if p else 0)" 2>/dev/null)
GOT=""
for i in 1 2 3 4 5 6 7 8; do
  sleep 3
  GOT=$(rpc $A a_dir peers.presence | python3 -c "
import json,sys
p=[r for r in json.load(sys.stdin)['result']['peers'] if r['fingerprint']=='$BFP']
print(f\"{p[0]['state']}|{p[0]['source']}\" if p else '|')" 2>/dev/null)
  case "$GOT" in away\|declared) break;; esac
done
[ "$GOT" = "away|declared" ] && pass "P6c alice 经心跳收到 bob 自报的 away（source=declared）" \
  || fail "P6c alice 视图=$GOT 期望 away|declared"

echo "=== P7 心跳使活跃好友不因沉默而老化 ==="
sleep 10
SEEN_AFTER=$(rpc $A a_dir peers.presence | python3 -c "
import json,sys
p=[r for r in json.load(sys.stdin)['result']['peers'] if r['fingerprint']=='$BFP']
print(p[0]['last_seen'] if p else 0)" 2>/dev/null)
[ "${SEEN_AFTER:-0}" -gt "${SEEN_BEFORE:-0}" ] && pass "P7 无人工发消息时 last_seen 仍前进（$SEEN_BEFORE -> $SEEN_AFTER）" \
  || fail "P7 last_seen 未推进: $SEEN_BEFORE -> $SEEN_AFTER（心跳没有刷新接触时间）"

echo "=== P8 未开启开关时不得有后台流量 ==="
for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 2
rm -f pr_a3.log
docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/pr_a3.log 2>&1"
sleep 12
if grep -q 'status tick' pr_a3.log; then fail "P8 未设 RSNEXT_STATUS_TICK 却启动了心跳"
else pass "P8 默认关闭（无开关时不产生周期拨号）"; fi

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
echo
echo "FAILURES=$FAIL"
exit $FAIL
