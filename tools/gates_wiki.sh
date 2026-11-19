#!/usr/bin/env bash
# Wiki acceptance: pages are channel logs, so convergence is proven with the channel merkle root.
#   W1 save creates the page; W2/W3 bad input is refused; W4 replication makes both nodes agree on
#   the current revision AND on the per-channel root; W5 a second author's edit wins by the same
#   deterministic rule on both sides; W6 the page is listed as a page, not as a plain channel.
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
body(){ rpc "$1" "$2" wiki.show "{\"page\":\"$3\"}" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["result"]["body"] if d.get("ok") else "?ERR")' 2>/dev/null; }
root(){ rpc "$1" "$2" node.info | python3 -c "import json,sys;print(json.load(sys.stdin)['result']['channel_roots'].get('wiki/$3',''))" 2>/dev/null; }

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
sleep 1
rm -f wk_a.log wk_b.log wk_*.out
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/peers.json b_dir/peers.json a_dir/pairing.json b_dir/pairing.json \
       a_dir/files b_dir/files a_dir/rsnext.sock b_dir/rsnext.sock inv.txt
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
[ -n "$AFP" ] && [ -n "$BFP" ] || { echo "ABORT: no node identity"; exit 1; }

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/wk_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/wk_b.log 2>&1"
sleep 9
AE=$(awk '/endpoint_id\(hex\)/{print $3}' wk_a.log); AA=$(awk '/local_addr/{print $3}' wk_a.log)
[ -n "$AE" ] && [ -n "$AA" ] || { echo "ABORT: daemon not up"; exit 1; }
docker exec -u $U -w /src $A $BIN invite2 a_dir P1 "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" >/dev/null 2>&1

echo "=== W1 保存即建页 ==="
docker exec -u $U -w /src $A $BIN wiki-save a_dir Manual "first version of the manual" > wk1.out 2>&1
R1=$?
[ "$R1" = "0" ] && grep -q 'revision 1' wk1.out && pass "W1a 首次保存建立页面并得到修订 1" || fail "W1a rc=$R1: $(tail -2 wk1.out | tr -d '\r')"
[ "$(body $A a_dir Manual)" = "first version of the manual" ] && pass "W1b wiki-show 返回当前版本内容" || fail "W1b 内容不符: $(body $A a_dir Manual)"

echo "=== W2/W3 非法输入被拒 ==="
docker exec -u $U -w /src $A $BIN wiki-save a_dir "bad name" 'x' > wk2.out 2>&1
R2=$?
[ "$R2" != "0" ] && grep -qi 'page name' wk2.out && pass "W2 含空格的页名被拒绝（非零退出 + 说明原因）" || fail "W2 非法页名未被拒 rc=$R2: $(tail -1 wk2.out | tr -d '\r')"
rpc $A a_dir wiki.save '{"page":"Manual","body":"   "}' | grep -q 'empty page body' && pass "W3 空正文被拒绝，不会遮蔽已有版本" || fail "W3 空正文未被拒绝"
[ "$(body $A a_dir Manual)" = "first version of the manual" ] && pass "W3b 被拒的保存没有改变当前版本" || fail "W3b 当前版本被空保存破坏"

echo "=== W4 复制后两端一致（内容 + 频道根）==="
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > wk4.out 2>&1
[ "$(body $B b_dir Manual)" = "first version of the manual" ] && pass "W4a bob 收到页面当前版本" || fail "W4a bob 内容: $(body $B b_dir Manual)"
RA=$(root $A a_dir Manual); RB=$(root $B b_dir Manual)
[ -n "$RA" ] && [ "$RA" = "$RB" ] && pass "W4b wiki/Manual 的 merkle 根两端一致 (${RA:0:12}…)" || fail "W4b 根不一致 alice=$RA bob=$RB"
rpc $B b_dir wiki.list | grep -q '"page": "Manual"' && pass "W4c 页面在对端被识别为 wiki 页面" || fail "W4c 对端未列出该页面"

echo "=== W5 第二作者编辑后仍收敛到同一当前版本 ==="
# ts has one-second resolution, so sleep: within the same second the winner is the higher author
# fingerprint by design (deterministic, lossless - history keeps both). What this gate must prove
# is that BOTH nodes pick the SAME revision, not that a particular author wins a same-second tie.
sleep 1
docker exec -u $U -w /src $B $BIN wiki-save b_dir Manual "bob rewrote the manual" > wk5.out 2>&1
[ "$(body $B b_dir Manual)" = "bob rewrote the manual" ] && pass "W5a bob 本地当前版本已更新" || fail "W5a $(body $B b_dir Manual)"
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > wk5b.out 2>&1
EA=$(body $A a_dir Manual); EB=$(body $B b_dir Manual)
[ "$EA" = "$EB" ] && [ "$EA" = "bob rewrote the manual" ] && pass "W5b alice 同步后得到同一当前版本（新时间戳胜出）" \
  || fail "W5b 两端当前版本不一致 alice=$EA bob=$EB"
RA2=$(root $A a_dir Manual); RB2=$(root $B b_dir Manual)
[ -n "$RA2" ] && [ "$RA2" = "$RB2" ] && pass "W5c 两次编辑之后频道根仍一致" || fail "W5c 根不一致 $RA2 / $RB2"
HN=$(rpc $A a_dir wiki.history '{"page":"Manual"}' | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["result"]["history"]))' 2>/dev/null)
[ "${HN:-0}" = "2" ] && pass "W5d 历史保留两条修订（保存是追加而非覆盖）" || fail "W5d 历史条数=$HN 期望 2"

echo "=== W6 wiki 页面不污染普通频道视图 ==="
docker exec -u $U -w /src $A $BIN channel-create a_dir crypto "not a page" >/dev/null 2>&1
P=$(rpc $A a_dir wiki.list | python3 -c 'import json,sys;print(",".join(sorted(x["page"] for x in json.load(sys.stdin)["result"]["pages"])))' 2>/dev/null)
[ "$P" = "Manual" ] && pass "W6 wiki.list 只列页面，不含普通频道 ($P)" || fail "W6 wiki.list = $P 期望 Manual"

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
echo
echo "FAILURES=$FAIL"
exit $FAIL
