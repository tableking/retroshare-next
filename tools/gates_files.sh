#!/usr/bin/env bash
# FileTransfer acceptance: one ls, then only what we do not hold.
#   F1 first batch pull transfers everything offered
#   F2 a second pull transfers nothing (no silent re-download)
#   F3 content held under ANOTHER name is copied locally, not fetched  (hash dedupe)
#   F4 same name, different content is replaced and ends up byte-identical to the offer
#   F5 a pre-existing .part resumes from its exact byte count
#   F6 an unbound peer cannot make us transfer anything
# Topology: rs-alice (seeder, 7801) / rs-bob (client, 7802), identities kept, state wiped.
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node
A=rs-alice; B=rs-bob; U=1000:1000
FAIL=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
# The CLI prints `key=N` when it dials itself, but `key: N` inside pretty JSON when it delegates
# to a running daemon - parse both, or the gate silently reads empties.
field() { grep -oE "\"$1\"[:=] *[0-9]+|$1=[0-9]+" "$2" | grep -oE '[0-9]+' | head -1; }
act() {
  local v
  # serde_json pretty-prints object keys sorted, so "action" lands BEFORE "name" - matching
  # neighbouring lines is wrong; parse the document. The delegated form is an rpc envelope.
  v=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
r=d.get('result', d) if isinstance(d, dict) else {}
for a in r.get('actions', []):
    if a.get('name') == sys.argv[2]:
        print(a.get('action', '')); break
" "$2" "$1" 2>/dev/null)
  [ -z "$v" ] && v=$(grep -E "^  $1 +" "$2" | head -1 | awk '{print $2}')
  echo "$v"
}
fpof()  { docker exec -u $U -w /src $1 $BIN id $2 2>/dev/null | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}' | head -1; }

echo "=== 0. reset（保留身份）==="
docker exec $A sh -c 'pkill -x rsnext-node; exit 0'; docker exec $B sh -c 'pkill -x rsnext-node; exit 0'
sleep 1
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/files b_dir/files a_dir/peers.json b_dir/peers.json \
       a_dir/pairing.json b_dir/pairing.json a_dir/inbox.json a_dir/rsnext.sock b_dir/rsnext.sock \
       inv.txt f*.out ff.log ff_b.log
AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
# An identity is untracked on purpose (it holds the node's secret seeds), so a checkout or a
# worktree wipe can leave the dirs with no identity at all. Regenerate rather than let every gate
# below fail on empty fingerprints - a cascade of 15 "failures" from one missing precondition is
# how you lose an afternoon.
if [ -z "$AFP" ] || [ -z "$BFP" ]; then
  echo "身份缺失，重新 init（本门禁从零配对，不受影响）"
  docker exec -u $U -w /src $A sh -c "$BIN init alice a_dir" >/dev/null 2>&1
  docker exec -u $U -w /src $B sh -c "$BIN init bob b_dir" >/dev/null 2>&1
  AFP=$(fpof $A a_dir); BFP=$(fpof $B b_dir)
fi
if [ -z "$AFP" ] || [ -z "$BFP" ]; then echo "ABORT: still no node identity (alice=$AFP bob=$BFP)"; exit 1; fi
echo "alice_fp=$AFP bob_fp=$BFP"

# alice's library: two byte-identical 6 MB payloads under different names, plus a small text
EXPECT=$(python3 - <<'PY'
import os, hashlib
os.makedirs('a_dir/files', exist_ok=True)
pat = bytes((i * 7 + 3) % 251 for i in range(2_000_000))
open('a_dir/files/big.bin', 'wb').write(pat * 3)
open('a_dir/files/dup.bin', 'wb').write(pat * 3)
open('a_dir/files/small.txt', 'wb').write(b'alice small payload\n' * 48)
tot = sum(os.path.getsize(f'a_dir/files/{n}') for n in ('big.bin', 'dup.bin', 'small.txt'))
print(tot)
PY
)
echo "alice offers 3 files, ${EXPECT} bytes total"

docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/ff.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/ff_b.log 2>&1"
sleep 9
AE=$(awk '/endpoint_id\(hex\)/{print $3}' ff.log); AA=$(awk '/local_addr/{print $3}' ff.log)
echo "alice $AE @ $AA"
docker exec -u $U -w /src $A $BIN invite2 a_dir P1 "$AA" > inv.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat inv.txt)\"" > /dev/null 2>&1
for f in big.bin dup.bin small.txt; do
  docker exec -u $U -w /src $A $BIN share a_dir "a_dir/files/$f" > /dev/null 2>&1
done

echo "=== F1 首次批量拉取 ==="
chk_rc() { if [ "$1" = "0" ]; then pass "$2"; else fail "$2 (rc=$1)"; fi; }
docker exec -u $U -w /src $B timeout 180 $BIN p2p-pull-all b_dir "$AE" "$AA" "$AFP" > f1.out 2>&1
R=$?; chk_rc "$R" "gateF1a pull-all 退出 0"
[ "$(field transferred f1.out)" = "3" ] && pass "gateF1b 三个文件全部传输" || fail "gateF1b 传输数=$(field transferred f1.out) 期望 3"
[ "$(field bytes f1.out)" = "$EXPECT" ] && pass "gateF1c 传输字节数与提供量一致(${EXPECT})" || fail "gateF1c bytes=$(field bytes f1.out) 期望 $EXPECT"
S1=$(sha256sum b_dir/files/big.bin 2>/dev/null | cut -c1-16); S2=$(sha256sum a_dir/files/big.bin | cut -c1-16)
[ -n "$S1" ] && [ "$S1" = "$S2" ] && pass "gateF1d 落盘内容 sha256 与源一致" || fail "gateF1d sha 不一致 bob=$S1 alice=$S2"

echo "=== F2 重复拉取不应再传一个字节 ==="
docker exec -u $U -w /src $B timeout 120 $BIN p2p-pull-all b_dir "$AE" "$AA" "$AFP" > f2.out 2>&1
[ "$(field transferred f2.out)" = "0" ] && [ "$(field skipped f2.out)" = "3" ] \
  && pass "gateF2a 第二次 transferred=0 skipped=3" || fail "gateF2a transferred=$(field transferred f2.out) skipped=$(field skipped f2.out)"
[ "$(field bytes f2.out)" = "0" ] && pass "gateF2b 零字节传输" || fail "gateF2b 重复拉取仍传了 $(field bytes f2.out) 字节"

echo "=== F3 内容已在本地但换了名字：本地复制，不走网络 ==="
rm -f b_dir/files/big.bin
docker exec -u $U -w /src $B timeout 120 $BIN p2p-pull-all b_dir "$AE" "$AA" "$AFP" > f3.out 2>&1
[ "$(act big.bin f3.out)" = "dedup" ] && pass "gateF3a big.bin 判定为 dedup" || fail "gateF3a 判定=$(act big.bin f3.out) 期望 dedup"
[ "$(field bytes f3.out)" = "0" ] && pass "gateF3b 补回缺失文件未产生网络流量" || fail "gateF3b 走了 $(field bytes f3.out) 字节网络"
[ "$(sha256sum b_dir/files/big.bin 2>/dev/null | cut -c1-16)" = "$S2" ] \
  && pass "gateF3c 复制出来的内容与源逐字节一致" || fail "gateF3c 复制后 sha 不符"

echo "=== F4 同名不同内容：替换并收敛到源的哈希 ==="
printf 'bob had something else entirely here\n' > b_dir/files/small.txt
docker exec -u $U -w /src $B $BIN share b_dir b_dir/files/small.txt > /dev/null 2>&1
docker exec -u $U -w /src $B timeout 120 $BIN p2p-pull-all b_dir "$AE" "$AA" "$AFP" > f4.out 2>&1
[ "$(act small.txt f4.out)" = "replaced" ] && pass "gateF4a 冲突名判定为 replaced" || fail "gateF4a 判定=$(act small.txt f4.out) 期望 replaced"
AS=$(sha256sum a_dir/files/small.txt | cut -c1-16); BS=$(sha256sum b_dir/files/small.txt 2>/dev/null | cut -c1-16)
[ "$AS" = "$BS" ] && pass "gateF4b 替换后与源一致（旧内容不会残留在同名文件里）" || fail "gateF4b alice=$AS bob=$BS"

echo "=== F5 半截 .part 必须续传而不是重来 ==="
python3 - <<'PY'
import os
os.makedirs('a_dir/files', exist_ok=True)
data = bytes((i * 11 + 5) % 253 for i in range(3_000_000))
open('a_dir/files/later.bin', 'wb').write(data)
os.makedirs('b_dir/files', exist_ok=True)
open('b_dir/files/later.bin.part', 'wb').write(data[:1_000_000])
PY
docker exec -u $U -w /src $A $BIN share a_dir a_dir/files/later.bin > /dev/null 2>&1
docker exec -u $U -w /src $B timeout 180 $BIN p2p-pull-all b_dir "$AE" "$AA" "$AFP" > f5.out 2>&1
[ "$(act later.bin f5.out)" = "resumed" ] && pass "gateF5a later.bin 判定为 resumed" || fail "gateF5a 判定=$(act later.bin f5.out) 期望 resumed"
# the "resuming from" line is printed by the transferring process: the CLI when it dials itself,
# the daemon's log when the call was delegated
grep -q 'resuming from 1000000B' f5.out ff_b.log 2>/dev/null && pass "gateF5b 从 1000000 字节处续传" || fail "gateF5b 未见 'resuming from 1000000B'"
[ "$(sha256sum b_dir/files/later.bin 2>/dev/null | cut -c1-16)" = "$(sha256sum a_dir/files/later.bin | cut -c1-16)" ] \
  && pass "gateF5c 续传结果 sha256 正确（半截数据没被污染）" || fail "gateF5c 续传后内容不一致"

echo "=== F6 未绑定的对端不能触发任何传输 ==="
docker exec -u $U -w /src $B timeout 60 $BIN p2p-pull-all b_dir "$AE" "$AA" "DEAD-BEEF-0000-1111" > f6.out 2>&1
R6=$?
[ "$R6" != "0" ] && pass "gateF6a 未绑定指纹 -> 非零退出($R6)" || fail "gateF6a 未绑定竟成功"
grep -qi 'not bound' f6.out && pass "gateF6b 报错说明原因（not bound）" || fail "gateF6b 缺少可读错误：$(tail -1 f6.out)"

echo
echo "FAILURES=$FAIL"
exit $FAIL
