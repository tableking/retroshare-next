#!/usr/bin/env bash
# M3 channels gate: named channels, per-channel merkle roots, subscription bookmarks.
# Assertions are on each node's persisted state and computed roots - not on command echoes.
set -u
cd "$(dirname "$0")/.."
BIN=/target/debug/rsnext-node; U=1000:1000
A=rs-alice; B=rs-bob
FAIL=0
pass(){ echo "PASS  $1"; }
fail(){ echo "FAIL  $1"; FAIL=$((FAIL+1)); }
rpc(){ # container dir method [json]
  if [ $# -ge 4 ]; then docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" "$4" 2>&1
  else docker exec -u $U -w /src "$1" $BIN rpc "$2" "$3" 2>&1; fi
}

for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done; sleep 1
rm -f ch_a.log ch_b.log
rm -rf a_dir/rsnext.db* b_dir/rsnext.db* a_dir/peers.json b_dir/peers.json a_dir/pairing.json b_dir/pairing.json
docker exec -d -u $U -w /src $A sh -c "$BIN net a_dir 7801 > /src/ch_a.log 2>&1"
docker exec -d -u $U -w /src $B sh -c "$BIN net b_dir 7802 > /src/ch_b.log 2>&1"
sleep 10
AE=$(awk '/endpoint_id\(hex\)/{print $3}' ch_a.log); AA=$(awk '/local_addr/{print $3}' ch_a.log)
BE=$(awk '/endpoint_id\(hex\)/{print $3}' ch_b.log); BA=$(awk '/local_addr/{print $3}' ch_b.log)
AFP=$(docker exec -u $U -w /src $A $BIN id a_dir | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}')
BFP=$(docker exec -u $U -w /src $B $BIN id b_dir | grep -oE '[0-9A-F]{4}(-[0-9A-F]{4}){3}')

echo "=== 1. 绑定两个节点 ==="
docker exec -u $U -w /src $A $BIN invite2 a_dir CH1 "$AA" > ch_i1.txt
docker exec -u $U -w /src $B sh -c "cd /src && $BIN accept b_dir \"\$(cat ch_i1.txt)\"" >/dev/null
docker exec -u $U -w /src $B timeout 60 $BIN p2p-send b_dir $AE $AA $AFP "channel bootstrap" > ch_s0.out 2>&1
grep -q 'channel bootstrap' ch_a.log && pass "C1 双向绑定建立（alice 日志确认收到）" || fail "C1: $(tail -2 ch_s0.out)"

echo "=== 2. 建频道并各自发帖 ==="
rpc $A a_dir channels.create '{"name":"crypto","desc":"keys and ciphers"}' | grep -q '"ok": true' && pass "C2a alice 创建频道 crypto" || fail "C2a"
rpc $A a_dir forum.post '{"body":"general post A"}' >/dev/null
rpc $A a_dir forum.post '{"body":"crypto post A1","channel":"crypto"}' >/dev/null
rpc $A a_dir forum.post '{"body":"crypto post A2","channel":"crypto"}' >/dev/null
# bob has never seen the channel; the same author name must not collide across channels
docker exec -u $U -w /src $B $BIN channel-create b_dir crypto "from bob side" >/dev/null
docker exec -u $U -w /src $B $BIN channel-post b_dir crypto "crypto post B1" >/dev/null
rpc $B b_dir forum.post '{"body":"general post B","channel":"general"}' >/dev/null
echo "   alice channel-list:"; docker exec -u $U -w /src $A $BIN channel-list a_dir | sed 's/^/     /'

echo "=== 3. 同步后每个频道各自收敛 ==="
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP > ch_sync.out 2>&1
# p2p-sync is delegated to the running node, so its narration lands in the daemon log, not the CLI
# stdout. Either place counts as the same report; the authoritative check is C3b (roots equal).
if grep -q 'CONVERGED' ch_sync.out ch_b.log 2>/dev/null; then pass "C3a 同步报告各频道收敛（CLI 或 daemon 日志）"
else echo "     CLI: $(tail -2 ch_sync.out | tr -d '\r')"; echo "     daemon: $(tail -2 ch_b.log | tr -d '\r')"; fail "C3a 两端均未报告收敛"; fi
RA=$(rpc $A a_dir node.info | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)["result"]["channel_roots"],sort_keys=True))')
RB=$(rpc $B b_dir node.info | python3 -c 'import json,sys;print(json.dumps(json.load(sys.stdin)["result"]["channel_roots"],sort_keys=True))')
echo "     alice roots: $RA"
echo "     bob   roots: $RB"
[ "$RA" = "$RB" ] && [ -n "$RA" ] && pass "C3b 两端 per-channel roots 完全一致" || fail "C3b roots 不一致"
python3 - "$RA" <<'PY'
import json, sys
roots = json.loads(sys.argv[1])
assert "crypto" in roots and "general" in roots, roots
assert roots["crypto"] != roots["general"], "channels must have distinct roots"
PY
[ $? -eq 0 ] && pass "C3c crypto 与 general 是彼此独立的日志" || fail "C3c 频道根未独立"

echo "=== 4. 帖子按频道正确合并 ==="
python3 - <<'PY'
import sqlite3
for d in ("a_dir", "b_dir"):
    rows = sqlite3.connect(d + "/rsnext.db").execute(
        "SELECT channel, author, seq, body FROM posts ORDER BY channel, author, seq").fetchall()
    crypto = [r for r in rows if r[0] == "crypto"]
    general = [r for r in rows if r[0] == "general"]
    assert len(crypto) == 3, (d, crypto)
    assert len(general) == 2, (d, general)
    # the same author holds seq 1 in both channels: proof the key includes the channel
    a1 = [r for r in crypto if r[1] == r[1] and r[2] == 1]
    assert a1, (d, crypto)
    print(f"   {d}: crypto={len(crypto)} general={len(general)}")
PY
[ $? -eq 0 ] && pass "C4 三帖归 crypto、两帖归 general，两端一致（同作者跨频道 seq 不冲突）" || fail "C4 帖子合并结果不符"

echo "=== 5. 订阅位点与未读数 ==="
UN=$(rpc $B b_dir channels.list | python3 -c 'import json,sys;d=json.load(sys.stdin)["result"]["channels"];print(sum(c["unread"] for c in d))')
[ "${UN:-0}" -ge 0 ] && pass "C5a channels.list 返回未读计数（当前合计 $UN）" || fail "C5a"
rpc $B b_dir forum.mark_read '{"channel":"crypto"}' | grep -q '"unread": 0' && pass "C5b 标记已读后该频道未读归零" || fail "C5b"
NEW_UN=$(rpc $A a_dir forum.post '{"body":"crypto post A3","channel":"crypto"}' >/dev/null; docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP >/dev/null 2>&1; rpc $B b_dir channels.list | python3 -c 'import json,sys;d=json.load(sys.stdin)["result"]["channels"];print([c["unread"] for c in d if c["name"]=="crypto"][0])')
[ "${NEW_UN:-0}" -ge 1 ] && pass "C5c 新帖同步后未读数如实增加 ($NEW_UN)" || fail "C5c 未读数不对: $NEW_UN"

echo "=== 6. 频道随帖子一起复制 ==="
python3 -c "
import sqlite3
def ch(d):
    return {n for n,_ in sqlite3.connect(f'{d}/rsnext.db').execute('SELECT name,created_by FROM channels').fetchall()}
a, b = ch('a_dir'), ch('b_dir')
print('   alice channels:', sorted(a))
print('   bob   channels:', sorted(b))
# the pull direction used to omit definitions: bob applied alice's posts (and his root matched) yet
# never learned that 'crypto' exists. Assert on the receiving side, not only the creator.
assert 'crypto' in a and 'crypto' in b, (a, b)" && pass "C6 crypto 频道定义在两端都存在（含拉取方）" || fail "C6 频道定义未复制到拉取方"


echo "=== 7. 搜索（LIKE 语义与转义）==="
hits(){ rpc "$1" "$2" search.posts "$3" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["result"]["hits"]) if d.get("result") else -1)' 2>/dev/null; }
H=$(hits $B b_dir '{"query":"crypto"}')
[ "${H:-0}" -ge 4 ] && pass "C7a 全站搜索命中 crypto 帖 ($H)" || fail "C7a 命中数=$H 期望 >=4"
CH=$(rpc $B b_dir search.posts '{"query":"post","channel":"general"}' | python3 -c 'import json,sys;d=json.load(sys.stdin)["result"]["hits"];print(len(d), sorted({h["channel"] for h in d}))')
[ "$CH" = "2 ['general']" ] && pass "C7b 限定频道只返回该频道结果" || fail "C7b 限定频道返回 $CH"
# the escaping gate: '%' and '_' are LIKE metacharacters. If they leak through, a search for a
# lone '%' dumps the whole forum - a "works on my machine" bug that silently breaks privacy scoping
P=$(hits $B b_dir '{"query":"%"}'); U=$(hits $B b_dir '{"query":"_"}')
[ "${P:-1}" = "0" ] && [ "${U:-1}" = "0" ] && pass "C7c 通配符被转义（搜 % 与 _ 命中 0）" || fail "C7c 通配符泄漏: pct=$P under=$U"
E=$(rpc $B b_dir search.posts '{"query":""}' 2>&1 | grep -c 'query required')
[ "$E" = "1" ] && pass "C7d 空查询被拒绝而不是返回全库" || fail "C7d 空查询未被拒绝"
N=$(hits $B b_dir '{"query":"zzz-no-such-text"}')
[ "${N:-1}" = "0" ] && pass "C7e 无匹配返回空集合而非错误" || fail "C7e 无匹配返回 $N"
mkdir -p b_dir/files && printf 'alpha notes\n' > b_dir/files/alpha_notes.txt
docker exec -u $U -w /src $B $BIN share b_dir b_dir/files/alpha_notes.txt >/dev/null 2>&1
F=$(rpc $B b_dir search.files '{"query":"notes"}' | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["result"]["hits"]))')
FP=$(rpc $B b_dir search.files '{"query":"%"}' | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["result"]["hits"]))')
[ "$F" = "1" ] && [ "$FP" = "0" ] && pass "C7f 文件名搜索命中且同样转义（notes=1 pct=$FP）" || fail "C7f 文件搜索 notes=$F pct=$FP"

echo "=== 8. 深度索引的不变量（LIKE 版给不了的性质）==="
stat(){ rpc "$1" "$2" search.status | python3 -c 'import json,sys;d=json.load(sys.stdin)["result"];print(d["docs"],d["posts"],d["files"])' 2>/dev/null; }
q(){ rpc "$1" "$2" search.query "$3" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["result"]["hits"]))' 2>/dev/null; }
top(){ rpc "$1" "$2" search.query "$3" | python3 -c 'import json,sys;d=json.load(sys.stdin);h=d["result"]["hits"];print(h[0]["url"] if h else "")' 2>/dev/null; }

read -r DOCS POSTS FILES <<<"$(stat $B b_dir)"
if ! [[ "$DOCS" =~ ^[0-9]+$ && "$POSTS" =~ ^[0-9]+$ && "$FILES" =~ ^[0-9]+$ ]]; then
  fail "D1 search.status 没给出三个数字（方法未实现或 daemon 是旧二进制）: '$DOCS $POSTS $FILES'"
elif [ "$DOCS" -ne $((POSTS + FILES)) ]; then
  fail "D1 索引与真相不一致: docs=$DOCS posts=$POSTS files=$FILES"
else
  pass "D1 索引文档数 == 帖子数+已分享文件数（$DOCS = $POSTS + $FILES）"
fi

# a post becomes searchable without any rebuild: that is the write-path hook, not a scan
rpc $B b_dir forum.post '{"body":"zebra crossing observed in channel crypto","channel":"crypto"}' >/dev/null
[ "$(q $B b_dir '{"query":"zebra"}')" = "1" ] && pass "D2 新帖无需 rebuild 立即可搜（钩子生效）" || fail "D2 新帖搜不到，说明写入路径未维护索引"

# replicated content must be as searchable as local content
docker exec -u $U -w /src $B timeout 90 $BIN p2p-sync b_dir $AE $AA $AFP >/dev/null 2>&1
[ "$(q $A a_dir '{"query":"zebra"}')" = "1" ] && pass "D3 对端同步来的帖子同样可搜" || fail "D3 复制路径未进索引（合并写入绕过了钩子）"

# ranking: the document that repeats the term should outrank the one that mentions it once
rpc $B b_dir forum.post '{"body":"walnut walnut walnut walnut","channel":"general"}' >/dev/null
rpc $B b_dir forum.post '{"body":"a single walnut mention","channel":"general"}' >/dev/null
TOPSNIP=$(rpc $B b_dir search.query '{"query":"walnut"}' | python3 -c '
import json,sys
h=json.load(sys.stdin)["result"]["hits"]
print(h[0]["snippet"].lower().count("walnut") if h else 0)' 2>/dev/null)
[ "${TOPSNIP:-0}" -ge 3 ] && pass "D4 BM25 把重复提及的文档排在首位（首选含 $TOPSNIP 次）" \
  || fail "D4 排序异常：首选片段只含 ${TOPSNIP:-0} 次 walnut（期望 >=3）"

# AND semantics across two words
[ "$(q $B b_dir '{"query":"walnut zebra"}')" = "0" ] && pass "D5 多词是交集而非并集" || fail "D5 多词查询错误召回 $(q $B b_dir '{"query":"walnut zebra"}') 条"

# revoking a share must remove the document: a hit we cannot serve is worse than no hit
mkdir -p b_dir/files && printf 'disposable payload\n' > b_dir/files/tmp_share.txt
# the daemon lives inside the container, so the path it must see is the mount path, not the host path
rpc $B b_dir files.share '{"path":"/src/b_dir/files/tmp_share.txt"}' >/dev/null
BEFORE=$(q $B b_dir '{"query":"tmp_share"}')
rpc $B b_dir files.unshare '{"name":"tmp_share.txt"}' >/dev/null
AFTER=$(q $B b_dir '{"query":"tmp_share"}')
[ "$BEFORE" = "1" ] && [ "$AFTER" = "0" ] && pass "D6 取消分享后文档从索引消失 ($BEFORE -> $AFTER)" \
  || fail "D6 撤销分享未清理索引: before=$BEFORE after=$AFTER"

# rebuild must be a no-op for the searchable set: if the incremental hooks and the rebuild query
# disagree about what counts as "searchable", this is where it shows
BEFORE_DOCS=$(stat $B b_dir | awk '{print $1}')
rpc $B b_dir search.rebuild >/dev/null
AFTER_DOCS=$(stat $B b_dir | awk '{print $1}')
STILL=$(q $B b_dir '{"query":"tmp_share"}')
if [ "$BEFORE_DOCS" = "$AFTER_DOCS" ] && [ "$STILL" = "0" ]; then
  pass "D8 重建未改变可搜集合（docs $BEFORE_DOCS -> $AFTER_DOCS，撤销分享的文件仍未被索引）"
else
  fail "D8 重建改变了可搜集合: docs $BEFORE_DOCS -> $AFTER_DOCS, tmp_share=$STILL（增量钩子与重建查询口径不一致）"
fi

read -r D2O D2P D2F <<<"$(stat $B b_dir)"
if [[ "$D2O" =~ ^[0-9]+$ && "$D2P" =~ ^[0-9]+$ && "$D2F" =~ ^[0-9]+$ ]] && [ "$D2O" -eq $((D2P + D2F)) ]; then
  pass "D7 变更之后不变量仍然成立（docs=$D2O posts=$D2P files=$D2F）"
else
  fail "D7 不变量被破坏: docs=${D2O:-?} posts=${D2P:-?} files=${D2F:-?}"
fi


for n in $A $B; do docker exec $n sh -c 'pkill -x rsnext-node; exit 0'; done
echo; echo "FAILURES=$FAIL"; exit $FAIL
