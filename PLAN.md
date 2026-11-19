# RetroShare-Next — 现代重写里程碑方案

依据 `test.txt` 架构蓝图（2026-11-18）转化。核心不变量：**F2F 纯去中心化信任网络 + 端到端加密 + 零云端依赖**；用现代工程解决旧版"界面复古、移动端残废、配置极难"。

## 技术栈定版
| 层 | 蓝图选型 | 落地形态 |
|---|---|---|
| 核心引擎 | Rust | `rsnext-core`：网络/加密/存储全 Rust，单二进制无头 daemon |
| 传输 | QUIC + iroh | iroh (iroh-docs 同步 + iroh-blobs 分块传输)，自动 NAT 穿透、网络切换不断线；Tor(Arti) 开关后置 |
| 密码学 | Ed25519+X25519, Noise, MLS, 后量子混合 | 身份=Ed25519；会话=X25519 Noise_XX；群聊 MLS (openmls)；KEM 混合 (ml-kem768+x25519) 后置里程碑 |
| 存储 | 本地 SQLite | rusqlite；消息/论坛/文件索引/关系签名 |
| 前端 | Tauri 2.0 + React | 桌面 Win/macOS/Linux + iOS/Android；深色、Cmd+K 命令面板、类 Discord 布局 |
| 移动端策略 | Home Node | 旧电脑/NAS/树莓派跑 headless daemon；手机=轻终端连自家节点 |
| AI（**已推迟，未排期**） | 本地 Ollama/llama.cpp | 网络诊断 Copilot、本地 RAG 语义搜索 (sqlite-vec)、论坛 TL;DR、共享文件元数据、FoF 反垃圾预警；**默认纯本地，可配自选 API** |

## 里程碑
- **M0 骨架** ✅(2026-11-18)：cargo workspace(rsnext-core+rsnext-node)，GNU toolchain，Identity=Ed25519+X25519 双密钥，人读指纹 4x4 分组。
- **M1 加好友 + 私聊** ✅(2026-11-18)：invite 深链 payload(指纹+公钥+一次性码)/accept 绑定 → Noise_XX(X25519+ChaCha20Poly1305+HKDF 手写实现，进程内 demo-xx 三步 transcript/k/tempk 全等) → 两进程 TCP-loopback E2E 双消息进 inbox.json 实证；**负面测试**：改码的 Mallory 被拒(exit 2, 0 入库)。iroh/QUIC 替换 loopback 传输=M2 第一项；SQLite 暂以 JSON 文件代管(M2 升级)。
- **M2 文件 + 论坛同步** ✅(2026-11-19, Linux/Docker)：iroh QUIC 私信/文件双向（`p2p-send/p2p-push/p2p-pull/p2p-ls`）、sha256 校验、**断点续传实证**（中断在 3.1 MB → `resuming from 3145728B` → 校验一致）、seeder 侧 `RSNEXT_MAX_KBPS` 限速实证（30 MB 30.1 s vs 不限速 0.5 s）、论坛 append-only 日志按 `(author,seq)` 定序 + merkle root 收敛（两端 `forum_root` 相同）、一次性配对码消费与重放拒绝、F2F 门与地址自学习（`my_addr` + 连接源地址 + 拨号成功即固化）。门禁入口 `bash tools/gates_m2.sh` → 当前 **FAILURES=0 / XFAIL=3**（36 项，含事件流 4 项：chat / peer-bonded / forum(对端) / forum(本地)）。**未做**：iroh-blobs 分块与边下边播（现为自写流式）、真 CRDT 因果排序（现为 set-merge）。
- **M3 进行中**(2026-11-19)：①**headless 控制面** unix socket JSON-RPC + **事件流** `events.subscribe`（chat/file/forum(对端与本地)/peer-bonded，慢订阅者收 `lagged` 计数不反压）；②**WebUI 桥**：`rsnext-node web <dir> [bind]` 提供极简 HTTP/1.1（仅 GET/POST+Content-Length，无 chunked）+ SSE 转发，默认只绑 127.0.0.1，鉴权用数据目录里 0600 的 bearer token，不新增任何依赖；单文件 UI（好友/论坛/私信/文件 + 实时事件）位于 `crates/rsnext-node/web/index.html`；③**Web-of-Trust**：证书签**完整身份**（Ed25519+X25519，缺一半即拒绝签发）、收到的证书**先验 issuer 公钥再入库**、本地信任分逐跳衰减（1.0/0.7/0.49，>4 跳视为无证据，分层松弛）。门禁：`gates_web.sh` 10/10、`gates_wot.sh`/`gates_mesh.sh`/`gates_u123.sh`/`gates_m2.sh` 均 FAILURES=0，单元测试 14/14。④**频道与订阅位点**：具名频道（定义随帖子一起复制）、**每频道独立 merkle 根**（一频道的内容不影响另一频道的收敛判定）、按书签时间戳计算的未读数（不用 seq：seq 是按作者编号的，跨作者比较会漏帖）。主键修正为 `(author, channel, seq)` 并带旧库迁移——旧的 `(author, seq)` 让同一作者在第二个频道发帖直接失败。门禁 `tools/gates_channel.sh`。
剩余：Tauri 打包（同一套 web 资源）。RSS 已完成：feed 条目落为频道帖子，因此直接继承 per-channel merkle 根、订阅位点与未读记账（验收 tools/gates_rss.sh，含两端根逐字节相等）。
Tauri 说明：其打包链需要 npm 与 webkit2gtk 系统库；当前容器 UDP/53 被阻、DNS 全断，npm registry 不可达，故桌面壳推迟到网络可用时。用户可见能力已由回环 web 壳提供（同一份 index.html + 0600 bearer token）。

- **M3 Tauri UI**（第三步前半，剩余部分）：把已完成的 web 资源包成桌面壳 + 命令面板。验收：桌面打包可运行。
- **M4 本地 AI —— 用户已决定推迟（2026-11-19），当前不排期**。原计划：Ollama 诊断助手、RAG 语义搜索（sqlite-vec）、帖子 TL;DR、共享文件自动描述、异常行为预警。**推迟期间的替代**：语义搜索由深度索引（倒排 + BM25）承担关键词召回，摘要不做，反垃圾交给封禁名单 + WoT 信任分。**若日后启用**，验收仍是"断网环境可用"。
- **M5 后量子 + 群聊 MLS**：openmls 群 + ml-kem 混合握手。
- **M6 移动端**：Tauri mobile + Home Node 连接向导。



## 验证基线

基线(2026-11-19 实测，单次串跑)：`bash tools/gates.sh` → **AGG_EXIT=0**：cargo test 14/14；gates_m2、gates_u123、gates_wot、gates_mesh 均 **FAILURES=0 / XFAIL=0**；gates_web 10/10。后续任何改动以"聚合仍为 0"为回归标准。注意：五套门禁共用容器与固定端口，**不可并发运行**（gates.sh 已加 /tmp 互斥锁，第二实例直接 rc=4）；并发曾产生过一次不可复现的 exit=1，不要把它当成产品缺陷去查。

## 未解项（诚实记录，勿当已完成）
现状缓解：**单边重启已自愈**——daemon 启动即向所有已知好友发 `hi`，对方按新源地址刷新（日志 `[startup]`）；双边同时重启仍需一个新鲜地址（`sync-all <dir> FP=ip:port` 或重发深链）。已排除：`bind_addr`、`clear_ip_transports().bind_addr` 均无效（查 `/proc/net/udp` 只有那个随机端口、`ip_addrs` 也只一条，故非打印错觉）；`QuicTransportConfig` 无端口字段。根治＝M5a 自托管 iroh-dns(pkarr)，用 `endpoint_id` 直接解析当前地址。
- U2 ✅已解(2026-11-19)：pair 只用于**首次绑定**；已绑定好友此后由 iroh 的 Ed25519 连接认证放行（`peer_gate` 比对存储的 endpoint_id，不符即 REFUSED）。旧设计把一次性码变成永久口令：码被轮换后好友反而连不上自己人（实测踩过）。语义由 6 个单元测试覆盖（`cargo test`），不依赖网络、不受 U1 干扰。
- U3 ✅已解(2026-11-19)：接收侧对 `<name>.part.lock` 用 `create_new` 独占声明，冲突时回 `a transfer is already in flight` 帧；完成或校验失败时释放。
- U4 ✅已解(2026-11-19)：**只有持续监听的进程才有权公布地址**。一次性 CLI 拨号曾把它的一次性源端口当作"我的地址"广播，覆盖掉真正可用的 daemon 地址（这就是加了启动通报后 U1 仍失败的真因）。现在 `ADVERTISE` 仅由 daemon 置位，且 daemon 对外连接复用**自身** Endpoint（`dial_with`/`say_hi_with`/`ask_where_with`）。
- U6 **自动纠正未生效（新发现，实测证据）**：alice 公布 `172.17.0.4:7801`，bob 库里仍是 `172.17.0.4:37914`（alice 早前 CLI 联系留下的一次性端口）。填-only 规则正确地阻止了它被更差的值覆盖，但也意味着**坏值一旦写入就再也无法被观测纠正**——只有 alice 的 daemon 主动联系 bob 时携带的 `my_addr` 才能改写它，而 `hi` 目前可能退回 CLI 拨号（ADVERTISE=false 因而不公布）。待查：确认 `hi` 的委托是否命中 daemon；若是，问题在 `say_hi_with` 的 `my_addr_of` 取值；若否，需要让 CLI 的 `hi` 显式失败而不是静默自拨。显式给定地址时投递正常（gate8d/8e 均以此判定）。
- U1 ✅已解(2026-11-19 复核)：固定端口 + 地址单一真值来源。**根因链**：①`net` 分支把端口硬编码 0（导致两轮误判"iroh 不支持固定端口"）；②daemon 内部又用一次性 `dial()` 拨号，`my_addr_of` 取的是**当次套接口**而非监听端口，于是把 5 万号的临时端口当成监听地址公布给好友；③地址公布是单向的，CLI 发起的联系永远教不会对端。现在 `ADVERTISED` 只在 daemon 绑定时写一次，所有请求与**应答**（`peer_addr`）都读它，观测到的源端口只用于首次填空。实测：`gates_mesh` A/B 全绿、`gate8d` 存储地址自动纠正为 7801、`SWb` 单边重启自愈。
- U6 ✅随 U1 关闭：委托路径曾**静默丢弃** CLI 的显式地址参数（`delegate_plan` 未转发 addr），现所有 p2p-* 均转发 `addr`。
- U7 ✅已解：push 未检查对端首帧裁决，导致"并发推送被拒"在调用方只显示为 `sending stopped by peer`；现在先判 `head.ok` 再灌数据，拒绝理由原样上抛（`gates_u123 U3` 严格断言"already in flight"）。

- U5 反复踩到的**顺序陷阱**：凡"UPDATE 一行"的写入必须发生在该行存在之后。addr 与 x25519 两次都是因为在 `bind_peer` 插入之前就 UPDATE 而静默丢失（表现为"地址永远是空"/"证书只绑一半身份"）。已各有一条单元测试钉住。
- **U1 ✅已解(2026-11-19)：`net <dir> <port>` 能钉住 UDP 端口**。此前判定"iroh 1.4.2 没有入口"是**我的错**：`net` 分支把端口硬编码成 0 传给 daemon，两轮"bind_addr 无效"的实验测的都是根本没请求固定端口的路径。正确用法＝`bind_addr(0.0.0.0:port)` 且**不要**先 `clear_ip_transports()`（清空传输会把绑定请求一起丢掉）。实测 `local_addr = 172.17.0.4:7801`。剩余边界：跑临时端口的节点仍需好友互助寻址（`find`/`peer-where`）或 M5a 自托管 pkarr。

## 全功能矩阵（对照原版 libretroshare services + plugins，实现里程碑 M2-M7）
| 原版功能 | 新版对应 | 里程碑 |
|---|---|---|
| 好友聊天 (chat service) | iroh 私信 + SQLite 存储 | M2 ✅ |
| 文件分享/下载 (FileTransfer) | 流式+断点续传+sha 校验+带宽限速 **已通**；**批量拉取(一次 ls，按 sha256 跳过已持有、跨名去重、同名冲突替换、半截续传) 已通**；分块/边下边播 待做 | M2 ✅/M3 ✅ |
| 论坛 forums + 频道 channels (P3/Forums) | append-only 日志 (author,seq) + merkle root 收敛 **已通**；订阅位点/频道 待做 | M2 ✅/M3 |
| 数据擦除 forget | 本地删除 + **墓碑**（合并身份是 (author,channel,seq)，没有墓碑则下次同步必然复活）；同事务清理搜索索引；序号跨墓碑单调不复用。**边界**：只擦本节点，已复制的朋友仍持有（F2F 无协作式分布式删除） | M3 ✅ |
| 私密圈 (上游 rsgxscircles) | 圈子=具名好友集；频道可绑定圈子，**在发送侧**过滤正文/根/频道定义（接收侧过滤等于把内容存下来再藏起来，不是机密性）。解除与恢复即时生效 **已通** | M3 ✅ |
| 在线状态 (上游 rsstatus) | 推导式（最近一次已通过门禁的联系，阈值 120s/900s）**+ 自报状态**：`hi` 帧携带 state/idle，心跳 = 周期性重发 `hi`（`RSNEXT_STATUS_TICK=<秒>`，**默认关闭**：定期拨遍所有好友是真实后台流量，尚未在差链路上测过代价）。视图合并规则：自报新鲜则用自报，过期回落观测，并标注 `source`。**尚未做**：默认开启与空闲时长的真实测量（当前由 CLI 声明） | M3 ✅ |
| 封禁名单 (上游 rsbanlist) | 指纹级永久拒绝，**在 peer_gate 最前面判定**（先证明身份再查名单等于无法断交）；带原因、可查、挺过重启、解封不破坏既有绑定 **已通** | M3 ✅ |
| Wiki 页面 (上游 rswiki) | 页面=`wiki/<slug>` 频道，修订只追加；当前版本按 (ts,author,seq) 全序，两端必然一致；秒级同秒平局由 CLI 明示 **已通** | M3 ✅ |
| RSS 阅读器 plugin | 本地 feed 抓取(RSS2.0/Atom，guid 去重、坏订阅隔离、4MiB 上限) + 条目入频道 **已通**；AI 摘要(M4 后) 待做 | M3 ✅ |
| VOIP plugin | WebRTC(Rust `webrtc` crate) 1v1 语音，走同一 NodeAddr 寻址 | M5b |
| Web-of-Trust / GXS 签名 (PkItem/X-PEERS) | Ed25519 信任签名链 + 本地图计算（好友的好友评分） | M3 |
| 隐藏服务 (Tor/I2P) | iroh relay 自托管 + 可选 Arti 洋葱路由开关 | M5a |
| WebUI (retroshare-webui) | **回环 HTTP + SSE 桥已落地**(`web <dir> [127.0.0.1:8780]`，bearer token 0600、无新依赖、仅绑回环；单文件 UI 直接消费 RPC+事件流)，Tauri 只需包装同一套资源 | M3(进行中) |
| 链接同步 (LinkedSync) | posts↔files 引用完整性随 Merkle 日志天然覆盖 | M2 |
| retroshare-friendserver | 不需要：invite 深链自包含（M1 已证） | — |

## 现代特性对照（旧版痛点 → 新版解法）
| RetroShare 2006 | RetroShare-Next |
|---|---|
| 复制粘贴几百行 PGP 证书 | 扫码/魔法深链加好友，一次点击双向绑定 |
| UPnP 手动端口映射、防火墙玄学 | QUIC/iroh 自动穿透 + AI 诊断大白话指引 |
| BBS 纯文本论坛 | Markdown 富文本 + AI 摘要/降噪/本地语义搜索；**深度索引已就位**（对齐上游 `src/deep_search/` 的形状：per-kind indexer、`retroshare://` 文档身份、weight+snippet；引擎为 SQLite 倒排 + BM25，因 Xapian 为外部 C++ 库不可得） |
| 下载完才能看 | 分块流式，边下边播 |
| Qt 桌面-only | Tauri 全平台 + 手机轻终端 + Home Node |

## 关键决策记录（追加）
7. **不用 `presets::N0`**：它挂 PkarrPublisher/PkarrResolver，会把 `endpoint_id→当前地址` 发布到 n0 公共 DNS——对"零云端依赖 + F2F"是外部依赖兼元数据泄漏。统一用 `presets::Minimal` + 自管地址（深链 + `my_addr` 学习）。公共名字系统若要用，走 M5a 自托管。
8. **对端拨号一律经 daemon**（`main::delegate_plan` → 控制面）：CLI 自己 dial 会新建一次性 endpoint，其源端口随进程消失，会把对端记录污染成死地址（实测导致 sync-all 全灭）。附带收益：UI/CLI/Home Node 只有"一个节点=一个监听套接口"这一种心智模型。
9. **帖子主键 = `(author, seq)`**，seq 每作者自增：单一本地自增 seq 会跨节点撞号，`INSERT OR IGNORE` 静默丢帖（实测丢了 bob 的一条）。

## 构建 / 验证入口（本机 Ubuntu 24.04，Docker-only，本机不装工具链）
```bash
docker run -d --name rsnext-dev -v $PWD:/src -v rsnext-target:/target \
  -v rsnext-cargo-registry:/usr/local/cargo/registry -e CARGO_TARGET_DIR=/target -w /src rust:1-bookworm sleep infinity
docker exec rsnext-dev cargo build --workspace
bash tools/gates_m2.sh     # 功能面：两容器 rs-alice/rs-bob 真实跨主机拓扑
bash tools/gates_u123.sh   # 安全语义 + 回归容错（U1 归 XFAIL）
bash tools/gates.sh        # 总入口：cargo test + 上面两套；当前 FAILURES=0，XFAIL 全为 U1
docker exec rsnext-dev cargo test --workspace   # 6 个单元测试直测 peer_gate 授权判定与 .part 排他
```

## 本机环境记录 (2026-11-18)
- 无 MSVC Build Tools（PATH 里 link.exe 是 git-bash 的，rust 链接会炸）→ 采用 **stable-x86_64-pc-windows-gnu** 工具链（自带 mingw）。
- 构建网络：默认直连即可；处于需要代理的环境时自行设置 HTTPS_PROXY。
- 工作目录：<repo-root>
- 构建环境定论(2026-11-19 实测): windows-gnu 链接 iroh 死于 mingw ld export-ordinal-too-large(PE 64K 导出表上限,目标性缺陷非本项目代码); MSVC 未装。唯一顺畅路线=Linux(rust:1-bookworm Docker 或 Ubuntu),Dockerfile+compose 已就位,Cargo.lock 锁 403 包跨机复现。禁再试 Windows 原生编译。
- 构建环境：Linux + Docker（在 rust:1-bookworm 容器内构建，主机不装工具链）。

验证基线(2026-11-19，单次串跑 `bash tools/gates.sh`)：**AGG_EXIT=0，六套全绿且 XFAIL=0** —— cargo test 19/19；gates_m2、gates_u123、gates_wot、gates_channel、gates_mesh 均 FAILURES=0；gates_web 10/10。后续任何改动以"聚合仍为 0 且无新增 XFAIL"为回归标准。注意：六套门禁共用容器与固定端口(7801/7802/7803/7812/7813)，**不可并发运行**（gates.sh 已加 /tmp 互斥锁，第二实例直接 rc=4）。
