# 基于 srsUE IMS APN 的 Python VoLTE 测试客户端设计文档

## 1. 文档目的

本文档用于指导在 Cursor IDE 中继续开发一个面向实验室内网环境的 Python IMS/VoLTE 测试客户端。

该客户端运行在 Linux 主机上，依托已运行的 srsUE 建立 LTE 接入和 IMS APN 数据通道，在 Linux 虚拟网卡之上自行完成：

- IMS SIP 注册
- IMS AKA 鉴权
- 3GPP IPsec 安全关联建立
- SIP 呼叫发起和维护
- RTP 语音媒体发送
- RTP 语音媒体接收
- AMR-WB 文件保存
- 定时结束通话并发送 BYE

本项目定位为单用户、单通话、固定流程的内网 Demo，不作为生产级 IMS 终端，也不考虑高并发、复杂异常恢复、网络切换和完整协议兼容性。

---

## 2. 项目背景

当前实验环境已经具备以下条件：

1. Linux 上运行 srsENB 和 srsUE。
2. srsUE 已成功接入 LTE 网络。
3. srsUE 已成功建立 IMS APN。
4. IMS APN 在 Linux 中暴露为虚拟网卡，例如：

```text
simu_d63cc342
```

5. 该虚拟网卡已获得 IMS APN 地址。
6. 通过该网卡可以访问 P-CSCF。
7. 抓包显示 IMS 网络使用：

```text
WWW-Authenticate: Digest
algorithm=AKAv1-MD5
```

以及：

```text
Security-Server: ipsec-3gpp
```

8. P-CSCF 返回的安全参数包括：

```text
ealg=null
alg=hmac-md5-96
prot=esp
mod=trans
spi-c
spi-s
port-c
port-s
```

因此，该网络并不是普通 SIP 网络，而是要求：

- IMS AKA 鉴权
- 3GPP IMS IPsec
- SIP over protected transport
- IMS 专用 SIP 头域
- 后续呼叫和媒体流程

---

## 3. 整体架构

```text
+---------------------------------------------------+
|             Python IMS Test Client                |
|                                                   |
|  +----------------+    +-----------------------+  |
|  | SIP/SDP Module |    | IMS AKA Module        |  |
|  +----------------+    +-----------------------+  |
|                                                   |
|  +----------------+    +-----------------------+  |
|  | IPsec/XFRM     |    | RTP/AMR-WB Module     |  |
|  +----------------+    +-----------------------+  |
|                                                   |
|  +---------------------------------------------+  |
|  | Call Orchestrator / State Machine           |  |
|  +---------------------------------------------+  |
+--------------------------+------------------------+
                           |
                           | bind to IMS APN IP
                           v
                +-------------------------+
                | simu_d63cc342           |
                | Linux virtual interface |
                +-------------------------+
                           |
                           v
                     +-----------+
                     | srsUE     |
                     +-----------+
                           |
                           v
                    LTE / EPC / IMS
```

### 3.1 srsUE 的职责

srsUE 继续负责：

- LTE PHY/MAC/RLC/PDCP/RRC/NAS
- LTE 鉴权
- IMS APN 建立
- EPS bearer 管理
- Linux 虚拟网卡数据转发
- QCI 5、QCI 1 等承载映射

Python 程序不能替代 srsUE。

### 3.2 Python 程序的职责

Python 程序负责：

- 通过 IMS APN 虚拟网卡发送和接收 IP 数据
- 建立 TCP SIP 连接
- 构造和解析 SIP 消息
- 完成 IMS AKA
- 建立 Linux XFRM state 和 policy
- 发送二次 REGISTER
- 发起 INVITE
- 处理 SIP 会话
- RTP 收发
- AMR-WB 文件处理
- 定时发送 BYE
- 释放资源

---

## 4. 第一版范围

### 4.1 必须实现

第一版仅要求支持以下成功流程：

```text
获取 IMS 网卡 IP
    ↓
连接 P-CSCF
    ↓
发送初始 REGISTER
    ↓
收到 401 Unauthorized
    ↓
解析 AKA 和 Security-Server 参数
    ↓
使用 CryptoMobile 计算 RES、CK、IK
    ↓
构造 Authorization
    ↓
建立 XFRM state 和 policy
    ↓
发送 IPsec 保护后的 REGISTER
    ↓
收到 200 OK
    ↓
发送 INVITE
    ↓
处理 100 / 180 / 183 / PRACK / 200
    ↓
发送 ACK
    ↓
发送 AMR-WB RTP
    ↓
接收 AMR-WB RTP
    ↓
保存远端语音为 .amr
    ↓
等待固定时间
    ↓
发送 BYE
    ↓
收到 200 OK
    ↓
停止媒体并清理资源
```

### 4.2 第一版不实现

第一版不考虑：

- 多用户
- 多路并发
- 自动重试
- SIP UDP 重传
- 注册刷新
- IPsec SA 自动续期
- SQN 自动重同步
- AUTS
- DNS 查询
- P-CSCF 自动发现
- 多 P-CSCF
- NAT 穿透
- ICE
- SRTP
- TLS
- 多 codec 协商
- RTP jitter buffer
- RTP 丢包补偿
- RTP 重排序
- 语音实时播放
- 麦克风采集
- 被叫接听
- IMS emergency call
- 网络切换
- 完整 QoS precondition
- 并发安全
- 生产级日志和监控

---

## 5. 技术选型

## 5.1 开发语言

使用：

```text
Python 3.11 或 Python 3.12
```

原因：

- 适合网络协议 PoC
- 字节流处理方便
- 调用 Linux 命令方便
- 调用 FFmpeg 方便
- 便于打印原始 SIP、SDP、RTP 和 XFRM 信息
- 单路 RTP 不存在性能压力

---

## 5.2 SIP

不使用：

- PJSIP
- SIPp 运行时
- 通用 SIP 软电话

第一版自行实现最小 SIP over TCP。

SIPp 和 sipp_ipsec 仅作为参考项目，用于参考：

- IMS REGISTER 报文
- Security-Client
- Security-Verify
- IMS AKA
- XFRM 方向
- INVITE/PRACK/ACK/BYE 流程

程序本身不依赖 SIPp。

---

## 5.3 IMS AKA

使用：

```text
CryptoMobile
```

CryptoMobile 用于 Milenage 计算，包括：

- f1
- f2
- f3
- f4
- f5
- RES
- CK
- IK
- AK
- MAC-A

程序自行负责：

- nonce Base64 解码
- RAND/AUTN 拆分
- SQN 恢复
- AUTN 校验
- AKAv1-MD5 Digest 构造
- Authorization 头生成

---

## 5.4 IPsec

不使用完整 IKE 或 strongSwan。

第一版直接调用 Linux：

```text
ip xfrm state
ip xfrm policy
```

Python 使用 `subprocess.run()` 执行。

主要用途：

- 建立 inbound/outbound ESP SA
- 建立 inbound/outbound policy
- 指定 SPI
- 指定认证算法
- 指定加密算法
- 指定传输模式
- 指定源地址、目的地址和端口 selector
- 删除测试过程中创建的 SA 和 policy

第一版以可读、可调试为优先，不使用 Netlink API。

---

## 5.5 RTP

使用 Python 标准库：

```text
socket
struct
threading
time
```

自行实现：

- RTP 固定头
- sequence number
- timestamp
- SSRC
- payload type
- marker
- RTP 发送
- RTP 接收
- 基础 RTP 头解析

---

## 5.6 AMR-WB

发送端：

```text
WAV
  ↓
FFmpeg 预先转换
  ↓
.amr
  ↓
Python 读取 AMR-WB storage frame
  ↓
转换为 RFC 4867 RTP payload
  ↓
通过 RTP 发送
```

接收端：

```text
RTP payload
  ↓
解析 RFC 4867 AMR-WB payload
  ↓
还原 AMR-WB storage frame
  ↓
写入 received.amr
  ↓
通话结束后手动使用 FFmpeg 转 WAV
```

第一版仅支持：

- AMR-WB
- 16 kHz
- 单声道
- 20 ms 一帧
- octet-aligned=1
- 每个 RTP 包一个 AMR-WB frame
- 无 CRC
- 无 interleaving
- 无 robust sorting

---

## 6. 项目结构

建议目录结构如下：

```text
ims-volte-demo/
├── README.md
├── requirements.txt
├── config/
│   └── demo.yaml
├── main.py
│
├── app/
│   ├── __init__.py
│   ├── orchestrator.py
│   └── state.py
│
├── network/
│   ├── __init__.py
│   ├── interface.py
│   └── route.py
│
├── sip/
│   ├── __init__.py
│   ├── message.py
│   ├── parser.py
│   ├── builder.py
│   ├── transport.py
│   ├── dialog.py
│   ├── register.py
│   └── call.py
│
├── aka/
│   ├── __init__.py
│   ├── milenage_service.py
│   └── digest_akav1.py
│
├── ipsec/
│   ├── __init__.py
│   ├── security_header.py
│   └── xfrm_manager.py
│
├── sdp/
│   ├── __init__.py
│   ├── parser.py
│   └── builder.py
│
├── media/
│   ├── __init__.py
│   ├── rtp_packet.py
│   ├── rtp_sender.py
│   ├── rtp_receiver.py
│   ├── amrwb_file.py
│   └── amrwb_payload.py
│
├── tools/
│   ├── __init__.py
│   ├── command.py
│   ├── capture.py
│   └── ffmpeg.py
│
├── logs/
├── captures/
├── media_files/
│   ├── send.amr
│   └── received.amr
│
└── tests/
    ├── test_sip_parser.py
    ├── test_aka.py
    ├── test_digest.py
    ├── test_sdp.py
    ├── test_rtp.py
    └── test_amrwb.py
```

---

## 7. 主要模块职责

## 7.1 Orchestrator

文件：

```text
app/orchestrator.py
```

职责：

- 驱动整个 Demo 流程
- 控制执行顺序
- 保存当前状态
- 调用注册模块
- 调用呼叫模块
- 启动和停止 RTP
- 定时触发 BYE
- 结束时清理 XFRM 和 socket

建议状态：

```text
INIT
NETWORK_READY
TCP_CONNECTED
REGISTER_SENT
AKA_CHALLENGE_RECEIVED
IPSEC_READY
REGISTERED
INVITE_SENT
EARLY_DIALOG
CALL_ESTABLISHED
MEDIA_RUNNING
TERMINATING
TERMINATED
FAILED
```

---

## 7.2 Network

文件：

```text
network/interface.py
network/route.py
```

职责：

- 获取指定 Linux 网卡 IPv4
- 验证网卡存在
- 验证网卡状态
- 验证 P-CSCF 路由
- 获取程序应绑定的本地 IMS IP

配置示例：

```yaml
network:
  interface: simu_d63cc342
  pcscf_ip: 190.0.0.10
  pcscf_port: 5060
```

---

## 7.3 SIP Transport

文件：

```text
sip/transport.py
```

职责：

- 创建 TCP socket
- 绑定 IMS APN IP
- 连接 P-CSCF
- 发送 SIP 字节流
- 接收 TCP 字节流
- 处理半包
- 处理粘包
- 根据 `Content-Length` 拆分 SIP 消息

第一版只支持 TCP。

---

## 7.4 SIP Message / Parser / Builder

文件：

```text
sip/message.py
sip/parser.py
sip/builder.py
```

职责：

- SIP 起始行模型
- SIP Header 模型
- SIP Body 模型
- Header 大小写不敏感
- 支持重复 Header
- 构造 REGISTER
- 构造 INVITE
- 构造 PRACK
- 构造 ACK
- 构造 BYE
- 构造 200 OK
- 解析响应码
- 解析 CSeq
- 解析 Call-ID
- 解析 From/To tag
- 解析 Contact
- 解析 Route/Record-Route
- 解析 WWW-Authenticate
- 解析 Security-Server
- 解析 Service-Route
- 解析 SDP

第一版不做完整 RFC 级实现，只覆盖现网成功流程。

---

## 7.5 IMS AKA

文件：

```text
aka/milenage_service.py
aka/digest_akav1.py
```

职责：

- 调用 CryptoMobile
- 输入 K、OPc、RAND、AUTN
- 输出 RES、CK、IK
- 校验 MAC-A
- 构造 AKAv1-MD5 Digest response
- 构造 SIP Authorization Header

配置需要包含：

```yaml
subscriber:
  imsi: "..."
  impi: "..."
  impu: "sip:..."
  realm: "ims.system.com"
  k: "..."
  opc: "..."
```

K、OPc 使用十六进制字符串。

---

## 7.6 IPsec / XFRM

文件：

```text
ipsec/security_header.py
ipsec/xfrm_manager.py
```

职责：

- 解析 Security-Server
- 生成 Security-Client
- 生成 Security-Verify
- 管理本地 SPI
- 管理 P-CSCF SPI
- 生成 `ip xfrm state` 命令
- 生成 `ip xfrm policy` 命令
- 执行命令
- 查询 XFRM 状态
- 清理 SA 和 policy

第一版需要重点记录：

- UE IP
- P-CSCF IP
- local protected port
- remote protected port
- spi-c
- spi-s
- CK
- IK
- inbound/outbound selector
- state 建立顺序
- policy 建立顺序

该模块是项目最大风险点，需要对照真实抓包和 sipp_ipsec 行为调试。

---

## 7.7 SIP Registration

文件：

```text
sip/register.py
```

职责：

1. 构造初始 REGISTER
2. 发送 REGISTER
3. 接收 401
4. 提取 AKA 和 IPsec 参数
5. 调用 AKA
6. 调用 XFRM
7. 构造二次 REGISTER
8. 携带 Authorization
9. 携带 Security-Verify
10. 通过 IPsec 发送
11. 处理 200 OK
12. 保存 Service-Route
13. 保存 P-Associated-URI
14. 保存注册相关 Dialog 信息

---

## 7.8 SDP

文件：

```text
sdp/parser.py
sdp/builder.py
```

职责：

- 构造本地 AMR-WB SDP
- 解析远端媒体 IP
- 解析远端 RTP 端口
- 解析 payload type
- 解析 AMR-WB codec
- 解析 fmtp
- 判断 `octet-align=1`
- 解析 sendrecv/inactive
- 识别 100rel 和基础 precondition 信息

第一版只支持一个 audio media。

---

## 7.9 Call

文件：

```text
sip/call.py
sip/dialog.py
```

职责：

- 构造 INVITE
- 保存 Call-ID
- 保存 From tag
- 保存 To tag
- 保存 Contact
- 保存 Route Set
- 处理 100
- 处理 180
- 处理 183
- 处理 RSeq
- 发送 PRACK
- 处理 200 PRACK
- 处理 200 INVITE
- 发送 ACK
- 建立 Dialog
- 定时发送 BYE
- 处理 200 BYE
- 处理远端 BYE 并回复 200

---

## 7.10 RTP

文件：

```text
media/rtp_packet.py
media/rtp_sender.py
media/rtp_receiver.py
```

职责：

- 构造 RTP Header
- 解析 RTP Header
- 按 20 ms 周期发送
- sequence 每包加 1
- AMR-WB timestamp 每包加 320
- socket 绑定 IMS APN IP
- 目标地址来自远端 SDP
- 接收远端 RTP
- 提取 payload
- 保存统计信息

第一版只处理单 SSRC。

---

## 7.11 AMR-WB

文件：

```text
media/amrwb_file.py
media/amrwb_payload.py
```

职责：

发送方向：

- 读取 `#!AMR-WB\n`
- 逐帧读取 AMR-WB storage frame
- 提取 FT、Q 和 speech data
- 转换为 RTP octet-aligned payload

接收方向：

- 解析 RTP CMR
- 解析 TOC
- 提取 FT、Q
- 提取 speech bits
- 还原 AMR-WB storage frame
- 写入 `received.amr`

---

## 8. 配置文件建议

文件：

```text
config/demo.yaml
```

示例结构：

```yaml
network:
  interface: simu_d63cc342
  pcscf_ip: 190.0.0.10
  pcscf_port: 5060
  local_sip_port: 5060
  local_protected_port: 15060
  local_rtp_port: 40000

subscriber:
  imsi: "001010123456789"
  impi: "001010123456789@ims.system.com"
  impu: "sip:001010123456789@ims.system.com"
  realm: "ims.system.com"
  k: "00112233445566778899AABBCCDDEEFF"
  opc: "00112233445566778899AABBCCDDEEFF"

call:
  target_uri: "sip:001010987654321@ims.system.com"
  duration_seconds: 30
  local_display_name: "IMS Demo UE"

media:
  codec: "AMR-WB"
  payload_type: 96
  clock_rate: 16000
  ptime_ms: 20
  octet_align: true
  send_file: "media_files/send.amr"
  receive_file: "media_files/received.amr"

debug:
  dump_sip: true
  dump_sdp: true
  dump_xfrm_commands: true
  execute_xfrm_commands: true
  capture_pcap: true
```

第一版可以先明文保存 K 和 OPc，因为仅用于受控内网 Demo。

---

## 9. 实现阶段

# 阶段 1：项目骨架和配置

目标：

- 创建目录结构
- 加载 YAML 配置
- 初始化日志
- 定义状态枚举
- 定义基础异常类型
- 提供统一主入口

验收：

```text
python main.py --config config/demo.yaml
```

能够加载配置并输出参数摘要。

---

# 阶段 2：网络检查

目标：

- 获取 `simu_d63cc342` IPv4
- 验证 P-CSCF 路由
- 验证 TCP 连接
- 确认 socket 绑定到 IMS IP

验收：

- 程序输出本地 IMS IP
- 成功连接 P-CSCF
- tcpdump 确认源 IP 为 IMS APN IP

---

# 阶段 3：SIP TCP 收发

目标：

- 实现 TCP transport
- 实现 SIP 消息边界解析
- 支持 Content-Length
- 输出原始发送和接收报文

验收：

- 能发送最小 REGISTER
- 能完整接收 401
- 不受 TCP 半包、粘包影响

---

# 阶段 4：SIP 解析和初始 REGISTER

目标：

- 实现 SIP parser
- 实现 SIP builder
- 构造初始 REGISTER
- 解析 401
- 提取 WWW-Authenticate
- 提取 Security-Server

验收：

程序能输出：

```text
realm
nonce
opaque
algorithm
qop
spi-c
spi-s
port-c
port-s
alg
ealg
prot
mod
```

---

# 阶段 5：IMS AKA

目标：

- 接入 CryptoMobile
- 解析 RAND 和 AUTN
- 计算 RES、CK、IK
- 校验 AUTN
- 生成 AKAv1-MD5 response
- 生成 Authorization Header

验收：

- 使用 3GPP 测试向量验证
- 对现网 401 计算成功
- 输出 MAC 校验结果
- 输出 RES、CK、IK 的十六进制调试值

---

# 阶段 6：Security Agreement 和 XFRM

目标：

- 生成本地 Security-Client
- 解析 Security-Server
- 生成 Security-Verify
- 生成 XFRM state 命令
- 生成 XFRM policy 命令
- 执行并验证 XFRM

验收：

```text
ip -s xfrm state
ip -s xfrm policy
```

可以看到对应 state 和 policy。

第二次 REGISTER 发送后，XFRM 计数器增加。

抓包出现 ESP。

---

# 阶段 7：IMS 注册成功

目标：

- 发送二次 REGISTER
- 携带 Authorization
- 携带 Security-Verify
- 使用正确端口
- 通过 IPsec
- 处理 200 OK
- 保存 Service-Route

验收：

- 收到 200 OK
- 状态变为 REGISTERED
- IMS 核心网可查询到用户已注册

---

# 阶段 8：INVITE 和呼叫建立

目标：

- 构造 INVITE
- 携带 SDP
- 发送到目标 IMPU
- 处理 100
- 处理 180
- 处理 183
- 根据 100rel 发送 PRACK
- 处理 200 INVITE
- 发送 ACK

验收：

- 远端 UE 正常响铃
- 远端接通
- 本端收到 200 INVITE
- 本端发送 ACK
- 状态变为 CALL_ESTABLISHED

---

# 阶段 9：AMR-WB RTP 发送

目标：

- 读取 `.amr`
- 转换 storage frame 到 RTP payload
- 每 20 ms 发送一帧
- RTP 绑定 IMS IP
- RTP 目标来自远端 SDP

验收：

- 远端 UE 能听到预置语音
- Wireshark 可以解析 RTP/AMR-WB
- sequence 连续
- timestamp 每包增加 320

---

# 阶段 10：AMR-WB RTP 接收

目标：

- 接收远端 RTP
- 解析 RTP
- 提取 AMR-WB payload
- 转换为 storage frame
- 写入 `received.amr`

验收：

```bash
ffmpeg -i media_files/received.amr received.wav
```

能够成功转码并听到远端语音。

---

# 阶段 11：定时 BYE 和资源清理

目标：

- 通话建立后启动定时器
- 到达固定时长后停止 RTP 发送
- 发送 BYE
- 处理 200 OK
- 停止 RTP 接收
- 关闭文件
- 关闭 SIP socket
- 删除 XFRM state 和 policy

验收：

- 远端正常结束通话
- 本端收到 200 BYE
- `ip xfrm state` 中测试 SA 被清理
- `received.amr` 文件正常关闭

---

## 10. 最小 SIP 流程

## 10.1 注册流程

```text
Python Client                     P-CSCF / IMS
     |                                  |
     |-------- REGISTER --------------->|
     |                                  |
     |<------- 401 Unauthorized --------|
     |        WWW-Authenticate          |
     |        Security-Server           |
     |                                  |
     |-- AKA / CK / IK / XFRM setup --> |
     |                                  |
     |==== REGISTER protected by ESP ===>|
     |        Authorization             |
     |        Security-Verify           |
     |                                  |
     |<==== 200 OK protected by ESP ====|
     |                                  |
```

---

## 10.2 呼叫流程

```text
Python Client                      IMS / Remote UE
     |                                   |
     |------------- INVITE ------------>|
     |<------------ 100 Trying ----------|
     |<------ 183 Session Progress ------|
     |------------- PRACK ------------->|
     |<------------ 200 OK --------------|
     |<------------ 180 Ringing ----------|
     |<------------ 200 OK ---------------|
     |-------------- ACK --------------->|
     |                                   |
     |========= RTP AMR-WB =============>|
     |<======== RTP AMR-WB ==============|
     |                                   |
     |-------------- BYE --------------->|
     |<------------ 200 OK --------------|
```

---

## 11. 日志要求

第一版要求日志尽量详细，方便在 Cursor 中继续定位问题。

建议日志包括：

- 当前状态
- Linux 网卡名
- 本地 IMS IP
- P-CSCF IP 和端口
- SIP TCP 连接信息
- 每条 SIP 请求和响应
- SIP 状态码
- Call-ID
- CSeq
- From tag
- To tag
- Route Set
- REGISTER 鉴权参数
- RAND
- AUTN
- RES
- CK
- IK
- Security-Client
- Security-Server
- Security-Verify
- XFRM 命令
- XFRM 命令执行结果
- SDP
- RTP 本地和远端地址
- payload type
- sequence
- timestamp
- RTP 收发包数
- AMR-WB 帧数
- BYE 结果

K、OPc 可以只在 debug 模式打印，默认不要输出。

---

## 12. 调试辅助

建议程序支持以下辅助能力：

### 12.1 自动抓包

通过 `tcpdump` 保存：

```text
captures/ims-demo-YYYYMMDD-HHMMSS.pcap
```

抓包范围：

```text
SIP
ESP
RTP
RTCP
```

### 12.2 XFRM 检查

程序在安装后执行：

```text
ip -s xfrm state
ip -s xfrm policy
```

并将输出写入日志。

### 12.3 SIP 原始报文落盘

每条 SIP 消息可保存为：

```text
logs/sip/
  001-send-register.txt
  002-recv-401.txt
  003-send-register-auth.txt
  004-recv-200.txt
```

### 12.4 SDP 落盘

```text
logs/sdp/local-offer.sdp
logs/sdp/remote-answer.sdp
```

---

## 13. 依赖建议

`requirements.txt` 可先包含：

```text
PyYAML
pycryptodome
pytest
```

CryptoMobile 根据实际安装方式引入。

标准库使用：

```text
socket
struct
threading
subprocess
hashlib
base64
dataclasses
enum
logging
time
secrets
pathlib
typing
```

系统依赖：

```text
iproute2
tcpdump
ffmpeg
```

---

## 14. 开发原则

1. 只实现当前现网成功流程。
2. 优先保证可观察、可抓包、可逐步验证。
3. 每个阶段独立验收后再进入下一阶段。
4. 不提前实现复杂异常场景。
5. 不做通用 SIP 库。
6. 不做完整 IMS UE。
7. 不做实时音频播放和采集。
8. 不做并发。
9. 不做生产级安全存储。
10. 所有网络参数均允许配置。
11. 所有 SIP 报文必须保留原始日志。
12. 所有 XFRM 命令必须可打印、可手工执行。
13. AKA、Digest、AMR-WB 转换必须有单元测试。
14. 第一阶段以真实抓包为准，不依赖理论猜测。
15. 对 SPI、port-c、port-s、CK、IK 的方向必须结合真实网络验证。

---

## 15. Cursor 开发任务建议

可以在 Cursor 中按以下任务逐个生成代码。

### Task 1

创建项目骨架、配置加载、日志和状态枚举。

### Task 2

实现 Linux 网卡 IPv4 获取和 P-CSCF 路由检查。

### Task 3

实现 SIP TCP Transport，支持半包、粘包和 Content-Length。

### Task 4

实现最小 SIP Message、Parser 和 Builder。

### Task 5

生成初始 REGISTER，并解析 401。

### Task 6

接入 CryptoMobile，实现 RAND/AUTN 解析和 Milenage。

### Task 7

实现 AKAv1-MD5 Digest 和 Authorization Header。

### Task 8

实现 Security-Client、Security-Server 和 Security-Verify 数据模型。

### Task 9

实现 XfrmManager，先输出命令，不自动执行。

### Task 10

启用 XFRM 自动执行，并完成二次 REGISTER。

### Task 11

解析 200 REGISTER，保存 Service-Route 和注册状态。

### Task 12

实现 SDP Builder 和 Parser。

### Task 13

实现 INVITE、PRACK、ACK 和 BYE。

### Task 14

实现 AMR-WB storage frame 读取。

### Task 15

实现 RFC 4867 octet-aligned RTP payload 生成。

### Task 16

实现 RTP Sender。

### Task 17

实现 RTP Receiver 和 AMR-WB 文件写入。

### Task 18

实现定时 BYE 和统一资源清理。

### Task 19

增加 tcpdump 自动抓包和调试文件输出。

### Task 20

根据真实抓包修正 IMS Header、IPsec selector 和 SDP。

---

## 16. 最终验收标准

Demo 达到以下结果即视为完成：

1. srsUE 已连接 IMS APN。
2. Python 程序识别 `simu_d63cc342`。
3. Python 程序发送初始 REGISTER。
4. 收到 401。
5. CryptoMobile 成功计算 AKA。
6. XFRM state 和 policy 建立成功。
7. 二次 REGISTER 通过 ESP 发送。
8. 收到 200 REGISTER。
9. 目标 UE 收到呼叫并响铃。
10. 目标 UE 接通。
11. Python 程序发送 ACK。
12. 目标 UE 能听到预置 AMR-WB 内容。
13. Python 程序成功接收远端 RTP。
14. 远端 RTP 被保存为 `.amr`。
15. `.amr` 可被 FFmpeg 转换为 WAV。
16. 固定时长后 Python 程序发送 BYE。
17. 收到 200 BYE。
18. 通话正常结束。
19. XFRM 和 socket 被清理。
20. 全流程有完整日志和 PCAP。

---

## 17. 风险点

### 17.1 IPsec SPI 和方向

这是最大风险点。

必须结合：

- 初始 REGISTER
- 401 Security-Server
- UE Security-Client
- 二次 REGISTER
- sipp_ipsec
- Linux XFRM 计数器
- Wireshark ESP 抓包

进行验证。

### 17.2 AKAv1-MD5 Digest

重点核对：

- username 使用 IMPI
- URI 和请求行一致
- RES 的编码形式
- qop
- nc
- cnonce
- opaque
- response 计算方式

### 17.3 IMS SIP Header

IMS 可能要求：

- P-Access-Network-Info
- P-Preferred-Identity
- Security-Client
- Security-Verify
- Supported
- Require
- Proxy-Require
- Contact feature tags
- Service-Route

应以现网真实 UE 抓包为模板。

### 17.4 SDP Precondition

现网若强制 QoS precondition，可能需要处理：

- curr:qos
- des:qos
- conf:qos
- UPDATE

第一版先尝试最小 SDP，失败后再补。

### 17.5 AMR-WB RTP

`.amr` 文件帧不能直接作为 RTP payload，需要进行 storage frame 和 RFC 4867 payload 转换。

---

## 18. 结论

本项目不是实现一个通用 IMS 软电话，而是实现一个固定流程的 Python IMS/VoLTE 测试客户端。

核心技术组合为：

```text
srsUE
+ Linux IMS APN virtual interface
+ Python SIP over TCP
+ CryptoMobile
+ Linux ip xfrm
+ Python RTP
+ AMR-WB
+ FFmpeg
```

建议严格按以下顺序开发：

```text
网络
  ↓
初始 REGISTER
  ↓
401 解析
  ↓
AKA
  ↓
XFRM
  ↓
注册成功
  ↓
INVITE
  ↓
ACK
  ↓
RTP 发送
  ↓
RTP 接收
  ↓
BYE
```

任何阶段未完成前，不进入后续阶段。
