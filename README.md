# AWS IoT Core Fleet Provisioning & Certificate Auto-Rotation Demo

基于 AWS IoT Core Fleet Provisioning 实现设备证书自动轮换的完整方案，使用 X.509 客户端证书 + 私钥（mTLS）进行双向认证，包含 Web 测试界面。

## Features

- **mTLS 双向认证** — 设备使用 X.509 客户端证书 + 私钥与 IoT Core 建立 TLS 连接
- **Fleet Provisioning** — 通过 Claim 证书自动注册设备并签发设备证书
- **IoT Policy ACL** — 基于证书的细粒度 Topic 级别访问控制
- **证书自动轮换** — 后台定时检查证书过期时间，到期前自动申请新证书、吊销旧证书
- **Web 测试界面** — 实时 Dashboard，可视化操作 Provision / MQTT / 轮换全流程

## 证书体系说明

本项目使用 X.509 证书 + 私钥实现 mTLS 双向认证，所有 MQTT 连接都通过 TLS 客户端证书验证身份：

```
┌─────────────────────────────────────────────────────────────┐
│                    证书信任链                                 │
│                                                             │
│  Amazon Root CA (AmazonRootCA1.pem)                         │
│  └── IoT Core 服务端证书 (自动，AWS管理)                      │
│  └── Claim 证书 (claim.cert.pem + claim.key.pem)            │
│       └── 用于 Fleet Provisioning 首次注册                    │
│  └── 设备证书 (device.cert.pem + device.key.pem)             │
│       └── 用于设备日常 MQTT 通信 + 证书轮换                    │
└─────────────────────────────────────────────────────────────┘
```

| 文件 | 类型 | 敏感性 | 用途 | 来源 |
|------|------|--------|------|------|
| `AmazonRootCA1.pem` | Root CA 公钥 | 公开 | 客户端验证 IoT Core 服务端身份 | [Amazon Trust](https://www.amazontrust.com/repository/) 公开下载 |
| `claim.cert.pem` | Claim 客户端证书 | 敏感 | 设备首次注册时的临时 mTLS 身份 | `setup_iot.py` 调用 IoT API 创建 |
| `claim.key.pem` | Claim 私钥 | 敏感 | 配合 Claim 证书完成 TLS 握手 | `setup_iot.py` 调用 IoT API 创建 |
| `device.cert.pem` | 设备客户端证书 | 敏感 | 设备正常运行时的 mTLS 身份 | Fleet Provisioning 过程中 IoT Core 签发 |
| `device.key.pem` | 设备私钥 | 敏感 | 配合设备证书完成 TLS 握手 | Fleet Provisioning 过程中设备端生成 |

### mTLS 连接过程

```
Device                                    IoT Core
  │                                          │
  │──── TLS ClientHello ────────────────────►│
  │◄─── ServerHello + Server Cert ──────────│  (IoT Core 出示服务端证书)
  │                                          │
  │  设备用 AmazonRootCA1.pem 验证服务端证书    │
  │                                          │
  │──── Client Cert + Signed Data ─────────►│  (设备出示客户端证书+私钥签名)
  │                                          │
  │  IoT Core 验证客户端证书是否由其 CA 签发     │
  │  IoT Core 根据证书关联的 Policy 做 ACL 鉴权  │
  │                                          │
  │◄─── TLS Established ───────────────────│
  │──── MQTT CONNECT ──────────────────────►│
  │◄─── MQTT CONNACK ─────────────────────│
```

## Architecture

```
┌─────────────┐   mTLS (证书+私钥)   ┌──────────────────┐
│  EC2 Device  │◄──────────────────►│   AWS IoT Core    │
│  Simulator   │                     │                   │
│              │  Fleet Provision     │  ┌─────────────┐ │
│  ┌────────┐  │  (Claim证书连接)     │  │ Provisioning│ │
│  │ Web UI │  │◄───────────────────►│  │  Template   │ │
│  └────────┘  │                     │  └──────┬──────┘ │
└─────────────┘                     │         │        │
                                     │  ┌──────▼──────┐ │
                                     │  │   Lambda    │ │
                                     │  │ Pre-Provision│ │
                                     │  │    Hook     │ │
                                     │  └─────────────┘ │
                                     └──────────────────┘
```

## 证书轮换流程

```
1. 设备使用当前设备证书+私钥建立 mTLS 连接
2. 通过 Fleet Provisioning MQTT API 请求新的密钥对和证书
3. IoT Core 签发新证书，设备获得新的 cert + key
4. 备份旧证书，原子性写入新证书和私钥
5. 从 Thing 上 Detach 旧证书，然后 Revoke 旧证书
6. 使用新证书+私钥重新建立 mTLS 连接
```

### 自动轮换

后台线程定期检查设备证书的过期时间，当剩余有效期小于设定阈值时自动执行上述轮换流程：

```
[Auto-Rotate Thread]
  │
  ├── 每 N 小时检查一次证书过期时间
  ├── 剩余 < M 天 → 自动执行轮换
  │     ├── 断开当前连接
  │     ├── 用当前证书做 Fleet Provisioning 获取新证书
  │     ├── Detach + Revoke 旧证书
  │     └── 用新证书重连
  └── 剩余 >= M 天 → 跳过，等下次检查
```

## Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.9+
- EC2 instance (or any machine with AWS credentials)

## Quick Start

### 1. Install dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Setup IoT resources (one-click)

```bash
python3 setup_iot.py
```

This automatically:
- Downloads Amazon Root CA (`AmazonRootCA1.pem`)
- Creates IoT Policies (`DevicePolicy`, `ClaimPolicy`) with least-privilege ACL
- Creates Pre-provisioning Lambda hook
- Creates Fleet Provisioning template with IAM role
- Creates Claim certificate + private key for initial device provisioning
- Generates `config.json` with all configuration

### 3. Start the web UI

```bash
# With authentication (recommended)
API_TOKEN=your-secret-token python3 app.py

# Without authentication (for Cloud9 / internal testing)
SKIP_AUTH=1 python3 app.py

# Custom port (e.g., for Cloud9 preview)
SKIP_AUTH=1 python3 -c "from app import app; app.run(host='0.0.0.0', port=8080)"
```

### 4. Use the web UI

1. **Provision** — 输入设备序列号，点击 "Provision Device"（使用 Claim 证书注册，获取设备证书）
2. **Connect** — 点击 "Connect"（使用设备证书建立 mTLS 连接）
3. **Pub/Sub** — 发布和订阅消息
4. **Manual Rotate** — 先 Disconnect，再点击 "Rotate Certificate"
5. **Auto-Rotate** — 设置检查间隔和提前天数，启动自动轮换

## IoT Policy ACL Design

### Device Policy（绑定到设备证书）
- `iot:Connect` — Client ID 必须等于 Thing Name
- `iot:Publish/Subscribe/Receive` — 只允许 `device/{thingName}/*` + Fleet Provisioning topics

### Claim Policy（绑定到 Claim 证书）
- 只允许 Fleet Provisioning 相关 MQTT topics
- 不允许访问任何业务 topic

## Project Structure

```
├── setup_iot.py          # 一键创建所有 AWS 资源 + 下载 Root CA
├── device_client.py      # 设备客户端（mTLS连接、Fleet Provisioning、证书轮换）
├── app.py                # Flask Web 服务 + REST API
├── cleanup.py            # 一键清理所有 AWS 资源
├── config.json           # 生成的配置（gitignored，含 endpoint 和证书路径）
├── templates/
│   └── index.html        # Web UI
├── certs/                # 证书和私钥目录（gitignored）
│   ├── AmazonRootCA1.pem #   Amazon Root CA（公开）
│   ├── claim.cert.pem    #   Claim 客户端证书（setup 生成）
│   ├── claim.key.pem     #   Claim 私钥（setup 生成）
│   └── device_xxx/       #   每个设备的证书+私钥（Fleet Provisioning 生成）
├── requirements.txt
├── .gitignore
└── README.md
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `us-east-1` | AWS Region |
| `IOT_TEMPLATE_NAME` | `CertRotationTemplate` | Provisioning template name |
| `API_TOKEN` | random | Web UI authentication token |
| `SKIP_AUTH` | unset | Set to `1` to disable authentication |
| `FLASK_SECRET` | random | Flask session secret key |

## Cleanup

```bash
python3 cleanup.py
```

Removes: Provisioning Template, Claim Certificate, IoT Policies, Lambda, IAM Roles, Thing Group.

## Security Notes

- All MQTT connections use mTLS (X.509 client certificate + private key)
- Private keys are stored with `0600` permissions
- Certificate files are written atomically (temp file + rename) to prevent corruption
- Old certificates are detached from Thing and revoked after rotation
- Claim certificates should be rotated periodically in production
- Token comparison uses `hmac.compare_digest` to prevent timing attacks
- Serial number input is validated to prevent path traversal

## License

MIT
