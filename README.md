# AWS IoT Core Fleet Provisioning & Certificate Auto-Rotation Demo

A complete solution for automatic device certificate rotation using AWS IoT Core Fleet Provisioning with mTLS (X.509 client certificate + private key) mutual authentication, including a web-based testing UI.

## Features

- **mTLS Mutual Authentication** — Devices connect to IoT Core using X.509 client certificates + private keys over TLS
- **Fleet Provisioning** — Automatic device registration and certificate issuance via claim certificates
- **IoT Policy ACL** — Certificate-based, fine-grained topic-level access control per device
- **Auto Certificate Rotation** — Background thread monitors cert expiry and auto-rotates before expiration
- **Web Test UI** — Real-time dashboard for provisioning, MQTT pub/sub, and rotation testing

## Certificate Architecture

This project uses X.509 certificates + private keys for mTLS mutual authentication. All MQTT connections are authenticated via TLS client certificates:

```
                        Certificate Trust Chain

  Amazon Root CA (AmazonRootCA1.pem)
  ├── IoT Core Server Certificate (managed by AWS, automatic)
  ├── Claim Certificate (claim.cert.pem + claim.key.pem)
  │     └── Used for Fleet Provisioning initial registration
  └── Device Certificate (device.cert.pem + device.key.pem)
        └── Used for daily MQTT communication + certificate rotation
```

| File | Type | Sensitivity | Purpose | Source |
|------|------|-------------|---------|--------|
| `AmazonRootCA1.pem` | Root CA public key | Public | Client verifies IoT Core server identity | [Amazon Trust](https://www.amazontrust.com/repository/) public download |
| `claim.cert.pem` | Claim client certificate | Sensitive | Temporary mTLS identity for initial device registration | Created by `setup_iot.py` via IoT API |
| `claim.key.pem` | Claim private key | Sensitive | Paired with claim cert for TLS handshake | Created by `setup_iot.py` via IoT API |
| `device.cert.pem` | Device client certificate | Sensitive | Device mTLS identity for normal operation | Issued by IoT Core during Fleet Provisioning |
| `device.key.pem` | Device private key | Sensitive | Paired with device cert for TLS handshake | Generated on device during Fleet Provisioning |

### mTLS Handshake Flow

```
Device                                    IoT Core
  │                                          │
  │──── TLS ClientHello ────────────────────►│
  │◄─── ServerHello + Server Cert ──────────│  (IoT Core presents server cert)
  │                                          │
  │  Device verifies server cert using       │
  │  AmazonRootCA1.pem                       │
  │                                          │
  │──── Client Cert + Signed Data ─────────►│  (Device presents client cert + private key signature)
  │                                          │
  │  IoT Core verifies client cert was       │
  │  issued by its CA, then applies IoT      │
  │  Policy ACL based on the certificate     │
  │                                          │
  │◄─── TLS Established ───────────────────│
  │──── MQTT CONNECT ──────────────────────►│
  │◄─── MQTT CONNACK ─────────────────────│
```

## Architecture

```
┌─────────────┐   mTLS (cert+key)    ┌──────────────────┐
│  EC2 Device  │◄───────────────────►│   AWS IoT Core    │
│  Simulator   │                      │                   │
│              │  Fleet Provision      │  ┌─────────────┐ │
│  ┌────────┐  │  (claim cert)        │  │ Provisioning│ │
│  │ Web UI │  │◄────────────────────►│  │  Template   │ │
│  └────────┘  │                      │  └──────┬──────┘ │
└─────────────┘                      │         │        │
                                      │  ┌──────▼──────┐ │
                                      │  │   Lambda    │ │
                                      │  │ Pre-Provision│ │
                                      │  │    Hook     │ │
                                      │  └─────────────┘ │
                                      └──────────────────┘
```

## Certificate Rotation Flow

```
1. Device connects using current device cert + private key (mTLS)
2. Requests new key pair + certificate via Fleet Provisioning MQTT API
3. IoT Core issues new certificate; device receives new cert + key
4. Backs up old cert, atomically writes new cert and private key
5. Detaches old cert from Thing, then revokes old cert
6. Reconnects using new cert + private key (mTLS)
```

### Auto-Rotation

A background thread periodically checks the device certificate expiry and automatically rotates when the remaining validity falls below a configurable threshold:

```
[Auto-Rotate Thread]
  │
  ├── Check cert expiry every N hours
  ├── Remaining < M days → auto-rotate
  │     ├── Disconnect current connection
  │     ├── Fleet Provision with current cert to get new cert
  │     ├── Detach + Revoke old cert
  │     └── Reconnect with new cert
  └── Remaining >= M days → skip, wait for next check
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

1. **Provision** — Enter device serial, click "Provision Device" (uses claim cert, gets device cert)
2. **Connect** — Click "Connect" (establishes mTLS connection with device cert)
3. **Pub/Sub** — Publish and subscribe to messages
4. **Manual Rotate** — Disconnect first, then click "Rotate Certificate"
5. **Auto-Rotate** — Set check interval and threshold days, start auto-rotation

## IoT Policy ACL Design

### Device Policy (attached to device certificate)
- `iot:Connect` — Client ID must equal Thing Name
- `iot:Publish/Subscribe/Receive` — Only `device/{thingName}/*` + Fleet Provisioning topics

### Claim Policy (attached to claim certificate)
- Only allows Fleet Provisioning MQTT topics
- No access to any business topics

## Project Structure

```
├── setup_iot.py          # One-click AWS resource creation + Root CA download
├── device_client.py      # Device client (mTLS connection, Fleet Provisioning, cert rotation)
├── app.py                # Flask web server + REST API
├── cleanup.py            # One-click AWS resource cleanup
├── config.json           # Generated config (gitignored, contains endpoint and cert paths)
├── templates/
│   └── index.html        # Web UI
├── certs/                # Certificates and private keys (gitignored)
│   ├── AmazonRootCA1.pem #   Amazon Root CA (public)
│   ├── claim.cert.pem    #   Claim client certificate (generated by setup)
│   ├── claim.key.pem     #   Claim private key (generated by setup)
│   └── device_xxx/       #   Per-device cert + key (generated by Fleet Provisioning)
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
- Token comparison uses `hmac.compare_digest` to prevent timing attacks
- Serial number input is validated with regex to prevent path traversal

## License

MIT
