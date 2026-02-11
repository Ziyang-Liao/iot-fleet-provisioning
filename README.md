# AWS IoT Core Fleet Provisioning & Certificate Auto-Rotation Demo

This project demonstrates AWS IoT Core Fleet Provisioning with automatic certificate rotation, including a web-based testing UI.

## Features

- **Fleet Provisioning** — Provision devices using claim certificates via MQTT
- **IoT Policy ACL** — Fine-grained topic-level access control per device
- **Certificate Rotation** — Manual and automatic certificate rotation with old cert revocation
- **Web Test UI** — Real-time dashboard for provisioning, MQTT pub/sub, and rotation testing
- **Security** — Token-based auth, input validation, atomic cert writes, timing-safe comparisons

## Architecture

```
┌─────────────┐     MQTT/TLS      ┌──────────────────┐
│  EC2 Device  │◄────────────────►│   AWS IoT Core    │
│  Simulator   │                   │                   │
│              │  Fleet Provision   │  ┌─────────────┐ │
│  ┌────────┐  │◄─────────────────►│  │ Provisioning│ │
│  │ Web UI │  │  (claim cert)     │  │  Template   │ │
│  └────────┘  │                   │  └──────┬──────┘ │
└─────────────┘                   │         │        │
                                   │  ┌──────▼──────┐ │
                                   │  │   Lambda    │ │
                                   │  │ Pre-Provision│ │
                                   │  │    Hook     │ │
                                   │  └─────────────┘ │
                                   └──────────────────┘
```

## Certificate Rotation Flow

```
1. Device uses current cert to connect for provisioning
2. Requests new keys + certificate via Fleet Provisioning MQTT API
3. Registers thing with new certificate
4. Backs up old cert, atomically writes new cert
5. Detaches old cert from thing, revokes old cert
6. Reconnects with new cert
```

## Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.9+
- EC2 instance (or any machine with AWS credentials)

## Quick Start

### 1. Install dependencies

```bash
pip3 install awsiotsdk flask boto3
```

### 2. Download Amazon Root CA

```bash
curl -o certs/AmazonRootCA1.pem https://www.amazontrust.com/repository/AmazonRootCA1.pem
```

### 3. Setup IoT resources

```bash
python3 setup_iot.py
```

This creates:
- IoT Policies (`DevicePolicy`, `ClaimPolicy`) with least-privilege ACL
- Pre-provisioning Lambda hook
- Fleet Provisioning template with IAM role
- Claim certificate for initial device provisioning
- `config.json` with all generated configuration

### 4. Start the web UI

```bash
# With authentication (recommended)
API_TOKEN=your-secret-token python3 app.py

# Without authentication (for Cloud9 / internal testing)
SKIP_AUTH=1 python3 app.py

# Custom port
SKIP_AUTH=1 python3 -c "from app import app; app.run(host='0.0.0.0', port=8080)"
```

### 5. Use the web UI

1. **Provision** — Enter device serial, click "Provision Device"
2. **Connect** — Click "Connect" to establish MQTT connection
3. **Pub/Sub** — Publish messages and subscribe to topics
4. **Rotate** — Disconnect first, then click "Rotate Certificate"
5. **Auto-Rotate** — Configure interval and start automatic rotation

## IoT Policy Design

### Device Policy
- `iot:Connect` — Only with client ID matching thing name
- `iot:Publish/Subscribe/Receive` — Only `device/{thingName}/*` + provisioning topics

### Claim Policy
- Only allows Fleet Provisioning MQTT topics (`$aws/certificates/create/*`, `$aws/provisioning-templates/*/provision/*`)

## Project Structure

```
├── setup_iot.py          # One-click IoT resource creation
├── device_client.py      # Device client (provisioning, MQTT, rotation)
├── app.py                # Flask web server with REST API
├── config.json           # Generated config (gitignored)
├── templates/
│   └── index.html        # Web UI
├── certs/                # Certificates (gitignored)
│   └── AmazonRootCA1.pem
├── requirements.txt
├── .gitignore
└── README.md
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_TOKEN` | random | Authentication token for web UI |
| `SKIP_AUTH` | unset | Set to `1` to disable authentication |
| `FLASK_SECRET` | random | Flask session secret key |

## Cleanup

To remove all created AWS resources:

```bash
python3 cleanup.py
```

## Security Notes

- Claim certificates should be rotated periodically in production
- Use HTTPS (e.g., behind ALB) for production deployments
- The `SKIP_AUTH` mode is only for internal/Cloud9 testing
- Device certificates are written atomically to prevent corruption
- Old certificates are detached and revoked after rotation

## License

MIT
