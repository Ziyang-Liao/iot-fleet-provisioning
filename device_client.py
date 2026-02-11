#!/usr/bin/env python3
"""IoT Device Client - Fleet Provisioning, MQTT, Certificate Rotation."""
import json, os, time, threading, uuid, shutil, tempfile, re, boto3
from datetime import datetime
from awscrt import mqtt
from awsiot import mqtt_connection_builder, iotidentity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.json")) as f:
    CONFIG = json.load(f)

# 共享 boto3 client，避免每次轮换都创建
_iot_client = None
def _get_iot_client():
    global _iot_client
    if _iot_client is None:
        _iot_client = boto3.client("iot", region_name=CONFIG["region"])
    return _iot_client

# serial number 校验：只允许字母数字和 -_
_SERIAL_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$')

def validate_serial(serial):
    if not _SERIAL_RE.match(serial):
        raise ValueError(f"Invalid serial: only alphanumeric, hyphen, underscore allowed (1-128 chars)")


class DeviceClient:
    def __init__(self, serial_number, on_log=None):
        validate_serial(serial_number)
        self.serial = serial_number
        self.device_dir = os.path.join(CONFIG["certs_dir"], f"device_{serial_number}")
        os.makedirs(self.device_dir, exist_ok=True)
        self.cert_path = os.path.join(self.device_dir, "device.cert.pem")
        self.key_path = os.path.join(self.device_dir, "device.key.pem")
        self.meta_path = os.path.join(self.device_dir, "meta.json")
        self.conn = None
        self.connected = False
        self._on_log = on_log or (lambda msg: print(f"[{serial_number}] {msg}"))
        self.cert_history = []
        self._load_meta()

    def _log(self, msg):
        self._on_log(f"[{datetime.utcnow().isoformat()}] {msg}")

    def _load_meta(self):
        if os.path.exists(self.meta_path):
            with open(self.meta_path) as f:
                self.cert_history = json.load(f).get("cert_history", [])

    def _save_meta(self, cert_id):
        self.cert_history.append({"cert_id": cert_id, "created_at": datetime.utcnow().isoformat()})
        # 原子写入 meta
        fd, tmp = tempfile.mkstemp(dir=self.device_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"serial": self.serial, "cert_history": self.cert_history}, f, indent=2)
            os.replace(tmp, self.meta_path)
        except Exception:
            os.unlink(tmp)
            raise

    def has_device_cert(self):
        return os.path.exists(self.cert_path) and os.path.exists(self.key_path)

    def _save_cert_atomic(self, cert_pem, key_pem):
        """原子性写入证书和私钥：先写两个临时文件，都成功后再一起 rename。"""
        pairs = [(self.cert_path, cert_pem), (self.key_path, key_pem)]
        tmps = []
        try:
            for target, content in pairs:
                fd, tmp = tempfile.mkstemp(dir=self.device_dir, suffix=".tmp")
                tmps.append(tmp)
                with os.fdopen(fd, "w") as f:
                    f.write(content)
                os.chmod(tmp, 0o600)
            # 两个临时文件都写成功后再 rename
            for (target, _), tmp in zip(pairs, tmps):
                os.replace(tmp, target)
        except Exception:
            for tmp in tmps:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise

    def provision(self, use_claim=True):
        """Fleet Provisioning: get device cert via claim cert or existing cert."""
        self._log("Starting fleet provisioning...")
        if use_claim:
            cert, key = CONFIG["claim_cert"], CONFIG["claim_key"]
            client_id = f"provision-{self.serial}-{uuid.uuid4().hex[:8]}"
        else:
            cert, key = self.cert_path, self.key_path
            client_id = self.serial

        conn = mqtt_connection_builder.mtls_from_path(
            endpoint=CONFIG["endpoint"], cert_filepath=cert, pri_key_filepath=key,
            ca_filepath=CONFIG["root_ca"], client_id=client_id,
            clean_session=True, keep_alive_secs=30,
        )
        conn.connect().result(timeout=15)
        self._log("Connected for provisioning")

        try:
            new_keys, thing_name = self._do_fleet_provision(conn)
        except Exception:
            conn.disconnect().result(timeout=5)
            raise

        self._log(f"Thing registered: {thing_name}")

        # Backup old certs
        if self.has_device_cert():
            bak = os.path.join(self.device_dir, f"backup_{int(time.time())}")
            os.makedirs(bak, exist_ok=True)
            shutil.copy2(self.cert_path, os.path.join(bak, "device.cert.pem"))
            shutil.copy2(self.key_path, os.path.join(bak, "device.key.pem"))
            self._log("Backed up old certificates")

        self._save_cert_atomic(new_keys.certificate_pem, new_keys.private_key)
        self._save_meta(new_keys.certificate_id)

        conn.disconnect().result(timeout=5)
        self._log("Provisioning complete!")
        return new_keys.certificate_id

    def _do_fleet_provision(self, conn):
        """执行 Fleet Provisioning MQTT 交互，返回 (keys_response, thing_name)。"""
        identity = iotidentity.IotIdentityClient(conn)
        result = {"keys": None, "register": None}
        errors = []
        events = {"keys": threading.Event(), "register": threading.Event()}

        def on_keys_accepted(resp):
            result["keys"] = resp; events["keys"].set()
        def on_keys_rejected(resp):
            errors.append(f"CreateKeys rejected: {resp.error_code} - {resp.error_message}"); events["keys"].set()
        def on_register_accepted(resp):
            result["register"] = resp; events["register"].set()
        def on_register_rejected(resp):
            errors.append(f"Register rejected: {resp.error_code} - {resp.error_message}"); events["register"].set()

        tmpl = CONFIG["template_name"]
        identity.subscribe_to_create_keys_and_certificate_accepted(
            iotidentity.CreateKeysAndCertificateSubscriptionRequest(), mqtt.QoS.AT_LEAST_ONCE, on_keys_accepted
        )[0].result(timeout=10)
        identity.subscribe_to_create_keys_and_certificate_rejected(
            iotidentity.CreateKeysAndCertificateSubscriptionRequest(), mqtt.QoS.AT_LEAST_ONCE, on_keys_rejected
        )[0].result(timeout=10)
        identity.subscribe_to_register_thing_accepted(
            iotidentity.RegisterThingSubscriptionRequest(template_name=tmpl), mqtt.QoS.AT_LEAST_ONCE, on_register_accepted
        )[0].result(timeout=10)
        identity.subscribe_to_register_thing_rejected(
            iotidentity.RegisterThingSubscriptionRequest(template_name=tmpl), mqtt.QoS.AT_LEAST_ONCE, on_register_rejected
        )[0].result(timeout=10)

        # Create keys
        self._log("Requesting new keys and certificate...")
        identity.publish_create_keys_and_certificate(
            iotidentity.CreateKeysAndCertificateRequest(), mqtt.QoS.AT_LEAST_ONCE
        ).result(timeout=10)

        if not events["keys"].wait(timeout=15):
            raise Exception("Timeout waiting for keys")
        if result["keys"] is None:
            raise Exception(errors[-1] if errors else "CreateKeys failed")

        new_keys = result["keys"]
        self._log(f"Got new certificate: {new_keys.certificate_id[:16]}...")

        # Register thing
        self._log("Registering thing...")
        identity.publish_register_thing(
            iotidentity.RegisterThingRequest(
                template_name=tmpl,
                certificate_ownership_token=new_keys.certificate_ownership_token,
                parameters={"SerialNumber": self.serial},
            ), mqtt.QoS.AT_LEAST_ONCE,
        ).result(timeout=10)

        if not events["register"].wait(timeout=15):
            raise Exception("Timeout waiting for registration")
        if result["register"] is None:
            raise Exception(errors[-1] if errors else "RegisterThing failed")

        return new_keys, result["register"].thing_name

    def rotate_certificate(self):
        """Rotate: provision new cert, then detach+revoke old cert."""
        if not self.has_device_cert():
            raise Exception("No device cert. Provision first.")
        if self.connected:
            self.disconnect()

        old_cert_id = self.cert_history[-1]["cert_id"] if self.cert_history else None
        new_cert_id = self.provision(use_claim=False)

        if old_cert_id:
            try:
                iot = _get_iot_client()
                cert_desc = iot.describe_certificate(certificateId=old_cert_id)["certificateDescription"]
                old_arn = cert_desc["certificateArn"]
                iot.detach_thing_principal(thingName=self.serial, principal=old_arn)
                self._log("Detached old certificate from thing")
                iot.update_certificate(certificateId=old_cert_id, newStatus="REVOKED")
                self._log(f"Revoked old certificate: {old_cert_id[:16]}...")
            except Exception as e:
                self._log(f"Warning: old cert cleanup issue: {e}")

        return new_cert_id

    def connect(self):
        if not self.has_device_cert():
            raise Exception("No device cert. Provision first.")
        if self.connected:
            return

        def on_interrupted(connection, error, **kwargs):
            self._log(f"Connection interrupted: {error}")
            self.connected = False

        def on_resumed(connection, return_code, session_present, **kwargs):
            self._log(f"Connection resumed (session_present={session_present})")
            self.connected = True

        self.conn = mqtt_connection_builder.mtls_from_path(
            endpoint=CONFIG["endpoint"], cert_filepath=self.cert_path, pri_key_filepath=self.key_path,
            ca_filepath=CONFIG["root_ca"], client_id=self.serial,
            clean_session=False, keep_alive_secs=30,
            on_connection_interrupted=on_interrupted, on_connection_resumed=on_resumed,
        )
        self.conn.connect().result(timeout=15)
        self.connected = True
        self._log("MQTT connected")

    def disconnect(self):
        if self.conn:
            try:
                if self.connected:
                    self.conn.disconnect().result(timeout=5)
            except Exception:
                pass
            self.connected = False
            self.conn = None
            self._log("MQTT disconnected")

    def publish(self, topic, payload):
        if not self.connected:
            raise Exception("Not connected")
        future, _ = self.conn.publish(topic, json.dumps(payload), mqtt.QoS.AT_LEAST_ONCE)
        future.result(timeout=10)
        self._log(f"Published to {topic}")

    def subscribe(self, topic, callback):
        if not self.connected:
            raise Exception("Not connected")
        future, _ = self.conn.subscribe(topic, mqtt.QoS.AT_LEAST_ONCE, callback)
        future.result(timeout=10)
        self._log(f"Subscribed to {topic}")

    def get_status(self):
        return {
            "serial": self.serial,
            "connected": self.connected,
            "has_cert": self.has_device_cert(),
            "cert_count": len(self.cert_history),
            "cert_history": self.cert_history[-5:],
            "current_cert_id": self.cert_history[-1]["cert_id"][:16] + "..." if self.cert_history else None,
            "auto_rotate": self._auto_rotate_running,
            "rotate_interval_hours": getattr(self, '_rotate_hours', None),
        }

    # === 自动轮换 ===

    _auto_rotate_running = False
    _auto_rotate_stop = None

    def _get_cert_expiry_days(self):
        """读取当前设备证书的剩余有效天数。"""
        try:
            from cryptography import x509
            with open(self.cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            remaining = cert.not_valid_after_utc - datetime.utcnow().replace(tzinfo=cert.not_valid_after_utc.tzinfo)
            return remaining.days
        except ImportError:
            # 没有 cryptography 库，用 IoT API 查
            try:
                iot = _get_iot_client()
                cert_id = self.cert_history[-1]["cert_id"]
                desc = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]
                expiry = desc["validity"]["notAfter"]
                from datetime import timezone
                remaining = expiry - datetime.now(timezone.utc)
                return remaining.days
            except Exception:
                return None

    def start_auto_rotate(self, check_interval_hours=24, rotate_before_days=30):
        """启动后台线程，定期检查证书过期时间，到期前自动轮换。"""
        if self._auto_rotate_running:
            self._log("Auto-rotate already running")
            return

        self._auto_rotate_stop = threading.Event()
        self._rotate_hours = check_interval_hours
        self._rotate_before_days = rotate_before_days

        def _loop():
            self._auto_rotate_running = True
            self._log(f"Auto-rotate started: check every {check_interval_hours}h, rotate when <{rotate_before_days}d remaining")
            while not self._auto_rotate_stop.is_set():
                try:
                    if self.has_device_cert():
                        days = self._get_cert_expiry_days()
                        if days is not None:
                            self._log(f"Certificate expires in {days} days")
                            if days < rotate_before_days:
                                self._log(f"Certificate expiring soon ({days}d < {rotate_before_days}d), rotating...")
                                was_connected = self.connected
                                new_id = self.rotate_certificate()
                                self._log(f"Auto-rotated to new certificate: {new_id[:16]}...")
                                if was_connected:
                                    self.connect()
                                    self._log("Auto-reconnected after rotation")
                            else:
                                self._log(f"Certificate OK, next check in {check_interval_hours}h")
                except Exception as e:
                    self._log(f"Auto-rotate error: {e}")
                self._auto_rotate_stop.wait(timeout=check_interval_hours * 3600)
            self._auto_rotate_running = False
            self._log("Auto-rotate stopped")

        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    def stop_auto_rotate(self):
        if self._auto_rotate_stop:
            self._auto_rotate_stop.set()
            self._log("Auto-rotate stopping...")
