#!/usr/bin/env python3
"""
IoT Device Client — Fleet Provisioning, MQTT Communication, and Certificate Rotation.

This module implements a simulated IoT device that:
1. Provisions itself using AWS IoT Core Fleet Provisioning (claim cert → device cert)
2. Connects to IoT Core via MQTT using mTLS (X.509 client certificate + private key)
3. Publishes/subscribes to MQTT topics with IoT Policy-based ACL
4. Rotates its X.509 certificate automatically or on-demand:
   - Uses current device cert to request a new cert via Fleet Provisioning
   - Atomically replaces cert + key files on disk
   - Detaches and revokes the old certificate
5. Supports automatic rotation via a background thread that monitors cert expiry

Certificate flow:
  [Claim Cert] --Fleet Provision--> [Device Cert #1] --Rotate--> [Device Cert #2] --> ...
"""
import json, os, time, threading, uuid, shutil, tempfile, re, boto3
from datetime import datetime
from awscrt import mqtt
from awsiot import mqtt_connection_builder, iotidentity

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.json")) as f:
    CONFIG = json.load(f)

# Shared boto3 IoT client — reused across rotations to avoid repeated client creation
_iot_client = None
def _get_iot_client():
    global _iot_client
    if _iot_client is None:
        _iot_client = boto3.client("iot", region_name=CONFIG["region"])
    return _iot_client

# Serial number validation: only alphanumeric, hyphen, underscore (prevents path traversal)
_SERIAL_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$')

def validate_serial(serial):
    if not _SERIAL_RE.match(serial):
        raise ValueError(f"Invalid serial: only alphanumeric, hyphen, underscore allowed (1-128 chars)")


class DeviceClient:
    """
    Simulates an IoT device with full lifecycle management:
    - Provisioning (claim cert → device cert via Fleet Provisioning)
    - MQTT connection (mTLS with device cert + private key)
    - Message publish/subscribe
    - Certificate rotation (manual or automatic)
    """

    def __init__(self, serial_number, on_log=None):
        validate_serial(serial_number)
        self.serial = serial_number
        # Each device gets its own directory for certs, keys, and metadata
        self.device_dir = os.path.join(CONFIG["certs_dir"], f"device_{serial_number}")
        os.makedirs(self.device_dir, exist_ok=True)
        self.cert_path = os.path.join(self.device_dir, "device.cert.pem")  # X.509 client certificate
        self.key_path = os.path.join(self.device_dir, "device.key.pem")    # Private key for mTLS
        self.meta_path = os.path.join(self.device_dir, "meta.json")        # Certificate history
        self.conn = None
        self.connected = False
        self._on_log = on_log or (lambda msg: print(f"[{serial_number}] {msg}"))
        self.cert_history = []
        self._load_meta()

    def _log(self, msg):
        self._on_log(f"[{datetime.utcnow().isoformat()}] {msg}")

    def _load_meta(self):
        """Load certificate rotation history from disk."""
        if os.path.exists(self.meta_path):
            with open(self.meta_path) as f:
                self.cert_history = json.load(f).get("cert_history", [])

    def _save_meta(self, cert_id):
        """Atomically save certificate history to prevent corruption on crash."""
        self.cert_history.append({"cert_id": cert_id, "created_at": datetime.utcnow().isoformat()})
        fd, tmp = tempfile.mkstemp(dir=self.device_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump({"serial": self.serial, "cert_history": self.cert_history}, f, indent=2)
            os.replace(tmp, self.meta_path)  # Atomic rename
        except Exception:
            os.unlink(tmp)
            raise

    def has_device_cert(self):
        """Check if this device has been provisioned (has cert + key on disk)."""
        return os.path.exists(self.cert_path) and os.path.exists(self.key_path)

    def _save_cert_atomic(self, cert_pem, key_pem):
        """
        Atomically write both certificate and private key files.
        Both temp files are written first, then both are renamed together.
        This prevents a half-written state where cert and key don't match.
        """
        pairs = [(self.cert_path, cert_pem), (self.key_path, key_pem)]
        tmps = []
        try:
            for target, content in pairs:
                fd, tmp = tempfile.mkstemp(dir=self.device_dir, suffix=".tmp")
                tmps.append(tmp)
                with os.fdopen(fd, "w") as f:
                    f.write(content)
                os.chmod(tmp, 0o600)  # Restrict permissions on private key
            # Only rename after BOTH temp files are successfully written
            for (target, _), tmp in zip(pairs, tmps):
                os.replace(tmp, target)
        except Exception:
            for tmp in tmps:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise

    # ==================== Fleet Provisioning ====================

    def provision(self, use_claim=True):
        """
        Provision this device using AWS IoT Core Fleet Provisioning.

        When use_claim=True (first time):
          - Connects with claim certificate (temporary identity)
          - Requests new device certificate + private key
          - Registers the device (Thing) with IoT Core

        When use_claim=False (rotation):
          - Connects with current device certificate
          - Requests a NEW certificate + private key
          - Re-registers the device with the new certificate

        Returns the new certificate ID.
        """
        self._log("Starting fleet provisioning...")
        if use_claim:
            # First-time provisioning: use the shared claim certificate
            cert, key = CONFIG["claim_cert"], CONFIG["claim_key"]
            client_id = f"provision-{self.serial}-{uuid.uuid4().hex[:8]}"
        else:
            # Rotation: use the current device certificate to get a new one
            cert, key = self.cert_path, self.key_path
            client_id = self.serial

        # Establish mTLS connection using the selected certificate + private key
        conn = mqtt_connection_builder.mtls_from_path(
            endpoint=CONFIG["endpoint"], cert_filepath=cert, pri_key_filepath=key,
            ca_filepath=CONFIG["root_ca"],  # Amazon Root CA to verify IoT Core server
            client_id=client_id,
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

        # Backup old certs before overwriting (safety net for rotation)
        if self.has_device_cert():
            bak = os.path.join(self.device_dir, f"backup_{int(time.time())}")
            os.makedirs(bak, exist_ok=True)
            shutil.copy2(self.cert_path, os.path.join(bak, "device.cert.pem"))
            shutil.copy2(self.key_path, os.path.join(bak, "device.key.pem"))
            self._log("Backed up old certificates")

        # Atomically write new certificate + private key to disk
        self._save_cert_atomic(new_keys.certificate_pem, new_keys.private_key)
        self._save_meta(new_keys.certificate_id)

        conn.disconnect().result(timeout=5)
        self._log("Provisioning complete!")
        return new_keys.certificate_id

    def _do_fleet_provision(self, conn):
        """
        Execute the Fleet Provisioning MQTT protocol:
        1. Subscribe to accepted/rejected topics for CreateKeysAndCertificate
        2. Subscribe to accepted/rejected topics for RegisterThing
        3. Publish CreateKeysAndCertificate request → get new cert + key
        4. Publish RegisterThing request → associate cert with Thing

        Returns (keys_response, thing_name).
        """
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

        # Subscribe to Fleet Provisioning response topics
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

        # Step 1: Request new certificate + private key from IoT Core
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

        # Step 2: Register the Thing with the new certificate
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

    # ==================== Certificate Rotation ====================

    def rotate_certificate(self):
        """
        Rotate the device certificate:
        1. Disconnect current MQTT connection (if any)
        2. Use current device cert to provision a NEW cert via Fleet Provisioning
        3. Detach old cert from the Thing in IoT Core
        4. Revoke old cert so it can never be used again
        5. Device can now reconnect with the new cert

        Returns the new certificate ID.
        """
        if not self.has_device_cert():
            raise Exception("No device cert. Provision first.")
        if self.connected:
            self.disconnect()

        old_cert_id = self.cert_history[-1]["cert_id"] if self.cert_history else None
        new_cert_id = self.provision(use_claim=False)

        # Clean up old certificate: detach from Thing, then revoke
        if old_cert_id:
            try:
                iot = _get_iot_client()
                cert_desc = iot.describe_certificate(certificateId=old_cert_id)["certificateDescription"]
                old_arn = cert_desc["certificateArn"]
                # Must detach before revoking
                iot.detach_thing_principal(thingName=self.serial, principal=old_arn)
                self._log("Detached old certificate from thing")
                iot.update_certificate(certificateId=old_cert_id, newStatus="REVOKED")
                self._log(f"Revoked old certificate: {old_cert_id[:16]}...")
            except Exception as e:
                self._log(f"Warning: old cert cleanup issue: {e}")

        return new_cert_id

    # ==================== MQTT Connection ====================

    def connect(self):
        """Establish mTLS MQTT connection using device certificate + private key."""
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

        # mTLS connection: device cert + private key authenticate the device
        # IoT Policy attached to the cert controls what topics the device can access
        self.conn = mqtt_connection_builder.mtls_from_path(
            endpoint=CONFIG["endpoint"],
            cert_filepath=self.cert_path,   # Device X.509 certificate
            pri_key_filepath=self.key_path,  # Device private key
            ca_filepath=CONFIG["root_ca"],   # Amazon Root CA (verify server)
            client_id=self.serial,           # Must match Thing Name per IoT Policy
            clean_session=False, keep_alive_secs=30,
            on_connection_interrupted=on_interrupted, on_connection_resumed=on_resumed,
        )
        self.conn.connect().result(timeout=15)
        self.connected = True
        self._log("MQTT connected")

    def disconnect(self):
        """Disconnect MQTT and clean up connection object."""
        if self.conn:
            try:
                if self.connected:
                    self.conn.disconnect().result(timeout=5)
            except Exception:
                pass
            self.connected = False
            self.conn = None
            self._log("MQTT disconnected")

    # ==================== Publish / Subscribe ====================

    def publish(self, topic, payload):
        """Publish a JSON message to an MQTT topic (requires active connection)."""
        if not self.connected:
            raise Exception("Not connected")
        future, _ = self.conn.publish(topic, json.dumps(payload), mqtt.QoS.AT_LEAST_ONCE)
        future.result(timeout=10)
        self._log(f"Published to {topic}")

    def subscribe(self, topic, callback):
        """Subscribe to an MQTT topic with a callback for incoming messages."""
        if not self.connected:
            raise Exception("Not connected")
        future, _ = self.conn.subscribe(topic, mqtt.QoS.AT_LEAST_ONCE, callback)
        future.result(timeout=10)
        self._log(f"Subscribed to {topic}")

    # ==================== Status ====================

    def get_status(self):
        """Return current device state for the web UI."""
        return {
            "serial": self.serial,
            "connected": self.connected,
            "has_cert": self.has_device_cert(),
            "cert_count": len(self.cert_history),
            "cert_history": self.cert_history[-5:],  # Last 5 certs
            "current_cert_id": self.cert_history[-1]["cert_id"][:16] + "..." if self.cert_history else None,
            "auto_rotate": self._auto_rotate_running,
            "rotate_interval_hours": getattr(self, '_rotate_hours', None),
        }

    # ==================== Auto-Rotation ====================

    _auto_rotate_running = False
    _auto_rotate_stop = None

    def _get_cert_expiry_days(self):
        """
        Get remaining validity days for the current device certificate.
        Tries local parsing first (cryptography lib), falls back to IoT API.
        """
        try:
            from cryptography import x509
            with open(self.cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            remaining = cert.not_valid_after_utc - datetime.utcnow().replace(tzinfo=cert.not_valid_after_utc.tzinfo)
            return remaining.days
        except ImportError:
            # Fallback: query IoT Core API for certificate validity
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
        """
        Start a background thread that automatically rotates the certificate
        when it's within `rotate_before_days` of expiration.

        The thread checks every `check_interval_hours` hours.
        If rotation is needed, it disconnects, rotates, and reconnects.
        """
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
                # Sleep until next check (or until stop is signaled)
                self._auto_rotate_stop.wait(timeout=check_interval_hours * 3600)
            self._auto_rotate_running = False
            self._log("Auto-rotate stopped")

        t = threading.Thread(target=_loop, daemon=True)
        t.start()

    def stop_auto_rotate(self):
        """Signal the auto-rotate background thread to stop."""
        if self._auto_rotate_stop:
            self._auto_rotate_stop.set()
            self._log("Auto-rotate stopping...")
