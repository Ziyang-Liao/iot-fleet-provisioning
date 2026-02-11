#!/usr/bin/env python3
"""Web UI for IoT Fleet Provisioning Demo."""
import json, os, secrets, hmac
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from device_client import DeviceClient

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# 简单 token 认证 — 启动时生成，打印到终端
API_TOKEN = os.environ.get("API_TOKEN", secrets.token_urlsafe(24))

devices = {}  # serial -> DeviceClient
logs = {}     # serial -> [log entries]


def check_auth():
    """检查 API token（header 或 session 或 cookie）。"""
    if session.get("authed"):
        return True
    token = request.headers.get("X-API-Token") or request.cookies.get("api_token") or ""
    return hmac.compare_digest(token, API_TOKEN)


def get_device(serial):
    if serial not in devices:
        logs[serial] = []
        def on_log(msg):
            logs[serial].append(msg)
            if len(logs[serial]) > 200:
                logs[serial] = logs[serial][-100:]
        devices[serial] = DeviceClient(serial, on_log=on_log)
    return devices[serial]


@app.before_request
def auth_check():
    # Cloud9 内网环境，通过环境变量控制是否跳过认证
    if os.environ.get("SKIP_AUTH"):
        return
    if request.endpoint in ("login", "do_login", "static"):
        return
    if not check_auth():
        if request.is_json:
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("login"))


@app.route("/login", methods=["GET"])
def login():
    return '''<!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>Login</title>
    <style>body{background:#0f1923;color:#e0e0e0;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh}
    .box{background:#1a2332;padding:30px;border-radius:8px;border:1px solid #2a3a4a}
    input{padding:8px;background:#0f1923;border:1px solid #2a3a4a;color:#e0e0e0;border-radius:4px;width:260px}
    button{padding:8px 20px;background:#ff9900;color:#000;border:none;border-radius:4px;cursor:pointer;margin-top:10px}
    .err{color:#e74c3c;font-size:.85em;margin-top:8px}</style></head>
    <body><div class="box"><h2 style="color:#ff9900;margin-bottom:15px">🔐 IoT Demo Login</h2>
    <form method="POST" action="/do_login">
    <label style="font-size:.85em;color:#8899aa">API Token</label><br>
    <input name="token" type="password" placeholder="Enter API token"><br>
    <button type="submit">Login</button></form></div></body></html>'''


@app.route("/do_login", methods=["POST"])
def do_login():
    if request.form.get("token") and hmac.compare_digest(request.form.get("token"), API_TOKEN):
        session["authed"] = True
        resp = redirect("/")
        resp.set_cookie("api_token", API_TOKEN, httponly=True, samesite="Lax", max_age=86400)
        return resp
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/provision", methods=["POST"])
def provision():
    serial = request.json.get("serial", "").strip()
    if not serial:
        return jsonify({"error": "serial required"}), 400
    try:
        dev = get_device(serial)
        cert_id = dev.provision(use_claim=True)
        return jsonify({"ok": True, "cert_id": cert_id, "status": dev.get_status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rotate", methods=["POST"])
def rotate():
    serial = request.json.get("serial", "").strip()
    if not serial:
        return jsonify({"error": "serial required"}), 400
    try:
        dev = get_device(serial)
        cert_id = dev.rotate_certificate()
        return jsonify({"ok": True, "cert_id": cert_id, "status": dev.get_status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/connect", methods=["POST"])
def connect():
    serial = request.json.get("serial", "").strip()
    try:
        dev = get_device(serial)
        dev.connect()
        return jsonify({"ok": True, "status": dev.get_status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/disconnect", methods=["POST"])
def disconnect():
    serial = request.json.get("serial", "").strip()
    try:
        dev = get_device(serial)
        dev.disconnect()
        return jsonify({"ok": True, "status": dev.get_status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/publish", methods=["POST"])
def publish():
    data = request.json
    serial = data.get("serial", "").strip()
    topic = data.get("topic", "").strip()
    payload = data.get("payload", {})
    if not topic.startswith(f"device/{serial}/"):
        return jsonify({"error": f"Topic must start with device/{serial}/"}), 400
    try:
        dev = get_device(serial)
        if isinstance(payload, str):
            payload = json.loads(payload)
        dev.publish(topic, payload)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscribe", methods=["POST"])
def subscribe():
    data = request.json
    serial = data.get("serial", "").strip()
    topic = data.get("topic", "").strip()
    if not topic.startswith(f"device/{serial}/"):
        return jsonify({"error": f"Topic must start with device/{serial}/"}), 400
    try:
        dev = get_device(serial)
        def cb(topic, payload, **kwargs):
            msg = f"[RECV] {topic}: {payload.decode()}"
            logs.setdefault(serial, []).append(f"[{datetime.utcnow().isoformat()}] {msg}")
        dev.subscribe(topic, cb)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/status", methods=["GET"])
def status():
    serial = request.args.get("serial", "").strip()
    if not serial or serial not in devices:
        return jsonify({"error": "device not found"}), 404
    return jsonify({"status": devices[serial].get_status(), "logs": logs.get(serial, [])[-50:]})


@app.route("/api/devices", methods=["GET"])
def list_devices():
    return jsonify({"devices": [d.get_status() for d in devices.values()]})


@app.route("/api/auto_rotate", methods=["POST"])
def auto_rotate():
    data = request.json
    serial = data.get("serial", "").strip()
    action = data.get("action", "start")  # start / stop
    hours = data.get("check_hours", 24)
    days = data.get("rotate_before_days", 30)
    try:
        dev = get_device(serial)
        if action == "start":
            dev.start_auto_rotate(check_interval_hours=hours, rotate_before_days=days)
        else:
            dev.stop_auto_rotate()
        return jsonify({"ok": True, "status": dev.get_status()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print(f"\n{'='*50}")
    print(f"  API Token: {API_TOKEN}")
    print(f"  Use this token to login via the web UI")
    print(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
