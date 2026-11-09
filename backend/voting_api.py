"""
Smart Voter - સુરક્ષિત મતદાન API (સંસ્થાની ખાનગી ચૂંટણી માટે)

મુખ્ય સુધારા (જૂના Aadhaar વાળા કોડ સામે):
  * ઓળખ: સભ્ય ID + મોબાઈલ OTP (Aadhaar બિલકુલ નહીં)
  * એક વ્યક્તિ = એક મત, ડેટાબેઝ સ્તરે atomic (race condition નથી)
  * ગુપ્ત મતદાન: ballots ટેબલમાં કોઈ મતદાર ID, સમય કે ક્રમ નથી
  * ચૂંટણીનો સમય સર્વર નક્કી કરે છે (ફોનની ઘડિયાળ નહીં)
  * પરિણામ ચૂંટણી પૂરી થયા પછી જ
  * "reset" એન્ડપોઈન્ટ કાઢી નાખ્યો; એડમિન ફક્ત secret token થી
  * ઓટો-રજીસ્ટ્રેશન બંધ: ફક્ત એડમિને ઉમેરેલા સભ્યો મત આપી શકે

જરૂરી environment variables:
  SECRET_KEY    - લાંબી random string (ટોકન/OTP સહી માટે)
  ADMIN_TOKEN   - એડમિન API માટે લાંબો secret
  VOTING_DB_PATH (વૈકલ્પિક) - ડેટાબેઝ ફાઈલનો કાયમી (persistent) path
  DEV_MODE=1    - ફક્ત ટેસ્ટિંગ: OTP લોગમાં દેખાય છે. અસલી ચૂંટણીમાં ક્યારેય નહીં.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

bp = Blueprint("voting_v2", __name__, url_prefix="/api/v2")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get("VOTING_DB_PATH", os.path.join(BASE_DIR, "smart_voter_db.sqlite"))
DEV_MODE = os.environ.get("DEV_MODE") == "1"

SECRET = os.environ.get("SECRET_KEY", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
if not DEV_MODE and (len(SECRET) < 32 or len(ADMIN_TOKEN) < 32):
    raise RuntimeError(
        "SECRET_KEY અને ADMIN_TOKEN (દરેક ઓછામાં ઓછા 32 અક્ષર) environment માં સેટ કરો."
    )
if DEV_MODE and not SECRET:
    SECRET = "dev-only-secret-" + secrets.token_hex(16)
if DEV_MODE and not ADMIN_TOKEN:
    ADMIN_TOKEN = "dev-admin-" + secrets.token_hex(16)

OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OTP_COOLDOWN_SECONDS = 60
SESSION_TTL_SECONDS = 1800
MEMBER_ID_RE = re.compile(r"^[A-Za-z0-9_\-/]{1,32}$")


# ---------------------------------------------------------------- database
def get_db():
    # isolation_level=None -> આપણે transaction જાતે (BEGIN IMMEDIATE) નિયંત્રિત કરીએ છીએ
    conn = sqlite3.connect(DATABASE, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_schema():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS election_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            title TEXT NOT NULL,
            starts_at TEXT NOT NULL,
            ends_at TEXT NOT NULL,
            nota_enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS members (
            member_id TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            mobile TEXT NOT NULL,
            ward_no INTEGER NOT NULL DEFAULT 0,
            has_voted INTEGER NOT NULL DEFAULT 0   -- જાણીજોઈને voted_at નથી (ગુપ્તતા)
        );
        CREATE TABLE IF NOT EXISTS election_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            party TEXT,
            ward_no INTEGER,            -- NULL = બધા મતદારો માટે
            photo_url TEXT
        );
        CREATE TABLE IF NOT EXISTS otp_codes (
            member_id TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            issued_at REAL NOT NULL
        );
        -- PK random હોવાથી WITHOUT ROWID ટેબલમાં insertion ક્રમ મળતો નથી
        CREATE TABLE IF NOT EXISTS ballots (
            ballot_key TEXT PRIMARY KEY,
            candidate_id INTEGER NOT NULL,   -- 0 = NOTA
            ward_no INTEGER NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS receipts (
            code_hash TEXT PRIMARY KEY
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL,
            event TEXT NOT NULL,
            detail TEXT
        );
        """
    )
    conn.close()


init_schema()


def audit(conn, event, detail=""):
    conn.execute(
        "INSERT INTO audit_log (at, event, detail) VALUES (?, ?, ?)",
        (utcnow().isoformat(), event, detail),
    )


# ------------------------------------------------------------------ helpers
def utcnow():
    return datetime.now(timezone.utc)


def parse_iso(s):
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise ValueError("timezone જરૂરી છે (દા.ત. 2026-12-01T09:00:00+05:30)")
    return dt.astimezone(timezone.utc)


def err(message, status):
    return jsonify({"status": "error", "message": message}), status


def normalize_mobile(raw):
    digits = re.sub(r"\D", "", str(raw or ""))
    return digits[-10:] if len(digits) >= 10 else ""


def hmac_hex(*parts):
    return hmac.new(SECRET.encode(), ":".join(parts).encode(), hashlib.sha256).hexdigest()


def make_token(member_id):
    payload = json.dumps({"m": member_id, "exp": int(time.time()) + SESSION_TTL_SECONDS})
    body = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"{body}.{hmac_hex('session', body)}"


def read_token(token):
    try:
        body, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, hmac_hex("session", body)):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if data["exp"] < time.time():
            return None
        return data["m"]
    except Exception:
        return None


# સરળ in-memory rate limit (gunicorn --workers 1 સાથે કામ કરે; વધુ workers માટે Redis વાપરો)
_hits = defaultdict(deque)


def rate_limited(key, limit, window):
    now = time.time()
    q = _hits[key]
    while q and q[0] < now - window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


def require_member(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        member_id = read_token(auth[7:]) if auth.startswith("Bearer ") else None
        if not member_id:
            return err("સત્ર પૂરું થયું છે. ફરી લૉગિન કરો.", 401)
        g.member_id = member_id
        return fn(*a, **kw)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        supplied = request.headers.get("X-Admin-Token", "")
        if not ADMIN_TOKEN or not hmac.compare_digest(supplied, ADMIN_TOKEN):
            return err("પરવાનગી નથી.", 403)
        return fn(*a, **kw)
    return wrapper


def election_state(conn):
    """('not_configured' | 'not_started' | 'open' | 'closed', config_row)"""
    cfg = conn.execute("SELECT * FROM election_config WHERE id = 1").fetchone()
    if not cfg:
        return "not_configured", None
    now = utcnow()
    if now < parse_iso(cfg["starts_at"]):
        return "not_started", cfg
    if now >= parse_iso(cfg["ends_at"]):
        return "closed", cfg
    return "open", cfg


def deliver_otp(mobile, code):
    """OTP SMS મોકલો. અસલી ઉપયોગ માટે અહીં SMS પ્રોવાઈડર (MSG91 / Twilio / Fast2SMS) જોડો."""
    if DEV_MODE:
        current_app.logger.warning("DEV OTP for ******%s : %s", mobile[-4:], code)
        return True
    # TODO: પ્રોવાઈડરનો API કોલ અહીં. સફળ થાય તો True, નહીંતર False.
    return False


# -------------------------------------------------------------- public API
@bp.get("/status")
def status():
    conn = get_db()
    state, cfg = election_state(conn)
    registered = conn.execute("SELECT COUNT(*) FROM members").fetchone()[0]
    voted = conn.execute("SELECT COUNT(*) FROM members WHERE has_voted = 1").fetchone()[0]
    conn.close()
    return jsonify({
        "status": "success",
        "state": state,
        "title": cfg["title"] if cfg else None,
        "starts_at": cfg["starts_at"] if cfg else None,
        "ends_at": cfg["ends_at"] if cfg else None,
        "registered": registered,
        "voted": voted,
    })


@bp.post("/auth/request-otp")
def request_otp():
    data = request.get_json(silent=True) or {}
    member_id = str(data.get("member_id", "")).strip()
    mobile = normalize_mobile(data.get("mobile"))
    if not MEMBER_ID_RE.match(member_id) or not mobile:
        return err("સભ્ય ID અને ૧૦-અંકનો મોબાઈલ નંબર દાખલ કરો.", 400)
    if rate_limited(f"otp-ip:{client_ip()}", 10, 600):
        return err("ઘણા પ્રયાસો. થોડી વાર પછી પ્રયાસ કરો.", 429)

    generic = jsonify({"status": "success", "message": "જો વિગતો સાચી હશે તો OTP મોબાઈલ પર મોકલાયો છે."})
    conn = get_db()
    member = conn.execute("SELECT * FROM members WHERE member_id = ?", (member_id,)).fetchone()
    # એકસરખો જવાબ: સભ્ય યાદીમાં છે કે નહીં એ બહારથી જાણી ન શકાય
    if not member or normalize_mobile(member["mobile"]) != mobile:
        conn.close()
        return generic

    row = conn.execute("SELECT issued_at FROM otp_codes WHERE member_id = ?", (member_id,)).fetchone()
    if row and time.time() - row["issued_at"] < OTP_COOLDOWN_SECONDS:
        conn.close()
        return err("નવો OTP માટે ૧ મિનિટ રાહ જુઓ.", 429)

    code = f"{secrets.randbelow(1_000_000):06d}"
    if not deliver_otp(mobile, code):
        conn.close()
        return err("SMS સેવા હમણાં ઉપલબ્ધ નથી. એડમિનનો સંપર્ક કરો.", 503)

    conn.execute(
        "INSERT OR REPLACE INTO otp_codes (member_id, code_hash, expires_at, attempts, issued_at) VALUES (?,?,?,?,?)",
        (member_id, hmac_hex("otp", member_id, code), time.time() + OTP_TTL_SECONDS, 0, time.time()),
    )
    audit(conn, "otp_issued", member_id)
    conn.close()
    return generic


@bp.post("/auth/verify-otp")
def verify_otp():
    data = request.get_json(silent=True) or {}
    member_id = str(data.get("member_id", "")).strip()
    code = re.sub(r"\D", "", str(data.get("otp", "")))
    if not MEMBER_ID_RE.match(member_id) or len(code) != 6:
        return err("માન્ય સભ્ય ID અને ૬-અંકનો OTP દાખલ કરો.", 400)
    if rate_limited(f"verify-ip:{client_ip()}", 20, 600):
        return err("ઘણા પ્રયાસો. થોડી વાર પછી પ્રયાસ કરો.", 429)

    bad = err("OTP ખોટો અથવા સમયસીમા પૂરી થઈ ગઈ છે.", 401)
    conn = get_db()
    row = conn.execute("SELECT * FROM otp_codes WHERE member_id = ?", (member_id,)).fetchone()
    if not row or row["expires_at"] < time.time() or row["attempts"] >= OTP_MAX_ATTEMPTS:
        conn.close()
        return bad
    if not hmac.compare_digest(row["code_hash"], hmac_hex("otp", member_id, code)):
        conn.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE member_id = ?", (member_id,))
        audit(conn, "otp_failed", member_id)
        conn.close()
        return bad

    conn.execute("DELETE FROM otp_codes WHERE member_id = ?", (member_id,))
    member = conn.execute("SELECT * FROM members WHERE member_id = ?", (member_id,)).fetchone()
    audit(conn, "login_ok", member_id)
    conn.close()
    return jsonify({
        "status": "success",
        "token": make_token(member_id),
        "full_name": member["full_name"],
        "ward_no": member["ward_no"],
        "already_voted": bool(member["has_voted"]),
    })


@bp.get("/ballot")
@require_member
def ballot():
    conn = get_db()
    state, cfg = election_state(conn)
    member = conn.execute("SELECT * FROM members WHERE member_id = ?", (g.member_id,)).fetchone()
    if not member:
        conn.close()
        return err("સભ્ય મળ્યા નથી.", 404)
    if state != "open":
        conn.close()
        return err("મતદાન ચાલુ નથી.", 403)
    if member["has_voted"]:
        conn.close()
        return err("તમે મત આપી ચૂક્યા છો.", 409)

    rows = conn.execute(
        "SELECT id, name, party, ward_no, photo_url FROM election_candidates "
        "WHERE ward_no IS NULL OR ward_no = ?", (member["ward_no"],)
    ).fetchall()
    candidates = [dict(r) for r in rows]
    secrets.SystemRandom().shuffle(candidates)   # ક્રમ રેન્ડમ: પહેલા નંબરનો ફાયદો ન રહે
    if cfg["nota_enabled"]:
        candidates.append({"id": 0, "name": "NOTA (ઉપરોક્તમાંથી કોઈ નહીં)", "party": "NOTA",
                           "ward_no": None, "photo_url": None})
    conn.close()
    return jsonify({"status": "success", "title": cfg["title"], "candidates": candidates})


@bp.post("/vote")
@require_member
def vote():
    data = request.get_json(silent=True) or {}
    try:
        candidate_id = int(data.get("candidate_id"))
    except (TypeError, ValueError):
        return err("માન્ય ઉમેદવાર પસંદ કરો.", 400)

    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")           # બીજા કોઈ લખનારને રોકે છે
        state, cfg = election_state(conn)
        if state != "open":
            conn.execute("ROLLBACK")
            return err("મતદાન ચાલુ નથી.", 403)

        member = conn.execute("SELECT * FROM members WHERE member_id = ?", (g.member_id,)).fetchone()
        if not member:
            conn.execute("ROLLBACK")
            return err("સભ્ય મળ્યા નથી.", 404)

        if candidate_id == 0:
            if not cfg["nota_enabled"]:
                conn.execute("ROLLBACK")
                return err("માન્ય ઉમેદવાર પસંદ કરો.", 400)
        else:
            ok = conn.execute(
                "SELECT 1 FROM election_candidates WHERE id = ? AND (ward_no IS NULL OR ward_no = ?)",
                (candidate_id, member["ward_no"]),
            ).fetchone()
            if not ok:
                conn.execute("ROLLBACK")
                return err("માન્ય ઉમેદવાર પસંદ કરો.", 400)

        # એક વ્યક્તિ = એક મત: શરત સાથેનો atomic UPDATE
        cur = conn.execute(
            "UPDATE members SET has_voted = 1 WHERE member_id = ? AND has_voted = 0", (g.member_id,)
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return err("તમે મત આપી ચૂક્યા છો.", 409)

        receipt = secrets.token_hex(5).upper()
        conn.execute("INSERT INTO ballots (ballot_key, candidate_id, ward_no) VALUES (?,?,?)",
                     (secrets.token_hex(16), candidate_id, member["ward_no"]))
        conn.execute("INSERT INTO receipts (code_hash) VALUES (?)", (hmac_hex("receipt", receipt),))
        audit(conn, "vote_cast", f"ward {member['ward_no']}")   # મતદાર ID જાણીજોઈને નહીં
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        current_app.logger.exception("vote failed")
        return err("મત નોંધાયો નથી. ફરી પ્રયાસ કરો.", 500)
    finally:
        conn.close()

    # રસીદમાં પસંદગી નથી: મતદાર સાબિત કરી શકે કે મત ગણાયો, પણ કોને આપ્યો તે નહીં
    return jsonify({"status": "success", "message": "તમારો મત નોંધાઈ ગયો છે.", "receipt": receipt})


@bp.get("/results")
def results():
    conn = get_db()
    state, cfg = election_state(conn)
    if state != "closed":
        conn.close()
        return err("પરિણામ ચૂંટણી પૂરી થયા પછી જ જાહેર થશે.", 403)
    names = {r["id"]: (r["name"], r["party"]) for r in conn.execute(
        "SELECT id, name, party FROM election_candidates")}
    counts = conn.execute(
        "SELECT candidate_id, ward_no, COUNT(*) AS votes FROM ballots GROUP BY candidate_id, ward_no"
    ).fetchall()
    total_votes = conn.execute("SELECT COUNT(*) FROM ballots").fetchone()[0]
    registered = conn.execute("SELECT COUNT(*) FROM members").fetchone()[0]
    conn.close()
    out = []
    for r in counts:
        name, party = names.get(r["candidate_id"], ("NOTA", "NOTA"))
        out.append({"candidate_id": r["candidate_id"], "name": name, "party": party,
                    "ward_no": r["ward_no"], "votes": r["votes"]})
    out.sort(key=lambda x: (x["ward_no"], -x["votes"]))
    return jsonify({"status": "success", "title": cfg["title"], "registered": registered,
                    "total_votes": total_votes,
                    "turnout_percentage": round(total_votes / registered * 100, 1) if registered else 0.0,
                    "results": out})


# ---------------------------------------------------------------- admin API
def _locked(conn):
    """ચૂંટણી ચાલુ હોય અથવા મત પડી ગયા હોય તો યાદી/ઉમેદવાર બદલાવી ન શકાય."""
    state, _ = election_state(conn)
    votes = conn.execute("SELECT COUNT(*) FROM ballots").fetchone()[0]
    return state == "open" or votes > 0


@bp.post("/admin/election")
@require_admin
def admin_election():
    d = request.get_json(silent=True) or {}
    try:
        starts, ends = parse_iso(d["starts_at"]), parse_iso(d["ends_at"])
        title = str(d["title"]).strip()
    except Exception as e:
        return err(f"title, starts_at, ends_at (timezone સાથે) જરૂરી: {e}", 400)
    if not title or ends <= starts:
        return err("title ખાલી ન હોય અને ends_at, starts_at પછી હોવો જોઈએ.", 400)
    conn = get_db()
    if _locked(conn):
        conn.close()
        return err("ચૂંટણી શરૂ થઈ ગઈ છે અથવા મત પડી ગયા છે; ફેરફાર શક્ય નથી.", 409)
    conn.execute(
        "INSERT OR REPLACE INTO election_config (id, title, starts_at, ends_at, nota_enabled) VALUES (1,?,?,?,?)",
        (title, starts.isoformat(), ends.isoformat(), 1 if d.get("nota_enabled", True) else 0),
    )
    audit(conn, "election_configured", title)
    conn.close()
    return jsonify({"status": "success"})


@bp.post("/admin/members")
@require_admin
def admin_members():
    items = (request.get_json(silent=True) or {}).get("members")
    if not isinstance(items, list) or not items:
        return err("members યાદી જરૂરી છે.", 400)
    conn = get_db()
    if _locked(conn):
        conn.close()
        return err("ચૂંટણી શરૂ થઈ ગઈ છે; મતદાર યાદી બદલાવી શકાય નહીં.", 409)
    added = 0
    try:
        conn.execute("BEGIN IMMEDIATE")
        for m in items:
            mid, name, mob = str(m.get("member_id", "")).strip(), str(m.get("full_name", "")).strip(), normalize_mobile(m.get("mobile"))
            if not MEMBER_ID_RE.match(mid) or not name or not mob:
                conn.execute("ROLLBACK")
                return err(f"ખોટી એન્ટ્રી: {m}", 400)
            conn.execute(
                "INSERT INTO members (member_id, full_name, mobile, ward_no) VALUES (?,?,?,?) "
                "ON CONFLICT(member_id) DO UPDATE SET full_name=excluded.full_name, "
                "mobile=excluded.mobile, ward_no=excluded.ward_no",
                (mid, name, mob, int(m.get("ward_no") or 0)),
            )
            added += 1
        audit(conn, "members_upserted", str(added))
        conn.execute("COMMIT")
    finally:
        conn.close()
    return jsonify({"status": "success", "count": added})


@bp.post("/admin/candidates")
@require_admin
def admin_candidates():
    items = (request.get_json(silent=True) or {}).get("candidates")
    if not isinstance(items, list) or not items:
        return err("candidates યાદી જરૂરી છે.", 400)
    conn = get_db()
    if _locked(conn):
        conn.close()
        return err("ચૂંટણી શરૂ થઈ ગઈ છે; ઉમેદવારો બદલાવી શકાય નહીં.", 409)
    for c in items:
        if not str(c.get("name", "")).strip():
            conn.close()
            return err("દરેક ઉમેદવારનું name જરૂરી છે.", 400)
        ward = c.get("ward_no")
        conn.execute(
            "INSERT INTO election_candidates (name, party, ward_no, photo_url) VALUES (?,?,?,?)",
            (c["name"].strip(), c.get("party"), int(ward) if ward not in (None, "") else None, c.get("photo_url")),
        )
    audit(conn, "candidates_added", str(len(items)))
    conn.close()
    return jsonify({"status": "success", "count": len(items)})


@bp.get("/admin/stats")
@require_admin
def admin_stats():
    conn = get_db()
    state, _ = election_state(conn)
    per_ward = [dict(r) for r in conn.execute(
        "SELECT ward_no, COUNT(*) AS registered, SUM(has_voted) AS voted FROM members GROUP BY ward_no")]
    conn.close()
    return jsonify({"status": "success", "state": state, "turnout_by_ward": per_ward})
