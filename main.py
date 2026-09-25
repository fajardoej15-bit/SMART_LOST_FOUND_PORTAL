from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, abort, flash, redirect, render_template, request, send_from_directory, session, url_for
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from auth_controller import AuthController
from database import get_connection, init_db

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_UPLOAD_DIR = BASE_DIR / "static" / "uploads"
PRIVATE_UPLOAD_DIR = BASE_DIR / "private_uploads"
AVATAR_UPLOAD_DIR = BASE_DIR / "static" / "uploads" / "avatars"
PUBLIC_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
PRIVATE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))
app.config.update(
    DEBUG=os.environ.get("FLASK_DEBUG", "False").lower() == "true",
    TESTING=False,
    SECRET_KEY=os.environ.get("SECRET_KEY", "smart-lost-found-portal-development-key"),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    ALLOWED_EXTENSIONS={"png", "jpg", "jpeg", "gif", "webp", "pdf"},
    AVATAR_EXTENSIONS={"png", "jpg", "jpeg"},
)
init_db()

CATEGORIES = [
    "Identification / Cards",
    "Phone / Tablet",
    "Wallet / Money",
    "Keys",
    "Bag",
    "Electronics",
    "Clothing",
    "Jewelry / Accessories",
    "Documents",
    "Other",
]
BARANGAYS = {
    "District 1": [
        "Bagong Ilog", "Bagong Katipunan", "Bambang", "Buting", "Caniogan",
        "Kalawaan", "Kapasigan (Poblacion)", "Kapitolyo", "Malinao", "Oranbo",
        "Palatiw", "Pineda", "Sagad", "San Antonio", "San Joaquin", "San Jose",
        "San Nicolas", "Santa Cruz", "Santa Rosa", "Santo Tomas", "Sumilang", "Ugong"
    ],
    "District 2": [
        "Dela Paz", "Manggahan", "Maybunga", "Pinagbuhatan", "Rosario",
        "San Miguel", "Santa Lucia", "Santolan"
    ],
}
ALL_BARANGAYS = [barangay for district in BARANGAYS.values() for barangay in district]


def now():
    return datetime.now().isoformat(timespec="seconds")


OTP_EXPIRY_MINUTES = 10
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
OTP_MAX_RESENDS = 5


def utc_now():
    return datetime.now(timezone.utc)


def parse_utc(value):
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def otp_hash(code):
    return hmac.new(
        str(app.config["SECRET_KEY"]).encode(),
        code.encode(),
        hashlib.sha256,
    ).hexdigest()


def send_otp_email(email, full_name, code):
    api_key = os.getenv("BREVO_API_KEY", "").strip()
    sender_email = os.getenv("BREVO_SENDER_EMAIL", "").strip()
    sender_name = os.getenv("BREVO_SENDER_NAME", "").strip()
    if not api_key or not sender_email or not sender_name:
        app.logger.error(
            "Brevo configuration missing: api_key=%s, sender_email=%s, sender_name=%s",
            "SET" if api_key else "MISSING",
            "SET" if sender_email else "MISSING",
            "SET" if sender_name else "MISSING",
        )
        return False

    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email,
        },
        "to": [{"email": email, "name": full_name}],
        "subject": "SMART Lost & Found - Email Verification",
        "textContent": (
            f"Hello {full_name},\n\n"
            f"Your SMART Lost & Found verification code is: {code}\n\n"
            "This code expires in 10 minutes.\n\n"
            "If you did not create this account, you can ignore this email."
        ),
    }
    request = Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "api-key": api_key,
        },
        method="POST",
    )
    try:
        app.logger.info("Attempting Brevo API request to https://api.brevo.com/v3/smtp/email")
        with urlopen(request, timeout=20) as response:
            app.logger.info("Brevo API response: status=%s", response.status)
            return 200 <= response.status < 300
    except HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        try:
            error_response = json.loads(response_body)
        except json.JSONDecodeError:
            error_response = {}
        error_code = error_response.get("code", "unknown")
        error_message = str(error_response.get("message", "Unstructured API error"))
        error_message = error_message.replace(api_key, "[redacted]")
        error_message = error_message.replace(code, "[redacted]")[:500]
        app.logger.error(
            "Brevo API HTTP error: status=%s code=%s message=%s",
            exc.code,
            error_code,
            error_message,
        )
        return False
    except (URLError, TimeoutError, OSError) as exc:
        app.logger.error(
            "Brevo API connection error: type=%s message=%s",
            type(exc).__name__,
            str(exc),
        )
        return False


def issue_otp(conn, user):
    code = f"{secrets.randbelow(1_000_000):06d}"
    sent_at = utc_now()
    conn.execute(
        "INSERT INTO otp_verifications(user_id,otp_hash,expires_at,attempts,resend_count,last_sent_at) "
        "VALUES(?,?,?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET otp_hash=excluded.otp_hash,"
        "expires_at=excluded.expires_at,attempts=0,resend_count=otp_verifications.resend_count,"
        "last_sent_at=excluded.last_sent_at",
        (user["id"], otp_hash(code), (sent_at + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat(), 0, 0, sent_at.isoformat()),
    )
    return send_otp_email(user["email"], user["full_name"] or "there", code)


def pending_verification_user():
    user_id = session.get("pending_verification_user_id")
    if not user_id:
        return None
    conn = get_connection()
    user = conn.execute(
        "SELECT id,email,full_name,account_status FROM users WHERE id=? AND account_status='PENDING'",
        (user_id,),
    ).fetchone()
    conn.close()
    return user


def is_admin(user=None):
    return bool(user and str(user["role"]).upper() == "ADMIN")


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return user


def user_required(message="Please log in to continue."):
    if not session.get("user_id"):
        flash(message, "info")
        return redirect(url_for("login", next=request.path))
    return None


def normal_user_required(message="Please log in to continue."):
    blocked = user_required(message)
    if blocked:
        return blocked
    if is_admin(current_user()):
        abort(403)
    return None


def admin_required():
    blocked = user_required("Please log in as an administrator to continue.")
    if blocked:
        return blocked
    if not is_admin(current_user()):
        abort(403)
    return None


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


def save_file(file, directory):
    if not file or not file.filename:
        return None
    if not allowed_file(file.filename):
        raise ValueError("Please upload a PNG, JPG, GIF, WEBP, or PDF file under 5 MB.")
    filename = f"{secrets.token_hex(16)}_{secure_filename(file.filename)}"
    file.save(directory / filename)
    return filename


def save_avatar(file):
    if not file or not file.filename:
        return None
    extension = Path(file.filename).suffix.lower().lstrip(".")
    if extension not in app.config["AVATAR_EXTENSIONS"]:
        raise ValueError("Profile pictures must be JPG, JPEG, or PNG images.")
    try:
        image = Image.open(file.stream)
        image.verify()
        file.stream.seek(0)
        with Image.open(file.stream) as checked_image:
            if checked_image.format not in {"JPEG", "PNG"}:
                raise ValueError("Profile pictures must be JPG, JPEG, or PNG images.")
    except (UnidentifiedImageError, OSError, ValueError):
        raise ValueError("The selected profile picture is not a valid image.")
    filename = f"avatar_{secrets.token_hex(16)}.{extension}"
    file.save(AVATAR_UPLOAD_DIR / filename)
    return filename


def delete_avatar(filename):
    if filename:
        path = AVATAR_UPLOAD_DIR / Path(filename).name
        if path.exists():
            path.unlink()


def avatar_url(user):
    filename = user["profile_picture"] if user and "profile_picture" in user.keys() else None
    return url_for("static", filename=f"uploads/avatars/{filename}") if filename else None


def initials(user):
    name = (user["full_name"] if user and "full_name" in user.keys() else "") or "User"
    parts = [part for part in name.split() if part]
    return "".join(part[0] for part in parts[:2]).upper() or "U"


def public_item_image(filename):
    return url_for("static", filename=f"uploads/{filename}") if filename else None


def validate_password(password):
    return len(password) >= 8 and re.search(r"[A-Za-z]", password) and re.search(r"\d", password)


def item_form_data():
    return {
        key: request.form.get(key, "").strip()
        for key in ("item_name", "category", "barangay", "item_date", "item_time", "specific_location", "description", "additional_details")
    }


def validate_item(data):
    if any(not data[key] for key in ("item_name", "category", "barangay", "item_date", "specific_location")):
        return "Please complete the item name, category, barangay, date, and specific location."
    if data["category"] not in CATEGORIES:
        return "Please select a valid item category."
    if data["barangay"] not in ALL_BARANGAYS:
        return "Please select a valid Pasig City barangay."
    if len(data["item_name"]) > 120 or len(data["description"]) > 3000 or len(data["specific_location"]) > 240:
        return "Please shorten the item details and try again."
    return None


def score_match(lost, found):
    score = 0
    if lost["category"].casefold() == found["category"].casefold():
        score += 30
    if lost["location"].casefold() == found["location"].casefold():
        score += 25
    if lost["item_date"] == found["item_date"]:
        score += 20
    lost_words = set((lost["item_name"] + " " + (lost["description"] or "")).casefold().split())
    found_words = set((found["item_name"] + " " + (found["description"] or "")).casefold().split())
    if lost_words.intersection(found_words):
        score += 25
    return score


def update_matches(conn):
    rows = conn.execute("SELECT * FROM items WHERE status IN ('ACTIVE','APPROVED')").fetchall()
    for lost in rows:
        if lost["item_type"] != "LOST":
            continue
        for found in rows:
            if found["item_type"] != "FOUND" or lost["id"] == found["id"]:
                continue
            score = score_match(lost, found)
            if score >= 25:
                existing = conn.execute(
                    "SELECT id FROM matches WHERE lost_item_id=? AND found_item_id=?",
                    (lost["id"], found["id"])
                ).fetchone()
                conn.execute(
                    "INSERT INTO matches(lost_item_id,found_item_id,score) VALUES(?,?,?) "
                    "ON CONFLICT(lost_item_id,found_item_id) DO UPDATE SET score=excluded.score",
                    (lost["id"], found["id"], score)
                )
                if not existing:
                    lost_owner = conn.execute("SELECT user_id FROM items WHERE id=?", (lost["id"],)).fetchone()
                    finder = conn.execute("SELECT user_id FROM items WHERE id=?", (found["id"],)).fetchone()
                    notify(
                        conn,
                        lost_owner["user_id"],
                        f"Possible Match Found: {found['item_name']} may match your lost item {lost['item_name']}.",
                        "POSSIBLE_MATCH",
                        item_id=found["id"],
                    )
                    if finder["user_id"] != lost_owner["user_id"]:
                        notify(
                            conn,
                            finder["user_id"],
                            f"Possible Owner Found: The item you surrendered, {found['item_name']}, may belong to another user.",
                            "POSSIBLE_OWNER",
                            item_id=found["id"],
                        )
                    notify_admins(
                        conn,
                        f"Possible match detected between lost item {lost['item_name']} and found item {found['item_name']}.",
                        "POSSIBLE_MATCH",
                        item_id=found["id"],
                    )
                    log_action(conn, "MATCH_DETECTED", f"Possible match detected for reports #{lost['id']} and #{found['id']}.")


def log_action(conn, action, details):
    conn.execute("INSERT INTO audit_logs(user_id,action,details) VALUES(?,?,?)", (session.get("user_id"), action, details))


def notify(conn, user_id, message, notification_type="INFO", claim_id=None, item_id=None):
    if user_id:
        conn.execute(
            "INSERT INTO notifications(user_id,claim_id,item_id,message,notification_type) VALUES(?,?,?,?,?)",
            (user_id, claim_id, item_id, message, notification_type)
        )
        log_action(conn, "NOTIFICATION_CREATED", f"{notification_type} notification created for user #{user_id}.")


def notify_admins(conn, message, notification_type="INFO", claim_id=None, item_id=None):
    admins = conn.execute(
        "SELECT id FROM users WHERE upper(role)='ADMIN' AND account_status='ACTIVE'"
    ).fetchall()
    for admin in admins:
        notify(conn, admin["id"], message, notification_type, claim_id, item_id)


def resolve_linked_reports(conn, item_id, timestamp, claim_id=None, excluded_user_ids=()):
    """Close the matched report and notify its owner when a case is completed."""
    item = conn.execute(
        "SELECT id,item_type,item_name,user_id FROM items WHERE id=?",
        (item_id,),
    ).fetchone()
    if not item:
        return []

    if item["item_type"] == "FOUND":
        linked = conn.execute(
            "SELECT items.id,items.item_type,items.item_name,items.user_id "
            "FROM matches JOIN items ON items.id=matches.lost_item_id "
            "WHERE matches.found_item_id=?",
            (item_id,),
        ).fetchall()
    else:
        linked = conn.execute(
            "SELECT items.id,items.item_type,items.item_name,items.user_id "
            "FROM matches JOIN items ON items.id=matches.found_item_id "
            "WHERE matches.lost_item_id=?",
            (item_id,),
        ).fetchall()

    resolved = []
    for linked_item in linked:
        if linked_item["id"] == item_id:
            continue
        changed = conn.execute(
            "UPDATE items SET status='RESOLVED',updated_at=? "
            "WHERE id=? AND status!='RESOLVED'",
            (timestamp, linked_item["id"]),
        )
        if changed.rowcount:
            resolved.append(linked_item)
            if linked_item["user_id"] not in excluded_user_ids:
                notify(
                    conn,
                    linked_item["user_id"],
                    f"Your {linked_item['item_type'].lower()} report for {linked_item['item_name']} is now resolved. "
                    "The matched lost-and-found case has been completed.",
                    "REPORT_RESOLVED",
                    claim_id,
                    linked_item["id"],
                )
    return resolved


def claim_code(claim_id):
    return f"CLM-{claim_id:04d}"


def mark_messages_read(conn, user_id, item_id=None, claim_id=None):
    conditions = ["recipient_id=?", "read_at IS NULL"]
    values = [user_id]
    if claim_id is not None:
        conditions.append("claim_id=?")
        values.append(claim_id)
    elif item_id is not None:
        conditions.extend(["item_id=?", "claim_id IS NULL"])
        values.append(item_id)
    changed = conn.execute(
        f"UPDATE messages SET read_at=? WHERE {' AND '.join(conditions)}",
        [now(), *values],
    )
    if changed.rowcount:
        log_action(conn, "MESSAGE_SEEN", f"{changed.rowcount} message(s) marked seen.")
    return changed.rowcount


@app.context_processor
def template_context():
    user = current_user()
    unread = 0
    unread_messages = 0
    if user:
        conn = get_connection()
        unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (user["id"],)).fetchone()[0]
        unread_messages = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient_id=? AND read_at IS NULL",
            (user["id"],)
        ).fetchone()[0]
        conn.close()
    return {
        "current_user": user,
        "categories": CATEGORIES,
        "barangays": BARANGAYS,
        "all_barangays": ALL_BARANGAYS,
        "public_item_image": public_item_image,
        "avatar_url": avatar_url,
        "initials": initials,
        "unread_notifications": unread,
        "unread_messages": unread_messages,
        "claim_code": claim_code,
        "is_admin": is_admin(user),
        "theme": (user["theme_preference"] if user and user["theme_preference"] in ("light", "dark", "system") else "light") if user else "light"
    }


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        question = request.form.get("security_question", "").strip()
        answer = request.form.get("security_answer", "").strip()

        if not all((full_name, email, password, confirm, question, answer)):
            flash("Please complete every field.", "danger")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "danger")
        elif not validate_password(password):
            flash("Password must be at least 8 characters and include a letter and a number.", "danger")
        elif password != confirm:
            flash("Passwords do not match.", "danger")
        elif len(question) < 8 or len(answer) < 2:
            flash("Please create a clear security question and answer.", "danger")
        else:
            conn = get_connection()
            duplicate = conn.execute("SELECT id FROM users WHERE lower(email)=?", (email,)).fetchone()
            if duplicate:
                conn.close()
                flash("That email is already registered.", "danger")
            else:
                try:
                    profile_picture = save_avatar(request.files.get("profile_picture"))
                except ValueError as exc:
                    conn.close()
                    flash(str(exc), "danger")
                    return render_template("register.html")

                username = "user_" + secrets.token_hex(5)
                pending_user = {
                    "id": None,
                    "email": email,
                    "full_name": full_name,
                }
                conn.execute(
                    "INSERT INTO users(username,email,password_hash,role,full_name,security_question,security_answer_hash,account_status,created_at,profile_picture) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (username, email, AuthController.password_hash(password), "user", full_name, question, AuthController.security_answer_hash(answer), "PENDING", now(), profile_picture)
                )
                pending_user["id"] = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                try:
                    if not issue_otp(conn, pending_user):
                        raise RuntimeError("Unable to send the verification email. Please try again later.")
                except (OSError, RuntimeError, ValueError) as exc:
                    conn.rollback()
                    conn.close()
                    delete_avatar(profile_picture)
                    flash(str(exc), "danger")
                    return render_template("register.html")
                log_action(conn, "USER_REGISTERED_PENDING", f"{full_name} started email verification.")
                conn.commit()
                conn.close()
                session["pending_verification_user_id"] = pending_user["id"]
                flash("A verification code has been sent to your email.", "success")
                return redirect(url_for("verify_otp"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        success, result = AuthController(str(BASE_DIR / "lost_found.db")).login(request.form.get("email", "").strip(), request.form.get("password", ""))
        if success:
            session.clear()
            session.update(user_id=result["id"], email=result["email"], role=result["role"])
            flash("Welcome back.", "success")
            return redirect(request.args.get("next") or (url_for("admin_dashboard") if is_admin(result) else url_for("dashboard")))
        if isinstance(result, str) and result == "Please verify your email before logging in.":
            conn = get_connection()
            user = conn.execute(
                "SELECT id FROM users WHERE lower(email)=lower(?) AND account_status='PENDING'",
                (request.form.get("email", "").strip(),),
            ).fetchone()
            conn.close()
            if user:
                session["pending_verification_user_id"] = user["id"]
                return redirect(url_for("verify_otp"))
        flash(result, "danger")
    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    user = pending_verification_user()
    if not user:
        session.pop("pending_verification_user_id", None)
        flash("There is no pending email verification.", "info")
        return redirect(url_for("register"))
    conn = get_connection()
    challenge = conn.execute("SELECT * FROM otp_verifications WHERE user_id=?", (user["id"],)).fetchone()
    if not challenge:
        conn.close()
        flash("Please request a new verification code.", "danger")
        return render_template("verify_otp.html", cooldown=0)
    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if not re.fullmatch(r"\d{6}", code):
            flash("Invalid OTP.", "danger")
        elif parse_utc(challenge["expires_at"]) <= utc_now():
            flash("OTP has expired.", "danger")
        elif challenge["attempts"] >= OTP_MAX_ATTEMPTS:
            flash("Too many attempts. Please request a new OTP.", "danger")
        elif not hmac.compare_digest(otp_hash(code), challenge["otp_hash"]):
            attempts = challenge["attempts"] + 1
            conn.execute("UPDATE otp_verifications SET attempts=? WHERE user_id=?", (attempts, user["id"]))
            conn.commit()
            flash("Too many attempts. Please request a new OTP." if attempts >= OTP_MAX_ATTEMPTS else "Invalid OTP.", "danger")
        else:
            conn.execute("UPDATE users SET account_status='ACTIVE' WHERE id=?", (user["id"],))
            conn.execute("DELETE FROM otp_verifications WHERE user_id=?", (user["id"],))
            log_action(conn, "EMAIL_VERIFIED", f"{user['full_name']} verified their email address.")
            notify_admins(conn, f"New user registration: {user['full_name']} created an account.", "NEW_USER")
            conn.commit()
            conn.close()
            session.pop("pending_verification_user_id", None)
            flash("Email verified successfully. You can now log in.", "success")
            return redirect(url_for("login"))
    cooldown = max(0, OTP_RESEND_COOLDOWN_SECONDS - int((utc_now() - parse_utc(challenge["last_sent_at"])).total_seconds()))
    conn.close()
    return render_template("verify_otp.html", cooldown=cooldown)


@app.post("/verify-otp/resend")
def resend_otp():
    user = pending_verification_user()
    if not user:
        flash("There is no pending email verification.", "info")
        return redirect(url_for("register"))
    conn = get_connection()
    challenge = conn.execute("SELECT * FROM otp_verifications WHERE user_id=?", (user["id"],)).fetchone()
    if not challenge:
        conn.close()
        flash("Please restart registration to request a verification code.", "danger")
        return redirect(url_for("register"))
    elapsed = (utc_now() - parse_utc(challenge["last_sent_at"])).total_seconds()
    if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
        conn.close()
        flash(f"Please wait {OTP_RESEND_COOLDOWN_SECONDS - int(elapsed)} seconds before requesting another code.", "danger")
        return redirect(url_for("verify_otp"))
    if challenge["resend_count"] >= OTP_MAX_RESENDS:
        conn.close()
        flash("Too many OTP resend requests. Please try again later.", "danger")
        return redirect(url_for("verify_otp"))
    code = f"{secrets.randbelow(1_000_000):06d}"
    sent_at = utc_now()
    if not send_otp_email(user["email"], user["full_name"] or "there", code):
        conn.close()
        flash("Unable to send the verification email. Please try again later.", "danger")
        return redirect(url_for("verify_otp"))
    conn.execute(
        "UPDATE otp_verifications SET otp_hash=?,expires_at=?,attempts=0,resend_count=resend_count+1,last_sent_at=? WHERE user_id=?",
        (otp_hash(code), (sent_at + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat(), sent_at.isoformat(), user["id"]),
    )
    conn.commit()
    conn.close()
    flash("A new OTP has been sent.", "success")
    return redirect(url_for("verify_otp"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST" and request.form.get("email"):
        email = request.form["email"].strip().lower()
        conn = get_connection()
        user = conn.execute("SELECT id,security_question FROM users WHERE lower(email)=? AND account_status='ACTIVE'", (email,)).fetchone()
        conn.close()
        session.pop("reset_user_id", None)
        if user:
            session["reset_user_id"] = user["id"]
            return render_template("forgot_password.html", security_question=user["security_question"] or "Your registered security question", answer_step=True)
        flash("If that email is registered, you will be able to continue with password recovery.", "info")
    return render_template("forgot_password.html", answer_step=bool(session.get("reset_user_id")), security_question=None)


@app.route("/reset-password", methods=["POST"])
def reset_password():
    user_id = session.get("reset_user_id")
    if not user_id:
        return redirect(url_for("forgot_password"))
    answer = request.form.get("security_answer", "").strip()
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    conn = get_connection()
    user = conn.execute("SELECT security_answer_hash,security_question FROM users WHERE id=?", (user_id,)).fetchone()
    if not user or not AuthController.check_security_answer(answer, user["security_answer_hash"]):
        conn.close()
        flash("The security answer is incorrect.", "danger")
        return render_template("forgot_password.html", answer_step=True, security_question=user["security_question"] if user else None)
    if not validate_password(new_password):
        conn.close()
        flash("Password must be at least 8 characters and include a letter and a number.", "danger")
        return render_template("forgot_password.html", answer_step=True, security_question=user["security_question"])
    if new_password != confirm:
        conn.close()
        flash("Passwords do not match.", "danger")
        return render_template("forgot_password.html", answer_step=True, security_question=user["security_question"])
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (AuthController.password_hash(new_password), user_id))
    conn.commit()
    conn.close()
    session.pop("reset_user_id", None)
    flash("Your password has been reset successfully. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if (blocked := normal_user_required()):
        return blocked
    user_id = session["user_id"]
    conn = get_connection()
    stats = {
        "active": conn.execute("SELECT COUNT(*) FROM items WHERE user_id=? AND status IN ('ACTIVE','APPROVED','PENDING REVIEW')", (user_id,)).fetchone()[0],
        "matches": conn.execute("SELECT COUNT(*) FROM matches m JOIN items i ON (i.id=m.lost_item_id OR i.id=m.found_item_id) WHERE i.user_id=?", (user_id,)).fetchone()[0],
        "claims": conn.execute("SELECT COUNT(*) FROM claims WHERE claimant_id=? AND status IN ('PENDING','PENDING REVIEW','UNDER REVIEW','REQUEST MORE INFORMATION')", (user_id,)).fetchone()[0],
        "resolved": conn.execute("SELECT COUNT(*) FROM items WHERE user_id=? AND status='RESOLVED'", (user_id,)).fetchone()[0]
    }
    recent = conn.execute("SELECT * FROM items WHERE status IN ('ACTIVE','APPROVED') ORDER BY id DESC LIMIT 6").fetchall()
    conn.close()
    return render_template("dashboard.html", stats=stats, recent_items=recent)


@app.route("/browse")
def browse():
    if (blocked := normal_user_required("Please log in to view Lost & Found reports.")):
        return blocked
    conn = get_connection()
    conditions = ["status IN ('ACTIVE','APPROVED')"]
    values = []
    search = request.args.get("search", "").strip()
    category = request.args.get("category", "")
    barangay = request.args.get("barangay", "")
    item_type = request.args.get("type", "")
    date = request.args.get("date", "")

    if search:
        conditions.append("(lower(item_name) LIKE ? OR lower(description) LIKE ?)")
        values += [f"%{search.casefold()}%"] * 2
    if category in CATEGORIES:
        conditions.append("category=?")
        values.append(category)
    if barangay in ALL_BARANGAYS:
        conditions.append("location=?")
        values.append(barangay)
    if item_type in ("LOST", "FOUND"):
        conditions.append("item_type=?")
        values.append(item_type)
    if date:
        conditions.append("item_date=?")
        values.append(date)

    items = conn.execute("SELECT * FROM items WHERE " + " AND ".join(conditions) + " ORDER BY id DESC", values).fetchall()
    conn.close()
    return render_template("browse.html", items=items, filters=request.args)


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    if (blocked := normal_user_required()):
        return blocked
    conn = get_connection()
    item = conn.execute(
        "SELECT items.*,users.full_name FROM items JOIN users ON users.id=items.user_id WHERE items.id=? "
        "AND (items.status IN ('ACTIVE','APPROVED') OR items.user_id=? OR upper(users.role)='ADMIN')",
        (item_id, session["user_id"])
    ).fetchone()
    matched_lost = None
    if item and item["item_type"] == "FOUND":
        lost_reports = conn.execute(
            "SELECT * FROM items WHERE user_id=? AND item_type='LOST' AND status IN ('ACTIVE','APPROVED')",
            (session["user_id"],)
        ).fetchall()
        for lost in lost_reports:
            if score_match(lost, item) >= 25:
                matched_lost = lost
                break
    conn.close()
    if item is None:
        abort(404)
    return render_template(
        "item_detail.html",
        item=item,
        is_surrenderer=item["user_id"] == session["user_id"],
        matched_lost=matched_lost,
        can_claim=item["item_type"] == "FOUND" and item["user_id"] != session["user_id"],
    )


def save_report(report_type, item_id=None):
    data = item_form_data()
    error = validate_item(data)
    if error:
        return error
    try:
        image = save_file(request.files.get("image"), PUBLIC_UPLOAD_DIR)
    except ValueError as exc:
        return str(exc)

    conn = get_connection()
    timestamp = now()
    if item_id is None:
        cur = conn.execute(
            "INSERT INTO items(user_id,item_type,item_name,category,location,specific_location,item_date,item_time,description,status,additional_details,image_filename,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (session["user_id"], report_type, data["item_name"], data["category"], data["barangay"], data["specific_location"], data["item_date"], data["item_time"], data["description"], "PENDING REVIEW", data["additional_details"], image, timestamp)
        )
        item_id = cur.lastrowid
        log_action(conn, "SUBMIT_REPORT", f"Report #{item_id} submitted for review.")
        user = conn.execute("SELECT full_name FROM users WHERE id=?", (session["user_id"],)).fetchone()
        label = user["full_name"] or "A user"
        if report_type == "LOST":
            notify_admins(
                conn,
                f"New Lost Item Report: {label} reported a lost item: {data['item_name']}.",
                "NEW_LOST_REPORT",
                item_id=item_id,
            )
            notify(
                conn,
                session["user_id"],
                "Lost Item Report Submitted: Your lost item report has been submitted successfully.",
                "REPORT_SUBMITTED",
                item_id=item_id,
            )
        else:
            notify_admins(
                conn,
                f"New Found Item Surrendered: {label} found and surrendered: {data['item_name']}.",
                "NEW_FOUND_SURRENDERED",
                item_id=item_id,
            )
            notify(
                conn,
                session["user_id"],
                "Item Successfully Surrendered: Your found item has been submitted and is waiting for Admin verification.",
                "SURRENDER_SUBMITTED",
                item_id=item_id,
            )
    else:
        owner = conn.execute("SELECT user_id FROM items WHERE id=?", (item_id,)).fetchone()
        if not owner or owner["user_id"] != session["user_id"]:
            conn.close()
            abort(403)
        if not image:
            image = conn.execute("SELECT image_filename FROM items WHERE id=?", (item_id,)).fetchone()["image_filename"]
        conn.execute(
            "UPDATE items SET item_name=?,category=?,location=?,specific_location=?,item_date=?,item_time=?,description=?,additional_details=?,image_filename=?,status='PENDING REVIEW',updated_at=? WHERE id=?",
            (data["item_name"], data["category"], data["barangay"], data["specific_location"], data["item_date"], data["item_time"], data["description"], data["additional_details"], image, timestamp, item_id)
        )
        log_action(conn, "UPDATE_REPORT", f"Report #{item_id} updated.")
        notify_admins(
            conn,
            f"Item update: Report #{item_id} ({data['item_name']}) was updated by its reporter.",
            "ITEM_UPDATED",
            item_id=item_id,
        )
        notify(
            conn,
            session["user_id"],
            f"Surrendered Item Updated: There is an update regarding {data['item_name']}.",
            "ITEM_UPDATED",
            item_id=item_id,
        )
    conn.commit()
    conn.close()
    return item_id


@app.route("/report", methods=["GET", "POST"])
def report():
    if (blocked := normal_user_required("You need an account to report a lost or found item.")):
        return blocked
    report_type = request.form.get("report_type") if request.method == "POST" else request.args.get("type", "")
    if request.method == "POST":
        if report_type not in ("LOST", "FOUND"):
            flash("Please choose whether you lost or found the item.", "danger")
        else:
            result = save_report(report_type)
            if isinstance(result, int):
                flash("Your report was submitted and is waiting for review.", "success")
                return redirect(url_for("report_confirmation", item_id=result))
            flash(result, "danger")
    return render_template("report_wizard.html", report_type=report_type)


@app.route("/report/lost", methods=["GET", "POST"])
def legacy_report_lost():
    return report()


@app.route("/report/found", methods=["GET", "POST"])
def legacy_report_found():
    return report()


@app.route("/report/confirmation/<int:item_id>")
def report_confirmation(item_id):
    if (blocked := normal_user_required()):
        return blocked
    conn = get_connection()
    item = conn.execute("SELECT * FROM items WHERE id=? AND user_id=?", (item_id, session["user_id"])).fetchone()
    conn.close()
    if item is None:
        abort(404)
    return render_template("confirmation.html", item=item)


@app.route("/my-reports")
def my_reports():
    if (blocked := normal_user_required()):
        return blocked
    conn = get_connection()
    items = conn.execute("SELECT * FROM items WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    claims = conn.execute(
        "SELECT claims.*,items.item_name,items.user_id AS finder_id,claimant.full_name AS claimant_name,claimant.profile_picture AS claimant_picture "
        "FROM claims JOIN items ON items.id=claims.item_id JOIN users AS claimant ON claimant.id=claims.claimant_id "
        "WHERE claims.claimant_id=? OR items.user_id=? ORDER BY claims.id DESC",
        (session["user_id"], session["user_id"])
    ).fetchall()
    conn.close()
    return render_template("my_reports.html", items=items, claims=claims)


@app.route("/matches/<int:item_id>")
def legacy_matches(item_id):
    if (blocked := normal_user_required()):
        return blocked
    conn = get_connection()
    item = conn.execute("SELECT * FROM items WHERE id=? AND user_id=?", (item_id, session["user_id"])).fetchone()
    if not item:
        conn.close()
        abort(404)
    other = "FOUND" if item["item_type"] == "LOST" else "LOST"
    candidates = conn.execute("SELECT * FROM items WHERE item_type=? AND id!=? AND status='ACTIVE'", (other, item_id)).fetchall()
    results = []
    for candidate in candidates:
        lost, found = (item, candidate) if item["item_type"] == "LOST" else (candidate, item)
        score = score_match(lost, found)
        if score >= 25:
            results.append({"item": candidate, "score": score})
    conn.close()
    results.sort(key=lambda result: result["score"], reverse=True)
    return render_template("matches.html", item=item, matches=results)


@app.route("/report/<int:item_id>/edit", methods=["GET", "POST"])
def edit_report(item_id):
    if (blocked := normal_user_required()):
        return blocked
    conn = get_connection()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    conn.close()
    if not item:
        abort(404)
    if item["user_id"] != session["user_id"]:
        abort(403)
    if request.method == "POST":
        result = save_report(item["item_type"], item_id)
        if isinstance(result, int):
            flash("Your report was updated and sent for review again.", "success")
            return redirect(url_for("my_reports"))
        flash(result, "danger")
    return render_template("report_wizard.html", report_type=item["item_type"], item=item)


@app.route("/claim/<int:item_id>", methods=["GET", "POST"])
def claim(item_id):
    if (blocked := normal_user_required()):
        return blocked
    conn = get_connection()
    item = conn.execute(
        "SELECT * FROM items WHERE id=? AND item_type='FOUND' AND status IN ('ACTIVE','APPROVED')",
        (item_id,)
    ).fetchone()
    if not item:
        conn.close()
        abort(404)
    if item["user_id"] == session["user_id"]:
        conn.close()
        flash("You cannot claim an item that you personally surrendered.", "danger")
        return redirect(url_for("item_detail", item_id=item_id))
    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        proof = request.form.get("proof", "").strip()
        if not reason or not proof:
            flash("Please provide a reason and proof of ownership.", "danger")
        else:
            try:
                proof_file = save_file(request.files.get("proof_file"), PRIVATE_UPLOAD_DIR)
                id_file = save_file(request.files.get("id_file"), PRIVATE_UPLOAD_DIR)
            except ValueError as exc:
                conn.close()
                flash(str(exc), "danger")
                return render_template("claim.html", item=item)

            existing = conn.execute("SELECT id FROM claims WHERE item_id=? AND claimant_id=? AND status NOT IN ('REJECTED','RESOLVED')", (item_id, session["user_id"])).fetchone()
            if existing:
                conn.close()
                flash("You already have an active claim request for this item.", "info")
                return redirect(url_for("claim_conversation", claim_id=existing["id"]))

            claim_row = conn.execute(
                "INSERT INTO claims(item_id,claimant_id,reason,proof,proof_filename,id_filename,status,updated_at) VALUES(?,?,?,?,?,?,?,?) RETURNING id",
                (item_id, session["user_id"], reason, proof, proof_file, id_file, "PENDING REVIEW", now())
            ).fetchone()
            new_claim_id = claim_row["id"]
            admin = conn.execute("SELECT id FROM users WHERE upper(role)='ADMIN' AND account_status='ACTIVE' ORDER BY id LIMIT 1").fetchone()
            notify(conn, session["user_id"], f"Your claim request {claim_code(new_claim_id)} has been submitted for review.", "CLAIM_SUBMITTED", new_claim_id, item_id)
            if admin:
                notify(conn, admin["id"], f"New claim request {claim_code(new_claim_id)} needs review.", "NEW_CLAIM", new_claim_id, item_id)
            log_action(conn, "SUBMIT_CLAIM", f"Claim {claim_code(new_claim_id)} submitted for item #{item_id}.")
            conn.commit()
            conn.close()
            flash("Your claim request has been submitted. An administrator will review your proof and contact you through the system.", "success")
            return redirect(url_for("claim_conversation", claim_id=new_claim_id))
    conn.close()
    return render_template("claim.html", item=item)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if (blocked := user_required()):
        return blocked
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        theme = request.form.get("theme_preference", "light")
        conn = get_connection()
        user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please provide a name and valid email.", "danger")
        elif theme not in ("light", "dark", "system"):
            flash("Please choose a valid appearance setting.", "danger")
        elif conn.execute("SELECT id FROM users WHERE lower(email)=? AND id!=?", (email, session["user_id"])).fetchone():
            flash("That email is already in use.", "danger")
        else:
            try:
                new_picture = save_avatar(request.files.get("profile_picture"))
            except ValueError as exc:
                conn.close()
                flash(str(exc), "danger")
                return render_template("profile.html", user=user)

            remove_picture = request.form.get("remove_picture") == "1"
            picture = None if remove_picture else (new_picture or user["profile_picture"])
            conn.execute("UPDATE users SET full_name=?,email=?,profile_picture=?,theme_preference=? WHERE id=?", (name, email, picture, theme, session["user_id"]))
            conn.commit()
            session["email"] = email
            if (new_picture or remove_picture) and user["profile_picture"] and user["profile_picture"] != picture:
                delete_avatar(user["profile_picture"])
            flash("Your profile was updated.", "success")
        conn.close()
    return render_template("profile.html", user=current_user())


@app.post("/theme")
def set_theme():
    if (blocked := normal_user_required()):
        return blocked
    theme = request.form.get("theme", "light")
    if theme not in ("light", "dark", "system"):
        abort(400)
    conn = get_connection()
    conn.execute("UPDATE users SET theme_preference=? WHERE id=?", (theme, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/claims/<int:claim_id>")
def claim_conversation(claim_id):
    if (blocked := user_required()):
        return blocked
    conn = get_connection()
    claim_row = conn.execute(
        "SELECT claims.*,items.item_name,items.item_type,items.location,items.item_date,items.description,users.full_name AS claimant_name,users.email AS claimant_email,users.profile_picture AS claimant_picture "
        "FROM claims JOIN items ON items.id=claims.item_id JOIN users ON users.id=claims.claimant_id WHERE claims.id=?",
        (claim_id,)
    ).fetchone()
    if not claim_row:
        conn.close()
        abort(404)
    if not is_admin(current_user()) and claim_row["claimant_id"] != session["user_id"]:
        conn.close()
        abort(403)
    changed = conn.execute(
        "UPDATE messages SET read_at=? WHERE claim_id=? AND recipient_id=? AND read_at IS NULL",
        (now(), claim_id, session["user_id"])
    )
    if changed.rowcount:
        log_action(conn, "MESSAGE_SEEN", f"{changed.rowcount} message(s) in claim conversation {claim_code(claim_id)} marked seen.")
    messages = conn.execute(
        "SELECT messages.*,users.full_name,users.email,users.profile_picture FROM messages JOIN users ON users.id=messages.sender_id WHERE messages.claim_id=? ORDER BY messages.id",
        (claim_id,)
    ).fetchall()
    conn.commit()
    conn.close()
    return render_template("claim_conversation.html", claim=claim_row, messages=messages, is_admin=is_admin(current_user()))


@app.post("/claims/<int:claim_id>/message")
def claim_message(claim_id):
    if (blocked := user_required()):
        return blocked
    body = request.form.get("body", "").strip()
    if not body:
        flash("Please write a message before sending.", "danger")
        return redirect(url_for("claim_conversation", claim_id=claim_id))
    conn = get_connection()
    claim_row = conn.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
    if not claim_row:
        conn.close()
        abort(404)
    admin = is_admin(current_user())
    if not admin and claim_row["claimant_id"] != session["user_id"]:
        conn.close()
        abort(403)
    recipient_id = claim_row["claimant_id"] if admin else conn.execute("SELECT id FROM users WHERE upper(role)='ADMIN' AND account_status='ACTIVE' ORDER BY id LIMIT 1").fetchone()[0]
    conn.execute("INSERT INTO messages(sender_id,recipient_id,item_id,claim_id,body) VALUES(?,?,?,?,?)", (session["user_id"], recipient_id, claim_row["item_id"], claim_id, body))
    notify(conn, recipient_id, f"New message in claim {claim_code(claim_id)}.", "NEW_MESSAGE", claim_id, claim_row["item_id"])
    log_action(conn, "MESSAGE_SENT", f"Message sent in claim {claim_code(claim_id)}.")
    conn.commit()
    conn.close()
    flash("Your message was sent.", "success")
    return redirect(url_for("claim_conversation", claim_id=claim_id))


@app.post("/claims/<int:claim_id>/upload")
def claim_additional_proof(claim_id):
    if (blocked := user_required()):
        return blocked
    conn = get_connection()
    claim_row = conn.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
    if not claim_row:
        conn.close()
        abort(404)
    if not is_admin(current_user()) and claim_row["claimant_id"] != session["user_id"]:
        conn.close()
        abort(403)
    try:
        filename = save_file(request.files.get("proof_file"), PRIVATE_UPLOAD_DIR)
    except ValueError as exc:
        conn.close()
        flash(str(exc), "danger")
        return redirect(url_for("claim_conversation", claim_id=claim_id))
    if not filename:
        conn.close()
        flash("Choose a proof image before uploading.", "danger")
        return redirect(url_for("claim_conversation", claim_id=claim_id))
    conn.execute("UPDATE claims SET proof_filename=?,status='PENDING REVIEW',updated_at=? WHERE id=?", (filename, now(), claim_id))
    admin = conn.execute("SELECT id FROM users WHERE upper(role)='ADMIN' AND account_status='ACTIVE' ORDER BY id LIMIT 1").fetchone()
    if not is_admin(current_user()) and admin:
        notify(conn, admin["id"], f"Additional proof was uploaded for claim {claim_code(claim_id)}.", "NEW_PROOF", claim_id, claim_row["item_id"])
    conn.commit()
    conn.close()
    flash("Additional proof was uploaded for administrator review.", "success")
    return redirect(url_for("claim_conversation", claim_id=claim_id))


@app.route("/notifications")
def notifications():
    if (blocked := user_required()):
        return blocked
    conn = get_connection()
    rows = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    conn.close()
    return render_template("notifications.html", notifications=rows, admin_view=is_admin(current_user()))


@app.route("/notifications/<int:notification_id>")
def open_notification(notification_id):
    if (blocked := user_required()):
        return blocked
    conn = get_connection()
    notification = conn.execute(
        "SELECT * FROM notifications WHERE id=? AND user_id=?",
        (notification_id, session["user_id"]),
    ).fetchone()
    if not notification:
        conn.close()
        abort(404)
    if not notification["is_read"]:
        conn.execute(
            "UPDATE notifications SET is_read=1 WHERE id=?",
            (notification_id,),
        )
        log_action(conn, "NOTIFICATION_READ", f"Notification #{notification_id} opened.")
    conn.commit()
    conn.close()
    if notification["claim_id"]:
        return redirect(url_for("claim_conversation", claim_id=notification["claim_id"]))
    if notification["item_id"]:
        if is_admin(current_user()):
            return redirect(url_for("admin_report_detail", item_id=notification["item_id"]))
        if notification["notification_type"] in {"NEW_MESSAGE", "POSSIBLE_MATCH", "POSSIBLE_OWNER"}:
            return redirect(url_for("messages", item_id=notification["item_id"]))
        return redirect(url_for("item_detail", item_id=notification["item_id"]))
    return redirect(url_for("notifications"))


@app.route("/messages")
def messages():
    if (blocked := normal_user_required()):
        return blocked
    item_id = request.args.get("item_id", type=int)
    conn = get_connection()
    admin = conn.execute(
        "SELECT id,full_name,email FROM users WHERE upper(role)='ADMIN' AND account_status='ACTIVE' ORDER BY id LIMIT 1"
    ).fetchone()
    conversation = []
    item = None
    if item_id:
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            conn.close()
            abort(404)
        has_matching_lost_report = False
        if item["item_type"] == "FOUND" and item["user_id"] != session["user_id"]:
            lost_reports = conn.execute(
                "SELECT * FROM items WHERE user_id=? AND item_type='LOST' AND status IN ('ACTIVE','APPROVED')",
                (session["user_id"],)
            ).fetchall()
            has_matching_lost_report = any(score_match(lost, item) >= 25 for lost in lost_reports)
        has_existing_conversation = conn.execute(
            "SELECT 1 FROM messages WHERE item_id=? AND (sender_id=? OR recipient_id=?) LIMIT 1",
            (item_id, session["user_id"], session["user_id"])
        ).fetchone()
        if (
            item["user_id"] != session["user_id"]
            and not is_admin(current_user())
            and not has_matching_lost_report
            and not has_existing_conversation
        ):
            conn.close()
            abort(403)
        mark_messages_read(conn, session["user_id"], item_id=item_id)
        conversation = conn.execute(
            "SELECT messages.*,users.full_name,users.email FROM messages "
            "JOIN users ON users.id=messages.sender_id "
            "WHERE messages.item_id=? AND messages.claim_id IS NULL "
            "AND (messages.sender_id=? OR messages.recipient_id=?) ORDER BY messages.id",
            (item_id, session["user_id"], session["user_id"])
        ).fetchall()
    rows = conn.execute(
        "SELECT messages.*,items.item_name,users.full_name,users.email "
        "FROM messages JOIN users ON users.id=messages.sender_id "
        "LEFT JOIN items ON items.id=messages.item_id "
        "WHERE messages.recipient_id=? OR messages.sender_id=? ORDER BY messages.id DESC",
        (session["user_id"], session["user_id"])
    ).fetchall()
    if not item_id:
        mark_messages_read(conn, session["user_id"])
    conversations = {}
    for message in rows:
        key = ("claim", message["claim_id"]) if message["claim_id"] else ("item", message["item_id"])
        if key not in conversations:
            unread_query = (
                "SELECT COUNT(*) FROM messages WHERE recipient_id=? AND read_at IS NULL AND claim_id=?"
                if message["claim_id"]
                else "SELECT COUNT(*) FROM messages WHERE recipient_id=? AND read_at IS NULL AND item_id=? AND claim_id IS NULL"
            )
            unread_count = conn.execute(
                unread_query,
                (session["user_id"], message["claim_id"] or message["item_id"]),
            ).fetchone()[0]
            conversation_data = dict(message)
            conversation_data["unread_count"] = unread_count
            conversations[key] = conversation_data
    conn.commit()
    conn.close()
    return render_template(
        "messages.html",
        conversations=list(conversations.values()),
        conversation=conversation,
        item=item,
        admin=admin,
        unread_messages=0 if not item_id else None,
    )


@app.route("/claims/<int:claim_id>/resolution")
def claim_resolution(claim_id):
    if (blocked := user_required()):
        return blocked
    conn = get_connection()
    resolution = conn.execute("""
        SELECT claims.*, claims.item_id AS report_id, items.item_name,
        items.item_type, items.location AS report_barangay, items.specific_location,
        items.item_date, items.item_time, items.image_filename,
        finder.id AS finder_id, finder.full_name AS finder_name,
        claimant.id AS claimant_id, claimant.full_name AS claimant_name,
        claimant.profile_picture AS claimant_picture
        FROM claims JOIN items ON items.id=claims.item_id
        JOIN users AS finder ON finder.id=items.user_id
        JOIN users AS claimant ON claimant.id=claims.claimant_id
        WHERE claims.id=? AND claims.status='RESOLVED'
    """, (claim_id,)).fetchone()
    conn.close()
    if not resolution:
        abort(404)
    if session["user_id"] not in (resolution["finder_id"], resolution["claimant_id"]) and not is_admin(current_user()):
        abort(403)
    return render_template("claim_resolution.html", resolution=resolution)


@app.route("/message", methods=["POST"])
def send_message():
    if (blocked := normal_user_required()):
        return blocked
    body = request.form.get("body", "").strip()
    item_id = request.form.get("item_id", type=int)
    claim_id = request.form.get("claim_id", type=int)
    if not body or (not item_id and not claim_id):
        flash("Please write a message connected to a report or claim.", "danger")
        return redirect(request.referrer or url_for("dashboard"))
    if claim_id:
        return redirect(url_for("claim_message", claim_id=claim_id), code=307)
    conn = get_connection()
    item = conn.execute("SELECT id FROM items WHERE id=? AND status='ACTIVE'", (item_id,)).fetchone()
    admin = conn.execute("SELECT id FROM users WHERE upper(role)='ADMIN' AND account_status='ACTIVE' ORDER BY id LIMIT 1").fetchone()
    if not item or not admin:
        conn.close()
        abort(403)
    conn.execute("INSERT INTO messages(sender_id,recipient_id,item_id,body) VALUES(?,?,?,?)", (session["user_id"], admin["id"], item_id, body))
    notify(conn, admin["id"], "A user sent a new report message.", "NEW_MESSAGE", None, item_id)
    log_action(conn, "MESSAGE_SENT", f"User sent a message about report #{item_id}.")
    conn.commit()
    conn.close()
    flash("Your message was sent to the administrator.", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/admin")
def admin_dashboard():
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    stats = {
        "users": conn.execute("SELECT COUNT(*) FROM users WHERE account_status='ACTIVE' OR account_status IS NULL").fetchone()[0],
        "lost": conn.execute("SELECT COUNT(*) FROM items WHERE item_type='LOST' AND status='ACTIVE'").fetchone()[0],
        "found": conn.execute("SELECT COUNT(*) FROM items WHERE item_type='FOUND' AND status='ACTIVE'").fetchone()[0],
        "claims": conn.execute("SELECT COUNT(*) FROM claims WHERE status IN ('PENDING','PENDING REVIEW','UNDER REVIEW','REQUEST MORE INFORMATION')").fetchone()[0],
        "review": conn.execute("SELECT COUNT(*) FROM items WHERE status='PENDING REVIEW'").fetchone()[0],
        "resolved": conn.execute("SELECT COUNT(*) FROM items WHERE status='RESOLVED'").fetchone()[0],
    }
    claims = conn.execute(
        "SELECT claims.id,claims.status,claims.created_at,items.item_name,users.full_name,users.profile_picture "
        "FROM claims JOIN items ON items.id=claims.item_id JOIN users ON users.id=claims.claimant_id "
        "WHERE claims.status NOT IN ('REJECTED','RESOLVED') ORDER BY claims.id DESC LIMIT 5"
    ).fetchall()
    reports = conn.execute(
        "SELECT items.id,items.item_type,items.item_name,items.location,items.status,users.full_name,users.profile_picture "
        "FROM items JOIN users ON users.id=items.user_id WHERE items.status='PENDING REVIEW' ORDER BY items.id DESC LIMIT 5"
    ).fetchall()
    users = conn.execute("SELECT id,full_name,email,role,account_status,profile_picture FROM users ORDER BY id DESC LIMIT 5").fetchall()
    admin_notifications = conn.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 5",
        (session["user_id"],)
    ).fetchall()
    activity_logs = conn.execute(
        "SELECT audit_logs.*,users.full_name FROM audit_logs "
        "LEFT JOIN users ON users.id=audit_logs.user_id ORDER BY audit_logs.id DESC LIMIT 10"
    ).fetchall()
    message_rows = conn.execute(
        "SELECT messages.*, "
        "CASE WHEN messages.sender_id=? THEN recipient.full_name ELSE sender.full_name END AS full_name, "
        "CASE WHEN messages.sender_id=? THEN recipient.email ELSE sender.email END AS email, "
        "items.item_name "
        "FROM messages "
        "JOIN users AS sender ON sender.id=messages.sender_id "
        "JOIN users AS recipient ON recipient.id=messages.recipient_id "
        "LEFT JOIN items ON items.id=messages.item_id "
        "WHERE messages.sender_id=? OR messages.recipient_id=? "
        "ORDER BY messages.id DESC LIMIT 50",
        (session["user_id"], session["user_id"], session["user_id"], session["user_id"]),
    ).fetchall()
    conn.close()
    conversations = {}
    for message in message_rows:
        key = (message["claim_id"], message["item_id"] if message["claim_id"] is None else None)
        if key not in conversations:
            conversations[key] = message
    return render_template("admin.html", stats=stats, claims=claims, reports=reports, users=users, conversations=list(conversations.values())[:5], admin_notifications=admin_notifications, activity_logs=activity_logs)


@app.route("/admin/users")
def admin_users():
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    users = conn.execute("SELECT id,full_name,email,role,account_status,created_at,profile_picture FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>")
def admin_user_detail(user_id):
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    user = conn.execute("SELECT id,full_name,email,role,account_status,created_at,profile_picture FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        abort(404)
    reports = conn.execute("SELECT id,item_type,item_name,location,status,item_date FROM items WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    claims = conn.execute("SELECT claims.id,claims.status,claims.created_at,items.item_name FROM claims JOIN items ON items.id=claims.item_id WHERE claims.claimant_id=? ORDER BY claims.id DESC", (user_id,)).fetchall()
    conn.close()
    return render_template("admin_user_detail.html", user=user, reports=reports, claims=claims)


@app.post("/admin/users/<int:user_id>/delete")
def admin_delete_user(user_id):
    if (blocked := admin_required()):
        return blocked
    if user_id == session["user_id"]:
        flash("You cannot delete the administrator account you are currently using.", "danger")
        return redirect(url_for("admin_user_detail", user_id=user_id))

    conn = get_connection()
    user = conn.execute(
        "SELECT id,full_name,email,profile_picture FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    if not user:
        conn.close()
        abort(404)

    report_files = [
        row["image_filename"]
        for row in conn.execute(
            "SELECT image_filename FROM items WHERE user_id=? AND image_filename IS NOT NULL",
            (user_id,),
        ).fetchall()
    ]
    claim_files = [
        filename
        for row in conn.execute(
            "SELECT proof_filename,id_filename FROM claims "
            "WHERE claimant_id=? OR item_id IN (SELECT id FROM items WHERE user_id=?)",
            (user_id, user_id),
        ).fetchall()
        for filename in (row["proof_filename"], row["id_filename"])
        if filename
    ]
    item_filter = "(SELECT id FROM items WHERE user_id=?)"
    claim_filter = (
        "(SELECT id FROM claims WHERE claimant_id=? "
        "OR item_id IN (SELECT id FROM items WHERE user_id=?))"
    )
    try:
        conn.execute(
            "DELETE FROM messages WHERE sender_id=? OR recipient_id=? "
            f"OR item_id IN {item_filter} OR claim_id IN {claim_filter}",
            (user_id, user_id, user_id, user_id, user_id),
        )
        conn.execute(
            "DELETE FROM notifications WHERE user_id=? "
            f"OR item_id IN {item_filter} OR claim_id IN {claim_filter}",
            (user_id, user_id, user_id, user_id),
        )
        conn.execute(
            f"DELETE FROM matches WHERE lost_item_id IN {item_filter} OR found_item_id IN {item_filter}",
            (user_id, user_id),
        )
        conn.execute(
            "DELETE FROM claims WHERE claimant_id=? OR item_id IN "
            "(SELECT id FROM items WHERE user_id=?)",
            (user_id, user_id),
        )
        conn.execute("DELETE FROM items WHERE user_id=?", (user_id,))
        conn.execute("UPDATE audit_logs SET user_id=NULL WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        flash("The user could not be deleted because related records are still in use.", "danger")
        return redirect(url_for("admin_user_detail", user_id=user_id))
    conn.close()

    delete_avatar(user["profile_picture"])
    for filename in report_files + claim_files:
        path = PRIVATE_UPLOAD_DIR / Path(filename).name
        if path.exists():
            path.unlink()
    flash(f"User {user['full_name'] or user['email']} was deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/reports")
def admin_reports():
    if (blocked := admin_required()):
        return blocked
    conditions = ["1=1"]
    values = []
    report_type = request.args.get("type")
    status = request.args.get("status")
    if report_type in ("LOST", "FOUND"):
        conditions.append("items.item_type=?")
        values.append(report_type)
    if status:
        conditions.append("items.status=?")
        values.append(status)
    conn = get_connection()
    reports = conn.execute("SELECT items.*,users.full_name,users.email FROM items JOIN users ON users.id=items.user_id WHERE " + " AND ".join(conditions) + " ORDER BY items.id DESC", values).fetchall()
    conn.close()
    return render_template("admin_reports.html", reports=reports)


@app.route("/admin/reports/<int:item_id>")
def admin_report_detail(item_id):
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    report_row = conn.execute("SELECT items.*,users.full_name,users.email,users.profile_picture FROM items JOIN users ON users.id=items.user_id WHERE items.id=?", (item_id,)).fetchone()
    mark_messages_read(conn, session["user_id"], item_id=item_id)
    messages = conn.execute("SELECT messages.*,users.full_name,users.email,users.profile_picture FROM messages JOIN users ON users.id=messages.sender_id WHERE messages.item_id=? AND messages.claim_id IS NULL ORDER BY messages.id", (item_id,)).fetchall()
    conn.commit()
    conn.close()
    if not report_row:
        abort(404)
    return render_template("admin_report_detail.html", report=report_row, messages=messages)


@app.route("/admin/claims")
def admin_claims():
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    claims = conn.execute(
        "SELECT claims.*,items.item_name,items.id AS report_id,users.full_name,users.email,users.profile_picture "
        "FROM claims JOIN items ON items.id=claims.item_id JOIN users ON users.id=claims.claimant_id ORDER BY claims.id DESC"
    ).fetchall()
    conn.close()
    return render_template("admin_claims.html", claims=claims)


@app.route("/admin/claims/<int:claim_id>")
def admin_claim_detail(claim_id):
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    claim_row = conn.execute(
        "SELECT claims.*,items.item_name,items.item_type,items.location,items.item_date,items.description,items.image_filename,users.full_name AS claimant_name,users.email AS claimant_email,users.profile_picture AS claimant_picture "
        "FROM claims JOIN items ON items.id=claims.item_id JOIN users ON users.id=claims.claimant_id WHERE claims.id=?",
        (claim_id,)
    ).fetchone()
    mark_messages_read(conn, session["user_id"], claim_id=claim_id)
    messages = conn.execute("SELECT messages.*,users.full_name,users.email,users.profile_picture FROM messages JOIN users ON users.id=messages.sender_id WHERE messages.claim_id=? ORDER BY messages.id", (claim_id,)).fetchall()
    conn.commit()
    conn.close()
    if not claim_row:
        abort(404)
    return render_template("admin_claim_detail.html", claim=claim_row, messages=messages)


@app.route("/admin/messages")
def admin_messages():
    if (blocked := admin_required()):
        return blocked
    conn = get_connection()
    mark_messages_read(conn, session["user_id"])
    rows = conn.execute(
        "SELECT messages.*, "
        "CASE WHEN messages.sender_id=? THEN recipient.full_name ELSE sender.full_name END AS full_name, "
        "CASE WHEN messages.sender_id=? THEN recipient.email ELSE sender.email END AS email, "
        "items.item_name "
        "FROM messages "
        "JOIN users AS sender ON sender.id=messages.sender_id "
        "JOIN users AS recipient ON recipient.id=messages.recipient_id "
        "LEFT JOIN items ON items.id=messages.item_id "
        "WHERE messages.sender_id=? OR messages.recipient_id=? "
        "ORDER BY messages.id DESC",
        (session["user_id"], session["user_id"], session["user_id"], session["user_id"]),
    ).fetchall()
    conversations = {}
    for message in rows:
        key = ("claim", message["claim_id"]) if message["claim_id"] else ("item", message["item_id"])
        if key not in conversations:
            unread_count = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient_id=? AND read_at IS NULL AND "
                + ("claim_id=?" if message["claim_id"] else "item_id=? AND claim_id IS NULL"),
                (session["user_id"], message["claim_id"] or message["item_id"]),
            ).fetchone()[0]
            conversation_data = dict(message)
            conversation_data["unread_count"] = unread_count
            conversations[key] = conversation_data
    conn.commit()
    conn.close()
    return render_template("admin_messages.html", conversations=list(conversations.values()), unread_messages=0)


@app.route("/admin/messages/<int:claim_id>")
def admin_message_detail(claim_id):
    if (blocked := admin_required()):
        return blocked
    return redirect(url_for("admin_claim_detail", claim_id=claim_id))


@app.post("/admin/report/<int:item_id>/<action>")
def admin_report_action(item_id, action):
    if (blocked := admin_required()):
        return blocked
    statuses = {"approve": "ACTIVE", "reject": "REJECTED", "request-info": "PENDING REVIEW", "resolve": "RESOLVED"}
    if action not in statuses:
        abort(404)
    conn = get_connection()
    row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not row:
        conn.close()
        abort(404)
    if action == "approve" and row["status"] == "ACTIVE":
        conn.close()
        flash(f"Report #{item_id} has already been approved.", "info")
        return redirect(url_for("admin_report_detail", item_id=item_id))
    notes = request.form.get("notes", "").strip()
    conn.execute("UPDATE items SET status=?,review_notes=?,updated_at=? WHERE id=?", (statuses[action], notes, now(), item_id))
    if notes:
        owner = conn.execute("SELECT user_id FROM items WHERE id=?", (item_id,)).fetchone()
        notify(conn, owner["user_id"], f"Administrator update for report #{item_id}: {notes}", "REPORT_UPDATE", None, item_id)
    log_action(conn, f"REPORT_{action.upper()}", f"Report #{item_id} marked {statuses[action]}.")
    update_matches(conn)
    owner_message = {
        "ACTIVE": "Surrendered Item Updated: Your report was approved and is now visible to the community.",
        "REJECTED": "Surrendered Item Updated: Your report was rejected by the Admin. Check Messages for more information.",
        "RESOLVED": "Item Status Changed: Your report has been marked returned/resolved.",
        "PENDING REVIEW": "Match Updated: Your report is under Admin review.",
    }.get(statuses[action])
    if owner_message:
        notify(conn, row["user_id"], owner_message, "REPORT_STATUS_UPDATED", None, item_id)
    if statuses[action] == "RESOLVED":
        linked_reports = resolve_linked_reports(conn, item_id, now())
        if linked_reports:
            notify(
                conn,
                row["user_id"],
                f"Report #{item_id} and its matched report are now resolved. The lost-and-found case is complete.",
                "REPORT_RESOLVED",
                None,
                item_id,
            )
    if statuses[action] == "ACTIVE" and row["status"] != "ACTIVE" and row["item_type"] == "FOUND":
        matches = conn.execute(
            "SELECT matches.lost_item_id,items.user_id AS owner_id,items.item_name "
            "FROM matches JOIN items ON items.id=matches.lost_item_id "
            "WHERE matches.found_item_id=?",
            (item_id,)
        ).fetchall()
        for match in matches:
            if match["owner_id"] == row["user_id"]:
                continue
            finder_message = (
                f"Update on Your Surrendered Item: {row['item_name']} has been reviewed by the Admin. "
                "Please check your Messages for more information."
            )
            owner_message = (
                f"Possible Match Found: A surrendered item may match the item you reported as lost "
                f"({match['item_name']}). Please check your Messages for more information."
            )
            notify(conn, row["user_id"], finder_message, "SURRENDERED_ITEM_REVIEWED", None, item_id)
            notify(conn, match["owner_id"], owner_message, "POSSIBLE_MATCH", None, item_id)
            conn.execute(
                "INSERT INTO messages(sender_id,recipient_id,item_id,body) VALUES(?,?,?,?)",
                (session["user_id"], row["user_id"], item_id, finder_message)
            )
            conn.execute(
                "INSERT INTO messages(sender_id,recipient_id,item_id,body) VALUES(?,?,?,?)",
                (session["user_id"], match["owner_id"], item_id, owner_message)
            )
    conn.commit()
    conn.close()
    flash(f"Report #{item_id} updated.", "success")
    return redirect(url_for("admin_report_detail", item_id=item_id))


@app.post("/admin/reports/<int:item_id>/message")
def admin_report_message(item_id):
    if (blocked := admin_required()):
        return blocked
    body = request.form.get("body", "").strip()
    conn = get_connection()
    report_row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not report_row:
        conn.close()
        abort(404)
    if not body:
        conn.close()
        flash("Please write a message.", "danger")
        return redirect(url_for("admin_report_detail", item_id=item_id))
    conn.execute("INSERT INTO messages(sender_id,recipient_id,item_id,body) VALUES(?,?,?,?)", (session["user_id"], report_row["user_id"], item_id, body))
    notify(conn, report_row["user_id"], "Administrator sent a message about your report.", "NEW_MESSAGE", None, item_id)
    log_action(conn, "MESSAGE_SENT", f"Administrator sent a message about report #{item_id}.")
    conn.commit()
    conn.close()
    flash("Message sent to the reporter.", "success")
    return redirect(url_for("admin_report_detail", item_id=item_id))


@app.post("/admin/claim/<int:claim_id>/<action>")
def admin_claim_action(claim_id, action):
    if (blocked := admin_required()):
        return blocked
    statuses = {"under-review": "UNDER REVIEW", "request-info": "REQUEST MORE INFORMATION", "approve": "APPROVED", "reject": "REJECTED", "resolve": "RESOLVED"}
    if action not in statuses:
        abort(404)
    conn = get_connection()
    claim_row = conn.execute("""
        SELECT claims.*, items.id AS report_id, items.item_name,
        items.item_type, items.location AS report_barangay, items.user_id AS finder_id,
        finder.full_name AS finder_name, claimant.full_name AS claimant_name
        FROM claims
        JOIN items ON items.id = claims.item_id
        JOIN users AS finder ON finder.id = items.user_id
        JOIN users AS claimant ON claimant.id = claims.claimant_id
        WHERE claims.id=?
    """, (claim_id,)).fetchone()
    if not claim_row:
        conn.close()
        abort(404)
    status = statuses[action]
    if action == "approve" and claim_row["status"] == "APPROVED":
        conn.close()
        flash(f"Claim {claim_code(claim_id)} has already been approved.", "info")
        return redirect(url_for("admin_claim_detail", claim_id=claim_id))
    if status == "RESOLVED" and claim_row["status"] != "APPROVED":
        conn.close()
        flash("Only an approved claim can be marked resolved after handover.", "danger")
        return redirect(url_for("admin_claim_detail", claim_id=claim_id))

    notes = request.form.get("notes", "").strip()
    release_barangay = request.form.get("release_barangay", "").strip()
    release_location = request.form.get("release_location", "").strip()
    release_instructions = request.form.get("release_instructions", "").strip()
    required_documents = request.form.get("required_documents", "").strip()
    coordination_contact = request.form.get("coordination_contact", "").strip()

    if release_barangay and release_barangay not in ALL_BARANGAYS:
        conn.close()
        flash("Please choose a valid Pasig City barangay.", "danger")
        return redirect(url_for("admin_claim_detail", claim_id=claim_id))

    try:
        with conn:
            timestamp = now()
            conn.execute(
                "UPDATE claims SET status=?,admin_notes=?,release_barangay=?,release_location=?,release_instructions=?,required_documents=?,coordination_contact=?,reviewed_at=?,updated_at=? WHERE id=?",
                (status, notes, release_barangay or claim_row["release_barangay"], release_location or claim_row["release_location"], release_instructions or claim_row["release_instructions"], required_documents or claim_row["required_documents"], coordination_contact or claim_row["coordination_contact"], timestamp, timestamp, claim_id)
            )
            if status == "RESOLVED":
                conn.execute("UPDATE items SET status='RESOLVED',updated_at=? WHERE id=?", (timestamp, claim_row["report_id"]))
                linked_reports = resolve_linked_reports(
                    conn,
                    claim_row["report_id"],
                    timestamp,
                    claim_id,
                    {claim_row["claimant_id"], claim_row["finder_id"]},
                )
                notify(
                    conn,
                    claim_row["claimant_id"],
                    f"Claim {claim_code(claim_id)} for {claim_row['item_name']} has been resolved. "
                    "The item was released to the rightful owner and the lost-and-found case is complete.",
                    "CLAIM_RESOLVED",
                    claim_id,
                    claim_row["report_id"],
                )
                if claim_row["finder_id"] != claim_row["claimant_id"]:
                    notify(
                        conn,
                        claim_row["finder_id"],
                        f"The item you reported as found, {claim_row['item_name']}, was successfully claimed by its rightful owner. "
                        f"Both reports are now resolved. Claim {claim_code(claim_id)} was completed on {timestamp}.",
                        "FINDER_CLAIM_RESOLVED",
                        claim_id,
                        claim_row["report_id"],
                    )
                if linked_reports:
                    lost_owner_ids = {
                        linked_item["user_id"]
                        for linked_item in linked_reports
                        if linked_item["user_id"] not in (claim_row["claimant_id"], claim_row["finder_id"])
                    }
                    for lost_owner_id in lost_owner_ids:
                        notify(
                            conn,
                            lost_owner_id,
                            f"The matched lost-and-found case for {claim_row['item_name']} is complete. "
                            "Both reports have been marked resolved.",
                            "REPORT_RESOLVED",
                            claim_id,
                            claim_row["report_id"],
                        )
            elif status == "APPROVED":
                release_area = release_location or claim_row["report_barangay"]
                claimant_message = f"Your claim request for {claim_row['item_name']} has been approved. Please claim the item at {release_area}, {release_barangay or claim_row['report_barangay']}. Bring {required_documents or 'your valid identification and proof of ownership'} and follow the administrator's instructions before visiting. Coordinate with {coordination_contact or 'the assigned administrator'} first."
                notify(conn, claim_row["claimant_id"], claimant_message, "CLAIM_APPROVED", claim_id, claim_row["report_id"])
                if claim_row["finder_id"] != claim_row["claimant_id"]:
                    notify(conn, claim_row["finder_id"], f"The item you reported as found, {claim_row['item_name']}, has been approved for claim after administrator review. It is now proceeding through the official release process. You do not need to approve the claimant.", "FINDER_CLAIM_APPROVED", claim_id, claim_row["report_id"])
                conn.execute("INSERT INTO messages(sender_id,recipient_id,item_id,claim_id,body) VALUES(?,?,?,?,?)", (session["user_id"], claim_row["claimant_id"], claim_row["report_id"], claim_id, notes or claimant_message))
            elif status == "REJECTED":
                notify(conn, claim_row["claimant_id"], f"Your claim request for {claim_row['item_name']} was rejected after administrator review. Please open the private conversation for details.", "CLAIM_REJECTED", claim_id, claim_row["report_id"])
            if notes and status not in ("APPROVED", "RESOLVED"):
                conn.execute("INSERT INTO messages(sender_id,recipient_id,item_id,claim_id,body) VALUES(?,?,?,?,?)", (session["user_id"], claim_row["claimant_id"], claim_row["report_id"], claim_id, notes))
            log_action(conn, f"CLAIM_{action.upper()}", f"Claim {claim_code(claim_id)} marked {status}.")
    finally:
        conn.close()

    flash(f"Claim {claim_code(claim_id)} updated.", "success")
    return redirect(url_for("claim_conversation", claim_id=claim_id))


@app.route("/admin/private/<path:filename>")
def private_file(filename):
    if (blocked := admin_required()):
        return blocked
    return send_from_directory(PRIVATE_UPLOAD_DIR, filename, as_attachment=True)


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You do not have permission to view or change that."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="That page or report was not found."), 404


@app.errorhandler(413)
def too_large(error):
    return render_template("error.html", code=413, message="That upload is too large. Please choose a file under 5 MB."), 413


@app.errorhandler(500)
def server_error(error):
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"SMART LOST & FOUND PORTAL - PASIG CITY: http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)