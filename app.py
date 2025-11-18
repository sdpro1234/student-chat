import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, ChatMessage
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
import google.generativeai as genai

load_dotenv()

# Config
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY") or "dev-secret-key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///student_chatbot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Fernet key
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
    print("Generated FERNET_KEY (save in .env):", FERNET_KEY)
fernet = Fernet(FERNET_KEY.encode())

GEMINI_MODEL_NAME = "gemini-2.5-flash-lite"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/")
def index():
    return render_template("index.html")


# ---------------- USER REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Login now.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- USER LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("student_chat"))

        flash("Invalid login", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


# ---------------- SET API KEY ----------------
@app.route("/set_api_key", methods=["GET", "POST"])
@login_required
def set_api_key():
    if request.method == "POST":
        api_key = request.form.get("api_key").strip()
        if not api_key:
            api_key = "AIzaSyAhX2YvC9SH-09BKsV3cK17H9-dJRGL1RU"
        encrypted = fernet.encrypt(api_key.encode()).decode()
        current_user.encrypted_api_key = encrypted
        db.session.commit()
        flash("API Key Saved!", "success")
        return redirect(url_for("student_chat"))

    decrypted = None
    if current_user.encrypted_api_key:
        try:
            decrypted = fernet.decrypt(current_user.encrypted_api_key.encode()).decode()
        except:
            decrypted = None

    return render_template("set_api_key.html", api_key=decrypted)


# ---------------- STUDENT CHAT PAGE ----------------
@app.route("/chat")
@login_required
def student_chat():
    if not current_user.encrypted_api_key:
        flash("Please set your API key first", "warning")
        return redirect(url_for("set_api_key"))

    return render_template("student_chat.html", username=current_user.username)


# ---------------- CHAT SEND MESSAGE ----------------
@app.route("/chat/send", methods=["POST"])
@login_required
def chat_send():
    try:
        if not request.is_json:
            print("Request is not JSON")
            return jsonify({"ok": False, "reply": "Request must be JSON"}), 400
        msg = request.json.get("message", "").strip()
        if not msg:
            print("Message is empty or missing")
            return jsonify({"ok": False, "reply": "Message is required"}), 400

        # save user msg
        db.session.add(ChatMessage(user_id=current_user.id, role="user", message=msg))
        db.session.commit()

        # decrypt api key
        try:
            api_key = fernet.decrypt(current_user.encrypted_api_key.encode()).decode()
            if not api_key or api_key == "" or api_key.lower().startswith("invalid"):
                raise Exception("API key missing or invalid")
        except Exception as e:
            print(f"API key decryption failed: {e}")
            # Set default valid API key
            api_key = "AIzaSyAhX2YvC9SH-09BKsV3cK17H9-dJRGL1RU"
            current_user.encrypted_api_key = fernet.encrypt(api_key.encode()).decode()
            db.session.commit()
            print("Default API key set for user.")


        # call gemini
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(GEMINI_MODEL_NAME)
            bot_res = model.generate_content(msg)
            reply = bot_res.text
            # Remove unwanted symbols and shorten response
            import re
            reply = re.sub(r'[\*#_\-]', '', reply)
            reply = ' '.join(reply.split())
            # Make response short and sweet (first 2 sentences)
            sentences = re.split(r'(?<=[.!?]) +', reply)
            reply = ' '.join(sentences[:2]).strip()
        except Exception as e:
            print(f"Gemini API error: {e}")
            reply = f"Gemini Error: {str(e)}"

        # save bot reply
        db.session.add(ChatMessage(user_id=current_user.id, role="bot", message=reply))
        db.session.commit()

        return jsonify({"ok": True, "reply": reply})
    except Exception as e:
        print(f"Unexpected error in chat_send: {e}")
        return jsonify({"ok": False, "reply": "Internal server error"}), 500


# -------------------------------------------------------
# ---------------- ADMIN LOGIN (FIXED LOGIN) ------------
# -------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials", "danger")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


# ---------------- ADMIN LOGOUT ----------------
@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))


# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    users = User.query.order_by(User.created_at.desc()).all()
    msgs = ChatMessage.query.order_by(ChatMessage.created_at.desc()).limit(200).all()

    return render_template("admin_dashboard.html", users=users, messages=msgs)


# ---------------- ADMIN USER VIEW ----------------
@app.route("/admin/user/<int:user_id>")
def admin_view_user(user_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    user = User.query.get_or_404(user_id)

    masked = None
    if user.encrypted_api_key:
        try:
            key = fernet.decrypt(user.encrypted_api_key.encode()).decode()
            masked = key[:4] + "..." + key[-4:]
        except:
            masked = "Invalid Encrypted Key"

    return render_template("admin_view_user.html", user=user, api_key_masked=masked)


# ---------------- ADMIN EXPORT CHAT ----------------
@app.route("/admin/export_chat/<int:user_id>")
def admin_export_chat(user_id):
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    msgs = ChatMessage.query.filter_by(user_id=user_id).order_by(ChatMessage.created_at).all()
    export = "\n".join(
        f"[{m.created_at}] {m.role.upper()}: {m.message}"
        for m in msgs
    )

    return app.response_class(export, mimetype="text/plain")


if __name__ == "__main__":
    app.run(debug=True)
