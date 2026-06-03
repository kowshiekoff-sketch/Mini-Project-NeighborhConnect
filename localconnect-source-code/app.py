from __future__ import annotations

import os
import random
import re
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

import stripe
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf import CSRFProtect
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    func,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = f"sqlite:///{BASE_DIR / 'instance' / 'localconnect.sqlite'}"

SERVICE_CATEGORIES = [
    "Electrician",
    "Plumber",
    "Carpenter",
    "AC Technician",
    "House Cleaner",
    "Painter",
    "Tutor",
    "Computer Repair",
    "Mobile Repair",
    "Home Appliance Service",
]

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(100), nullable=False),
    Column("email", String(150), nullable=False, unique=True),
    Column("password", String(255), nullable=False),
    Column("role", String(30), nullable=False),
    Column("phone", String(20)),
    Column("location", String(120)),
    Column("is_active", Boolean, default=True, nullable=False),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

service_providers = Table(
    "service_providers",
    metadata,
    Column("provider_id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("name", String(100), nullable=False),
    Column("service_type", String(80), nullable=False),
    Column("phone", String(20), nullable=False),
    Column("address", Text, nullable=False),
    Column("location", String(120), nullable=False),
    Column("rating", Float, default=0),
    Column("availability", String(40), default="Available"),
    Column("verified", Boolean, default=False, nullable=False),
    Column("price", Float, default=0),
    Column("bio", Text),
    Column("latitude", Float),
    Column("longitude", Float),
    Column("emergency_enabled", Boolean, default=False, nullable=False),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

bookings = Table(
    "bookings",
    metadata,
    Column("booking_id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("provider_id", Integer, ForeignKey("service_providers.provider_id"), nullable=False),
    Column("date", String(20), nullable=False),
    Column("time", String(20), nullable=False),
    Column("status", String(30), default="Pending"),
    Column("notes", Text),
    Column("emergency", Boolean, default=False, nullable=False),
    Column("amount", Float, default=0),
    Column("payment_status", String(30), default="Unpaid"),
    Column("payment_provider", String(40)),
    Column("payment_reference", String(180)),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

reviews = Table(
    "reviews",
    metadata,
    Column("review_id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("provider_id", Integer, ForeignKey("service_providers.provider_id"), nullable=False),
    Column("booking_id", Integer, ForeignKey("bookings.booking_id")),
    Column("rating", Integer, nullable=False),
    Column("comment", Text),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

notifications = Table(
    "notifications",
    metadata,
    Column("notification_id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("message", Text, nullable=False),
    Column("is_read", Boolean, default=False, nullable=False),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

messages = Table(
    "messages",
    metadata,
    Column("message_id", Integer, primary_key=True, autoincrement=True),
    Column("booking_id", Integer, ForeignKey("bookings.booking_id"), nullable=False),
    Column("sender_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("body", Text, nullable=False),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

reports = Table(
    "reports",
    metadata,
    Column("report_id", Integer, primary_key=True, autoincrement=True),
    Column("provider_id", Integer, ForeignKey("service_providers.provider_id"), nullable=False),
    Column("user_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("reason", Text, nullable=False),
    Column("status", String(30), default="Open"),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

password_reset_otps = Table(
    "password_reset_otps",
    metadata,
    Column("otp_id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("otp_hash", String(255), nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("used_at", DateTime),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)

admin_audit_logs = Table(
    "admin_audit_logs",
    metadata,
    Column("audit_id", Integer, primary_key=True, autoincrement=True),
    Column("admin_id", Integer, ForeignKey("users.user_id"), nullable=False),
    Column("action", String(80), nullable=False),
    Column("target_type", String(80), nullable=False),
    Column("target_id", Integer, nullable=False),
    Column("details", Text),
    Column("created_at", DateTime, default=func.now(), nullable=False),
)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "localconnect-dev-key-change-me"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", DEFAULT_DB),
        WTF_CSRF_TIME_LIMIT=3600,
        STRIPE_SECRET_KEY=os.environ.get("STRIPE_SECRET_KEY", ""),
        STRIPE_CURRENCY=os.environ.get("STRIPE_CURRENCY", "inr"),
        ALLOW_DEMO_PAYMENTS=os.environ.get("ALLOW_DEMO_PAYMENTS", "true").lower() == "true",
        ADMIN_REGISTRATION_KEY=os.environ.get("ADMIN_REGISTRATION_KEY", ""),
        MAIL_HOST=os.environ.get("MAIL_HOST", ""),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME", ""),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD", ""),
        MAIL_FROM=os.environ.get("MAIL_FROM", "noreply@localconnect.test"),
    )
    if str(app.config["SQLALCHEMY_DATABASE_URI"]).startswith("sqlite:///"):
        Path(str(app.config["SQLALCHEMY_DATABASE_URI"]).replace("sqlite:///", "")).parent.mkdir(exist_ok=True)
    app.engine = create_engine(app.config["SQLALCHEMY_DATABASE_URI"], future=True)
    stripe.api_key = app.config["STRIPE_SECRET_KEY"]
    CSRFProtect(app)

    with app.app_context():
        init_db(app.engine)

    @app.before_request
    def load_user() -> None:
        g.user = None
        user_id = session.get("user_id")
        if user_id:
            g.user = query_one("SELECT * FROM users WHERE user_id = :user_id", {"user_id": user_id})

    @app.context_processor
    def inject_globals() -> dict:
        unread = 0
        if g.get("user"):
            unread = query_one(
                "SELECT COUNT(*) AS total FROM notifications WHERE user_id = :user_id AND is_read = false",
                {"user_id": g.user["user_id"]},
            )["total"]
        return {"categories": SERVICE_CATEGORIES, "unread_notifications": unread}

    @app.route("/")
    def index():
        featured = query_all(
            """
            SELECT p.*, COUNT(r.review_id) AS review_count
            FROM service_providers p
            LEFT JOIN reviews r ON r.provider_id = p.provider_id
            WHERE p.verified = true
            GROUP BY p.provider_id
            ORDER BY p.rating DESC, review_count DESC
            LIMIT 6
            """
        )
        stats = {
            "providers": query_one("SELECT COUNT(*) AS total FROM service_providers WHERE verified = true")["total"],
            "bookings": query_one("SELECT COUNT(*) AS total FROM bookings")["total"],
            "reviews": query_one("SELECT COUNT(*) AS total FROM reviews")["total"],
        }
        return render_template("index.html", featured=featured, stats=stats)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            form = clean_form(request.form)
            role = form.get("role", "customer")
            errors = validate_registration(form, role)
            if errors:
                for error in errors:
                    flash(error, "danger")
                return render_template("auth/register.html", form=form)

            email = form["email"].lower()
            admin_key = form.get("admin_key", "")
            if role == "admin" and admin_key != app.config["ADMIN_REGISTRATION_KEY"]:
                flash("Invalid admin registration key.", "danger")
                return render_template("auth/register.html", form=form)

            try:
                user_id = execute_insert(
                    users,
                    {
                        "name": form["name"],
                        "email": email,
                        "password": generate_password_hash(form["password"]),
                        "role": role,
                        "phone": form.get("phone", ""),
                        "location": form.get("location", ""),
                        "is_active": True,
                    },
                )
            except IntegrityError:
                flash("Email already registered. Please log in.", "warning")
                return redirect(url_for("login"))

            if role == "provider":
                execute_insert(
                    service_providers,
                    {
                        "user_id": user_id,
                        "name": form["name"],
                        "service_type": form.get("service_type", "Electrician"),
                        "phone": form.get("phone", ""),
                        "address": form.get("location", ""),
                        "location": form.get("location", ""),
                        "availability": "Available",
                        "verified": False,
                        "price": 499,
                        "bio": "New provider profile awaiting admin approval.",
                        "latitude": 12.9716,
                        "longitude": 77.5946,
                        "emergency_enabled": False,
                    },
                )
                notify_admins(f"Provider approval needed: {form['name']}")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        return render_template("auth/register.html", form={})

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = query_one(
                "SELECT * FROM users WHERE email = :email AND is_active = true",
                {"email": email},
            )
            if user and check_password_hash(user["password"], password):
                session.clear()
                session["user_id"] = user["user_id"]
                session.permanent = True
                flash(f"Welcome back, {user['name']}!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid email or password.", "danger")
        return render_template("auth/login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("index"))

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        dev_code = None
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            otp = request.form.get("otp", "").strip()
            new_password = request.form.get("new_password", "")
            user = query_one("SELECT * FROM users WHERE email = :email", {"email": email})
            if not user:
                flash("If the email exists, password reset instructions were sent.", "success")
                return render_template("auth/reset.html")

            if otp and new_password:
                if not validate_password(new_password):
                    flash("New password must be at least 8 characters and include letters and numbers.", "danger")
                    return render_template("auth/reset.html", email=email)
                valid_otp = query_one(
                    """
                    SELECT * FROM password_reset_otps
                    WHERE user_id = :user_id AND used_at IS NULL AND expires_at > :now
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    {"user_id": user["user_id"], "now": utcnow()},
                )
                if valid_otp and check_password_hash(valid_otp["otp_hash"], otp):
                    execute_sql(
                        "UPDATE users SET password = :password WHERE user_id = :user_id",
                        {"password": generate_password_hash(new_password), "user_id": user["user_id"]},
                    )
                    execute_sql(
                        "UPDATE password_reset_otps SET used_at = :used_at WHERE otp_id = :otp_id",
                        {"used_at": utcnow(), "otp_id": valid_otp["otp_id"]},
                    )
                    add_notification(user["user_id"], "Your password was reset successfully.")
                    flash("Password reset successful. Please log in.", "success")
                    return redirect(url_for("login"))
                flash("Invalid or expired OTP.", "danger")
                return render_template("auth/reset.html", email=email)

            code = f"{random.SystemRandom().randint(100000, 999999)}"
            execute_insert(
                password_reset_otps,
                {
                    "user_id": user["user_id"],
                    "otp_hash": generate_password_hash(code),
                    "expires_at": utcnow() + timedelta(minutes=10),
                },
            )
            sent = send_email(
                user["email"],
                "LocalConnect password reset OTP",
                f"Your LocalConnect password reset OTP is {code}. It expires in 10 minutes.",
            )
            if not sent:
                dev_code = code
            add_notification(user["user_id"], "A password reset OTP was generated.")
            flash("If the email exists, password reset instructions were sent.", "success")
        return render_template("auth/reset.html", demo_code=dev_code)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        if g.user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        if g.user["role"] == "provider":
            provider = provider_for_user(g.user["user_id"])
            bookings_for_provider = query_all(
                """
                SELECT b.*, u.name AS customer_name, u.phone AS customer_phone
                FROM bookings b
                JOIN users u ON u.user_id = b.user_id
                WHERE b.provider_id = :provider_id
                ORDER BY b.date DESC, b.time DESC
                """,
                {"provider_id": provider["provider_id"]},
            )
            provider_reviews = query_all(
                """
                SELECT r.*, u.name AS customer_name
                FROM reviews r JOIN users u ON u.user_id = r.user_id
                WHERE r.provider_id = :provider_id
                ORDER BY r.created_at DESC
                """,
                {"provider_id": provider["provider_id"]},
            )
            return render_template("dashboards/provider.html", provider=provider, bookings=bookings_for_provider, reviews=provider_reviews)

        customer_bookings = query_all(
            """
            SELECT b.*, p.name AS provider_name, p.service_type, p.phone AS provider_phone
            FROM bookings b
            JOIN service_providers p ON p.provider_id = b.provider_id
            WHERE b.user_id = :user_id
            ORDER BY b.date DESC, b.time DESC
            """,
            {"user_id": g.user["user_id"]},
        )
        recommendations = recommended_providers(g.user["user_id"])
        return render_template("dashboards/customer.html", bookings=customer_bookings, recommendations=recommendations)

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        provider = provider_for_user(g.user["user_id"]) if g.user["role"] == "provider" else None
        if request.method == "POST":
            form = clean_form(request.form)
            errors = validate_profile(form, provider is not None)
            if errors:
                for error in errors:
                    flash(error, "danger")
                return render_template("profile.html", provider=provider)

            execute_sql(
                "UPDATE users SET name = :name, phone = :phone, location = :location WHERE user_id = :user_id",
                {
                    "name": form["name"],
                    "phone": form.get("phone", ""),
                    "location": form.get("location", ""),
                    "user_id": g.user["user_id"],
                },
            )
            if provider:
                execute_sql(
                    """
                    UPDATE service_providers
                    SET name = :name, service_type = :service_type, phone = :phone, address = :address,
                        location = :location, availability = :availability, price = :price, bio = :bio,
                        latitude = :latitude, longitude = :longitude, emergency_enabled = :emergency_enabled
                    WHERE provider_id = :provider_id
                    """,
                    {
                        "name": form["name"],
                        "service_type": form["service_type"],
                        "phone": form["phone"],
                        "address": form["address"],
                        "location": form["location"],
                        "availability": form["availability"],
                        "price": float(form["price"]),
                        "bio": form["bio"],
                        "latitude": float(form.get("latitude") or 12.9716),
                        "longitude": float(form.get("longitude") or 77.5946),
                        "emergency_enabled": bool(request.form.get("emergency_enabled")),
                        "provider_id": provider["provider_id"],
                    },
                )
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
        return render_template("profile.html", provider=provider)

    @app.route("/providers")
    def providers():
        filters = {
            "service_type": request.args.get("service_type", ""),
            "location": request.args.get("location", "").strip(),
            "min_rating": request.args.get("min_rating", ""),
            "availability": request.args.get("availability", ""),
            "emergency": request.args.get("emergency", ""),
        }
        where = ["verified = true"]
        params = {}
        if filters["service_type"] in SERVICE_CATEGORIES:
            where.append("service_type = :service_type")
            params["service_type"] = filters["service_type"]
        if filters["location"]:
            where.append("(location LIKE :location OR address LIKE :location)")
            params["location"] = f"%{filters['location'][:80]}%"
        if filters["min_rating"]:
            where.append("rating >= :min_rating")
            params["min_rating"] = safe_float(filters["min_rating"], 0)
        if filters["availability"] in {"Available", "Busy"}:
            where.append("availability = :availability")
            params["availability"] = filters["availability"]
        if filters["emergency"]:
            where.append("emergency_enabled = true")

        provider_items = query_all(
            f"""
            SELECT p.*, COUNT(r.review_id) AS review_count
            FROM service_providers p
            LEFT JOIN reviews r ON r.provider_id = p.provider_id
            WHERE {' AND '.join(where)}
            GROUP BY p.provider_id
            ORDER BY p.rating DESC, p.availability ASC
            """,
            params,
        )
        return render_template("providers/list.html", providers=provider_items, filters=filters)

    @app.route("/providers/<int:provider_id>")
    def provider_detail(provider_id: int):
        provider = query_one("SELECT * FROM service_providers WHERE provider_id = :provider_id", {"provider_id": provider_id})
        if not provider:
            abort(404)
        provider_reviews = query_all(
            """
            SELECT r.*, u.name AS customer_name
            FROM reviews r JOIN users u ON u.user_id = r.user_id
            WHERE r.provider_id = :provider_id
            ORDER BY r.created_at DESC
            """,
            {"provider_id": provider_id},
        )
        return render_template("providers/detail.html", provider=provider, reviews=provider_reviews)

    @app.route("/book/<int:provider_id>", methods=["GET", "POST"])
    @role_required("customer")
    def book(provider_id: int):
        provider = query_one(
            "SELECT * FROM service_providers WHERE provider_id = :provider_id AND verified = true",
            {"provider_id": provider_id},
        )
        if not provider:
            abort(404)
        if request.method == "POST":
            form = clean_form(request.form)
            errors = validate_booking(form, provider)
            if errors:
                for error in errors:
                    flash(error, "danger")
                return render_template("bookings/book.html", provider=provider)

            emergency = bool(request.form.get("emergency"))
            booking_id = execute_insert(
                bookings,
                {
                    "user_id": g.user["user_id"],
                    "provider_id": provider_id,
                    "date": form["date"],
                    "time": form["time"],
                    "status": "Pending",
                    "notes": form.get("notes", ""),
                    "emergency": emergency,
                    "amount": provider["price"],
                    "payment_status": "Unpaid",
                },
            )
            add_notification(g.user["user_id"], f"Booking #{booking_id} requested with {provider['name']}.")
            add_notification(provider["user_id"], f"New booking request #{booking_id} from {g.user['name']}.")
            flash("Booking request sent. You can complete payment from your dashboard.", "success")
            return redirect(url_for("payment", booking_id=booking_id))
        return render_template("bookings/book.html", provider=provider)

    @app.route("/booking/<int:booking_id>/status", methods=["POST"])
    @role_required("provider")
    def update_booking_status(booking_id: int):
        provider = provider_for_user(g.user["user_id"])
        booking = query_one(
            "SELECT * FROM bookings WHERE booking_id = :booking_id AND provider_id = :provider_id",
            {"booking_id": booking_id, "provider_id": provider["provider_id"]},
        )
        if not booking:
            abort(404)
        status = request.form.get("status", "")
        if status not in {"Accepted", "Rejected", "Completed"}:
            abort(400)
        execute_sql("UPDATE bookings SET status = :status WHERE booking_id = :booking_id", {"status": status, "booking_id": booking_id})
        add_notification(booking["user_id"], f"Booking #{booking_id} status updated to {status}.")
        flash("Booking status updated.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/booking/<int:booking_id>/payment", methods=["GET", "POST"])
    @login_required
    def payment(booking_id: int):
        booking = booking_for_current_user(booking_id)
        if request.method == "POST":
            if request.form.get("provider") == "stripe" and app.config["STRIPE_SECRET_KEY"]:
                checkout = stripe.checkout.Session.create(
                    mode="payment",
                    payment_method_types=["card"],
                    line_items=[
                        {
                            "quantity": 1,
                            "price_data": {
                                "currency": app.config["STRIPE_CURRENCY"],
                                "unit_amount": int(float(booking["amount"]) * 100),
                                "product_data": {"name": f"LocalConnect booking #{booking_id} - {booking['provider_name']}"},
                            },
                        }
                    ],
                    metadata={"booking_id": str(booking_id)},
                    success_url=url_for("payment_success", booking_id=booking_id, _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
                    cancel_url=url_for("payment", booking_id=booking_id, _external=True),
                )
                execute_sql(
                    "UPDATE bookings SET payment_provider = 'stripe', payment_reference = :reference WHERE booking_id = :booking_id",
                    {"reference": checkout.id, "booking_id": booking_id},
                )
                return redirect(checkout.url, code=303)

            if not app.config["ALLOW_DEMO_PAYMENTS"]:
                flash("Demo payments are disabled. Configure STRIPE_SECRET_KEY to accept online payments.", "warning")
                return redirect(url_for("payment", booking_id=booking_id))
            mark_booking_paid(booking, "demo", f"demo-{secrets.token_hex(8)}")
            flash("Payment marked as paid for demo purposes.", "success")
            return redirect(url_for("dashboard"))
        return render_template(
            "bookings/payment.html",
            booking=booking,
            stripe_enabled=bool(app.config["STRIPE_SECRET_KEY"]),
            demo_payments_enabled=app.config["ALLOW_DEMO_PAYMENTS"],
        )

    @app.route("/booking/<int:booking_id>/payment/success")
    @login_required
    def payment_success(booking_id: int):
        booking = booking_for_current_user(booking_id)
        session_id = request.args.get("session_id", "")
        if not app.config["STRIPE_SECRET_KEY"] or not session_id:
            abort(400)
        checkout = stripe.checkout.Session.retrieve(session_id)
        if checkout.payment_status == "paid" and checkout.metadata.get("booking_id") == str(booking_id):
            mark_booking_paid(booking, "stripe", session_id)
            flash("Payment successful.", "success")
        else:
            flash("Payment was not completed.", "warning")
        return redirect(url_for("dashboard"))

    @app.route("/booking/<int:booking_id>/review", methods=["GET", "POST"])
    @role_required("customer")
    def review(booking_id: int):
        booking = query_one(
            """
            SELECT b.*, p.name AS provider_name, p.provider_id
            FROM bookings b JOIN service_providers p ON p.provider_id = b.provider_id
            WHERE b.booking_id = :booking_id AND b.user_id = :user_id
            """,
            {"booking_id": booking_id, "user_id": g.user["user_id"]},
        )
        if not booking or booking["status"] != "Completed":
            abort(404)
        existing = query_one("SELECT * FROM reviews WHERE booking_id = :booking_id", {"booking_id": booking_id})
        if request.method == "POST":
            rating = int(request.form.get("rating", "0"))
            comment = request.form.get("comment", "").strip()
            if rating < 1 or rating > 5 or len(comment) < 5:
                flash("Please provide a 1-5 rating and a useful comment.", "danger")
                return render_template("bookings/review.html", booking=booking, existing=existing)
            if existing:
                execute_sql(
                    "UPDATE reviews SET rating = :rating, comment = :comment WHERE review_id = :review_id",
                    {"rating": rating, "comment": comment[:1000], "review_id": existing["review_id"]},
                )
            else:
                execute_insert(
                    reviews,
                    {
                        "user_id": g.user["user_id"],
                        "provider_id": booking["provider_id"],
                        "booking_id": booking_id,
                        "rating": rating,
                        "comment": comment[:1000],
                    },
                )
            refresh_provider_rating(booking["provider_id"])
            flash("Review saved. Thank you for the feedback.", "success")
            return redirect(url_for("dashboard"))
        return render_template("bookings/review.html", booking=booking, existing=existing)

    @app.route("/booking/<int:booking_id>/chat", methods=["GET", "POST"])
    @login_required
    def chat(booking_id: int):
        booking = booking_for_current_user(booking_id)
        if request.method == "POST":
            body = request.form.get("body", "").strip()
            if 1 <= len(body) <= 1000:
                execute_insert(messages, {"booking_id": booking_id, "sender_id": g.user["user_id"], "body": body})
                other_user = booking["provider_user_id"] if g.user["role"] == "customer" else booking["user_id"]
                add_notification(other_user, f"New chat message on booking #{booking_id}.")
            return redirect(url_for("chat", booking_id=booking_id))
        chat_messages = query_all(
            """
            SELECT m.*, u.name AS sender_name
            FROM messages m JOIN users u ON u.user_id = m.sender_id
            WHERE m.booking_id = :booking_id
            ORDER BY m.created_at
            """,
            {"booking_id": booking_id},
        )
        return render_template("bookings/chat.html", booking=booking, messages=chat_messages)

    @app.route("/notifications", endpoint="notifications")
    @login_required
    def notifications_view():
        items = query_all(
            "SELECT * FROM notifications WHERE user_id = :user_id ORDER BY created_at DESC",
            {"user_id": g.user["user_id"]},
        )
        execute_sql("UPDATE notifications SET is_read = true WHERE user_id = :user_id", {"user_id": g.user["user_id"]})
        return render_template("notifications.html", notifications=items)

    @app.route("/report/<int:provider_id>", methods=["POST"])
    @role_required("customer")
    def report_provider(provider_id: int):
        reason = request.form.get("reason", "").strip()
        if len(reason) < 10:
            flash("Please include a clear reason for reporting the listing.", "danger")
            return redirect(url_for("provider_detail", provider_id=provider_id))
        execute_insert(reports, {"provider_id": provider_id, "user_id": g.user["user_id"], "reason": reason[:1000]})
        notify_admins(f"New fake listing report for provider #{provider_id}.")
        flash("Report submitted for admin review.", "success")
        return redirect(url_for("provider_detail", provider_id=provider_id))

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        pending = query_all("SELECT * FROM service_providers WHERE verified = false ORDER BY created_at DESC")
        all_users = query_all("SELECT user_id, name, email, role, location, is_active FROM users ORDER BY created_at DESC")
        report_rows = query_all(
            """
            SELECT r.*, p.name AS provider_name, u.name AS reporter_name
            FROM reports r
            JOIN service_providers p ON p.provider_id = r.provider_id
            JOIN users u ON u.user_id = r.user_id
            ORDER BY r.created_at DESC
            """
        )
        audits = query_all(
            """
            SELECT a.*, u.name AS admin_name
            FROM admin_audit_logs a JOIN users u ON u.user_id = a.admin_id
            ORDER BY a.created_at DESC
            LIMIT 10
            """
        )
        metrics = {
            "users": query_one("SELECT COUNT(*) AS total FROM users")["total"],
            "providers": query_one("SELECT COUNT(*) AS total FROM service_providers")["total"],
            "pending": len(pending),
            "bookings": query_one("SELECT COUNT(*) AS total FROM bookings")["total"],
        }
        return render_template("dashboards/admin.html", pending=pending, users=all_users, reports=report_rows, metrics=metrics, audits=audits)

    @app.route("/admin/provider/<int:provider_id>/<action>", methods=["POST"])
    @admin_required
    def admin_provider_action(provider_id: int, action: str):
        provider = query_one("SELECT * FROM service_providers WHERE provider_id = :provider_id", {"provider_id": provider_id})
        if not provider:
            abort(404)
        if provider["user_id"] == g.user["user_id"]:
            abort(403)
        if action == "approve":
            execute_sql("UPDATE service_providers SET verified = true WHERE provider_id = :provider_id", {"provider_id": provider_id})
            add_notification(provider["user_id"], "Your provider profile has been approved.")
            log_admin_action("approve_provider", "provider", provider_id, provider["name"])
            flash("Provider approved.", "success")
        elif action == "remove":
            execute_sql("UPDATE users SET is_active = false WHERE user_id = :user_id", {"user_id": provider["user_id"]})
            execute_sql("UPDATE service_providers SET verified = false WHERE provider_id = :provider_id", {"provider_id": provider_id})
            log_admin_action("remove_provider", "provider", provider_id, provider["name"])
            flash("Listing removed and linked user deactivated.", "warning")
        else:
            abort(400)
        return redirect(url_for("admin_dashboard"))

    @app.cli.command("init-db")
    def init_db_command():
        init_db(app.engine)
        print("Initialized LocalConnect database.")

    return app


def get_engine() -> Engine:
    return current_app_engine()


def current_app_engine() -> Engine:
    from flask import current_app

    return current_app.engine


def query_one(sql: str, params: dict | None = None):
    with get_engine().begin() as conn:
        return conn.execute(text(sql), params or {}).mappings().first()


def query_all(sql: str, params: dict | None = None):
    with get_engine().begin() as conn:
        return conn.execute(text(sql), params or {}).mappings().all()


def execute_sql(sql: str, params: dict | None = None) -> None:
    with get_engine().begin() as conn:
        conn.execute(text(sql), params or {})


def execute_insert(table: Table, values: dict) -> int:
    with get_engine().begin() as conn:
        result = conn.execute(table.insert().values(**values))
        pk = result.inserted_primary_key
        return int(pk[0]) if pk else 0


def init_db(engine: Engine) -> None:
    metadata.create_all(engine)
    seed_data(engine)


def seed_data(engine: Engine) -> None:
    with engine.begin() as conn:
        if conn.execute(select(func.count()).select_from(users)).scalar_one() > 0:
            return
        seed_users = [
            ("Admin User", "admin@localconnect.test", "admin123", "admin", "9000000000", "Central"),
            ("Meera Customer", "customer@localconnect.test", "customer123", "customer", "9000000001", "Indiranagar"),
            ("Ravi Electric Works", "provider@localconnect.test", "provider123", "provider", "9000000002", "Indiranagar"),
            ("Asha Plumbing Care", "asha@localconnect.test", "provider123", "provider", "9000000003", "Koramangala"),
            ("CleanNest Team", "clean@localconnect.test", "provider123", "provider", "9000000004", "Whitefield"),
            ("Bright Tutors", "tutor@localconnect.test", "provider123", "provider", "9000000005", "Jayanagar"),
        ]
        ids = {}
        for name, email, password, role, phone, location in seed_users:
            result = conn.execute(
                users.insert().values(
                    name=name,
                    email=email,
                    password=generate_password_hash(password),
                    role=role,
                    phone=phone,
                    location=location,
                    is_active=True,
                )
            )
            ids[email] = result.inserted_primary_key[0]

        seed_providers = [
            (ids["provider@localconnect.test"], "Ravi Electric Works", "Electrician", "9000000002", "12 CMH Road, Indiranagar", "Indiranagar", 4.8, "Available", True, 650, "Certified electrician for wiring, switchboards, inverter setup, and urgent power faults.", 12.9784, 77.6408, True),
            (ids["asha@localconnect.test"], "Asha Plumbing Care", "Plumber", "9000000003", "5th Block, Koramangala", "Koramangala", 4.6, "Available", True, 550, "Leak repair, bathroom fittings, water heater lines, and scheduled maintenance.", 12.9352, 77.6245, True),
            (ids["clean@localconnect.test"], "CleanNest Team", "House Cleaner", "9000000004", "Hope Farm Junction, Whitefield", "Whitefield", 4.4, "Busy", True, 900, "Deep cleaning, kitchen cleaning, moving-in cleaning, and recurring home care.", 12.9698, 77.7499, False),
            (ids["tutor@localconnect.test"], "Bright Tutors", "Tutor", "9000000005", "4th T Block, Jayanagar", "Jayanagar", 4.9, "Available", True, 700, "Math, science, and computer basics tutoring for school students.", 12.9250, 77.5938, False),
        ]
        provider_ids = []
        for row in seed_providers:
            result = conn.execute(
                service_providers.insert().values(
                    user_id=row[0],
                    name=row[1],
                    service_type=row[2],
                    phone=row[3],
                    address=row[4],
                    location=row[5],
                    rating=row[6],
                    availability=row[7],
                    verified=row[8],
                    price=row[9],
                    bio=row[10],
                    latitude=row[11],
                    longitude=row[12],
                    emergency_enabled=row[13],
                )
            )
            provider_ids.append(result.inserted_primary_key[0])

        booking_result = conn.execute(
            bookings.insert().values(
                user_id=ids["customer@localconnect.test"],
                provider_id=provider_ids[0],
                date="2026-06-05",
                time="10:30",
                status="Completed",
                notes="Fan replacement and switchboard check",
                emergency=False,
                amount=650,
                payment_status="Paid",
                payment_provider="demo",
                payment_reference="seed-demo",
            )
        )
        booking_id = booking_result.inserted_primary_key[0]
        conn.execute(
            reviews.insert().values(
                user_id=ids["customer@localconnect.test"],
                provider_id=provider_ids[0],
                booking_id=booking_id,
                rating=5,
                comment="Quick response and clean work. Very trustworthy.",
            )
        )
        conn.execute(messages.insert().values(booking_id=booking_id, sender_id=ids["customer@localconnect.test"], body="Please bring a replacement regulator if needed."))
        conn.execute(messages.insert().values(booking_id=booking_id, sender_id=ids["provider@localconnect.test"], body="Sure, I will carry one and confirm before installing."))
        conn.execute(notifications.insert().values(user_id=ids["customer@localconnect.test"], message="Your last booking was completed. Please rate the provider."))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(role: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            if g.user["role"] != role:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        if g.user["role"] != "admin" or not g.user["is_active"]:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def provider_for_user(user_id: int):
    provider = query_one("SELECT * FROM service_providers WHERE user_id = :user_id", {"user_id": user_id})
    if not provider:
        abort(404)
    return provider


def booking_for_current_user(booking_id: int):
    booking = query_one(
        """
        SELECT b.*, p.name AS provider_name, p.provider_id, p.service_type, p.user_id AS provider_user_id,
               u.name AS customer_name
        FROM bookings b
        JOIN service_providers p ON p.provider_id = b.provider_id
        JOIN users u ON u.user_id = b.user_id
        WHERE b.booking_id = :booking_id
        """,
        {"booking_id": booking_id},
    )
    if not booking:
        abort(404)
    if g.user["role"] == "admin":
        return booking
    if g.user["role"] == "customer" and booking["user_id"] == g.user["user_id"]:
        return booking
    if g.user["role"] == "provider" and booking["provider_user_id"] == g.user["user_id"]:
        return booking
    abort(403)


def add_notification(user_id: int, message: str) -> None:
    execute_insert(notifications, {"user_id": user_id, "message": message, "is_read": False})


def notify_admins(message: str) -> None:
    for admin in query_all("SELECT user_id FROM users WHERE role = 'admin' AND is_active = true"):
        add_notification(admin["user_id"], message)


def log_admin_action(action: str, target_type: str, target_id: int, details: str) -> None:
    execute_insert(
        admin_audit_logs,
        {
            "admin_id": g.user["user_id"],
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
        },
    )


def refresh_provider_rating(provider_id: int) -> None:
    avg = query_one("SELECT AVG(rating) AS rating FROM reviews WHERE provider_id = :provider_id", {"provider_id": provider_id})["rating"] or 0
    execute_sql("UPDATE service_providers SET rating = :rating WHERE provider_id = :provider_id", {"rating": round(avg, 1), "provider_id": provider_id})


def recommended_providers(user_id: int):
    history = query_all(
        """
        SELECT p.service_type, p.location
        FROM bookings b JOIN service_providers p ON p.provider_id = b.provider_id
        WHERE b.user_id = :user_id
        """,
        {"user_id": user_id},
    )
    liked_services = {row["service_type"] for row in history}
    liked_locations = {row["location"] for row in history}
    provider_rows = query_all("SELECT * FROM service_providers WHERE verified = true ORDER BY rating DESC")

    scored = []
    for provider in provider_rows:
        score = provider["rating"] * 10
        if provider["service_type"] in liked_services:
            score += 12
        if provider["location"] in liked_locations:
            score += 8
        if provider["availability"] == "Available":
            score += 5
        if provider["emergency_enabled"]:
            score += 3
        scored.append((score, provider))
    return [provider for _, provider in sorted(scored, key=lambda item: item[0], reverse=True)[:4]]


def mark_booking_paid(booking, provider: str, reference: str) -> None:
    execute_sql(
        """
        UPDATE bookings
        SET payment_status = 'Paid', payment_provider = :provider, payment_reference = :reference
        WHERE booking_id = :booking_id
        """,
        {"provider": provider, "reference": reference, "booking_id": booking["booking_id"]},
    )
    add_notification(booking["user_id"], f"Payment received for booking #{booking['booking_id']}.")
    add_notification(booking["provider_user_id"], f"Payment marked paid for booking #{booking['booking_id']}.")


def send_email(to_email: str, subject: str, body: str) -> bool:
    from flask import current_app

    if not current_app.config["MAIL_HOST"]:
        return False
    msg = EmailMessage()
    msg["From"] = current_app.config["MAIL_FROM"]
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(current_app.config["MAIL_HOST"], current_app.config["MAIL_PORT"], timeout=10) as smtp:
            smtp.starttls()
            if current_app.config["MAIL_USERNAME"]:
                smtp.login(current_app.config["MAIL_USERNAME"], current_app.config["MAIL_PASSWORD"])
            smtp.send_message(msg)
        return True
    except OSError:
        return False


def clean_form(form) -> dict:
    return {key: value.strip() if isinstance(value, str) else value for key, value in form.items()}


def validate_registration(form: dict, role: str) -> list[str]:
    errors = []
    if role not in {"customer", "provider", "admin"}:
        errors.append("Invalid role selected.")
    if len(form.get("name", "")) < 2:
        errors.append("Name is required.")
    if not validate_email(form.get("email", "")):
        errors.append("Valid email is required.")
    if not validate_password(form.get("password", "")):
        errors.append("Password must be at least 8 characters and include letters and numbers.")
    if role == "provider":
        if form.get("service_type") not in SERVICE_CATEGORIES:
            errors.append("Choose a valid service category.")
        if len(form.get("phone", "")) < 8:
            errors.append("Provider phone number is required.")
    return errors


def validate_profile(form: dict, is_provider: bool) -> list[str]:
    errors = []
    if len(form.get("name", "")) < 2:
        errors.append("Name is required.")
    if is_provider:
        if form.get("service_type") not in SERVICE_CATEGORIES:
            errors.append("Choose a valid service category.")
        if form.get("availability") not in {"Available", "Busy"}:
            errors.append("Choose a valid availability.")
        if safe_float(form.get("price"), -1) < 0:
            errors.append("Price must be zero or more.")
        if len(form.get("address", "")) < 5:
            errors.append("Provider address is required.")
    return errors


def validate_booking(form: dict, provider) -> list[str]:
    errors = []
    date_text = form.get("date", "")
    time_text = form.get("time", "")
    try:
        datetime.strptime(date_text, "%Y-%m-%d")
        datetime.strptime(time_text, "%H:%M")
    except ValueError:
        errors.append("Choose a valid booking date and time.")
    if request.form.get("emergency") and not provider["emergency_enabled"]:
        errors.append("This provider does not accept emergency requests.")
    if len(form.get("notes", "")) > 1000:
        errors.append("Booking notes are too long.")
    return errors


def validate_email(email: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ""))


def validate_password(password: str) -> bool:
    return len(password or "") >= 8 and bool(re.search(r"[A-Za-z]", password)) and bool(re.search(r"\d", password))


def safe_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
